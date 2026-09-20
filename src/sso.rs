//! Dedicated loopback ports for system apps that share Authentik SSO.
//!
//! Chat and S3 cannot share the chrome port: Vite `base: "/"` would collide with
//! studio `/api/session`. Each app gets `http://127.0.0.1:<port>/` reverse-proxied
//! with the same reqwest cookie jar as the stand (Authentik outpost cookie is
//! `Domain=mcpwork.space`).
//!
//! Chat is AG-UI (CopilotKit-style), not a classic WS-only SPA. The AG-UI 1.0
//! default binding is HTTP POST of `RunAgentInput` JSON with
//! `Accept: text/event-stream`; the run comes back as SSE
//! (`Content-Type: text/event-stream`). HttpAgent also sets those headers.
//! Optional HTTP + protobuf (`application/vnd.ag-ui.event+proto`) is the same
//! POST with a framed body stream. Buffering `res.bytes().await` would hang the
//! composer until the run finished or the GET/write timeout killed it.
//!
//! The Chat SPA's HttpAgent URL is often an absolute `chat.mcpwork.space`
//! origin. That hop never sees the native jar (WebView cookies: Tauri #12988 /
//! #13045). Chat HTML is patched with a small inject script so fetch /
//! EventSource / HttpAgent hit studio-owned `POST /api/studio/ag-ui`. Rust
//! then forwards with the Authentik jar. Injected HTML is stored in
//! [`crate::inject_cache::InjectCache`]; the SSE byte stream never consults it.
//!
//! WebView cookies stay unused. Set-Cookie from the origin is kept in the jar,
//! not copied to the iframe. WebSocket upgrades stay 501 (jar lives in Rust;
//! default AG-UI does not need WS). SSE streaming is the AG-UI path that must
//! work: bytes as-is, 15 minute timeout, `Accept-Encoding: identity`.

use std::sync::Arc;
use std::time::Duration;

use axum::body::{Body, Bytes};
use axum::extract::State;
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Uri};
use axum::response::IntoResponse;
use axum::routing::{any, get};
use axum::Router;
use reqwest::Response;

use crate::apps::SystemTab;
use crate::config::StudioConfig;
use crate::inject::{
    agui_upstream_path, is_html_content_type_str, is_javascript_content_type,
    rewrite_http_agent_urls, script_src_for_request, STUDIO_AGUI_PATH, STUDIO_INJECT_JS_PATH,
};
use crate::inject_cache::{is_stream_media, InjectCache, InjectObject};
use crate::proxy::Proxy;
use crate::session::Session;

pub use crate::inject::{
    inject_agui_markup, sanitize_agui_target, INJECT_JS as AGUI_INJECT_JS,
    INJECT_MARKER as AGUI_INJECT_MARKER, STUDIO_AGUI_PATH as AGUI_ENDPOINT,
    STUDIO_INJECT_JS_PATH as AGUI_INJECT_JS_PATH,
};

const SKIP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
    "host",
    "cookie",
    "set-cookie",
    "content-length",
    "content-encoding",
    "accept-encoding",
    "origin",
    "referer",
    "x-studio-agui-url",
];

#[derive(Debug, Clone)]
pub struct SsoBind {
    pub tab: SystemTab,
    pub origin: String,
    pub port: u16,
}

impl SsoBind {
    pub fn chrome_path(&self) -> String {
        format!("http://127.0.0.1:{}/", self.port)
    }
}

#[derive(Clone)]
struct SsoState {
    proxy: Arc<Proxy>,
    origin: String,
    tab: SystemTab,
    inject_cache: Arc<InjectCache>,
}

pub fn router(proxy: Arc<Proxy>, origin: String) -> Router {
    router_for(proxy, origin, SystemTab::Chat)
}

pub fn router_for(proxy: Arc<Proxy>, origin: String, tab: SystemTab) -> Router {
    router_with_cache(proxy, origin, tab, Arc::new(InjectCache::new()))
}

pub fn router_with_cache(
    proxy: Arc<Proxy>,
    origin: String,
    tab: SystemTab,
    inject_cache: Arc<InjectCache>,
) -> Router {
    let mut app = Router::new();
    if tab == SystemTab::Chat {
        app = app
            .route(STUDIO_INJECT_JS_PATH, get(agui_inject_js))
            .route(STUDIO_AGUI_PATH, any(agui_studio));
    }
    app.fallback(any(sso_any)).with_state(SsoState {
        proxy,
        origin,
        tab,
        inject_cache,
    })
}

async fn sso_any(
    State(state): State<SsoState>,
    method: Method,
    headers: HeaderMap,
    uri: Uri,
    body: Bytes,
) -> axum::response::Response {
    if is_websocket_upgrade(&headers) {
        return websocket_unsupported(uri.path());
    }
    let Some(session) = state.proxy.live.session() else {
        return unauthorized();
    };
    let path = if uri.path().is_empty() {
        "/"
    } else {
        uri.path()
    };
    let pq = Proxy::path_and_query(path, uri.query());
    if state.tab == SystemTab::Chat && looks_like_chat_document(&method, path, &headers) {
        return chat_document(&session, &state, path, &pq, headers).await;
    }
    let timeout = sso_timeout(&method, &headers, &pq, &state.proxy.cfg);
    forward_sso(&session, &state.origin, method, &pq, headers, body, timeout).await
}

async fn agui_studio(
    State(state): State<SsoState>,
    method: Method,
    headers: HeaderMap,
    uri: Uri,
    body: Bytes,
) -> axum::response::Response {
    if state.tab != SystemTab::Chat {
        return StatusCode::NOT_FOUND.into_response();
    }
    handle_studio_agui(&state.proxy, &state.origin, method, headers, uri, body).await
}

/// Studio-owned AG-UI run: `session.client` + streamed SSE. Used on the Chat
/// loopback port and on chrome `/api/studio/ag-ui`.
pub async fn handle_studio_agui(
    proxy: &Proxy,
    chat_origin: &str,
    method: Method,
    headers: HeaderMap,
    uri: Uri,
    body: Bytes,
) -> axum::response::Response {
    if is_websocket_upgrade(&headers) {
        return websocket_unsupported(uri.path());
    }
    let Some(session) = proxy.live.session() else {
        return unauthorized();
    };
    let Some(pq) = agui_upstream_path(&headers, uri.query(), chat_origin) else {
        return (
            StatusCode::BAD_REQUEST,
            axum::Json(serde_json::json!({ "error": "ag-ui url вне chat origin" })),
        )
            .into_response();
    };
    let mut incoming = headers;
    if !wants_event_stream(&incoming) {
        incoming.insert(
            axum::http::header::ACCEPT,
            HeaderValue::from_static("text/event-stream"),
        );
    }
    // Stream path: never consult InjectCache.
    let mut res = forward_sso(
        &session,
        chat_origin,
        method,
        &pq,
        incoming,
        body,
        proxy.cfg.stream_timeout,
    )
    .await;
    res.headers_mut().insert(
        HeaderName::from_static("x-studio-agui"),
        HeaderValue::from_static("inject"),
    );
    res
}

async fn agui_inject_js() -> axum::response::Response {
    let script = InjectObject::script();
    let mut res = axum::response::Response::new(Body::from(script.body));
    res.headers_mut().insert(
        axum::http::header::CONTENT_TYPE,
        HeaderValue::from_static("text/javascript; charset=utf-8"),
    );
    res.headers_mut().insert(
        axum::http::header::CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=86400"),
    );
    res.headers_mut().insert(
        HeaderName::from_static("x-studio-agui"),
        HeaderValue::from_static("inject"),
    );
    res.headers_mut().insert(
        HeaderName::from_static("x-studio-inject-cache"),
        HeaderValue::from_static("script"),
    );
    res
}

fn unauthorized() -> axum::response::Response {
    (
        StatusCode::UNAUTHORIZED,
        axum::Json(serde_json::json!({ "error": "нужен вход" })),
    )
        .into_response()
}

/// Chat HTML (and rewritten JS) GET: cache lookup → fetch → inject → store.
/// Does not run for SSE / POST RunAgentInput.
async fn chat_document(
    session: &Session,
    state: &SsoState,
    path: &str,
    path_and_query: &str,
    incoming: HeaderMap,
) -> axum::response::Response {
    let origin = state.origin.trim_end_matches('/');
    let url = format!("{origin}{path_and_query}");
    let expect_js = path.rsplit('.').next() == Some("js");
    let key_ct = if expect_js {
        "text/javascript"
    } else {
        "text/html"
    };
    let key = InjectCache::key(&url, key_ct);
    if let Some(hit) = state.inject_cache.get_fresh(&key) {
        return inject_object_response(hit, "hit");
    }

    let timeout = state.proxy.cfg.get_timeout;
    let mut req = session.client.get(&url).timeout(timeout);
    req = attach_forward_headers(req, origin, &incoming, false);
    if let Some(stale) = state.inject_cache.get(&key) {
        if let Some(etag) = &stale.etag {
            if let Ok(val) = HeaderValue::from_str(etag) {
                req = req.header(axum::http::header::IF_NONE_MATCH, val);
            }
        }
        if let Some(lm) = &stale.last_modified {
            if let Ok(val) = HeaderValue::from_str(lm) {
                req = req.header(axum::http::header::IF_MODIFIED_SINCE, val);
            }
        }
    }

    match req.send().await {
        Ok(res) => {
            if sso_unusable(&res, origin) {
                if let Some(hit) = state.inject_cache.get(&key) {
                    return inject_object_response(hit, "stale");
                }
                return error_html(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "оффлайн: Authentik отправил на логин. Сначала войдите в стол — cookie общий на mcpwork.space.",
                );
            }
            if res.status() == reqwest::StatusCode::NOT_MODIFIED {
                if let Some(hit) = state.inject_cache.get(&key) {
                    state.inject_cache.touch(&key);
                    return inject_object_response(hit, "revalidated");
                }
            }
            let ct = content_type_of(&res);
            if is_stream_media(&ct) {
                return sso_response(res);
            }
            if is_javascript_content_type(&ct) {
                return finish_js(res, origin, &url, path, &incoming, &state.inject_cache).await;
            }
            if !is_html_content_type_str(&ct) {
                return sso_response(res);
            }
            finish_html(res, origin, &url, path, &incoming, &state.inject_cache).await
        }
        Err(err) => {
            if let Some(hit) = state.inject_cache.get(&key) {
                return inject_object_response(hit, "stale");
            }
            error_html(
                StatusCode::BAD_GATEWAY,
                &format!("прокси SSO не достучался до {origin}: {err}"),
            )
        }
    }
}

async fn finish_html(
    res: Response,
    origin: &str,
    url: &str,
    path: &str,
    incoming: &HeaderMap,
    cache: &InjectCache,
) -> axum::response::Response {
    let status = res.status().as_u16();
    let etag = header_string(&res, reqwest::header::ETAG);
    let last_modified = header_string(&res, reqwest::header::LAST_MODIFIED);
    let bytes = match res.bytes().await {
        Ok(b) => b,
        Err(err) => {
            return error_html(StatusCode::BAD_GATEWAY, &err.to_string());
        }
    };
    let src = script_src_for_request(incoming);
    let html = inject_agui_markup(
        &rewrite_http_agent_urls(&String::from_utf8_lossy(&bytes), origin),
        &src,
    );
    let object = InjectObject::html(status, Bytes::from(html.into_bytes()), etag, last_modified);
    let accept = incoming
        .get(axum::http::header::ACCEPT)
        .and_then(|v| v.to_str().ok());
    if InjectCache::may_store("GET", accept, "text/html", path) {
        cache.put(InjectCache::key(url, "text/html"), object.clone());
    }
    inject_object_response(object, "miss")
}

async fn finish_js(
    res: Response,
    origin: &str,
    url: &str,
    path: &str,
    incoming: &HeaderMap,
    cache: &InjectCache,
) -> axum::response::Response {
    let status = res.status().as_u16();
    let ct = content_type_of(&res);
    let etag = header_string(&res, reqwest::header::ETAG);
    let last_modified = header_string(&res, reqwest::header::LAST_MODIFIED);
    let cache_control = header_string(&res, reqwest::header::CACHE_CONTROL);
    let bytes = match res.bytes().await {
        Ok(b) => b,
        Err(err) => {
            return error_html(StatusCode::BAD_GATEWAY, &err.to_string());
        }
    };
    let text = String::from_utf8_lossy(&bytes);
    let rewritten = rewrite_http_agent_urls(&text, origin);
    if rewritten != text {
        let object = InjectObject::asset(
            status,
            ct,
            Bytes::from(rewritten.into_bytes()),
            etag,
            last_modified,
            cache_control.as_deref(),
        );
        let accept = incoming
            .get(axum::http::header::ACCEPT)
            .and_then(|v| v.to_str().ok());
        if InjectCache::may_store("GET", accept, "text/javascript", path) {
            cache.put(InjectCache::key(url, "text/javascript"), object.clone());
        }
        return inject_object_response(object, "miss");
    }
    let mut out = axum::response::Response::new(Body::from(bytes));
    *out.status_mut() = StatusCode::from_u16(status).unwrap_or(StatusCode::OK);
    if let Ok(val) = HeaderValue::from_str(&ct) {
        out.headers_mut()
            .insert(axum::http::header::CONTENT_TYPE, val);
    }
    out.headers_mut().insert(
        HeaderName::from_static("x-studio-sso"),
        HeaderValue::from_static("live"),
    );
    out
}

fn inject_object_response(
    hit: InjectObject,
    cache_state: &'static str,
) -> axum::response::Response {
    let kind = match hit.kind {
        crate::inject_cache::ArtifactKind::Html => "html",
        crate::inject_cache::ArtifactKind::Script => "script",
        crate::inject_cache::ArtifactKind::Asset => "asset",
    };
    let mut res = axum::response::Response::new(Body::from(hit.body));
    *res.status_mut() = StatusCode::from_u16(hit.status).unwrap_or(StatusCode::OK);
    if let Ok(val) = HeaderValue::from_str(&hit.content_type) {
        res.headers_mut()
            .insert(axum::http::header::CONTENT_TYPE, val);
    }
    res.headers_mut().insert(
        HeaderName::from_static("x-studio-sso"),
        HeaderValue::from_static("live"),
    );
    res.headers_mut().insert(
        HeaderName::from_static("x-studio-agui"),
        HeaderValue::from_static("inject"),
    );
    res.headers_mut().insert(
        HeaderName::from_static("x-studio-inject-cache"),
        HeaderValue::from_static(cache_state),
    );
    res.headers_mut().insert(
        HeaderName::from_static("x-studio-agui-inject"),
        HeaderValue::from_static(kind),
    );
    res.headers_mut()
        .remove(axum::http::header::CONTENT_SECURITY_POLICY);
    res.headers_mut().remove(HeaderName::from_static(
        "content-security-policy-report-only",
    ));
    if let Some(etag) = hit.etag {
        if let Ok(val) = HeaderValue::from_str(&etag) {
            res.headers_mut().insert(axum::http::header::ETAG, val);
        }
    }
    res
}

fn header_string(res: &Response, name: reqwest::header::HeaderName) -> Option<String> {
    res.headers()
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
}

fn content_type_of(res: &Response) -> String {
    res.headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/octet-stream")
        .to_string()
}

fn looks_like_chat_document(method: &Method, path: &str, headers: &HeaderMap) -> bool {
    if *method != Method::GET {
        return false;
    }
    if is_sse_request(headers, path) {
        return false;
    }
    let path_only = path.split('?').next().unwrap_or(path);
    if is_obvious_non_document(path_only) {
        return false;
    }
    let accept = headers
        .get(axum::http::header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if is_stream_media(accept) {
        return false;
    }
    let accept_l = accept.to_ascii_lowercase();
    path_only == "/"
        || path_only.ends_with('/')
        || path_only.ends_with(".html")
        || path_only.ends_with(".js")
        || accept_l.contains("text/html")
        || accept_l.contains("javascript")
}

fn is_obvious_non_document(path: &str) -> bool {
    let p = path.to_ascii_lowercase();
    p.ends_with(".css")
        || p.ends_with(".png")
        || p.ends_with(".jpg")
        || p.ends_with(".jpeg")
        || p.ends_with(".gif")
        || p.ends_with(".svg")
        || p.ends_with(".webp")
        || p.ends_with(".ico")
        || p.ends_with(".woff")
        || p.ends_with(".woff2")
        || p.ends_with(".ttf")
        || p.ends_with(".map")
}

fn attach_forward_headers(
    mut req: reqwest::RequestBuilder,
    origin: &str,
    incoming: &HeaderMap,
    identity: bool,
) -> reqwest::RequestBuilder {
    for (name, value) in incoming.iter() {
        if SKIP.contains(&name.as_str()) {
            continue;
        }
        req = req.header(name.clone(), value.clone());
    }
    if let Ok(val) = HeaderValue::from_str(origin) {
        req = req.header("origin", val);
    }
    if let Ok(val) = HeaderValue::from_str(&format!("{origin}/")) {
        req = req.header("referer", val);
    }
    if identity {
        req = req.header(
            axum::http::header::ACCEPT_ENCODING,
            HeaderValue::from_static("identity"),
        );
    }
    req
}

pub async fn forward_sso(
    session: &Session,
    origin: &str,
    method: Method,
    path_and_query: &str,
    incoming: HeaderMap,
    body: Bytes,
    timeout: Duration,
) -> axum::response::Response {
    let origin = origin.trim_end_matches('/');
    let url = format!("{origin}{path_and_query}");
    let stream_run = is_sse_request(&incoming, path_and_query);
    let client = if stream_run {
        &session.stream_client
    } else {
        &session.client
    };
    let mut req = client
        .request(
            reqwest::Method::from_bytes(method.as_str().as_bytes()).unwrap_or(reqwest::Method::GET),
            &url,
        )
        .timeout(timeout);
    req = attach_forward_headers(req, origin, &incoming, stream_run);
    if !body.is_empty() && method != Method::GET && method != Method::HEAD {
        req = req.body(body);
    }
    match req.send().await {
        Ok(res) => {
            if sso_unusable(&res, origin) {
                return error_html(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "оффлайн: Authentik отправил на логин. Сначала войдите в стол — cookie общий на mcpwork.space.",
                );
            }
            sso_response(res)
        }
        Err(err) => error_html(
            StatusCode::BAD_GATEWAY,
            &format!("прокси SSO не достучался до {origin}: {err}"),
        ),
    }
}

fn sso_unusable(res: &Response, origin: &str) -> bool {
    !StudioConfig::url_matches_origin(res.url(), origin)
}

/// AG-UI HttpAgent: `Accept: text/event-stream`. Protobuf binding adds
/// `application/vnd.ag-ui.event+proto` on the same POST.
/// Live METRO-ARK chat also GETs `/api/runs/{id}?since=` as SSE.
fn wants_event_stream(headers: &HeaderMap) -> bool {
    accept_is_agui_stream(headers.get(axum::http::header::ACCEPT))
}

fn is_runs_sse_path(path: &str) -> bool {
    let p = path.split('?').next().unwrap_or(path);
    p == "/api/runs" || p.starts_with("/api/runs/")
}

fn is_sse_request(headers: &HeaderMap, path: &str) -> bool {
    wants_event_stream(headers) || is_runs_sse_path(path)
}

fn accept_is_agui_stream(value: Option<&HeaderValue>) -> bool {
    value
        .and_then(|v| v.to_str().ok())
        .is_some_and(is_agui_stream_accept)
}

fn is_agui_stream_accept(accept: &str) -> bool {
    let accept = accept.to_ascii_lowercase();
    accept.contains("text/event-stream") || accept.contains("application/vnd.ag-ui.event+proto")
}

fn sso_timeout(method: &Method, incoming: &HeaderMap, path: &str, cfg: &StudioConfig) -> Duration {
    if is_sse_request(incoming, path) {
        cfg.stream_timeout
    } else if *method == Method::GET || *method == Method::HEAD {
        cfg.get_timeout
    } else {
        cfg.write_timeout
    }
}

fn is_event_stream_content_type(headers: &HeaderMap) -> bool {
    headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(is_stream_media)
}

/// Stream origin bytes as they arrive. Never injects. Never the inject cache.
fn sso_response(res: Response) -> axum::response::Response {
    let status = StatusCode::from_u16(res.status().as_u16()).unwrap_or(StatusCode::OK);
    let mut headers = HeaderMap::new();
    for (name, value) in res.headers().iter() {
        if SKIP.contains(&name.as_str()) {
            continue;
        }
        if let Ok(copied) = HeaderValue::from_bytes(value.as_bytes()) {
            headers.append(name.clone(), copied);
        }
    }
    headers.insert(
        HeaderName::from_static("x-studio-sso"),
        HeaderValue::from_static("live"),
    );
    if is_event_stream_content_type(&headers) {
        headers
            .entry(axum::http::header::CACHE_CONTROL)
            .or_insert(HeaderValue::from_static("no-cache"));
        headers
            .entry(HeaderName::from_static("x-accel-buffering"))
            .or_insert(HeaderValue::from_static("no"));
    }
    let mut out = axum::response::Response::new(Body::from_stream(res.bytes_stream()));
    *out.status_mut() = status;
    *out.headers_mut() = headers;
    out
}

fn is_websocket_upgrade(headers: &HeaderMap) -> bool {
    headers
        .get(axum::http::header::UPGRADE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.eq_ignore_ascii_case("websocket"))
}

fn websocket_unsupported(path: &str) -> axum::response::Response {
    error_html(
        StatusCode::NOT_IMPLEMENTED,
        &format!(
            "WebSocket `{path}` студия пока не проксирует (cookie jar в Rust, не в WebView). HTTP/SSE AG-UI к этому origin идёт."
        ),
    )
}

fn error_html(status: StatusCode, message: &str) -> axum::response::Response {
    let body = format!(
        "<!doctype html><html lang=\"ru\"><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
         <title>studio sso</title>\
         <body style=\"background:#161412;color:#e8d5a8;font-family:'DejaVu Sans',sans-serif;padding:24px\">\
         <p>{message}</p></body></html>"
    );
    let mut res = axum::response::Response::new(Body::from(body));
    *res.status_mut() = status;
    res.headers_mut().insert(
        axum::http::header::CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    res
}

pub async fn settle_system_apps(client: &reqwest::Client, cfg: &StudioConfig) {
    for tab in SystemTab::ALL {
        let url = format!("{}/", cfg.origin_for_system(tab));
        let _ = client
            .get(&url)
            .header("Accept", "text/html,application/json")
            .timeout(cfg.probe_timeout.max(Duration::from_secs(8)))
            .send()
            .await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::{now_secs, ReadCache};
    use crate::progress::ProgressHub;
    use crate::session::LiveState;
    use std::convert::Infallible;
    use std::pin::Pin;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::task::{Context, Poll};
    use tokio::runtime::Runtime;
    use tokio::sync::{mpsc, Notify};

    fn dummy_session() -> Session {
        let jar = Arc::new(reqwest::cookie::Jar::default());
        Session::new("s".into(), "u".into(), jar).unwrap()
    }

    fn test_proxy(stand: String, cache_dir: std::path::PathBuf) -> Arc<Proxy> {
        let mut cfg = StudioConfig::production(std::path::PathBuf::from("ui"), 0, Some(cache_dir));
        cfg.stand_host = stand;
        cfg.get_timeout = Duration::from_millis(800);
        cfg.write_timeout = Duration::from_millis(800);
        cfg.stream_timeout = Duration::from_secs(5);
        Arc::new(Proxy {
            cfg,
            cache: ReadCache::open(std::env::temp_dir().join(format!(
                "designer-sso-cache-{}-{}",
                std::process::id(),
                now_secs()
            )))
            .unwrap(),
            live: Arc::new(LiveState::new()),
            progress: ProgressHub::new(),
        })
    }

    /// `mpsc` → `Stream` without a extra crate (axum `Body::from_stream`).
    struct BodyChan {
        rx: mpsc::Receiver<Result<Bytes, Infallible>>,
    }

    impl futures_core::Stream for BodyChan {
        type Item = Result<Bytes, Infallible>;

        fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            self.rx.poll_recv(cx)
        }
    }

    #[test]
    fn unauthenticated_sso_port_is_401() {
        let dir = std::env::temp_dir().join(format!(
            "designer-sso-401-{}-{}",
            std::process::id(),
            now_secs()
        ));
        let _ = std::fs::create_dir_all(&dir);
        let proxy = test_proxy("http://127.0.0.1:1".into(), dir.clone());
        let rt = Runtime::new().unwrap();
        rt.block_on(async {
            let app = router(proxy, "http://127.0.0.1:1".into());
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            tokio::spawn(async move {
                axum::serve(listener, app).await.unwrap();
            });
            let res = reqwest::Client::new()
                .get(format!("http://{addr}/api/me"))
                .send()
                .await
                .unwrap();
            assert_eq!(res.status(), reqwest::StatusCode::UNAUTHORIZED);
        });
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn forwards_csrf_header_and_strips_set_cookie() {
        let dir = std::env::temp_dir().join(format!(
            "designer-sso-fwd-{}-{}",
            std::process::id(),
            now_secs()
        ));
        let _ = std::fs::create_dir_all(&dir);
        let proxy = test_proxy("http://127.0.0.1:1".into(), dir.clone());
        let rt = Runtime::new().unwrap();
        rt.block_on(async {
            use axum::extract::Request;
            let origin_app = axum::Router::new().fallback(|req: Request| async move {
                let csrf = req
                    .headers()
                    .get("x-csrf-token")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("")
                    .to_string();
                let origin = req
                    .headers()
                    .get("origin")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("")
                    .to_string();
                let mut res = axum::response::Response::new(Body::from(format!(
                    "{{\"csrf\":\"{csrf}\",\"origin\":\"{origin}\"}}"
                )));
                res.headers_mut().insert(
                    axum::http::header::CONTENT_TYPE,
                    HeaderValue::from_static("application/json"),
                );
                res.headers_mut().insert(
                    axum::http::header::SET_COOKIE,
                    HeaderValue::from_static("access_token=secret; Path=/; HttpOnly"),
                );
                res
            });
            let origin_lis = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let origin_addr = origin_lis.local_addr().unwrap();
            tokio::spawn(async move {
                axum::serve(origin_lis, origin_app).await.unwrap();
            });
            let origin = format!("http://{origin_addr}");
            proxy.live.set_session(dummy_session());
            let app = router(proxy, origin.clone());
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            tokio::spawn(async move {
                axum::serve(listener, app).await.unwrap();
            });
            let res = reqwest::Client::new()
                .post(format!("http://{addr}/api/me"))
                .header("x-csrf-token", "tok-1")
                .header("cookie", "should-not-leak=1")
                .send()
                .await
                .unwrap();
            assert_eq!(res.status(), reqwest::StatusCode::OK);
            assert!(res.headers().get("set-cookie").is_none());
            assert_eq!(
                res.headers()
                    .get("x-studio-sso")
                    .and_then(|v| v.to_str().ok()),
                Some("live")
            );
            let json: serde_json::Value = res.json().await.unwrap();
            assert_eq!(json["csrf"], "tok-1");
            assert_eq!(json["origin"], origin);
        });
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn login_redirect_off_origin_is_unusable() {
        let dir = std::env::temp_dir().join(format!(
            "designer-sso-redir-{}-{}",
            std::process::id(),
            now_secs()
        ));
        let _ = std::fs::create_dir_all(&dir);
        let session = dummy_session();
        let rt = Runtime::new().unwrap();
        rt.block_on(async {
            let login = axum::Router::new().fallback(|| async { "authentik login" });
            let login_lis = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let login_addr = login_lis.local_addr().unwrap();
            tokio::spawn(async move {
                axum::serve(login_lis, login).await.unwrap();
            });
            let login_url = format!("http://{login_addr}/if/flow/");
            let app = axum::Router::new().fallback(move || {
                let target = login_url.clone();
                async move { axum::response::Redirect::temporary(&target) }
            });
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            tokio::spawn(async move {
                axum::serve(listener, app).await.unwrap();
            });
            let origin = format!("http://{addr}");
            let res = forward_sso(
                &session,
                &origin,
                Method::GET,
                "/",
                HeaderMap::new(),
                Bytes::new(),
                Duration::from_millis(800),
            )
            .await;
            assert_eq!(res.status(), StatusCode::SERVICE_UNAVAILABLE);
        });
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn websocket_upgrade_is_not_proxied() {
        assert!(is_websocket_upgrade(&{
            let mut h = HeaderMap::new();
            h.insert(
                axum::http::header::UPGRADE,
                HeaderValue::from_static("websocket"),
            );
            h
        }));
        assert!(!is_websocket_upgrade(&HeaderMap::new()));
    }

    #[test]
    fn agui_accept_uses_stream_timeout() {
        let cfg = StudioConfig::production(std::path::PathBuf::from("ui"), 0, None);
        let mut sse = HeaderMap::new();
        sse.insert(
            axum::http::header::ACCEPT,
            HeaderValue::from_static("text/event-stream"),
        );
        assert_eq!(
            sso_timeout(&Method::POST, &sse, "/agent", &cfg),
            cfg.stream_timeout
        );
        assert_eq!(
            sso_timeout(&Method::GET, &sse, "/api/runs/x", &cfg),
            cfg.stream_timeout
        );
        assert_eq!(
            sso_timeout(&Method::GET, &HeaderMap::new(), "/api/runs/x?since=0", &cfg),
            cfg.stream_timeout
        );
        assert_ne!(cfg.stream_timeout, cfg.get_timeout);
        assert_ne!(cfg.stream_timeout, cfg.write_timeout);
        assert!(cfg.stream_timeout >= Duration::from_secs(5 * 60));

        let mut proto = HeaderMap::new();
        proto.insert(
            axum::http::header::ACCEPT,
            HeaderValue::from_static("application/vnd.ag-ui.event+proto, text/event-stream;q=0.9"),
        );
        assert_eq!(
            sso_timeout(&Method::POST, &proto, "/agent", &cfg),
            cfg.stream_timeout
        );
        assert_eq!(
            sso_timeout(&Method::GET, &HeaderMap::new(), "/", &cfg),
            cfg.get_timeout
        );
        assert_eq!(
            sso_timeout(&Method::POST, &HeaderMap::new(), "/api/agent/game", &cfg),
            cfg.write_timeout
        );
        assert!(wants_event_stream(&sse));
        assert!(!wants_event_stream(&HeaderMap::new()));
        assert!(is_runs_sse_path(
            "/api/runs/30289690-b756-416a-ac0d-5bc9a3396ef7"
        ));
        assert!(!is_runs_sse_path("/api/agent/game"));
    }

    #[test]
    fn streams_sse_first_chunk_before_origin_finishes() {
        let dir = std::env::temp_dir().join(format!(
            "designer-sso-sse-{}-{}",
            std::process::id(),
            now_secs()
        ));
        let _ = std::fs::create_dir_all(&dir);
        let proxy = test_proxy("http://127.0.0.1:1".into(), dir.clone());
        let rt = Runtime::new().unwrap();
        rt.block_on(async {
            let release = Arc::new(Notify::new());
            let first_sent = Arc::new(AtomicBool::new(false));
            let origin_app = {
                let release = release.clone();
                let first_sent = first_sent.clone();
                axum::Router::new().route(
                    "/agent",
                    axum::routing::post(move |req: axum::extract::Request| {
                        let release = release.clone();
                        let first_sent = first_sent.clone();
                        async move {
                            let accept_enc = req
                                .headers()
                                .get(axum::http::header::ACCEPT_ENCODING)
                                .and_then(|v| v.to_str().ok())
                                .unwrap_or("")
                                .to_string();
                            let accept = req
                                .headers()
                                .get(axum::http::header::ACCEPT)
                                .and_then(|v| v.to_str().ok())
                                .unwrap_or("")
                                .to_string();
                            let csrf = req
                                .headers()
                                .get("x-csrf-token")
                                .and_then(|v| v.to_str().ok())
                                .unwrap_or("")
                                .to_string();
                            let ctype = req
                                .headers()
                                .get(axum::http::header::CONTENT_TYPE)
                                .and_then(|v| v.to_str().ok())
                                .unwrap_or("")
                                .to_string();
                            let (tx, rx) = mpsc::channel::<Result<Bytes, Infallible>>(4);
                            tokio::spawn(async move {
                                let chunk = format!(
                                    "data: {{\"type\":\"RUN_STARTED\",\"ae\":\"{accept_enc}\",\"accept\":\"{accept}\",\"csrf\":\"{csrf}\",\"ct\":\"{ctype}\"}}\n\n"
                                );
                                let _ = tx.send(Ok(Bytes::from(chunk))).await;
                                first_sent.store(true, Ordering::SeqCst);
                                release.notified().await;
                                let _ = tx
                                    .send(Ok(Bytes::from(
                                        "data: {\"type\":\"RUN_FINISHED\"}\n\n",
                                    )))
                                    .await;
                            });
                            let mut res = axum::response::Response::new(Body::from_stream(
                                BodyChan { rx },
                            ));
                            res.headers_mut().insert(
                                axum::http::header::CONTENT_TYPE,
                                HeaderValue::from_static("text/event-stream"),
                            );
                            res.headers_mut().insert(
                                axum::http::header::CACHE_CONTROL,
                                HeaderValue::from_static("no-cache"),
                            );
                            res.headers_mut().insert(
                                HeaderName::from_static("x-accel-buffering"),
                                HeaderValue::from_static("no"),
                            );
                            res.headers_mut().insert(
                                axum::http::header::SET_COOKIE,
                                HeaderValue::from_static("access_token=secret; Path=/; HttpOnly"),
                            );
                            res
                        }
                    }),
                )
            };
            let origin_lis = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let origin_addr = origin_lis.local_addr().unwrap();
            tokio::spawn(async move {
                axum::serve(origin_lis, origin_app).await.unwrap();
            });
            let origin = format!("http://{origin_addr}");
            proxy.live.set_session(dummy_session());
            let app = router(proxy, origin);
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            tokio::spawn(async move {
                axum::serve(listener, app).await.unwrap();
            });

            let mut res = reqwest::Client::new()
                .post(format!("http://{addr}/agent"))
                .header("accept", "text/event-stream")
                .header("content-type", "application/json")
                .header("x-csrf-token", "tok-sse")
                .body(r#"{"threadId":"t1","runId":"r1","messages":[]}"#)
                .send()
                .await
                .unwrap();
            assert_eq!(res.status(), reqwest::StatusCode::OK);
            assert!(res.headers().get("set-cookie").is_none());
            let ct = res
                .headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            assert!(
                ct.contains("text/event-stream"),
                "content-type was {ct}"
            );
            assert_eq!(
                res.headers()
                    .get("cache-control")
                    .and_then(|v| v.to_str().ok()),
                Some("no-cache")
            );
            assert_eq!(
                res.headers()
                    .get("x-accel-buffering")
                    .and_then(|v| v.to_str().ok()),
                Some("no")
            );

            // First SSE event must arrive while origin is still blocked on `release`.
            // write_timeout is 800ms; sleeping past that proves stream_timeout is used.
            let first = tokio::time::timeout(Duration::from_millis(400), res.chunk())
                .await
                .expect("first SSE chunk must not wait for the origin run to finish")
                .expect("chunk")
                .expect("body");
            let first = String::from_utf8_lossy(&first);
            assert!(
                first.contains("RUN_STARTED"),
                "unexpected first chunk: {first}"
            );
            assert!(first.contains("\"ae\":\"identity\""));
            assert!(first.contains("text/event-stream"));
            assert!(first.contains("tok-sse"));
            assert!(first.contains("application/json"));
            assert!(
                first_sent.load(Ordering::SeqCst),
                "origin must have emitted the first chunk"
            );
            assert!(
                !first.contains("RUN_FINISHED"),
                "must not buffer the rest of the run: {first}"
            );

            tokio::time::sleep(Duration::from_millis(1200)).await;
            release.notify_one();

            let mut rest = Vec::new();
            while let Some(chunk) = res.chunk().await.unwrap() {
                rest.extend_from_slice(&chunk);
            }
            let rest = String::from_utf8_lossy(&rest);
            assert!(
                rest.contains("RUN_FINISHED"),
                "missing terminal event after release: {rest}"
            );
        });
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn inject_markup_lands_in_head_once() {
        let html = "<!doctype html><html><head><title>chat</title></head><body>ok</body></html>";
        let out = inject_agui_markup(html, "http://127.0.0.1:9/api/studio/ag-ui-inject.js");
        assert!(out.contains(AGUI_INJECT_MARKER));
        assert!(out.contains("/api/studio/ag-ui-inject.js"));
        let head = out.split("</head>").next().unwrap();
        assert!(head.contains(AGUI_INJECT_MARKER));
        let twice = inject_agui_markup(&out, "/nope.js");
        assert_eq!(twice.matches(AGUI_INJECT_MARKER).count(), 1);
        assert!(!twice.contains("/nope.js"));
        let bare = inject_agui_markup("<p>no head</p>", "/api/studio/ag-ui-inject.js");
        assert!(bare.contains(&format!(
            "<script id=\"studio-agui-inject\" src=\"/api/studio/ag-ui-inject.js\" {AGUI_INJECT_MARKER}>"
        )));
        assert!(AGUI_INJECT_JS.contains("__STUDIO_AGUI_INJECT__"));
        assert!(AGUI_INJECT_JS.contains("/api/studio/ag-ui"));
        assert!(AGUI_INJECT_JS.contains("X-Studio-Agui-Url"));
        assert!(AGUI_INJECT_JS.contains("text/event-stream"));
        assert!(AGUI_INJECT_JS.contains("application/json"));
        assert!(AGUI_INJECT_JS.contains("EventSource"));
        assert!(!AGUI_INJECT_JS.contains("looksAguiUrl"));
    }

    #[test]
    fn agui_target_stays_on_chat_origin() {
        assert_eq!(
            sanitize_agui_target("/agent", "https://chat.mcpwork.space").as_deref(),
            Some("/agent")
        );
        assert_eq!(
            sanitize_agui_target(
                "https://chat.mcpwork.space/api/copilotkit?x=1",
                "https://chat.mcpwork.space"
            )
            .as_deref(),
            Some("/api/copilotkit?x=1")
        );
        assert!(
            sanitize_agui_target("https://evil.example/agent", "https://chat.mcpwork.space")
                .is_none()
        );
        assert!(
            sanitize_agui_target(AGUI_ENDPOINT, "https://chat.mcpwork.space").is_none(),
            "studio streamer path must not loop"
        );
    }

    #[test]
    fn chat_html_gets_agui_inject_s3_does_not() {
        let dir = std::env::temp_dir().join(format!(
            "designer-sso-inject-html-{}-{}",
            std::process::id(),
            now_secs()
        ));
        let _ = std::fs::create_dir_all(&dir);
        let rt = Runtime::new().unwrap();
        rt.block_on(async {
            let origin_app = axum::Router::new().fallback(|| async {
                let mut res = axum::response::Response::new(Body::from(
                    "<!doctype html><html><head><title>app</title></head><body>desk</body></html>",
                ));
                res.headers_mut().insert(
                    axum::http::header::CONTENT_TYPE,
                    HeaderValue::from_static("text/html; charset=utf-8"),
                );
                res.headers_mut().insert(
                    axum::http::header::CONTENT_SECURITY_POLICY,
                    HeaderValue::from_static("script-src 'self'"),
                );
                res
            });
            let origin_lis = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let origin_addr = origin_lis.local_addr().unwrap();
            tokio::spawn(async move {
                axum::serve(origin_lis, origin_app).await.unwrap();
            });
            let origin = format!("http://{origin_addr}");

            let chat_proxy = test_proxy("http://127.0.0.1:1".into(), dir.join("chat"));
            chat_proxy.live.set_session(dummy_session());
            let chat_app = router_for(chat_proxy, origin.clone(), SystemTab::Chat);
            let chat_lis = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let chat_addr = chat_lis.local_addr().unwrap();
            tokio::spawn(async move {
                axum::serve(chat_lis, chat_app).await.unwrap();
            });

            let s3_proxy = test_proxy("http://127.0.0.1:1".into(), dir.join("s3"));
            s3_proxy.live.set_session(dummy_session());
            let s3_app = router_for(s3_proxy, origin, SystemTab::S3);
            let s3_lis = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let s3_addr = s3_lis.local_addr().unwrap();
            tokio::spawn(async move {
                axum::serve(s3_lis, s3_app).await.unwrap();
            });

            let client = reqwest::Client::new();
            let chat = client
                .get(format!("http://{chat_addr}/"))
                .send()
                .await
                .unwrap();
            assert_eq!(chat.status(), reqwest::StatusCode::OK);
            assert_eq!(
                chat.headers()
                    .get("x-studio-agui")
                    .and_then(|v| v.to_str().ok()),
                Some("inject")
            );
            assert!(chat.headers().get("content-security-policy").is_none());
            let chat_html = chat.text().await.unwrap();
            assert!(
                chat_html.contains(AGUI_INJECT_MARKER),
                "chat html missing inject: {chat_html}"
            );
            assert!(chat_html.contains("/api/studio/ag-ui-inject.js"));
            assert!(chat_html.contains("<title>app</title>"));

            let js = client
                .get(format!(
                    "http://{chat_addr}{AGUI_INJECT_JS_PATH}"
                ))
                .send()
                .await
                .unwrap();
            assert_eq!(js.status(), reqwest::StatusCode::OK);
            let js_body = js.text().await.unwrap();
            assert!(js_body.contains("window.fetch"));
            assert!(js_body.contains("/api/studio/ag-ui"));

            let s3 = client
                .get(format!("http://{s3_addr}/"))
                .send()
                .await
                .unwrap();
            assert_eq!(s3.status(), reqwest::StatusCode::OK);
            assert!(s3.headers().get("x-studio-agui").is_none());
            let s3_html = s3.text().await.unwrap();
            assert!(
                !s3_html.contains(AGUI_INJECT_MARKER),
                "s3 html must not be patched: {s3_html}"
            );
            assert!(!s3_html.contains("/api/studio/ag-ui-inject.js"));
            assert_eq!(
                client
                    .get(format!("http://{s3_addr}{AGUI_INJECT_JS_PATH}"))
                    .send()
                    .await
                    .unwrap()
                    .status(),
                reqwest::StatusCode::OK,
                "s3 fallback may proxy the path to origin HTML, but must not serve inject js as a studio route"
            );
            // S3 has no studio inject route; origin HTML fallback is not the inject script.
            let s3_js = client
                .get(format!("http://{s3_addr}{AGUI_INJECT_JS_PATH}"))
                .send()
                .await
                .unwrap()
                .text()
                .await
                .unwrap();
            assert!(
                !s3_js.contains("__STUDIO_AGUI_INJECT__"),
                "s3 must not serve the chat inject script"
            );
        });
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn studio_agui_endpoint_streams_first_chunk_before_origin_finishes() {
        let dir = std::env::temp_dir().join(format!(
            "designer-sso-agui-inject-sse-{}-{}",
            std::process::id(),
            now_secs()
        ));
        let _ = std::fs::create_dir_all(&dir);
        let proxy = test_proxy("http://127.0.0.1:1".into(), dir.clone());
        let rt = Runtime::new().unwrap();
        rt.block_on(async {
            let release = Arc::new(Notify::new());
            let first_sent = Arc::new(AtomicBool::new(false));
            let origin_app = {
                let release = release.clone();
                let first_sent = first_sent.clone();
                axum::Router::new().route(
                    "/agent",
                    axum::routing::post(move |req: axum::extract::Request| {
                        let release = release.clone();
                        let first_sent = first_sent.clone();
                        async move {
                            let accept_enc = req
                                .headers()
                                .get(axum::http::header::ACCEPT_ENCODING)
                                .and_then(|v| v.to_str().ok())
                                .unwrap_or("")
                                .to_string();
                            let accept = req
                                .headers()
                                .get(axum::http::header::ACCEPT)
                                .and_then(|v| v.to_str().ok())
                                .unwrap_or("")
                                .to_string();
                            let leaked = req
                                .headers()
                                .get("x-studio-agui-url")
                                .is_some();
                            let (tx, rx) = mpsc::channel::<Result<Bytes, Infallible>>(4);
                            tokio::spawn(async move {
                                let chunk = format!(
                                    "data: {{\"type\":\"RUN_STARTED\",\"ae\":\"{accept_enc}\",\"accept\":\"{accept}\",\"leaked\":{leaked}}}\n\n"
                                );
                                let _ = tx.send(Ok(Bytes::from(chunk))).await;
                                first_sent.store(true, Ordering::SeqCst);
                                release.notified().await;
                                let _ = tx
                                    .send(Ok(Bytes::from(
                                        "data: {\"type\":\"RUN_FINISHED\"}\n\n",
                                    )))
                                    .await;
                            });
                            let mut res =
                                axum::response::Response::new(Body::from_stream(BodyChan { rx }));
                            res.headers_mut().insert(
                                axum::http::header::CONTENT_TYPE,
                                HeaderValue::from_static("text/event-stream"),
                            );
                            res
                        }
                    }),
                )
            };
            let origin_lis = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let origin_addr = origin_lis.local_addr().unwrap();
            tokio::spawn(async move {
                axum::serve(origin_lis, origin_app).await.unwrap();
            });
            let origin = format!("http://{origin_addr}");
            proxy.live.set_session(dummy_session());
            let app = router_for(proxy, origin.clone(), SystemTab::Chat);
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            tokio::spawn(async move {
                axum::serve(listener, app).await.unwrap();
            });

            let mut res = reqwest::Client::new()
                .post(format!("http://{addr}{AGUI_ENDPOINT}"))
                .header("accept", "text/event-stream")
                .header("content-type", "application/json")
                .header("x-studio-agui-url", format!("{origin}/agent"))
                .header("x-studio-agui-url-evil", "https://evil.example/agent")
                .body(r#"{"threadId":"t1","runId":"r1","messages":[]}"#)
                .send()
                .await
                .unwrap();
            assert_eq!(res.status(), reqwest::StatusCode::OK);
            assert_eq!(
                res.headers()
                    .get("x-studio-agui")
                    .and_then(|v| v.to_str().ok()),
                Some("inject")
            );
            let ct = res
                .headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            assert!(ct.contains("text/event-stream"), "content-type was {ct}");
            assert_eq!(
                res.headers()
                    .get("cache-control")
                    .and_then(|v| v.to_str().ok()),
                Some("no-cache")
            );
            assert_eq!(
                res.headers()
                    .get("x-accel-buffering")
                    .and_then(|v| v.to_str().ok()),
                Some("no")
            );

            let first = tokio::time::timeout(Duration::from_millis(400), res.chunk())
                .await
                .expect("first SSE chunk must not wait for the origin run to finish")
                .expect("chunk")
                .expect("body");
            let first = String::from_utf8_lossy(&first);
            assert!(
                first.contains("RUN_STARTED"),
                "unexpected first chunk: {first}"
            );
            assert!(first.contains("\"ae\":\"identity\""));
            assert!(first.contains("text/event-stream"));
            assert!(first.contains("\"leaked\":false"));
            assert!(!first.contains("RUN_FINISHED"));
            assert!(first_sent.load(Ordering::SeqCst));

            tokio::time::sleep(Duration::from_millis(1200)).await;
            release.notify_one();
            let mut rest = Vec::new();
            while let Some(chunk) = res.chunk().await.unwrap() {
                rest.extend_from_slice(&chunk);
            }
            assert!(String::from_utf8_lossy(&rest).contains("RUN_FINISHED"));

            let blocked = reqwest::Client::new()
                .post(format!("http://{addr}{AGUI_ENDPOINT}"))
                .header("accept", "text/event-stream")
                .header("x-studio-agui-url", "https://evil.example/agent")
                .body("{}")
                .send()
                .await
                .unwrap();
            assert_eq!(blocked.status(), reqwest::StatusCode::BAD_REQUEST);
        });
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn websocket_upgrade_returns_501_on_sso_and_agui() {
        let dir = std::env::temp_dir().join(format!(
            "designer-sso-ws-501-{}-{}",
            std::process::id(),
            now_secs()
        ));
        let _ = std::fs::create_dir_all(&dir);
        let proxy = test_proxy("http://127.0.0.1:1".into(), dir.clone());
        let rt = Runtime::new().unwrap();
        rt.block_on(async {
            proxy.live.set_session(dummy_session());
            let app = router_for(proxy, "http://127.0.0.1:1".into(), SystemTab::Chat);
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            tokio::spawn(async move {
                axum::serve(listener, app).await.unwrap();
            });
            let client = reqwest::Client::new();
            for path in ["/ws", AGUI_ENDPOINT] {
                let res = client
                    .get(format!("http://{addr}{path}"))
                    .header("upgrade", "websocket")
                    .header("connection", "Upgrade")
                    .send()
                    .await
                    .unwrap();
                assert_eq!(
                    res.status(),
                    reqwest::StatusCode::NOT_IMPLEMENTED,
                    "ws path {path}"
                );
                let body = res.text().await.unwrap();
                assert!(body.contains("WebSocket"), "{path}: {body}");
            }
        });
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn inject_cache_hit_skips_origin_and_sse_is_never_stored() {
        use crate::inject_cache::InjectCache;
        use std::sync::atomic::AtomicUsize;
        let dir = std::env::temp_dir().join(format!(
            "designer-sso-inject-cache-{}-{}",
            std::process::id(),
            now_secs()
        ));
        let _ = std::fs::create_dir_all(&dir);
        let rt = Runtime::new().unwrap();
        rt.block_on(async {
            let gets = Arc::new(AtomicUsize::new(0));
            let origin_app = {
                let gets = gets.clone();
                axum::Router::new()
                    .route(
                        "/",
                        axum::routing::get(move || {
                            let gets = gets.clone();
                            async move {
                                gets.fetch_add(1, Ordering::SeqCst);
                                let mut res = axum::response::Response::new(Body::from(
                                    r#"<!doctype html><html><head><title>chat</title></head><body>
<script>new HttpAgent({ url: "ORIGIN/agent" });</script>
</body></html>"#,
                                ));
                                res.headers_mut().insert(
                                    axum::http::header::CONTENT_TYPE,
                                    HeaderValue::from_static("text/html; charset=utf-8"),
                                );
                                res
                            }
                        }),
                    )
                    .route(
                        "/agent",
                        axum::routing::post(|| async {
                            let mut res = axum::response::Response::new(Body::from(
                                "data: {\"type\":\"RUN_STARTED\"}\n\n",
                            ));
                            res.headers_mut().insert(
                                axum::http::header::CONTENT_TYPE,
                                HeaderValue::from_static("text/event-stream"),
                            );
                            res
                        }),
                    )
            };
            let origin_lis = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let origin_addr = origin_lis.local_addr().unwrap();
            tokio::spawn(async move {
                axum::serve(origin_lis, origin_app).await.unwrap();
            });
            let origin = format!("http://{origin_addr}");
            let cache = Arc::new(InjectCache::new());
            let proxy = test_proxy("http://127.0.0.1:1".into(), dir.clone());
            proxy.live.set_session(dummy_session());
            let app = router_with_cache(proxy, origin.clone(), SystemTab::Chat, cache.clone());
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            tokio::spawn(async move {
                axum::serve(listener, app).await.unwrap();
            });
            let client = reqwest::Client::new();
            let first = client.get(format!("http://{addr}/")).send().await.unwrap();
            assert_eq!(first.status(), reqwest::StatusCode::OK);
            assert_eq!(
                first
                    .headers()
                    .get("x-studio-inject-cache")
                    .and_then(|v| v.to_str().ok()),
                Some("miss")
            );
            let html = first.text().await.unwrap();
            assert!(html.contains(AGUI_INJECT_MARKER));
            assert!(html.contains("/api/studio/ag-ui"));
            assert_eq!(gets.load(Ordering::SeqCst), 1);
            assert_eq!(cache.len(), 1);

            let second = client.get(format!("http://{addr}/")).send().await.unwrap();
            assert_eq!(
                second
                    .headers()
                    .get("x-studio-inject-cache")
                    .and_then(|v| v.to_str().ok()),
                Some("hit")
            );
            let cached_html = second.text().await.unwrap();
            assert!(cached_html.contains(AGUI_INJECT_MARKER));
            assert_eq!(
                gets.load(Ordering::SeqCst),
                1,
                "cache hit must not re-fetch"
            );
            assert_eq!(cache.len(), 1);

            let sse = client
                .post(format!("http://{addr}{AGUI_ENDPOINT}"))
                .header("accept", "text/event-stream")
                .header("content-type", "application/json")
                .header("x-studio-agui-url", format!("{origin}/agent"))
                .body(r#"{"threadId":"t1","runId":"r1","messages":[]}"#)
                .send()
                .await
                .unwrap();
            assert_eq!(sse.status(), reqwest::StatusCode::OK);
            assert!(sse
                .headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .contains("text/event-stream"));
            assert!(sse.headers().get("x-studio-inject-cache").is_none());
            let _ = sse.bytes().await;
            assert_eq!(
                cache.len(),
                1,
                "event-stream / POST RunAgentInput must not enter inject cache"
            );
        });
        let _ = std::fs::remove_dir_all(dir);
    }
}
