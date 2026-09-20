//! Dedicated loopback ports for system apps that share Authentik SSO.
//!
//! Chat and S3 cannot share the chrome port: Vite `base: "/"` would collide with
//! studio `/api/session`. Each app gets `http://127.0.0.1:<port>/` reverse-proxied
//! with the same reqwest cookie jar as the stand (Authentik outpost cookie is
//! `Domain=mcpwork.space`).
//!
//! Live Chat (`chat.mcpwork.space`) is a Next.js Longgraph shell, not CopilotKit
//! `HttpAgent` and not a WebSocket SPA. The composer `POST /api/agent/{id}`
//! (`content-type: application/json`) returns `202 application/json`
//! `{runId,threadId}`. The run is `GET /api/runs/{uuid}?since=` with
//! `Accept: text/event-stream` and `Content-Type: text/event-stream` JSON `data:`
//! events. Relative `/api/…` already hits this loopback proxy (cookie jar in
//! Rust; WebView cookies are unused: Tauri #12988 / #13045).
//!
//! Chat HTML (only) gets a small inject so an **absolute** chat-origin GET
//! `/api/runs/{uuid}` SSE still reaches [`STUDIO_AGUI_PATH`]. Injected HTML is
//! stored in [`crate::inject_cache::InjectCache`]; the SSE byte stream never
//! consults it. Buffering `res.bytes().await` on the run would hang until the
//! GET/write timeout killed it.
//!
//! WebSocket upgrades stay 501 (jar lives in Rust; production chat does not use
//! WS for the run). Stream path: bytes as-is, 15 minute timeout,
//! `Accept-Encoding: identity`.

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
    agui_upstream_path, inject_agui_markup, is_chat_run_sse_path, is_html_content_type_str,
    script_src_for_request, STUDIO_AGUI_PATH, STUDIO_INJECT_JS_PATH,
};
use crate::inject_cache::{is_stream_media, InjectCache, InjectObject};
use crate::proxy::Proxy;
use crate::session::Session;

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

/// Studio-owned GET `/api/runs/{uuid}` SSE: `session.stream_client`. Used on
/// the Chat loopback port and on chrome `/api/studio/ag-ui`.
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
    if method != Method::GET && method != Method::HEAD {
        return (
            StatusCode::METHOD_NOT_ALLOWED,
            axum::Json(serde_json::json!({ "error": "чат стримит GET /api/runs/{id}?since=" })),
        )
            .into_response();
    }
    let Some(session) = proxy.live.session() else {
        return unauthorized();
    };
    let Some(pq) = agui_upstream_path(&headers, uri.query(), chat_origin) else {
        return (
            StatusCode::BAD_REQUEST,
            axum::Json(
                serde_json::json!({ "error": "только GET /api/runs/{uuid} на chat origin" }),
            ),
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

/// Chat HTML GET: cache lookup → fetch → inject → store. Not SSE, not JS bundles.
async fn chat_document(
    session: &Session,
    state: &SsoState,
    path: &str,
    path_and_query: &str,
    incoming: HeaderMap,
) -> axum::response::Response {
    let origin = state.origin.trim_end_matches('/');
    let url = format!("{origin}{path_and_query}");
    let key = InjectCache::key(&url, "text/html");
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
    _origin: &str,
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
    let html = inject_agui_markup(&String::from_utf8_lossy(&bytes), &src);
    let object = InjectObject::html(status, Bytes::from(html.into_bytes()), etag, last_modified);
    let accept = incoming
        .get(axum::http::header::ACCEPT)
        .and_then(|v| v.to_str().ok());
    if InjectCache::may_store("GET", accept, "text/html", path) {
        cache.put(InjectCache::key(url, "text/html"), object.clone());
    }
    inject_object_response(object, "miss")
}

fn inject_object_response(
    hit: InjectObject,
    cache_state: &'static str,
) -> axum::response::Response {
    let kind = match hit.kind {
        crate::inject_cache::ArtifactKind::Html => "html",
        crate::inject_cache::ArtifactKind::Script => "script",
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
    if is_sse_request(method, headers, path) {
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
        || path_only.starts_with("/s/")
        || accept_l.contains("text/html")
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
        || p.ends_with(".js")
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
    let stream_run = is_sse_request(&method, &incoming, path_and_query);
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

/// Live chat run: `GET /api/runs/{uuid}?since=` with `Accept: text/event-stream`.
fn wants_event_stream(headers: &HeaderMap) -> bool {
    accept_is_event_stream(headers.get(axum::http::header::ACCEPT))
}

fn is_sse_request(method: &Method, headers: &HeaderMap, path: &str) -> bool {
    wants_event_stream(headers) || (*method == Method::GET && is_chat_run_sse_path(path))
}

fn accept_is_event_stream(value: Option<&HeaderValue>) -> bool {
    value
        .and_then(|v| v.to_str().ok())
        .is_some_and(is_event_stream_accept)
}

fn is_event_stream_accept(accept: &str) -> bool {
    accept.to_ascii_lowercase().contains("text/event-stream")
}

fn sso_timeout(method: &Method, incoming: &HeaderMap, path: &str, cfg: &StudioConfig) -> Duration {
    if is_sse_request(method, incoming, path) {
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
            "WebSocket `{path}` студия пока не проксирует (cookie jar в Rust, не в WebView). HTTP/SSE чата: GET /api/runs/{{id}}?since=."
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
    use crate::cache::ReadCache;
    use crate::inject::{INJECT_JS, INJECT_MARKER};
    use crate::progress::ProgressHub;
    use crate::session::LiveState;
    use std::convert::Infallible;
    use std::pin::Pin;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::{Context, Poll};
    use tokio::runtime::Runtime;
    use tokio::sync::{mpsc, Notify};

    const RUN: &str = "/api/runs/30289690-b756-416a-ac0d-5bc9a3396ef7";
    const RUN_SINCE: &str = "/api/runs/30289690-b756-416a-ac0d-5bc9a3396ef7?since=0";
    /// Short GET/write timeouts so a held SSE stream proves `stream_timeout` is used.
    const SHORT_TIMEOUT: Duration = Duration::from_millis(400);

    fn temp_dir(label: &str) -> std::path::PathBuf {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let dir = std::env::temp_dir().join(format!(
            "designer-sso-{label}-{}-{stamp}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn dummy_session() -> Session {
        let jar = Arc::new(reqwest::cookie::Jar::default());
        Session::new("s".into(), "u".into(), jar).unwrap()
    }

    /// Proxy with a live dummy session; the stand origin is never contacted here.
    fn logged_in_proxy(cache_dir: &std::path::Path) -> Arc<Proxy> {
        let mut cfg = StudioConfig::production(
            std::path::PathBuf::from("ui"),
            0,
            Some(cache_dir.to_path_buf()),
        );
        cfg.stand_host = "http://127.0.0.1:1".into();
        cfg.get_timeout = SHORT_TIMEOUT;
        cfg.write_timeout = SHORT_TIMEOUT;
        cfg.stream_timeout = Duration::from_secs(5);
        let proxy = Arc::new(Proxy {
            cfg,
            cache: ReadCache::open(cache_dir.join("reads")).unwrap(),
            live: Arc::new(LiveState::new()),
            progress: ProgressHub::new(),
        });
        proxy.live.set_session(dummy_session());
        proxy
    }

    async fn serve(app: Router) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        format!("http://{addr}")
    }

    fn header_str<'a>(headers: &'a reqwest::header::HeaderMap, name: &str) -> Option<&'a str> {
        headers.get(name).and_then(|v| v.to_str().ok())
    }

    fn html_response(html: &'static str) -> axum::response::Response {
        let mut res = axum::response::Response::new(Body::from(html));
        res.headers_mut().insert(
            axum::http::header::CONTENT_TYPE,
            HeaderValue::from_static("text/html; charset=utf-8"),
        );
        res
    }

    /// `mpsc` → `Stream` without an extra crate (axum `Body::from_stream`).
    struct BodyChan {
        rx: mpsc::Receiver<Result<Bytes, Infallible>>,
    }

    impl futures_core::Stream for BodyChan {
        type Item = Result<Bytes, Infallible>;

        fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            self.rx.poll_recv(cx)
        }
    }

    /// Mock chat origin whose `GET /api/runs/{id}` emits one `RUN_STARTED` event
    /// echoing the request headers it saw, then blocks until `release`.
    struct SseOrigin {
        origin: String,
        release: Arc<Notify>,
    }

    async fn spawn_sse_origin() -> SseOrigin {
        let release = Arc::new(Notify::new());
        let app = {
            let release = release.clone();
            Router::new().route(
                "/api/runs/{id}",
                axum::routing::get(move |req: axum::extract::Request| {
                    let release = release.clone();
                    async move {
                        let seen = |name: &str| {
                            req.headers()
                                .get(name)
                                .and_then(|v| v.to_str().ok())
                                .unwrap_or("")
                                .to_string()
                        };
                        let first = serde_json::json!({
                            "type": "RUN_STARTED",
                            "accept_encoding": seen("accept-encoding"),
                            "accept": seen("accept"),
                            "csrf": seen("x-csrf-token"),
                            "agui_url_leaked": req.headers().contains_key("x-studio-agui-url"),
                            "cookie_leaked": req.headers().contains_key("cookie"),
                        });
                        let (tx, rx) = mpsc::channel::<Result<Bytes, Infallible>>(4);
                        tokio::spawn(async move {
                            let _ = tx.send(Ok(Bytes::from(format!("data: {first}\n\n")))).await;
                            release.notified().await;
                            let _ = tx
                                .send(Ok(Bytes::from("data: {\"type\":\"RUN_FINISHED\"}\n\n")))
                                .await;
                        });
                        let mut res =
                            axum::response::Response::new(Body::from_stream(BodyChan { rx }));
                        res.headers_mut().insert(
                            axum::http::header::CONTENT_TYPE,
                            HeaderValue::from_static("text/event-stream"),
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
        SseOrigin {
            origin: serve(app).await,
            release,
        }
    }

    /// First SSE event as JSON; must arrive while the origin is still holding the run.
    async fn first_event(res: &mut reqwest::Response) -> serde_json::Value {
        let chunk = tokio::time::timeout(SHORT_TIMEOUT, res.chunk())
            .await
            .expect("first SSE chunk must not wait for the origin run to finish")
            .expect("chunk")
            .expect("body");
        let text = String::from_utf8_lossy(&chunk);
        assert!(
            !text.contains("RUN_FINISHED"),
            "must not buffer the run: {text}"
        );
        let json = text.trim().strip_prefix("data: ").expect("sse data line");
        serde_json::from_str(json).expect("json event")
    }

    async fn rest_of_body(res: &mut reqwest::Response) -> String {
        let mut rest = Vec::new();
        while let Some(chunk) = res.chunk().await.unwrap() {
            rest.extend_from_slice(&chunk);
        }
        String::from_utf8_lossy(&rest).into_owned()
    }

    #[test]
    fn unauthenticated_sso_port_is_401() {
        let dir = temp_dir("401");
        let proxy = logged_in_proxy(&dir);
        proxy.live.clear_session();
        Runtime::new().unwrap().block_on(async {
            let addr = serve(router(proxy, "http://127.0.0.1:1".into())).await;
            let res = reqwest::get(format!("{addr}/api/me")).await.unwrap();
            assert_eq!(res.status(), reqwest::StatusCode::UNAUTHORIZED);
        });
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn forwards_headers_with_native_jar_and_strips_set_cookie() {
        let dir = temp_dir("fwd");
        let proxy = logged_in_proxy(&dir);
        Runtime::new().unwrap().block_on(async {
            let origin_app = Router::new().fallback(|req: axum::extract::Request| async move {
                let body = serde_json::json!({
                    "csrf": req.headers().get("x-csrf-token").and_then(|v| v.to_str().ok()),
                    "origin": req.headers().get("origin").and_then(|v| v.to_str().ok()),
                    "cookie_leaked": req.headers().contains_key("cookie"),
                });
                let mut res = axum::response::Response::new(Body::from(body.to_string()));
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
            let origin = serve(origin_app).await;
            let addr = serve(router(proxy, origin.clone())).await;
            let res = reqwest::Client::new()
                .post(format!("{addr}/api/me"))
                .header("x-csrf-token", "tok-1")
                .header("cookie", "webview-cookie=1")
                .send()
                .await
                .unwrap();
            assert_eq!(res.status(), reqwest::StatusCode::OK);
            assert!(
                res.headers().get("set-cookie").is_none(),
                "origin cookies stay in the Rust jar, never reach the WebView"
            );
            let json: serde_json::Value = res.json().await.unwrap();
            assert_eq!(json["csrf"], "tok-1");
            assert_eq!(
                json["origin"], origin,
                "Origin is rewritten to the upstream"
            );
            assert_eq!(json["cookie_leaked"], false, "WebView cookies are dropped");
        });
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn login_redirect_off_origin_is_unusable() {
        let session = dummy_session();
        Runtime::new().unwrap().block_on(async {
            let login = serve(Router::new().fallback(|| async { "authentik login" })).await;
            let login_url = format!("{login}/if/flow/");
            let origin = serve(Router::new().fallback(move || {
                let target = login_url.clone();
                async move { axum::response::Redirect::temporary(&target) }
            }))
            .await;
            let res = forward_sso(
                &session,
                &origin,
                Method::GET,
                "/",
                HeaderMap::new(),
                Bytes::new(),
                SHORT_TIMEOUT,
            )
            .await;
            assert_eq!(res.status(), StatusCode::SERVICE_UNAVAILABLE);
        });
    }

    #[test]
    fn run_sse_requests_get_the_stream_timeout() {
        let cfg = StudioConfig::production(std::path::PathBuf::from("ui"), 0, None);
        let mut sse = HeaderMap::new();
        sse.insert(
            axum::http::header::ACCEPT,
            HeaderValue::from_static("text/event-stream"),
        );
        let none = HeaderMap::new();
        assert_eq!(
            sso_timeout(&Method::GET, &sse, RUN_SINCE, &cfg),
            cfg.stream_timeout
        );
        assert_eq!(
            sso_timeout(&Method::GET, &none, RUN_SINCE, &cfg),
            cfg.stream_timeout,
            "GET /api/runs/{{uuid}} is the run even without Accept"
        );
        assert_eq!(
            sso_timeout(&Method::GET, &sse, "/api/threads/x/runs", &cfg),
            cfg.stream_timeout,
            "Accept: text/event-stream alone still streams"
        );
        assert_eq!(sso_timeout(&Method::GET, &none, "/", &cfg), cfg.get_timeout);
        assert_eq!(
            sso_timeout(&Method::POST, &none, "/api/agent/game", &cfg),
            cfg.write_timeout
        );
        assert_eq!(
            sso_timeout(&Method::POST, &none, &format!("{RUN}/cancel"), &cfg),
            cfg.write_timeout
        );
        assert_eq!(
            sso_timeout(&Method::GET, &none, &format!("{RUN}/scouts/abc"), &cfg),
            cfg.get_timeout
        );
    }

    #[test]
    fn relative_run_sse_streams_gzip_off_and_outlives_get_timeout() {
        let dir = temp_dir("sse");
        let proxy = logged_in_proxy(&dir);
        Runtime::new().unwrap().block_on(async {
            let upstream = spawn_sse_origin().await;
            let addr = serve(router(proxy, upstream.origin.clone())).await;

            let mut res = reqwest::Client::new()
                .get(format!("{addr}{RUN_SINCE}"))
                .header("accept", "text/event-stream")
                .header("x-csrf-token", "tok-sse")
                .send()
                .await
                .unwrap();
            assert_eq!(res.status(), reqwest::StatusCode::OK);
            assert!(res.headers().get("set-cookie").is_none());
            assert!(header_str(res.headers(), "content-type")
                .unwrap_or("")
                .contains("text/event-stream"));

            let first = first_event(&mut res).await;
            assert_eq!(first["type"], "RUN_STARTED");
            assert_eq!(first["accept_encoding"], "identity", "no gzip on the run");
            assert_eq!(first["accept"], "text/event-stream");
            assert_eq!(first["csrf"], "tok-sse");
            assert_eq!(first["cookie_leaked"], false);

            // Hold the run past get/write timeout: only stream_timeout may apply.
            tokio::time::sleep(SHORT_TIMEOUT + SHORT_TIMEOUT / 2).await;
            upstream.release.notify_one();
            assert!(rest_of_body(&mut res).await.contains("RUN_FINISHED"));
        });
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn studio_streamer_resolves_target_header_and_streams() {
        let dir = temp_dir("agui");
        let proxy = logged_in_proxy(&dir);
        Runtime::new().unwrap().block_on(async {
            let upstream = spawn_sse_origin().await;
            let addr = serve(router(proxy, upstream.origin.clone())).await;

            let mut res = reqwest::Client::new()
                .get(format!("{addr}{STUDIO_AGUI_PATH}"))
                .header(
                    "x-studio-agui-url",
                    format!("{}{RUN_SINCE}", upstream.origin),
                )
                .send()
                .await
                .unwrap();
            assert_eq!(res.status(), reqwest::StatusCode::OK);
            assert!(header_str(res.headers(), "content-type")
                .unwrap_or("")
                .contains("text/event-stream"));
            assert_eq!(
                header_str(res.headers(), "cache-control"),
                Some("no-cache"),
                "the WebView must never cache the run"
            );

            let first = first_event(&mut res).await;
            assert_eq!(first["type"], "RUN_STARTED");
            assert_eq!(first["accept_encoding"], "identity");
            assert_eq!(
                first["accept"], "text/event-stream",
                "Accept is added when missing"
            );
            assert_eq!(first["agui_url_leaked"], false, "studio header stays local");

            upstream.release.notify_one();
            assert!(rest_of_body(&mut res).await.contains("RUN_FINISHED"));
        });
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn studio_streamer_rejects_foreign_targets_and_non_get() {
        let dir = temp_dir("agui-reject");
        let proxy = logged_in_proxy(&dir);
        Runtime::new().unwrap().block_on(async {
            let upstream = spawn_sse_origin().await;
            let addr = serve(router(proxy, upstream.origin.clone())).await;
            let client = reqwest::Client::new();

            let evil = client
                .get(format!("{addr}{STUDIO_AGUI_PATH}"))
                .header("x-studio-agui-url", "https://evil.example/agent")
                .send()
                .await
                .unwrap();
            assert_eq!(evil.status(), reqwest::StatusCode::BAD_REQUEST);

            let invented = client
                .get(format!("{addr}{STUDIO_AGUI_PATH}"))
                .query(&[("to", "/api/copilotkit")])
                .send()
                .await
                .unwrap();
            assert_eq!(invented.status(), reqwest::StatusCode::BAD_REQUEST);

            let post = client
                .post(format!("{addr}{STUDIO_AGUI_PATH}"))
                .header("x-studio-agui-url", format!("{}{RUN}", upstream.origin))
                .body("{}")
                .send()
                .await
                .unwrap();
            assert_eq!(post.status(), reqwest::StatusCode::METHOD_NOT_ALLOWED);
        });
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn websocket_upgrade_returns_501_on_sso_and_streamer() {
        let dir = temp_dir("ws");
        let proxy = logged_in_proxy(&dir);
        Runtime::new().unwrap().block_on(async {
            let addr = serve(router(proxy, "http://127.0.0.1:1".into())).await;
            let client = reqwest::Client::new();
            for path in ["/ws", STUDIO_AGUI_PATH] {
                let res = client
                    .get(format!("{addr}{path}"))
                    .header("upgrade", "websocket")
                    .header("connection", "Upgrade")
                    .send()
                    .await
                    .unwrap();
                assert_eq!(res.status(), reqwest::StatusCode::NOT_IMPLEMENTED, "{path}");
            }
        });
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn chat_html_gets_inject_s3_html_does_not() {
        let dir = temp_dir("inject-html");
        Runtime::new().unwrap().block_on(async {
            const PAGE: &str =
                "<!doctype html><html><head><title>app</title></head><body>desk</body></html>";
            let origin = serve(Router::new().fallback(|| async { html_response(PAGE) })).await;
            let chat = serve(router_for(
                logged_in_proxy(&dir.join("chat")),
                origin.clone(),
                SystemTab::Chat,
            ))
            .await;
            let s3 = serve(router_for(
                logged_in_proxy(&dir.join("s3")),
                origin,
                SystemTab::S3,
            ))
            .await;
            let client = reqwest::Client::new();

            let chat_html = client.get(format!("{chat}/")).send().await.unwrap();
            assert_eq!(chat_html.status(), reqwest::StatusCode::OK);
            let chat_html = chat_html.text().await.unwrap();
            let src = format!("{chat}{STUDIO_INJECT_JS_PATH}");
            assert_eq!(
                chat_html,
                inject_agui_markup(PAGE, &src),
                "chat HTML is the origin page plus the loopback script tag"
            );

            let js = client.get(&src).send().await.unwrap();
            assert_eq!(js.status(), reqwest::StatusCode::OK);
            assert!(header_str(js.headers(), "content-type")
                .unwrap_or("")
                .contains("javascript"));
            let js = js.text().await.unwrap();
            assert_eq!(js, INJECT_JS);
            assert!(js.contains("__STUDIO_AGUI_INJECT__"), "idempotency flag");

            let s3_html = client.get(format!("{s3}/")).send().await.unwrap();
            assert_eq!(s3_html.status(), reqwest::StatusCode::OK);
            assert_eq!(s3_html.text().await.unwrap(), PAGE, "S3 HTML is untouched");
            let s3_js = client
                .get(format!("{s3}{STUDIO_INJECT_JS_PATH}"))
                .send()
                .await
                .unwrap()
                .text()
                .await
                .unwrap();
            assert_eq!(
                s3_js, PAGE,
                "S3 has no studio route; the path is proxied to origin"
            );
        });
        let _ = std::fs::remove_dir_all(dir);
    }

    /// Mock chat origin: HTML at `/`, run SSE, JSON 202 composer. Counts HTML GETs.
    fn chat_origin_app(html_gets: Arc<AtomicUsize>) -> Router {
        Router::new()
            .route(
                "/",
                axum::routing::get(move || {
                    let html_gets = html_gets.clone();
                    async move {
                        html_gets.fetch_add(1, Ordering::SeqCst);
                        html_response(
                            "<!doctype html><html><head><title>chat</title></head><body></body></html>",
                        )
                    }
                }),
            )
            .route(
                "/api/runs/{id}",
                axum::routing::get(|| async {
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
            .route(
                "/api/agent/{id}",
                axum::routing::post(|| async {
                    let mut res = axum::response::Response::new(Body::from(
                        r#"{"runId":"r1","threadId":"t1"}"#,
                    ));
                    *res.status_mut() = StatusCode::ACCEPTED;
                    res.headers_mut().insert(
                        axum::http::header::CONTENT_TYPE,
                        HeaderValue::from_static("application/json"),
                    );
                    res
                }),
            )
    }

    #[test]
    fn cached_chat_html_is_served_without_a_second_origin_get() {
        let dir = temp_dir("inject-cache-hit");
        Runtime::new().unwrap().block_on(async {
            let html_gets = Arc::new(AtomicUsize::new(0));
            let origin = serve(chat_origin_app(html_gets.clone())).await;
            let cache = Arc::new(InjectCache::new());
            let addr = serve(router_with_cache(
                logged_in_proxy(&dir),
                origin,
                SystemTab::Chat,
                cache.clone(),
            ))
            .await;
            let client = reqwest::Client::new();

            let first = client.get(format!("{addr}/")).send().await.unwrap();
            assert_eq!(first.status(), reqwest::StatusCode::OK);
            let first = first.text().await.unwrap();
            assert!(first.contains(INJECT_MARKER));
            assert_eq!(html_gets.load(Ordering::SeqCst), 1);
            assert_eq!(cache.len(), 1);

            let second = client.get(format!("{addr}/")).send().await.unwrap();
            assert_eq!(second.text().await.unwrap(), first);
            assert_eq!(html_gets.load(Ordering::SeqCst), 1, "hit must not re-fetch");
        });
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn run_sse_and_composer_json_never_enter_inject_cache() {
        let dir = temp_dir("inject-cache-skip");
        Runtime::new().unwrap().block_on(async {
            let origin = serve(chat_origin_app(Arc::new(AtomicUsize::new(0)))).await;
            let cache = Arc::new(InjectCache::new());
            let addr = serve(router_with_cache(
                logged_in_proxy(&dir),
                origin,
                SystemTab::Chat,
                cache.clone(),
            ))
            .await;
            let client = reqwest::Client::new();

            let sse = client
                .get(format!("{addr}{RUN_SINCE}"))
                .header("accept", "text/event-stream")
                .send()
                .await
                .unwrap();
            assert_eq!(sse.status(), reqwest::StatusCode::OK);
            assert!(header_str(sse.headers(), "content-type")
                .unwrap_or("")
                .contains("text/event-stream"));
            assert!(sse.text().await.unwrap().contains("RUN_STARTED"));

            let agent = client
                .post(format!("{addr}/api/agent/game"))
                .header("content-type", "application/json")
                .body(r#"{"threadId":"t1","messages":[]}"#)
                .send()
                .await
                .unwrap();
            assert_eq!(agent.status(), reqwest::StatusCode::ACCEPTED);
            assert!(header_str(agent.headers(), "content-type")
                .unwrap_or("")
                .contains("application/json"));

            assert_eq!(cache.len(), 0);
            let _ = client.get(format!("{addr}/")).send().await.unwrap();
            assert_eq!(cache.len(), 1, "only HTML is stored");
        });
        let _ = std::fs::remove_dir_all(dir);
    }
}
