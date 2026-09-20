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
//! WebView cookies stay unused (Tauri #12988 / #13045). Set-Cookie from the
//! origin is kept in the jar, not copied to the iframe. WebSocket upgrades stay
//! 501 (jar lives in Rust). SSE streaming is the AG-UI path that must work.

use std::sync::Arc;
use std::time::Duration;

use axum::body::{Body, Bytes};
use axum::extract::State;
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Uri};
use axum::response::IntoResponse;
use axum::Router;
use reqwest::Response;

use crate::apps::SystemTab;
use crate::config::StudioConfig;
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
}

pub fn router(proxy: Arc<Proxy>, origin: String) -> Router {
    Router::new()
        .fallback(axum::routing::any(sso_any))
        .with_state(SsoState { proxy, origin })
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
        return (
            StatusCode::UNAUTHORIZED,
            axum::Json(serde_json::json!({ "error": "нужен вход" })),
        )
            .into_response();
    };
    let path = if uri.path().is_empty() {
        "/"
    } else {
        uri.path()
    };
    let pq = Proxy::path_and_query(path, uri.query());
    let timeout = sso_timeout(&method, &headers, &state.proxy.cfg);
    forward_sso(&session, &state.origin, method, &pq, headers, body, timeout).await
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
    let stream_run = wants_event_stream(&incoming);
    let mut req = session
        .client
        .request(
            reqwest::Method::from_bytes(method.as_str().as_bytes()).unwrap_or(reqwest::Method::GET),
            &url,
        )
        .timeout(timeout);
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
    // reqwest `gzip(true)` would send Accept-Encoding: gzip and decode the body.
    // Gzip on text/event-stream buffers the run and breaks AG-UI SSE.
    if stream_run {
        req = req.header(
            axum::http::header::ACCEPT_ENCODING,
            HeaderValue::from_static("identity"),
        );
    }
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
fn wants_event_stream(headers: &HeaderMap) -> bool {
    accept_is_agui_stream(headers.get(axum::http::header::ACCEPT))
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

fn sso_timeout(method: &Method, incoming: &HeaderMap, cfg: &StudioConfig) -> Duration {
    if wants_event_stream(incoming) {
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
        .is_some_and(|v| {
            let v = v.to_ascii_lowercase();
            v.contains("text/event-stream") || v.contains("application/vnd.ag-ui.event+proto")
        })
}

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
    // Stream origin bytes as they arrive. Do not `bytes().await` the AG-UI run.
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
    use crate::session::{build_client, LiveState};
    use std::convert::Infallible;
    use std::pin::Pin;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::task::{Context, Poll};
    use tokio::runtime::Runtime;
    use tokio::sync::{mpsc, Notify};

    fn dummy_session() -> Session {
        let jar = Arc::new(reqwest::cookie::Jar::default());
        Session {
            slug: "s".into(),
            username: "u".into(),
            client: build_client(jar.clone()).unwrap(),
            jar,
        }
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
        assert_eq!(sso_timeout(&Method::POST, &sse, &cfg), cfg.stream_timeout);
        assert_eq!(sso_timeout(&Method::GET, &sse, &cfg), cfg.stream_timeout);
        assert_ne!(cfg.stream_timeout, cfg.get_timeout);
        assert_ne!(cfg.stream_timeout, cfg.write_timeout);
        assert!(cfg.stream_timeout >= Duration::from_secs(5 * 60));

        let mut proto = HeaderMap::new();
        proto.insert(
            axum::http::header::ACCEPT,
            HeaderValue::from_static("application/vnd.ag-ui.event+proto, text/event-stream;q=0.9"),
        );
        assert_eq!(sso_timeout(&Method::POST, &proto, &cfg), cfg.stream_timeout);
        assert_eq!(
            sso_timeout(&Method::GET, &HeaderMap::new(), &cfg),
            cfg.get_timeout
        );
        assert_eq!(
            sso_timeout(&Method::POST, &HeaderMap::new(), &cfg),
            cfg.write_timeout
        );
        assert!(wants_event_stream(&sse));
        assert!(!wants_event_stream(&HeaderMap::new()));
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
}
