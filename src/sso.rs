//! Dedicated loopback ports for system apps that share Authentik SSO.
//!
//! Chat and S3 are Vite SPAs with `base: "/"`. Mounting them under
//! `/stand/<slug>/…` or on the chrome port would collide with studio
//! `/api/session` vs app `/api/me`. Each app gets `http://127.0.0.1:<port>/`
//! and is reverse-proxied with the same reqwest cookie jar as the stand
//! (Authentik outpost cookie is `Domain=mcpwork.space`).
//!
//! WebView cookies stay unused (Tauri #12988 / #13045). Set-Cookie from the
//! origin is kept in the jar, not copied to the iframe.

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
    let timeout = if method == Method::GET || method == Method::HEAD {
        state.proxy.cfg.get_timeout
    } else {
        state.proxy.cfg.write_timeout
    };
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
            sso_response(res).await
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

async fn sso_response(res: Response) -> axum::response::Response {
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
    let bytes = match res.bytes().await {
        Ok(b) => b,
        Err(err) => return error_html(StatusCode::BAD_GATEWAY, &err.to_string()),
    };
    let mut out = axum::response::Response::new(Body::from(bytes));
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
            "WebSocket `{path}` студия пока не проксирует (cookie jar в Rust, не в WebView). HTTP/polling к этому origin идёт."
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
    use tokio::runtime::Runtime;

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
}
