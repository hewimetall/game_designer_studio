//! Reverse proxy to the live stand. GET uses stale-if-error; POST is live-only.

use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode};
use bytes::Bytes;
use reqwest::Response;

use crate::cache::{now_secs, CachedObject, ReadCache};
use crate::config::StudioConfig;
use crate::progress::ProgressHub;
use crate::session::{LiveState, Session};
use crate::stand::{
    atlas_paths_for_saved_file, atlas_paths_from_bindings, changed_atlas_get_paths,
    slug_from_stand_path, write_updates_get,
};

const HOP: &[&str] = &[
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
];

pub struct Proxy {
    pub cfg: StudioConfig,
    pub cache: ReadCache,
    pub live: Arc<LiveState>,
    pub progress: Arc<ProgressHub>,
}

impl Proxy {
    pub fn path_and_query(path: &str, query: Option<&str>) -> String {
        match query {
            Some(q) if !q.is_empty() => format!("{path}?{q}"),
            _ => path.to_string(),
        }
    }

    pub async fn forward(
        &self,
        session: &Session,
        method: Method,
        path_and_query: &str,
        incoming: HeaderMap,
        body: Bytes,
    ) -> axum::response::Response {
        let is_get = method == Method::GET || method == Method::HEAD;
        let timeout = if is_get {
            self.cfg.get_timeout
        } else {
            self.cfg.write_timeout
        };
        let url = format!("{}{path_and_query}", self.cfg.stand_origin());
        let cache_key = ReadCache::key("GET", path_and_query);
        match stand_request(
            &session.client,
            method.clone(),
            &url,
            &incoming,
            body.clone(),
            timeout,
        )
        .await
        {
            Ok(res) => {
                if is_get && (origin_unusable(&res, &self.cfg) || res.status().is_server_error()) {
                    self.live.set_online(false);
                    if let Some(hit) = self.cache.get(&cache_key) {
                        return stale_response(hit);
                    }
                    if origin_unusable(&res, &self.cfg) {
                        return error_json(
                            StatusCode::SERVICE_UNAVAILABLE,
                            "оффлайн и нет кеша: стенд отправил на логин Authentik",
                        );
                    }
                } else if !is_get && origin_unusable(&res, &self.cfg) {
                    self.live.set_online(false);
                    return error_json(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "оффлайн: сохранить на стенд нельзя (стенд отправил на логин Authentik)",
                    );
                }
                let status = res.status().as_u16();
                let content_type = content_type_of(&res);
                let bytes = match res.bytes().await {
                    Ok(b) => b,
                    Err(err) => return error_json(StatusCode::BAD_GATEWAY, &err.to_string()),
                };
                self.live.set_online(true);
                if is_get && cacheable_get(status, &content_type) {
                    self.cache.put(
                        cache_key,
                        CachedObject {
                            status,
                            content_type: content_type.clone(),
                            body: bytes.clone(),
                            fetched_at: now_secs(),
                        },
                    );
                    self.live.set_cached(self.cache.len());
                } else if !is_get && (200..300).contains(&status) {
                    let incoming_ct = incoming
                        .get(axum::http::header::CONTENT_TYPE)
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("");
                    let related = self.related_gets_after_write(path_and_query, &body);
                    let mut refresh = Vec::new();
                    if let Some(get_pq) = write_updates_get(method.as_str(), path_and_query) {
                        if cacheable_write_body(incoming_ct, &body) {
                            self.cache.put(
                                ReadCache::key("GET", &get_pq),
                                CachedObject {
                                    status: 200,
                                    content_type: write_cache_content_type(incoming_ct),
                                    body: body.clone(),
                                    fetched_at: now_secs(),
                                },
                            );
                        }
                        refresh.push(get_pq);
                    }
                    refresh.extend(related);
                    refresh.sort();
                    refresh.dedup();
                    if !refresh.is_empty() {
                        Box::pin(self.warm_gets(session, &refresh)).await;
                    }
                }
                live_response(status, &content_type, bytes)
            }
            Err(err) => {
                self.live.set_online(false);
                if is_get {
                    if let Some(hit) = self.cache.get(&cache_key) {
                        return stale_response(hit);
                    }
                    return error_json(
                        StatusCode::SERVICE_UNAVAILABLE,
                        &format!("оффлайн и нет кеша: {err}"),
                    );
                }
                error_json(
                    StatusCode::SERVICE_UNAVAILABLE,
                    &format!("оффлайн: сохранить на стенд нельзя ({err})"),
                )
            }
        }
    }

    pub async fn prefetch_json(&self, session: &Session, paths: &[String]) -> usize {
        let api_n = paths.iter().filter(|p| p.contains("/api/")).count() as u64;
        self.progress.set_phase("sync");
        self.progress.add_files_total(api_n);
        let mut ok = 0usize;
        let mut live_ok = 0usize;
        for path in paths {
            if !path.contains("/api/") {
                continue;
            }
            let mut headers = HeaderMap::new();
            headers.insert(
                axum::http::header::ACCEPT,
                if is_atlas_get_path(path) {
                    HeaderValue::from_static("image/*,*/*;q=0.8")
                } else {
                    HeaderValue::from_static("application/json")
                },
            );
            self.progress.start_file(path);
            let res = self
                .forward(session, Method::GET, path, headers, Bytes::new())
                .await;
            let content_type = res
                .headers()
                .get(axum::http::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            if res.status().is_success() && prefetch_body_ok(path, content_type) {
                ok += 1;
                let stale = res
                    .headers()
                    .get("x-studio-cache")
                    .and_then(|v| v.to_str().ok())
                    == Some("stale");
                if !stale {
                    live_ok += 1;
                }
                if let Some(hit) = self.cache.get(&ReadCache::key("GET", path)) {
                    self.progress.add_bytes(hit.body.len() as u64);
                }
            }
            self.progress.complete_file();
        }
        if live_ok > 0 {
            self.live.mark_sync_ok(self.cache.len());
        } else {
            self.live.set_cached(self.cache.len());
        }
        ok
    }

    /// Silent GET warm so POST /sprites can seed `/api/sprites/atlas/{name}`
    /// without flipping the Sync progress overlay.
    async fn warm_gets(&self, session: &Session, paths: &[String]) {
        let headers = HeaderMap::new();
        for path in paths {
            let _ = self
                .forward(session, Method::GET, path, headers.clone(), Bytes::new())
                .await;
        }
    }

    fn related_gets_after_write(&self, path_and_query: &str, body: &Bytes) -> Vec<String> {
        let Some(slug) = slug_from_stand_path(path_and_query) else {
            return Vec::new();
        };
        let path = path_and_query
            .split_once('?')
            .map_or(path_and_query, |(path, _)| path);
        if path.ends_with("/api/sprites") {
            let previous = self
                .cache
                .get(&ReadCache::key("GET", path))
                .map(|hit| hit.body);
            return changed_atlas_get_paths(slug, previous.as_deref(), body);
        }
        if path.ends_with("/api/spawn-bindings") {
            return atlas_paths_from_bindings(slug, body);
        }
        if let Some((_, rest)) = path.split_once("/api/sprites/save-file/") {
            let sprites_pq = format!("/stand/{slug}/api/sprites");
            if let Some(hit) = self.cache.get(&ReadCache::key("GET", &sprites_pq)) {
                return atlas_paths_for_saved_file(slug, &hit.body, rest);
            }
        }
        Vec::new()
    }
}

fn origin_unusable(res: &Response, cfg: &StudioConfig) -> bool {
    if !cfg.url_host_is_stand(res.url()) {
        return true;
    }
    content_type_of(res)
        .to_ascii_lowercase()
        .contains("text/html")
}

pub fn cacheable_get(status: u16, content_type: &str) -> bool {
    if !(200..300).contains(&status) {
        return false;
    }
    let ct = content_type.to_ascii_lowercase();
    ct.contains("json") || ct.starts_with("image/") || ct.contains("octet-stream")
}

fn cacheable_write_body(content_type: &str, body: &Bytes) -> bool {
    !body.is_empty() && cacheable_get(200, content_type)
}

fn is_atlas_get_path(path: &str) -> bool {
    path.contains("/api/sprites/atlas/")
}

fn prefetch_body_ok(path: &str, content_type: &str) -> bool {
    let ct = content_type.to_ascii_lowercase();
    if is_atlas_get_path(path) {
        ct.starts_with("image/") || ct.contains("octet-stream")
    } else {
        ct.contains("json")
    }
}

fn write_cache_content_type(content_type: &str) -> String {
    let ct = content_type.to_ascii_lowercase();
    if ct.contains("json") {
        "application/json".into()
    } else {
        content_type.to_string()
    }
}

async fn stand_request(
    client: &reqwest::Client,
    method: Method,
    url: &str,
    incoming: &HeaderMap,
    body: Bytes,
    timeout: Duration,
) -> Result<Response, String> {
    let mut req = client
        .request(
            reqwest::Method::from_bytes(method.as_str().as_bytes()).unwrap_or(reqwest::Method::GET),
            url,
        )
        .timeout(timeout);
    if let Some(ct) = incoming.get(axum::http::header::CONTENT_TYPE) {
        if let Ok(v) = ct.to_str() {
            req = req.header("content-type", v);
        }
    }
    if let Some(accept) = incoming.get(axum::http::header::ACCEPT) {
        if let Ok(v) = accept.to_str() {
            req = req.header("accept", v);
        }
    }
    if !body.is_empty() && method != Method::GET && method != Method::HEAD {
        req = req.body(body);
    }
    req.send().await.map_err(|err| err.to_string())
}

fn content_type_of(res: &Response) -> String {
    res.headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/octet-stream")
        .to_string()
}

fn live_response(status: u16, content_type: &str, body: Bytes) -> axum::response::Response {
    let mut res = axum::response::Response::new(Body::from(body));
    *res.status_mut() = StatusCode::from_u16(status).unwrap_or(StatusCode::OK);
    if let Ok(val) = HeaderValue::from_str(content_type) {
        res.headers_mut()
            .insert(axum::http::header::CONTENT_TYPE, val);
    }
    res.headers_mut().insert(
        HeaderName::from_static("x-studio-cache"),
        HeaderValue::from_static("live"),
    );
    let _ = HOP;
    res
}

fn stale_response(hit: CachedObject) -> axum::response::Response {
    let mut res = axum::response::Response::new(Body::from(hit.body));
    *res.status_mut() = StatusCode::from_u16(hit.status).unwrap_or(StatusCode::OK);
    if let Ok(val) = HeaderValue::from_str(&hit.content_type) {
        res.headers_mut()
            .insert(axum::http::header::CONTENT_TYPE, val);
    }
    res.headers_mut().insert(
        HeaderName::from_static("x-studio-cache"),
        HeaderValue::from_static("stale"),
    );
    res.headers_mut().insert(
        HeaderName::from_static("age"),
        HeaderValue::from_str(&now_secs().saturating_sub(hit.fetched_at).to_string())
            .unwrap_or(HeaderValue::from_static("0")),
    );
    res
}

fn error_json(status: StatusCode, message: &str) -> axum::response::Response {
    let body = serde_json::json!({
        "error": message,
        "offline": status == StatusCode::SERVICE_UNAVAILABLE,
    });
    let mut res = axum::response::Response::new(Body::from(body.to_string()));
    *res.status_mut() = status;
    res.headers_mut().insert(
        axum::http::header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    res
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::build_client;
    use std::sync::Arc;
    use tokio::runtime::Runtime;

    fn test_cfg(stand_host: String, cache_dir: std::path::PathBuf) -> StudioConfig {
        let mut cfg = StudioConfig::production(std::path::PathBuf::from("ui"), 0, Some(cache_dir));
        cfg.stand_host = stand_host;
        cfg.get_timeout = Duration::from_millis(400);
        cfg.write_timeout = Duration::from_millis(400);
        cfg
    }

    fn dummy_session() -> Session {
        let jar = Arc::new(reqwest::cookie::Jar::default());
        Session {
            slug: "s".into(),
            username: "u".into(),
            client: build_client(jar.clone()).unwrap(),
            jar,
        }
    }

    fn seed_bestiary(cache: &ReadCache) -> String {
        let pq = "/stand/s/api/bestiary".to_string();
        cache.put(
            ReadCache::key("GET", &pq),
            CachedObject {
                status: 200,
                content_type: "application/json".into(),
                body: Bytes::from_static(b"{\"ok\":true}"),
                fetched_at: 1,
            },
        );
        pq
    }

    #[test]
    fn path_and_query_keeps_kind() {
        assert_eq!(
            Proxy::path_and_query("/stand/s/api/level", Some("kind=Hub")),
            "/stand/s/api/level?kind=Hub"
        );
    }

    #[test]
    fn html_login_pages_are_not_cached() {
        assert!(!cacheable_get(200, "text/html; charset=utf-8"));
        assert!(cacheable_get(200, "application/json"));
        assert!(cacheable_get(200, "image/png"));
        assert!(!cacheable_get(500, "application/json"));
        assert!(!cacheable_get(302, "application/json"));
    }

    #[test]
    fn get_uses_stale_cache_when_origin_unreachable() {
        let dir = std::env::temp_dir().join(format!(
            "designer-proxy-{}-{}",
            std::process::id(),
            now_secs()
        ));
        let cache = ReadCache::open(&dir).unwrap();
        let pq = seed_bestiary(&cache);
        let proxy = Proxy {
            cfg: test_cfg("http://127.0.0.1:1".into(), dir.clone()),
            cache,
            live: Arc::new(LiveState::new()),
            progress: crate::progress::ProgressHub::new(),
        };
        let session = dummy_session();
        let rt = Runtime::new().unwrap();
        rt.block_on(async {
            let res = proxy
                .forward(&session, Method::GET, &pq, HeaderMap::new(), Bytes::new())
                .await;
            assert_eq!(res.status(), StatusCode::OK);
            assert_eq!(
                res.headers()
                    .get("x-studio-cache")
                    .and_then(|v| v.to_str().ok()),
                Some("stale")
            );
            assert!(!proxy.live.is_online());
            assert_eq!(proxy.live.snapshot().mode, "оффлайн");

            let post = proxy
                .forward(
                    &session,
                    Method::POST,
                    &pq,
                    HeaderMap::new(),
                    Bytes::from_static(b"{\"x\":1}"),
                )
                .await;
            assert_eq!(post.status(), StatusCode::SERVICE_UNAVAILABLE);
            let bytes = axum::body::to_bytes(post.into_body(), 64 * 1024)
                .await
                .unwrap();
            let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(json["offline"], true);
            assert!(json["error"].as_str().unwrap().contains("оффлайн"));
        });
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn get_5xx_serves_stale_if_error() {
        let dir = std::env::temp_dir().join(format!(
            "designer-proxy5xx-{}-{}",
            std::process::id(),
            now_secs()
        ));
        let cache = ReadCache::open(&dir).unwrap();
        let pq = seed_bestiary(&cache);
        let rt = Runtime::new().unwrap();
        rt.block_on(async {
            let app = axum::Router::new()
                .fallback(|| async { (StatusCode::INTERNAL_SERVER_ERROR, "boom") });
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            tokio::spawn(async move {
                axum::serve(listener, app).await.unwrap();
            });
            let proxy = Proxy {
                cfg: test_cfg(format!("http://{addr}"), dir.clone()),
                cache,
                live: Arc::new(LiveState::new()),
                progress: crate::progress::ProgressHub::new(),
            };
            let session = dummy_session();
            let res = proxy
                .forward(&session, Method::GET, &pq, HeaderMap::new(), Bytes::new())
                .await;
            assert_eq!(res.status(), StatusCode::OK);
            assert_eq!(
                res.headers()
                    .get("x-studio-cache")
                    .and_then(|v| v.to_str().ok()),
                Some("stale")
            );
        });
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn post_sprites_json_warms_new_atlas_get() {
        let dir = std::env::temp_dir().join(format!(
            "designer-proxy-atlas-{}-{}",
            std::process::id(),
            now_secs()
        ));
        let cache = ReadCache::open(&dir).unwrap();
        cache.put(
            ReadCache::key("GET", "/stand/s/api/sprites"),
            CachedObject {
                status: 200,
                content_type: "application/json".into(),
                body: Bytes::from_static(
                    br#"{"atlases":{"mutant_basic":{"path":"sprites/mutants/old.png"}}}"#,
                ),
                fetched_at: 1,
            },
        );
        let rt = Runtime::new().unwrap();
        rt.block_on(async {
            let app = axum::Router::new()
                .route(
                    "/stand/s/api/sprites/atlas/{*name}",
                    axum::routing::get(|| async {
                        ([(axum::http::header::CONTENT_TYPE, "image/png")], b"PNGIMG".to_vec())
                    }),
                )
                .fallback(|| async { (StatusCode::OK, "ok") });
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            tokio::spawn(async move {
                axum::serve(listener, app).await.unwrap();
            });
            let proxy = Proxy {
                cfg: test_cfg(format!("http://{addr}"), dir.clone()),
                cache,
                live: Arc::new(LiveState::new()),
                progress: crate::progress::ProgressHub::new(),
            };
            let session = dummy_session();
            let mut headers = HeaderMap::new();
            headers.insert(
                axum::http::header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            );
            let body = Bytes::from(
                r#"{"atlases":{"mutant_basic":{"path":"sprites/mutants/old.png"},"матка танк":{"path":"sprites/units/new.png"}}}"#
                    .to_string(),
            );
            let post = proxy
                .forward(
                    &session,
                    Method::POST,
                    "/stand/s/api/sprites",
                    headers,
                    body,
                )
                .await;
            assert_eq!(post.status(), StatusCode::OK);
            let hit = proxy
                .cache
                .get(&ReadCache::key(
                    "GET",
                    "/stand/s/api/sprites/atlas/матка танк",
                ))
                .expect("new atlas GET must be warmed after sprites POST");
            assert_eq!(&hit.body[..], b"PNGIMG");
        });
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn post_png_updates_file_get_cache() {
        let dir = std::env::temp_dir().join(format!(
            "designer-proxy-png-{}-{}",
            std::process::id(),
            now_secs()
        ));
        let cache = ReadCache::open(&dir).unwrap();
        let rt = Runtime::new().unwrap();
        rt.block_on(async {
            let app = axum::Router::new().fallback(|| async { (StatusCode::OK, "ok") });
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            tokio::spawn(async move {
                axum::serve(listener, app).await.unwrap();
            });
            let proxy = Proxy {
                cfg: test_cfg(format!("http://{addr}"), dir.clone()),
                cache,
                live: Arc::new(LiveState::new()),
                progress: crate::progress::ProgressHub::new(),
            };
            let session = dummy_session();
            let mut headers = HeaderMap::new();
            headers.insert(
                axum::http::header::CONTENT_TYPE,
                HeaderValue::from_static("image/png"),
            );
            let png = Bytes::from_static(b"\x89PNG\r\n");
            let post = proxy
                .forward(
                    &session,
                    Method::POST,
                    "/stand/s/api/sprites/save-file/units/queen.png",
                    headers,
                    png.clone(),
                )
                .await;
            assert_eq!(post.status(), StatusCode::OK);
            let hit = proxy
                .cache
                .get(&ReadCache::key(
                    "GET",
                    "/stand/s/api/sprites/file/units/queen.png",
                ))
                .expect("save-file POST must seed the file GET cache");
            assert_eq!(hit.content_type, "image/png");
            assert_eq!(&hit.body[..], &png[..]);
        });
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn post_spawn_bindings_refreshes_get_from_origin() {
        let dir = std::env::temp_dir().join(format!(
            "designer-proxy-bind-{}-{}",
            std::process::id(),
            now_secs()
        ));
        let cache = ReadCache::open(&dir).unwrap();
        let rt = Runtime::new().unwrap();
        rt.block_on(async {
            const ORIGIN_JSON: &str =
                r#"{"bindings":{"QueenTank":{"atlas":"матка танк","slot_anims":{"idle":"idle"}}}}"#;
            let app = axum::Router::new()
                .route(
                    "/stand/s/api/spawn-bindings",
                    axum::routing::get(|| async {
                        (
                            [(axum::http::header::CONTENT_TYPE, "application/json")],
                            ORIGIN_JSON,
                        )
                    })
                    .post(|| async { "ok" }),
                )
                .route(
                    "/stand/s/api/sprites/atlas/{*name}",
                    axum::routing::get(|| async {
                        (
                            [(axum::http::header::CONTENT_TYPE, "image/png")],
                            b"PNGIMG".to_vec(),
                        )
                    }),
                );
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            tokio::spawn(async move {
                axum::serve(listener, app).await.unwrap();
            });
            let proxy = Proxy {
                cfg: test_cfg(format!("http://{addr}"), dir.clone()),
                cache,
                live: Arc::new(LiveState::new()),
                progress: crate::progress::ProgressHub::new(),
            };
            let session = dummy_session();
            let mut headers = HeaderMap::new();
            headers.insert(
                axum::http::header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            );
            let post_body = Bytes::from(
                r#"{"bindings":{"QueenTank":{"atlas":"матка танк","slot_anims":{}}}}"#.to_string(),
            );
            let post = proxy
                .forward(
                    &session,
                    Method::POST,
                    "/stand/s/api/spawn-bindings",
                    headers,
                    post_body.clone(),
                )
                .await;
            assert_eq!(post.status(), StatusCode::OK);
            let hit = proxy
                .cache
                .get(&ReadCache::key("GET", "/stand/s/api/spawn-bindings"))
                .expect("bindings GET must refresh from origin after POST");
            assert_eq!(&hit.body[..], ORIGIN_JSON.as_bytes());
            assert_ne!(&hit.body[..], &post_body[..]);
            let atlas = proxy
                .cache
                .get(&ReadCache::key(
                    "GET",
                    "/stand/s/api/sprites/atlas/матка танк",
                ))
                .expect("QueenTank atlas GET must be warmed after bindings POST");
            assert_eq!(&atlas.body[..], b"PNGIMG");
        });
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn save_file_warms_matching_atlas_get() {
        let dir = std::env::temp_dir().join(format!(
            "designer-proxy-save-atlas-{}-{}",
            std::process::id(),
            now_secs()
        ));
        let cache = ReadCache::open(&dir).unwrap();
        cache.put(
            ReadCache::key("GET", "/stand/s/api/sprites"),
            CachedObject {
                status: 200,
                content_type: "application/json".into(),
                body: Bytes::from(
                    r#"{"atlases":{"матка танк":{"path":"sprites/units/queen.png"}}}"#.to_string(),
                ),
                fetched_at: 1,
            },
        );
        let rt = Runtime::new().unwrap();
        rt.block_on(async {
            let app = axum::Router::new()
                .route(
                    "/stand/s/api/sprites/atlas/{*name}",
                    axum::routing::get(|| async {
                        (
                            [(axum::http::header::CONTENT_TYPE, "image/png")],
                            b"ATLASPNG".to_vec(),
                        )
                    }),
                )
                .fallback(|| async { (StatusCode::OK, "ok") });
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            tokio::spawn(async move {
                axum::serve(listener, app).await.unwrap();
            });
            let proxy = Proxy {
                cfg: test_cfg(format!("http://{addr}"), dir.clone()),
                cache,
                live: Arc::new(LiveState::new()),
                progress: crate::progress::ProgressHub::new(),
            };
            let session = dummy_session();
            let mut headers = HeaderMap::new();
            headers.insert(
                axum::http::header::CONTENT_TYPE,
                HeaderValue::from_static("image/png"),
            );
            let png = Bytes::from_static(b"\x89PNG\r\n");
            let post = proxy
                .forward(
                    &session,
                    Method::POST,
                    "/stand/s/api/sprites/save-file/units/queen.png",
                    headers,
                    png,
                )
                .await;
            assert_eq!(post.status(), StatusCode::OK);
            let hit = proxy
                .cache
                .get(&ReadCache::key(
                    "GET",
                    "/stand/s/api/sprites/atlas/матка танк",
                ))
                .expect("save-file must warm Bestiary atlas GET");
            assert_eq!(&hit.body[..], b"ATLASPNG");
        });
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn prefetch_json_counts_atlas_images() {
        let dir = std::env::temp_dir().join(format!(
            "designer-prefetch-atlas-{}-{}",
            std::process::id(),
            now_secs()
        ));
        let cache = ReadCache::open(&dir).unwrap();
        let rt = Runtime::new().unwrap();
        rt.block_on(async {
            let app = axum::Router::new().route(
                "/stand/s/api/sprites/atlas/{*name}",
                axum::routing::get(|| async {
                    (
                        [(axum::http::header::CONTENT_TYPE, "image/png")],
                        b"PNGIMG".to_vec(),
                    )
                }),
            );
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            tokio::spawn(async move {
                axum::serve(listener, app).await.unwrap();
            });
            let proxy = Proxy {
                cfg: test_cfg(format!("http://{addr}"), dir.clone()),
                cache,
                live: Arc::new(LiveState::new()),
                progress: crate::progress::ProgressHub::new(),
            };
            let session = dummy_session();
            let n = proxy
                .prefetch_json(&session, &["/stand/s/api/sprites/atlas/матка танк".into()])
                .await;
            assert_eq!(n, 1);
            let hit = proxy
                .cache
                .get(&ReadCache::key(
                    "GET",
                    "/stand/s/api/sprites/atlas/матка танк",
                ))
                .expect("portrait atlas GET must be cached");
            assert_eq!(&hit.body[..], b"PNGIMG");
        });
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn prefetch_skips_non_api_paths() {
        let dir = std::env::temp_dir().join(format!(
            "designer-prefetch-{}-{}",
            std::process::id(),
            now_secs()
        ));
        let cache = ReadCache::open(&dir).unwrap();
        let proxy = Proxy {
            cfg: test_cfg("http://127.0.0.1:1".into(), dir.clone()),
            cache,
            live: Arc::new(LiveState::new()),
            progress: crate::progress::ProgressHub::new(),
        };
        let session = dummy_session();
        let rt = Runtime::new().unwrap();
        rt.block_on(async {
            let n = proxy
                .prefetch_json(&session, &["/stand/s/level/".into()])
                .await;
            assert_eq!(n, 0);
        });
        let _ = std::fs::remove_dir_all(dir);
    }
}
