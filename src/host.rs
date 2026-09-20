use std::net::SocketAddr;
use std::sync::Arc;
use std::thread;

use axum::body::Bytes;
use axum::extract::{Path as AxumPath, State};
use axum::http::{header, HeaderMap, Method, StatusCode, Uri};
use axum::response::{Html, IntoResponse, Redirect};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use tokio::net::TcpListener;
use tokio::runtime::Runtime;

use crate::apps::{DesignerTab, SystemTab};
use crate::assets::{
    baked_is_packaged, looks_like_packaged_editor, read_chrome, read_spa, refresh_app,
    refresh_app_join, SpaSource,
};
use crate::auth::{login_with_password, resume_from_jar};
use crate::cache::ReadCache;
use crate::config::StudioConfig;
use crate::progress::{Progress, ProgressHub};
use crate::proxy::Proxy;
use crate::remember::{self, RememberedLogin};
use crate::session::{LiveState, Session};
use crate::slug::parse_slug;
use crate::sso::{self, SsoBind};
use crate::stand::{
    atlas_paths_from_bindings, health_path, level_paths_from_list, prefetch_json_paths,
};

#[derive(Clone)]
struct AppState {
    proxy: Arc<Proxy>,
    sso: Arc<Vec<SsoBind>>,
}

#[derive(Debug, Clone)]
pub struct LocalHost {
    pub addr: SocketAddr,
    pub progress: Arc<ProgressHub>,
    pub sso: Vec<SsoBind>,
}

impl LocalHost {
    pub fn chrome_url(&self) -> String {
        format!("http://127.0.0.1:{}/", self.addr.port())
    }
}

pub fn bind_local_host(cfg: StudioConfig) -> Result<LocalHost, String> {
    let addr = SocketAddr::from(([127, 0, 0, 1], cfg.bind_port));
    let listener = std::net::TcpListener::bind(addr).map_err(|err| err.to_string())?;
    listener
        .set_nonblocking(true)
        .map_err(|err| err.to_string())?;
    let bound = listener.local_addr().map_err(|err| err.to_string())?;
    let mut sso_listeners = Vec::new();
    let mut sso_binds = Vec::new();
    for tab in SystemTab::ALL {
        let sso_listener = std::net::TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .map_err(|err| err.to_string())?;
        sso_listener
            .set_nonblocking(true)
            .map_err(|err| err.to_string())?;
        let sso_addr = sso_listener.local_addr().map_err(|err| err.to_string())?;
        sso_binds.push(SsoBind {
            tab,
            origin: cfg.origin_for_system(tab).to_string(),
            port: sso_addr.port(),
        });
        sso_listeners.push(sso_listener);
    }
    let cache = ReadCache::open(cfg.cache_dir.join("reads")).map_err(|err| err.to_string())?;
    let live = Arc::new(LiveState::new());
    let progress = ProgressHub::new();
    let proxy = Arc::new(Proxy {
        cfg,
        cache,
        live: live.clone(),
        progress: progress.clone(),
    });
    let sso = Arc::new(sso_binds.clone());

    thread::Builder::new()
        .name("designer-studio-host".into())
        .spawn(move || {
            let runtime = Runtime::new().expect("host runtime");
            runtime.block_on(async move {
                let listener = TcpListener::from_std(listener).expect("async listener");
                let probe = proxy.clone();
                tokio::spawn(async move { probe_loop(probe).await });
                let restore = proxy.clone();
                tokio::spawn(async move {
                    restore_session_if_needed(&restore).await;
                });
                for (bind, std_lis) in sso.iter().cloned().zip(sso_listeners) {
                    let proxy = proxy.clone();
                    tokio::spawn(async move {
                        let listener = TcpListener::from_std(std_lis).expect("sso listener");
                        let _ =
                            axum::serve(listener, sso::router_for(proxy, bind.origin, bind.tab))
                                .await;
                    });
                }
                axum::serve(listener, router(proxy, sso))
                    .await
                    .expect("host serve");
            });
        })
        .map_err(|err| err.to_string())?;

    Ok(LocalHost {
        addr: bound,
        progress,
        sso: sso_binds,
    })
}

fn router(proxy: Arc<Proxy>, sso: Arc<Vec<SsoBind>>) -> Router {
    Router::new()
        .route("/", get(chrome))
        .route("/api/studio", get(studio_manifest))
        .route("/api/studio/progress", get(studio_progress))
        .route("/api/studio/sync", get(sync_status).post(run_sync))
        .route("/api/session", get(session_status))
        .route("/api/session/login", post(login))
        .route("/api/session/logout", post(logout))
        .route("/api/studio/ag-ui", axum::routing::any(chrome_agui))
        .route("/stand/{slug}/api/{*rest}", axum::routing::any(stand_api))
        .route("/stand/{slug}/{app}", get(spa_slash))
        .route("/stand/{slug}/{app}/", get(spa_index))
        .route("/stand/{slug}/{app}/{*rest}", get(spa_asset))
        .with_state(AppState { proxy, sso })
}

async fn chrome(State(state): State<AppState>) -> Html<String> {
    Html(read_chrome(&state.proxy.cfg))
}

async fn chrome_agui(
    State(state): State<AppState>,
    method: Method,
    headers: HeaderMap,
    uri: Uri,
    body: Bytes,
) -> axum::response::Response {
    let origin = state
        .sso
        .iter()
        .find(|app| app.tab == SystemTab::Chat)
        .map(|app| app.origin.as_str())
        .unwrap_or_else(|| state.proxy.cfg.origin_for_system(SystemTab::Chat))
        .to_string();
    sso::handle_studio_agui(&state.proxy, &origin, method, headers, uri, body).await
}

async fn studio_manifest(State(state): State<AppState>) -> Json<serde_json::Value> {
    let slug = state
        .proxy
        .live
        .session()
        .map(|session| session.slug.clone());
    let mut tabs = Vec::new();
    for tab in DesignerTab::ALL {
        let path = match &slug {
            Some(slug) => tab.stand_path(slug),
            None => format!("/stand/{{slug}}/{}/", tab.id()),
        };
        tabs.push(serde_json::json!({
            "id": tab.id(),
            "label": tab.label(),
            "code": tab.station_code(),
            "kind": "stand",
            "path": path,
        }));
    }
    for app in state.sso.iter() {
        tabs.push(serde_json::json!({
            "id": app.tab.id(),
            "label": app.tab.label(),
            "code": app.tab.station_code(),
            "kind": "sso",
            "path": app.chrome_path(),
            "origin": app.origin,
        }));
    }
    Json(serde_json::json!({
        "product": "METRO-ARK Studio",
        "tabs": tabs,
        "excluded": ["game", "alife"],
    }))
}

async fn studio_progress(State(state): State<AppState>) -> Json<Progress> {
    Json(state.proxy.progress.snapshot())
}

async fn sync_status(State(state): State<AppState>) -> Json<serde_json::Value> {
    let snap = state.proxy.live.snapshot();
    Json(serde_json::json!({
        "online": snap.online,
        "mode": snap.mode,
        "slug": snap.slug,
        "cached_objects": snap.cached_objects,
        "last_probe": snap.last_probe,
        "last_sync_ok": snap.last_sync_ok,
        "stand": state.proxy.cfg.stand_origin(),
    }))
}

async fn session_status(State(state): State<AppState>) -> Json<serde_json::Value> {
    restore_session_if_needed(&state.proxy).await;
    let remembered = remember::load(&state.proxy.cfg.cache_dir);
    match state.proxy.live.session() {
        Some(session) => Json(serde_json::json!({
            "authenticated": true,
            "slug": session.slug,
            "username": session.username,
            "desk": DesignerTab::Level.stand_path(&session.slug),
            "remember": remembered.is_some(),
        })),
        None => match remembered {
            Some(login) => Json(serde_json::json!({
                "authenticated": false,
                "remember": true,
                "slug": login.slug,
                "username": login.username,
            })),
            None => Json(serde_json::json!({
                "authenticated": false,
                "remember": false,
            })),
        },
    }
}

#[derive(Deserialize)]
struct LoginBody {
    slug: String,
    username: String,
    password: String,
    #[serde(default)]
    remember: bool,
}

async fn login(
    State(state): State<AppState>,
    Json(body): Json<LoginBody>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let slug = parse_slug(&body.slug).map_err(|err| {
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": err })),
        )
    })?;
    let session = login_with_password(
        &state.proxy.cfg,
        &slug,
        body.username.trim(),
        &body.password,
    )
    .await
    .map_err(|err| {
        (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": err })),
        )
    })?;
    let username = session.username.clone();
    persist_or_clear_remember(&state.proxy, &session, body.remember, body.username.trim());
    state.proxy.live.set_session(session);
    schedule_post_login_sync(state.proxy.clone(), body.remember);
    Ok(Json(serde_json::json!({
        "ok": true,
        "slug": slug,
        "username": username,
        "desk": DesignerTab::Level.stand_path(&slug),
        "mode": state.proxy.live.snapshot().mode,
    })))
}

fn persist_or_clear_remember(proxy: &Proxy, session: &Session, remember: bool, username: &str) {
    if remember {
        let _ = remember::save(
            &proxy.cfg.cache_dir,
            &RememberedLogin {
                slug: session.slug.clone(),
                username: username.to_string(),
            },
        );
        let _ = remember::save_session_jar(
            &proxy.cfg.cache_dir,
            session.jar.as_ref(),
            &proxy.cfg.cookie_jar_urls(),
        );
    } else {
        remember::clear(&proxy.cfg.cache_dir);
    }
}

/// Prefetch + Chat/S3 settle run after the login JSON. Do not `.await` this
/// from the login handler.
fn schedule_post_login_sync(proxy: Arc<Proxy>, persist_jar: bool) {
    tokio::spawn(async move {
        let Some(session) = proxy.live.session() else {
            return;
        };
        crate::sso::settle_system_apps(&session.client, &proxy.cfg).await;
        if persist_jar {
            let _ = remember::save_session_jar(
                &proxy.cfg.cache_dir,
                session.jar.as_ref(),
                &proxy.cfg.cookie_jar_urls(),
            );
        }
        proxy.progress.begin("sync");
        let mut paths = prefetch_json_paths(&session.slug);
        let _ = proxy.prefetch_json(&session, &paths).await;
        if let Some(list) = proxy.cache.get(&crate::cache::ReadCache::key(
            "GET",
            &format!("/stand/{}/api/levels", session.slug),
        )) {
            paths.extend(level_paths_from_list(&session.slug, &list.body));
            let extra: Vec<String> = paths.into_iter().skip(5).collect();
            let _ = proxy.prefetch_json(&session, &extra).await;
        }
        let atlas_paths = atlas_prefetch_from_cache(&proxy.cache, &session.slug);
        if !atlas_paths.is_empty() {
            let _ = proxy.prefetch_json(&session, &atlas_paths).await;
        }
        proxy.progress.finish();
    });
}

async fn restore_session_if_needed(proxy: &Proxy) {
    if proxy.live.session().is_some() {
        return;
    }
    let Some(meta) = remember::load(&proxy.cfg.cache_dir) else {
        return;
    };
    let Some(jar) = remember::load_session_jar(&proxy.cfg.cache_dir) else {
        return;
    };
    match resume_from_jar(&proxy.cfg, &meta.slug, jar).await {
        Ok(session) => proxy.live.set_session(session),
        Err(_) => remember::clear_session_blob(&proxy.cfg.cache_dir),
    }
}

async fn logout(State(state): State<AppState>) -> Json<serde_json::Value> {
    state.proxy.live.clear_session();
    remember::clear_session_blob(&state.proxy.cfg.cache_dir);
    Json(serde_json::json!({ "ok": true }))
}

async fn run_sync(State(state): State<AppState>) -> Result<Json<serde_json::Value>, StatusCode> {
    let Some(session) = state.proxy.live.session() else {
        return Err(StatusCode::UNAUTHORIZED);
    };
    state.proxy.progress.begin("sync");
    let mut paths = prefetch_json_paths(&session.slug);
    let n = state.proxy.prefetch_json(&session, &paths).await;
    let mut extra_n = 0usize;
    if let Some(list) = state.proxy.cache.get(&crate::cache::ReadCache::key(
        "GET",
        &format!("/stand/{}/api/levels", session.slug),
    )) {
        let extra = level_paths_from_list(&session.slug, &list.body);
        extra_n += state.proxy.prefetch_json(&session, &extra).await;
        paths.extend(extra);
    }
    let atlas_paths = atlas_prefetch_from_cache(&state.proxy.cache, &session.slug);
    extra_n += state.proxy.prefetch_json(&session, &atlas_paths).await;
    let mut spa = 0usize;
    for tab in DesignerTab::ALL {
        if refresh_app_join(&state.proxy, &session, &session.slug, tab.id())
            .await
            .unwrap_or(false)
        {
            spa += 1;
        }
    }
    state.proxy.progress.finish();
    Ok(Json(serde_json::json!({
        "ok": true,
        "fetched": n + extra_n,
        "spa_updated": spa,
        "mode": state.proxy.live.snapshot().mode,
        "cached_objects": state.proxy.cache.len(),
    })))
}

fn atlas_prefetch_from_cache(cache: &ReadCache, slug: &str) -> Vec<String> {
    cache
        .get(&ReadCache::key(
            "GET",
            &format!("/stand/{slug}/api/spawn-bindings"),
        ))
        .map(|hit| atlas_paths_from_bindings(slug, &hit.body))
        .unwrap_or_default()
}

async fn stand_api(
    State(state): State<AppState>,
    AxumPath((slug, rest)): AxumPath<(String, String)>,
    method: Method,
    headers: HeaderMap,
    uri: Uri,
    body: Bytes,
) -> axum::response::Response {
    let Some(session) = state.proxy.live.session() else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": "нужен вход" })),
        )
            .into_response();
    };
    if session.slug != slug {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({ "error": "другой стенд" })),
        )
            .into_response();
    }
    let path = format!("/stand/{slug}/api/{rest}");
    let pq = Proxy::path_and_query(&path, uri.query());
    state
        .proxy
        .forward(&session, method, &pq, headers, body)
        .await
}

async fn spa_slash(
    AxumPath((slug, app)): AxumPath<(String, String)>,
) -> Result<Redirect, StatusCode> {
    if parse_slug(&slug).is_err() {
        return Err(StatusCode::BAD_REQUEST);
    }
    if DesignerTab::from_id(&app).is_none() {
        return Err(StatusCode::NOT_FOUND);
    }
    Ok(Redirect::temporary(&format!("/stand/{slug}/{app}/")))
}

async fn spa_index(
    State(state): State<AppState>,
    AxumPath((slug, app)): AxumPath<(String, String)>,
) -> impl IntoResponse {
    fill_overlay_for_tab(&state, &slug, &app).await;
    spa_file(&state, &slug, &app, "index.html")
}

async fn spa_asset(
    State(state): State<AppState>,
    AxumPath((slug, app, rest)): AxumPath<(String, String, String)>,
) -> impl IntoResponse {
    spa_file(&state, &slug, &app, &rest)
}

async fn fill_overlay_for_tab(state: &AppState, slug: &str, app: &str) {
    if DesignerTab::from_id(app).is_none() {
        return;
    }
    let Some(session) = state.proxy.live.session() else {
        return;
    };
    // Private game may bake hashed SPAs: first paint is local, overlay SWR.
    // Public chrome-only: wait for the stand so the iframe is not an empty shell.
    // Do not require probe-online here — first tab after login must still fetch.
    if baked_is_packaged(app) {
        maybe_refresh_spa(state, slug, app);
        return;
    }
    if let Some((bytes, SpaSource::Overlay)) = read_spa(&state.proxy.cfg, app, "index.html") {
        if looks_like_packaged_editor(&bytes) {
            maybe_refresh_spa(state, slug, app);
            return;
        }
    }
    let _ = refresh_app(&state.proxy, &session, slug, app).await;
}

fn maybe_refresh_spa(state: &AppState, slug: &str, app: &str) {
    let Some(session) = state.proxy.live.session() else {
        return;
    };
    if !state.proxy.live.is_online() {
        return;
    }
    if DesignerTab::from_id(app).is_none() {
        return;
    }
    let proxy = state.proxy.clone();
    let slug = slug.to_string();
    let app = app.to_string();
    tokio::spawn(async move {
        let _ = refresh_app(&proxy, &session, &slug, &app).await;
    });
}

fn spa_file(
    state: &AppState,
    slug: &str,
    app: &str,
    rest: &str,
) -> Result<(StatusCode, HeaderMap, Bytes), StatusCode> {
    if parse_slug(slug).is_err() {
        return Err(StatusCode::BAD_REQUEST);
    }
    if DesignerTab::from_id(app).is_none() {
        return Err(StatusCode::NOT_FOUND);
    }
    if rest.contains("..") {
        return Err(StatusCode::BAD_REQUEST);
    }
    let rel = if rest.is_empty() { "index.html" } else { rest };
    let (bytes, source) = match read_spa(&state.proxy.cfg, app, rel) {
        Some(hit) => hit,
        None if rel == "index.html" || rel.ends_with("/index.html") => {
            return Ok((
                StatusCode::OK,
                spa_headers("index.html", SpaSource::Baked),
                Bytes::from(missing_editor_html(app)),
            ));
        }
        None => return Err(StatusCode::NOT_FOUND),
    };
    Ok((StatusCode::OK, spa_headers(rel, source), bytes))
}

fn spa_headers(rel: &str, source: SpaSource) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        content_type_for_name(rel).parse().unwrap(),
    );
    headers.insert(
        header::HeaderName::from_static("x-studio-spa"),
        source.as_str().parse().unwrap(),
    );
    if rel.contains("/assets/") || rel.starts_with("assets/") {
        headers.insert(
            header::CACHE_CONTROL,
            "public, max-age=31536000, immutable".parse().unwrap(),
        );
    }
    headers
}

fn missing_editor_html(app: &str) -> String {
    format!(
        "<!doctype html><html lang=\"ru\"><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
         <title>{app}</title>\
         <body data-studio-placeholder=\"stand\" style=\"background:#161412;color:#e8d5a8;font-family:'DejaVu Sans','Noto Sans',sans-serif;padding:24px\">\
         <p>Вкладка <strong>{app}</strong> грузится со стенда <code>my.mcpwork.space</code>.</p>\
         <p>В этом билде нет зашитого редактора — только chrome. Повтор через пару секунд.</p>\
         <script>setTimeout(function(){{location.reload();}},2000);</script>\
         </body></html>"
    )
}

fn content_type_for_name(name: &str) -> &'static str {
    let ext = name.rsplit('.').next().unwrap_or("");
    match ext {
        "html" => "text/html; charset=utf-8",
        "js" => "text/javascript; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "json" => "application/json",
        "woff2" => "font/woff2",
        _ => "application/octet-stream",
    }
}

async fn probe_loop(proxy: Arc<Proxy>) {
    let mut tick = tokio::time::interval(std::time::Duration::from_secs(4));
    loop {
        tick.tick().await;
        let Some(session) = proxy.live.session() else {
            continue;
        };
        let url = format!("{}{}", proxy.cfg.stand_origin(), health_path(&session.slug));
        match session
            .client
            .get(&url)
            .timeout(proxy.cfg.probe_timeout)
            .send()
            .await
        {
            Ok(res) if res.status().is_success() => proxy.live.set_online(true),
            _ => proxy.live.set_online(false),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::await_loopback;
    use crate::config::StudioConfig;
    use std::path::PathBuf;

    const CHROME: &str = include_str!("../ui/index.html");

    /// Temp root with the real chrome on disk; cache under `root/cache`.
    fn fixture(label: &str) -> (PathBuf, StudioConfig) {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let root = std::env::temp_dir().join(format!(
            "designer-host-{label}-{}-{stamp}",
            std::process::id()
        ));
        let ui = root.join("ui");
        std::fs::create_dir_all(&ui).unwrap();
        std::fs::write(ui.join("index.html"), CHROME).unwrap();
        let mut cfg = StudioConfig::production(ui, 0, Some(root.join("cache")));
        // Never reach the live stand / Authentik from a unit test.
        cfg.stand_host = "http://127.0.0.1:1".into();
        cfg.auth_host = "http://127.0.0.1:1".into();
        cfg.probe_timeout = std::time::Duration::from_millis(500);
        (root, cfg)
    }

    fn bound(cfg: StudioConfig) -> LocalHost {
        let host = bind_local_host(cfg).expect("bind");
        await_loopback(host.addr);
        host
    }

    fn remember_akadmin(cache: &std::path::Path) {
        remember::save(
            cache,
            &RememberedLogin {
                slug: "cursorgo".into(),
                username: "akadmin".into(),
            },
        )
        .unwrap();
    }

    fn save_dead_jar(cache: &std::path::Path) {
        let jar = reqwest::cookie::Jar::default();
        let url = reqwest::Url::parse("https://auth.mcpwork.space/").unwrap();
        jar.add_cookie_str("authentik_session=dead-cookie; Path=/; Secure", &url);
        remember::save_session_jar(cache, &jar, &["https://auth.mcpwork.space/".into()]).unwrap();
    }

    async fn serve(app: Router) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        format!("http://{addr}")
    }

    /// Mock Authentik `/api/v3/core/users/me/`.
    async fn mock_authentik(whoami: (StatusCode, serde_json::Value)) -> String {
        serve(Router::new().route(
            "/api/v3/core/users/me/",
            get(move || {
                let (status, body) = whoami.clone();
                async move { (status, Json(body)) }
            }),
        ))
        .await
    }

    async fn get_json(client: &reqwest::Client, url: String) -> serde_json::Value {
        client.get(url).send().await.unwrap().json().await.unwrap()
    }

    async fn status_of(client: &reqwest::Client, url: String) -> reqwest::StatusCode {
        client.get(url).send().await.unwrap().status()
    }

    fn header<'a>(res: &'a reqwest::Response, name: &str) -> Option<&'a str> {
        res.headers().get(name).and_then(|v| v.to_str().ok())
    }

    fn header_is(res: &reqwest::Response, name: &str, needle: &str) -> bool {
        header(res, name).is_some_and(|v| v.contains(needle))
    }

    #[test]
    fn chrome_login_gate_has_remember_and_no_totp() {
        assert!(
            CHROME.contains("name=\"remember\""),
            "login body `remember` flag comes from the gate checkbox"
        );
        let lower = CHROME.to_ascii_lowercase();
        assert!(!lower.contains("totp"), "this Authentik has no TOTP stage");
        assert!(!lower.contains("one-time-code"));
    }

    #[test]
    fn tauri_chrome_may_navigate_loopback_and_listen_events() {
        let conf: serde_json::Value =
            serde_json::from_str(include_str!("../tauri.conf.json")).unwrap();
        assert_eq!(conf["app"]["withGlobalTauri"], true);
        let caps: serde_json::Value =
            serde_json::from_str(include_str!("../capabilities/default.json")).unwrap();
        let urls = caps["remote"]["urls"].as_array().unwrap();
        assert!(urls.iter().any(|u| u == "http://127.0.0.1:*"), "{urls:?}");
        let perms = caps["permissions"].as_array().unwrap();
        assert!(perms.iter().any(|p| p == "core:event:default"), "{perms:?}");
    }

    #[test]
    fn placeholder_html_is_not_a_packaged_editor() {
        let placeholder = missing_editor_html("level");
        assert!(placeholder.contains("data-studio-placeholder"));
        assert!(!looks_like_packaged_editor(placeholder.as_bytes()));
    }

    #[test]
    fn loopback_host_routes_manifest_session_and_stand_paths() {
        let (root, cfg) = fixture("routes");
        let host = bound(cfg);
        let base = host.chrome_url();
        Runtime::new().unwrap().block_on(async {
            let client = reqwest::Client::new();

            let studio = get_json(&client, format!("{base}api/studio")).await;
            let ids: Vec<&str> = studio["tabs"]
                .as_array()
                .unwrap()
                .iter()
                .map(|tab| tab["id"].as_str().unwrap())
                .collect();
            assert_eq!(ids, ["level", "sprites", "bestiary", "chat", "s3"]);
            assert_eq!(studio["excluded"], serde_json::json!(["game", "alife"]));
            assert_eq!(studio["tabs"][0]["kind"], "stand");
            assert_eq!(studio["tabs"][0]["path"], "/stand/{slug}/level/");
            assert_eq!(studio["tabs"][3]["kind"], "sso");
            let chat_path = studio["tabs"][3]["path"].as_str().unwrap();
            assert!(chat_path.starts_with("http://127.0.0.1:"), "{chat_path}");
            assert_eq!(studio["tabs"][3]["origin"], "https://chat.mcpwork.space");
            assert_eq!(studio["tabs"][4]["origin"], "https://s3.mcpwork.space");

            let session = get_json(&client, format!("{base}api/session")).await;
            assert_eq!(session["authenticated"], false);
            assert_eq!(session["remember"], false);

            let sync = get_json(&client, format!("{base}api/studio/sync")).await;
            assert_eq!(sync["online"], false);

            let progress = get_json(&client, format!("{base}api/studio/progress")).await;
            assert_eq!(progress["phase"], "idle");
            assert_eq!(progress["files_done"], 0);

            let home = client.get(&base).send().await.unwrap();
            assert!(header_is(&home, "content-type", "text/html"));
            assert_eq!(
                home.text().await.unwrap(),
                CHROME,
                "chrome is served from ui_dir"
            );

            let no_follow = reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap();
            assert_eq!(
                status_of(&no_follow, format!("{base}stand/cursorgo/level")).await,
                reqwest::StatusCode::TEMPORARY_REDIRECT
            );
            for excluded in ["game", "alife"] {
                assert_eq!(
                    status_of(&client, format!("{base}stand/cursorgo/{excluded}/")).await,
                    reqwest::StatusCode::NOT_FOUND,
                    "{excluded}"
                );
            }
            assert_eq!(
                status_of(&client, format!("{base}stand/NewEditor/level/")).await,
                reqwest::StatusCode::BAD_REQUEST,
                "slug shape is validated"
            );
            assert_eq!(
                status_of(&client, format!("{base}stands/cursorgo/level/")).await,
                reqwest::StatusCode::NOT_FOUND,
                "only singular /stand/"
            );

            let spa = client
                .get(format!("{base}stand/cursorgo/level/"))
                .send()
                .await
                .unwrap();
            assert_eq!(spa.status(), reqwest::StatusCode::OK);
            assert!(header_is(&spa, "content-type", "text/html"));
            assert_eq!(header(&spa, "x-studio-spa"), Some("baked"));

            // Without a session nothing proxies: stand API, chrome streamer, SSO port.
            assert_eq!(
                status_of(&client, format!("{base}stand/cursorgo/api/levels")).await,
                reqwest::StatusCode::UNAUTHORIZED
            );
            assert_eq!(
                status_of(
                    &client,
                    format!(
                        "{base}api/studio/ag-ui?to=/api/runs/30289690-b756-416a-ac0d-5bc9a3396ef7"
                    )
                )
                .await,
                reqwest::StatusCode::UNAUTHORIZED
            );
            let chat_port = host
                .sso
                .iter()
                .find(|app| app.tab == SystemTab::Chat)
                .unwrap()
                .port;
            assert_eq!(
                status_of(&client, format!("http://127.0.0.1:{chat_port}/api/me")).await,
                reqwest::StatusCode::UNAUTHORIZED
            );
        });
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn remembered_login_is_returned_until_cleared() {
        let (root, cfg) = fixture("remember");
        let cache = cfg.cache_dir.clone();
        remember_akadmin(&cache);
        let host = bound(cfg);
        let base = host.chrome_url();
        Runtime::new().unwrap().block_on(async {
            let client = reqwest::Client::new();
            let session = get_json(&client, format!("{base}api/session")).await;
            assert_eq!(session["authenticated"], false);
            assert_eq!(session["remember"], true);
            assert_eq!(session["slug"], "cursorgo");
            assert_eq!(session["username"], "akadmin");
            assert!(session.get("password").is_none());

            remember::clear(&cache);
            let cleared = get_json(&client, format!("{base}api/session")).await;
            assert_eq!(cleared["authenticated"], false);
            assert_eq!(cleared["remember"], false);
        });
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn rejected_session_blob_is_cleared_but_login_stays_remembered() {
        let (root, mut cfg) = fixture("blob-rejected");
        let cache = cfg.cache_dir.clone();
        remember_akadmin(&cache);
        save_dead_jar(&cache);
        let rt = Runtime::new().unwrap();
        cfg.auth_host = rt.block_on(mock_authentik((
            StatusCode::FORBIDDEN,
            serde_json::json!({ "detail": "Authentication credentials were not provided." }),
        )));
        let host = bound(cfg);
        let base = host.chrome_url();
        rt.block_on(async {
            let session = get_json(&reqwest::Client::new(), format!("{base}api/session")).await;
            assert_eq!(session["authenticated"], false);
            assert_eq!(session["remember"], true);
            assert_eq!(session["slug"], "cursorgo");
            assert_eq!(session["username"], "akadmin");
        });
        assert!(
            remember::load_session_jar(&cache).is_none(),
            "a jar Authentik rejects is dropped so it is not retried forever"
        );
        assert!(
            remember::load(&cache).is_some(),
            "slug/username prefill survives"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn accepted_session_blob_restores_login_without_the_gate() {
        let (root, mut cfg) = fixture("blob-accepted");
        let cache = cfg.cache_dir.clone();
        remember_akadmin(&cache);
        save_dead_jar(&cache);
        let rt = Runtime::new().unwrap();
        cfg.auth_host = rt.block_on(mock_authentik((
            StatusCode::OK,
            serde_json::json!({ "user": { "pk": 17, "username": "akadmin", "is_active": true } }),
        )));
        let host = bound(cfg);
        let base = host.chrome_url();
        rt.block_on(async {
            let client = reqwest::Client::new();
            let session = get_json(&client, format!("{base}api/session")).await;
            assert_eq!(session["authenticated"], true);
            assert_eq!(session["slug"], "cursorgo");
            assert_eq!(session["username"], "akadmin");
            assert_eq!(session["desk"], "/stand/cursorgo/level/");
            assert_eq!(session["remember"], true);

            let studio = get_json(&client, format!("{base}api/studio")).await;
            assert_eq!(studio["tabs"][0]["path"], "/stand/cursorgo/level/");
        });
        assert!(remember::load_session_jar(&cache).is_some(), "blob is kept");
        let _ = std::fs::remove_dir_all(root);
    }
}
