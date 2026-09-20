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
                        let _ = axum::serve(listener, sso::router(proxy, bind.origin)).await;
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
        .route("/stand/{slug}/api/{*rest}", axum::routing::any(stand_api))
        .route("/stand/{slug}/{app}", get(spa_slash))
        .route("/stand/{slug}/{app}/", get(spa_index))
        .route("/stand/{slug}/{app}/{*rest}", get(spa_asset))
        .with_state(AppState { proxy, sso })
}

async fn chrome(State(state): State<AppState>) -> Html<String> {
    Html(read_chrome(&state.proxy.cfg))
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
    use crate::config::StudioConfig;

    fn assert_chrome_has_no_totp(html: &str) {
        let lower = html.to_ascii_lowercase();
        assert!(!lower.contains("totp"), "chrome must not mention TOTP");
        assert!(!html.contains("one-time-code"));
        assert!(!html.contains("есть TOTP"));
        assert!(!html.contains("showTotp"));
        assert!(!html.contains("totpNeeded"));
        assert!(!html.contains("totpWrap"));
        assert!(!html.contains("name=\"totp\""));
        assert!(!html.contains("id=\"totp\""));
        assert!(!html.contains("form.totp"));
        assert!(!html.contains("TOTP, если есть"));
    }

    #[test]
    fn spa_rejects_unknown_apps() {
        assert!(DesignerTab::from_id("game").is_none());
        assert!(DesignerTab::from_id("alife").is_none());
        assert!(DesignerTab::from_id("level").is_some());
    }

    #[test]
    fn chrome_hides_gate_and_remote_nav() {
        let html = include_str!("../ui/index.html");
        assert!(html.contains("[hidden] { display: none !important; }"));
        assert!(html.contains("MutationObserver"));
        assert!(html.contains("setProperty"));
        assert!(html.contains("querySelectorAll(\"nav.studio-nav, .studio-nav\")"));
        assert!(html.contains("nav.studio-nav,.studio-nav,"));
        assert!(html.contains("Синхронизировать"));
        assert!(html.contains("ОФФЛАЙН"));
        assert!(html.contains("id=\"desks\""));
        assert!(html.contains("id=\"xfer\""));
        assert!(html.contains("id=\"xferRail\""));
        assert!(html.contains("--ticket-h"));
        assert!(html.contains("xfer-card"));
        assert!(html.contains("Вкладка ·"));
        assert!(html.contains("index/solid/App"));
        assert!(html.contains("ЗАГРУЗКА"));
        assert!(html.contains("/api/studio/progress"));
        assert!(html.contains("studio-progress"));
        assert!(html.contains("name=\"remember\""));
        assert!(html.contains("Запомнить вход"));
        assert!(html.contains("fillRemembered"));
        assert!(html.contains("const frames = new Map()"));
        assert_chrome_has_no_totp(html);
        assert!(html.contains("class=\"stand\""));
        assert!(html.contains("autocomplete=\"organization\""));
        assert!(html.contains("autocomplete=\"username\""));
        assert!(html.contains("autocomplete=\"current-password\""));
        assert!(html.contains("min-height: 44px"));
        assert!(!html.contains("Стенд (slug)"));
        assert!(html.contains("tabPath"));
        assert!(html.contains("studioTabs"));
        assert!(!html.contains("\"/stand/\" + slug + \"/\" + tab.id"));
        assert!(html.contains("isTauriWebview"));
        assert!(html.contains("__TAURI_INTERNALS__"));
        assert!(html.contains("listen(\"studio-progress\""));
        assert!(html.contains("applyStudioProgress"));
        assert!(html.contains("setInterval(pollProgress, 250)"));
        assert!(!html.contains("setInterval(() => { pollProgress(); }, 250)"));
        assert!(html.contains("Загрузка"));
        assert!(include_str!("../capabilities/default.json").contains("http://127.0.0.1:*"));
        assert!(include_str!("../capabilities/default.json").contains("core:event:default"));
        assert!(!html.contains("grid-template-columns: minmax(140px, 220px) 1fr auto"));
        assert!(!html.contains("bottom: calc(16px + env(safe-area-inset-bottom))"));
        assert!(include_str!("../tauri.conf.json").contains("\"withGlobalTauri\": true"));
        assert!(html.contains("placeholder=\"cursorgo\""));
        assert!(!html.contains("placeholder=\"neweditor\""));
        assert!(!html.contains("src=\"/stand"));
        assert!(!html.contains("game-client"));
        let placeholder = missing_editor_html("level");
        assert!(placeholder.contains("data-studio-placeholder"));
        assert!(!placeholder.contains("package_designer_studio_ui"));
        assert!(!looks_like_packaged_editor(placeholder.as_bytes()));
    }

    #[test]
    fn loopback_host_keeps_web_paths_and_excludes_game() {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0);
        let root =
            std::env::temp_dir().join(format!("designer-host-{}-{}", std::process::id(), stamp));
        let ui = root.join("ui");
        std::fs::create_dir_all(&ui).unwrap();
        std::fs::write(ui.join("index.html"), include_str!("../ui/index.html")).unwrap();
        let host = bind_local_host(StudioConfig::production(ui, 0, Some(root.join("cache"))))
            .expect("bind");
        std::thread::sleep(std::time::Duration::from_millis(150));
        let base = host.chrome_url();
        let rt = Runtime::new().unwrap();
        rt.block_on(async {
            let client = reqwest::Client::new();
            let studio: serde_json::Value = client
                .get(format!("{base}api/studio"))
                .send()
                .await
                .unwrap()
                .json()
                .await
                .unwrap();
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
            assert!(chat_path.starts_with("http://127.0.0.1:"));
            assert_eq!(studio["tabs"][3]["origin"], "https://chat.mcpwork.space");
            assert_eq!(studio["tabs"][4]["origin"], "https://s3.mcpwork.space");

            let session: serde_json::Value = client
                .get(format!("{base}api/session"))
                .send()
                .await
                .unwrap()
                .json()
                .await
                .unwrap();
            assert_eq!(session["authenticated"], false);
            assert_eq!(session["remember"], false);

            let sync: serde_json::Value = client
                .get(format!("{base}api/studio/sync"))
                .send()
                .await
                .unwrap()
                .json()
                .await
                .unwrap();
            assert_eq!(sync["mode"], "оффлайн");

            let progress: serde_json::Value = client
                .get(format!("{base}api/studio/progress"))
                .send()
                .await
                .unwrap()
                .json()
                .await
                .unwrap();
            assert_eq!(progress["phase"], "idle");
            assert_eq!(progress["files_done"], 0);
            assert_eq!(progress["files_total"], 0);
            assert_eq!(progress["bytes_done"], 0);
            assert_eq!(progress["path"], "");

            let home = client
                .get(&base)
                .send()
                .await
                .unwrap()
                .text()
                .await
                .unwrap();
            assert!(home.contains("[hidden] { display: none !important; }"));
            assert!(home.contains("MutationObserver"));
            assert!(home.contains("querySelectorAll(\"nav.studio-nav, .studio-nav\")"));
            assert!(home.contains("id=\"desks\""));
            assert!(home.contains("id=\"xfer\""));
            assert!(home.contains("/api/studio/progress"));
            assert!(home.contains("tabPath"));
            assert!(home.contains("studioTabs"));
            assert!(home.contains("name=\"remember\""));
            assert!(home.contains("Запомнить вход"));
            assert!(home.contains("fillRemembered"));
            assert_chrome_has_no_totp(&home);
            assert!(!home.contains("src=\"/stand"));
            assert!(!home.contains("\"/stand/\" + slug + \"/\" + tab.id"));

            let no_follow = reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap();
            assert_eq!(
                no_follow
                    .get(format!("{base}stand/cursorgo/level"))
                    .send()
                    .await
                    .unwrap()
                    .status(),
                reqwest::StatusCode::TEMPORARY_REDIRECT
            );
            assert_eq!(
                no_follow
                    .get(format!("{base}stand/cursorgo/game"))
                    .send()
                    .await
                    .unwrap()
                    .status(),
                reqwest::StatusCode::NOT_FOUND
            );

            assert_eq!(
                client
                    .get(format!("{base}stand/cursorgo/api/levels"))
                    .send()
                    .await
                    .unwrap()
                    .status(),
                reqwest::StatusCode::UNAUTHORIZED
            );
            assert_eq!(
                client
                    .get(format!("{base}stand/cursorgo/game/"))
                    .send()
                    .await
                    .unwrap()
                    .status(),
                reqwest::StatusCode::NOT_FOUND
            );
            assert_eq!(
                client
                    .get(format!("{base}stand/cursorgo/alife/"))
                    .send()
                    .await
                    .unwrap()
                    .status(),
                reqwest::StatusCode::NOT_FOUND
            );
            let chat_port = host
                .sso
                .iter()
                .find(|app| app.tab.id() == "chat")
                .unwrap()
                .port;
            assert_eq!(
                client
                    .get(format!("http://127.0.0.1:{chat_port}/api/me"))
                    .send()
                    .await
                    .unwrap()
                    .status(),
                reqwest::StatusCode::UNAUTHORIZED
            );
            assert_eq!(
                client
                    .get(format!("{base}stand/NewEditor/level/"))
                    .send()
                    .await
                    .unwrap()
                    .status(),
                reqwest::StatusCode::BAD_REQUEST
            );
            assert_eq!(
                client
                    .get(format!("{base}stands/cursorgo/level/"))
                    .send()
                    .await
                    .unwrap()
                    .status(),
                reqwest::StatusCode::NOT_FOUND
            );
            let spa = client
                .get(format!("{base}stand/cursorgo/level/"))
                .send()
                .await
                .unwrap();
            assert_eq!(spa.status(), reqwest::StatusCode::OK);
            let body = spa.text().await.unwrap();
            assert!(
                body.contains("id=\"root\"")
                    || body.contains("assets/")
                    || body.contains("data-studio-placeholder")
            );
            assert!(!body.contains("/game"));
        });
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn remembered_login_is_returned_until_cleared() {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0);
        let root = std::env::temp_dir().join(format!(
            "designer-remember-{}-{}",
            std::process::id(),
            stamp
        ));
        let ui = root.join("ui");
        std::fs::create_dir_all(&ui).unwrap();
        std::fs::write(ui.join("index.html"), include_str!("../ui/index.html")).unwrap();
        let cache = root.join("cache");
        remember::save(
            &cache,
            &RememberedLogin {
                slug: "cursorgo".into(),
                username: "akadmin".into(),
            },
        )
        .unwrap();
        let host =
            bind_local_host(StudioConfig::production(ui, 0, Some(cache.clone()))).expect("bind");
        std::thread::sleep(std::time::Duration::from_millis(150));
        let base = host.chrome_url();
        let rt = Runtime::new().unwrap();
        rt.block_on(async {
            let client = reqwest::Client::new();
            let session: serde_json::Value = client
                .get(format!("{base}api/session"))
                .send()
                .await
                .unwrap()
                .json()
                .await
                .unwrap();
            assert_eq!(session["authenticated"], false);
            assert_eq!(session["remember"], true);
            assert_eq!(session["slug"], "cursorgo");
            assert_eq!(session["username"], "akadmin");
            assert!(session.get("password").is_none());

            remember::clear(&cache);
            let cleared: serde_json::Value = client
                .get(format!("{base}api/session"))
                .send()
                .await
                .unwrap()
                .json()
                .await
                .unwrap();
            assert_eq!(cleared["authenticated"], false);
            assert_eq!(cleared["remember"], false);
            assert!(cleared.get("password").is_none());
        });
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn login_handler_does_not_await_prefetch() {
        let src = include_str!("host.rs");
        let login_fn = src
            .split("async fn login(")
            .nth(1)
            .expect("login fn")
            .split("\nfn persist_or_clear_remember")
            .next()
            .expect("login end");
        assert!(login_fn.contains("schedule_post_login_sync"));
        assert!(!login_fn.contains("prefetch_json"));
        assert!(!login_fn.contains("settle_system_apps"));
        assert!(src.contains("fn schedule_post_login_sync"));
        assert!(src.contains("tokio::spawn"));
    }

    #[test]
    fn expired_or_dummy_session_blob_stays_unauthenticated() {
        use reqwest::cookie::Jar;
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0);
        let root = std::env::temp_dir().join(format!(
            "designer-session-blob-{}-{}",
            std::process::id(),
            stamp
        ));
        let ui = root.join("ui");
        std::fs::create_dir_all(&ui).unwrap();
        std::fs::write(ui.join("index.html"), include_str!("../ui/index.html")).unwrap();
        let cache = root.join("cache");
        remember::save(
            &cache,
            &RememberedLogin {
                slug: "cursorgo".into(),
                username: "akadmin".into(),
            },
        )
        .unwrap();
        let jar = Jar::default();
        let url = reqwest::Url::parse("https://auth.mcpwork.space/").unwrap();
        jar.add_cookie_str("authentik_session=dead-cookie; Path=/; Secure", &url);
        remember::save_session_jar(&cache, &jar, &["https://auth.mcpwork.space/".into()]).unwrap();
        let mut cfg = StudioConfig::production(ui, 0, Some(cache.clone()));
        cfg.probe_timeout = std::time::Duration::from_millis(400);
        let host = bind_local_host(cfg).expect("bind");
        std::thread::sleep(std::time::Duration::from_millis(150));
        let base = host.chrome_url();
        let rt = Runtime::new().unwrap();
        rt.block_on(async {
            let client = reqwest::Client::new();
            let session: serde_json::Value = client
                .get(format!("{base}api/session"))
                .send()
                .await
                .unwrap()
                .json()
                .await
                .unwrap();
            assert_eq!(session["authenticated"], false);
            assert_eq!(session["remember"], true);
            assert_eq!(session["slug"], "cursorgo");
            assert_eq!(session["username"], "akadmin");
            assert!(session.get("password").is_none());
        });
        let _ = std::fs::remove_dir_all(root);
    }
}
