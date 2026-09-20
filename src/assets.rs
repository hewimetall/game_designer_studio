//! Studio chrome (`ui/index.html`) ships inside the binary.
//!
//! Public `hewimetall/game_designer_studio` is chrome-only: Level / Sprites /
//! Bestiary are not baked. Opening a tab loads `/stand/<slug>/<app>/` through
//! the local proxy; if overlay is empty, the host waits on the live stand
//! (`https://my.mcpwork.space/stand/<slug>/…`) and fills the overlay cache.
//! Private `hewimetall/game` may still rust-embed hashed Vite folders under
//! `ui/{level,sprites,bestiary}` for a local first paint (stale-while-revalidate).
//! Game / A-Life are never fetched. Vite content-hashes mean an unchanged
//! `index.html` ⇒ unchanged JS.
//!
//! Overlay fetch is a BFS over the chunk graph: `index.html` script/link tags
//! are not enough once Solid `lazy()` splits Workbench into `./Chunk-xxxxx.js`
//! next to the entry. `collect_relative_refs`, `collect_bare_chunk_refs`,
//! and `resolve_against` walk HTML + JS + CSS until the graph is closed.
//!
//! <https://v2.tauri.app/reference/config/> frontendDist embeds a folder into
//! the binary the same way. <https://vite.dev/guide/build> hashed `/assets/*`
//! are immutable; we revalidate only the HTML entry. With `base: './'`, Vite
//! resolves async preload deps via `import.meta.url`
//! (<https://vite.dev/config/build-options#build-modulepreload>).

use std::collections::{HashSet, VecDeque};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use bytes::Bytes;
use rust_embed::Embed;
use sha2::{Digest, Sha256};

use crate::apps::DesignerTab;
use crate::config::StudioConfig;
use crate::progress::ProgressHub;
use crate::proxy::Proxy;
use crate::session::Session;

const MAX_REMOTE_HTML: usize = 64 * 1024;
const MAX_REMOTE_ASSET: usize = 2 * 1024 * 1024;
const MAX_SPA_FILES: usize = 48;
const MAX_SPA_DEPTH: usize = 8;

#[derive(Embed)]
#[folder = "ui"]
struct BakedUi;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpaSource {
    Overlay,
    Disk,
    Baked,
}

impl SpaSource {
    pub fn as_str(self) -> &'static str {
        match self {
            SpaSource::Overlay => "overlay",
            SpaSource::Disk => "disk",
            SpaSource::Baked => "baked",
        }
    }
}

pub fn spa_overlay_dir(cfg: &StudioConfig) -> PathBuf {
    cfg.cache_dir.join("spa")
}

pub fn read_chrome(cfg: &StudioConfig) -> String {
    let disk = cfg.ui_dir.join("index.html");
    if let Ok(text) = fs::read_to_string(&disk) {
        return text;
    }
    baked_text("index.html").unwrap_or_else(|| {
        "<!doctype html><title>METRO-ARK Studio</title><p>chrome не зашит</p>".into()
    })
}

pub fn read_spa(cfg: &StudioConfig, app: &str, rest: &str) -> Option<(Bytes, SpaSource)> {
    let rel = spa_rel(app, rest);
    let overlay = spa_overlay_dir(cfg).join(&rel);
    if overlay.is_file() {
        if let Ok(bytes) = fs::read(&overlay) {
            return Some((Bytes::from(bytes), SpaSource::Overlay));
        }
    }
    let disk = cfg.ui_dir.join(&rel);
    if disk.is_file() {
        if let Ok(bytes) = fs::read(&disk) {
            return Some((Bytes::from(bytes), SpaSource::Disk));
        }
    }
    baked_bytes(&rel).map(|bytes| (bytes, SpaSource::Baked))
}

pub fn baked_index_hash(app: &str) -> Option<String> {
    baked_bytes(&format!("{app}/index.html")).map(|b| sha256_hex(&b))
}

/// True when this build rust-embed'd a Vite SPA for `app`. Chrome-only public
/// binaries return false so the host waits on the stand overlay instead.
pub fn baked_is_packaged(app: &str) -> bool {
    baked_bytes(&format!("{app}/index.html")).is_some_and(|html| looks_like_packaged_editor(&html))
}

pub fn overlay_index_hash(cfg: &StudioConfig, app: &str) -> Option<String> {
    let path = spa_overlay_dir(cfg).join(app).join("index.html");
    fs::read(path).ok().map(|b| sha256_hex(&b))
}

fn spa_rel(app: &str, rest: &str) -> String {
    let rest = if rest.is_empty() { "index.html" } else { rest };
    format!("{app}/{rest}")
}

fn baked_bytes(rel: &str) -> Option<Bytes> {
    let rel = rel.replace('\\', "/");
    BakedUi::get(&rel).map(|file| Bytes::copy_from_slice(&file.data))
}

fn baked_text(rel: &str) -> Option<String> {
    baked_bytes(rel).and_then(|b| String::from_utf8(b.to_vec()).ok())
}

/// Background: if stand HTML for this app differs, download that app only.
pub async fn refresh_app(
    proxy: &Proxy,
    session: &Session,
    slug: &str,
    app: &str,
) -> Result<bool, String> {
    proxy.progress.begin("overlay");
    let result = refresh_app_inner(proxy, session, slug, app).await;
    match &result {
        Ok(_) => proxy.progress.finish(),
        Err(err) => proxy.progress.fail(err),
    }
    result
}

/// Same fetch, but join a Sync job already counting files/bytes.
pub async fn refresh_app_join(
    proxy: &Proxy,
    session: &Session,
    slug: &str,
    app: &str,
) -> Result<bool, String> {
    proxy.progress.set_phase("overlay");
    refresh_app_inner(proxy, session, slug, app).await
}

async fn refresh_app_inner(
    proxy: &Proxy,
    session: &Session,
    slug: &str,
    app: &str,
) -> Result<bool, String> {
    if DesignerTab::from_id(app).is_none() {
        return Ok(false);
    }
    proxy.progress.ensure_files_total(1);
    let remote = fetch_stand_bytes(
        session,
        proxy.cfg.stand_origin(),
        &format!("/stand/{slug}/{app}/"),
        MAX_REMOTE_HTML,
        proxy.cfg.get_timeout,
        &proxy.progress,
    )
    .await?;
    if !looks_like_packaged_editor(&remote) {
        return Ok(false);
    }
    let remote_hash = sha256_hex(&remote);
    if Some(remote_hash.as_str()) == overlay_index_hash(&proxy.cfg, app).as_deref() {
        return Ok(false);
    }
    if Some(remote_hash.as_str()) == baked_index_hash(app).as_deref() {
        let _ = fs::remove_dir_all(spa_overlay_dir(&proxy.cfg).join(app));
        return Ok(false);
    }
    let html = std::str::from_utf8(&remote).unwrap_or("");
    let mut queue: VecDeque<(String, usize)> = collect_all_refs("index.html", html)
        .into_iter()
        .map(|rel| (rel, 1usize))
        .collect();
    let mut seen = HashSet::from(["index.html".to_string()]);
    let mut files: Vec<(String, Bytes)> = Vec::new();
    proxy.progress.note_remaining(queue.len() as u64);
    while let Some((rel, depth)) = queue.pop_front() {
        if !seen.insert(rel.clone()) {
            proxy.progress.note_remaining(queue.len() as u64);
            continue;
        }
        if !is_spa_asset_rel(&rel) {
            proxy.progress.note_remaining(queue.len() as u64);
            continue;
        }
        if depth > MAX_SPA_DEPTH {
            proxy.progress.note_remaining(queue.len() as u64);
            continue;
        }
        if files.len() >= MAX_SPA_FILES {
            return Err(format!("слишком много файлов SPA ({app})"));
        }
        proxy.progress.note_remaining(queue.len() as u64 + 1);
        let bytes = match fetch_stand_bytes(
            session,
            proxy.cfg.stand_origin(),
            &format!("/stand/{slug}/{app}/{rel}"),
            MAX_REMOTE_ASSET,
            proxy.cfg.get_timeout,
            &proxy.progress,
        )
        .await
        {
            Ok(bytes) => bytes,
            Err(_) if !is_critical_spa_rel(&rel) => {
                proxy.progress.note_remaining(queue.len() as u64);
                continue;
            }
            Err(err) => return Err(err),
        };
        if depth < MAX_SPA_DEPTH && is_graph_source(&rel) {
            if let Ok(text) = std::str::from_utf8(&bytes) {
                for child in collect_all_refs(&rel, text) {
                    queue.push_back((child, depth + 1));
                }
            }
        }
        files.push((rel, bytes));
        proxy.progress.note_remaining(queue.len() as u64);
    }
    let overlay_app = spa_overlay_dir(&proxy.cfg).join(app);
    let staging = spa_overlay_dir(&proxy.cfg).join(format!("{app}.staging"));
    let _ = fs::remove_dir_all(&staging);
    for (rel, bytes) in &files {
        write_atomic(&staging.join(rel), bytes)?;
    }
    write_atomic(&staging.join("index.html"), &remote)?;
    let _ = fs::remove_dir_all(&overlay_app);
    fs::rename(&staging, &overlay_app).map_err(|err| err.to_string())?;
    Ok(true)
}

async fn fetch_stand_bytes(
    session: &Session,
    origin: &str,
    path: &str,
    max: usize,
    timeout: std::time::Duration,
    progress: &ProgressHub,
) -> Result<Bytes, String> {
    progress.start_file(path);
    let url = format!("{origin}{path}");
    let mut res = session
        .client
        .get(&url)
        .timeout(timeout)
        .send()
        .await
        .map_err(|err| err.to_string())?;
    if !res.status().is_success() {
        return Err(format!("{} {}", res.status(), path));
    }
    progress.set_current_len(res.content_length());
    let mut out = Vec::new();
    loop {
        match res.chunk().await {
            Ok(Some(chunk)) => {
                let next = out.len().saturating_add(chunk.len());
                if next > max {
                    return Err(format!("слишком большой ответ {path} ({next} байт)"));
                }
                progress.add_bytes(chunk.len() as u64);
                out.extend_from_slice(&chunk);
            }
            Ok(None) => break,
            Err(err) => return Err(err.to_string()),
        }
    }
    progress.complete_file();
    Ok(Bytes::from(out))
}

pub fn looks_like_packaged_editor(html: &[u8]) -> bool {
    let Ok(text) = std::str::from_utf8(html) else {
        return false;
    };
    if text.len() > MAX_REMOTE_HTML {
        return false;
    }
    let has_root = text.contains("id=\"root\"") || text.contains("id='root'");
    let has_vite = text.contains("type=\"module\"") && text.contains("./assets/");
    has_root && has_vite
}

pub fn collect_relative_refs(html: &str) -> Vec<String> {
    let mut refs = Vec::new();
    for (prefix, quote) in [
        ("src=\"", '"'),
        ("href=\"", '"'),
        ("src='", '\''),
        ("href='", '\''),
    ] {
        let mut rest = html;
        while let Some(at) = rest.find(prefix) {
            rest = &rest[at + prefix.len()..];
            let Some(end) = rest.find(quote) else { break };
            let raw = &rest[..end];
            rest = &rest[end + 1..];
            if let Some(rel) = normalize_rel(raw) {
                push_unique(&mut refs, rel);
            }
        }
    }
    refs
}

/// Relative `./Chunk-xxxxx.js`, hashed `"assets/foo-HASH.css"`, and import-looking
/// bare specifiers such as `from"solid-B7kQ2n1x.js"`.
fn collect_bare_chunk_refs(text: &str) -> Vec<String> {
    let mut refs = Vec::new();
    collect_dot_slash_refs(text, &mut refs);
    collect_import_looking_refs(text, &mut refs);
    collect_hashed_quoted_refs(text, &mut refs);
    refs
}

fn collect_all_refs(parent: &str, text: &str) -> Vec<String> {
    let mut refs = Vec::new();
    for rel in collect_relative_refs(text)
        .into_iter()
        .chain(collect_bare_chunk_refs(text))
    {
        let resolved = resolve_against(parent, &rel);
        if resolved.is_empty() || resolved.contains("..") {
            continue;
        }
        push_unique(&mut refs, resolved);
    }
    refs
}

/// Join a sibling chunk with its parent directory. Paths already under `assets/`
/// are SPA-root-relative (Vite `__vite__mapDeps` / HTML tags).
fn resolve_against(parent: &str, rel: &str) -> String {
    let rel = rel.strip_prefix("./").unwrap_or(rel);
    if rel.is_empty() || rel.contains("..") || rel.starts_with('/') {
        return String::new();
    }
    if rel.starts_with("assets/") {
        return rel.to_string();
    }
    match parent.rsplit_once('/') {
        Some((dir, _)) => format!("{dir}/{rel}"),
        None => rel.to_string(),
    }
}

fn collect_dot_slash_refs(text: &str, refs: &mut Vec<String>) {
    // Require a quote or `(` before `./` so `../secret.js` is not parsed as `secret.js`.
    for prefix in ["\"./", "'./", "(./"] {
        let mut rest = text;
        let end_ch = match prefix.as_bytes()[0] {
            b'"' => '"',
            b'\'' => '\'',
            _ => ')',
        };
        while let Some(at) = rest.find(prefix) {
            rest = &rest[at + prefix.len()..];
            let Some(end) = rest.find(end_ch) else { break };
            let raw = &rest[..end];
            rest = &rest[end + 1..];
            if looks_like_chunk_rel(raw) {
                push_unique(refs, raw.to_string());
            }
        }
    }
}

fn collect_import_looking_refs(text: &str, refs: &mut Vec<String>) {
    for (prefix, quote) in [
        ("import(\"", '"'),
        ("import('", '\''),
        ("import\"", '"'),
        ("import'", '\''),
        ("from\"", '"'),
        ("from'", '\''),
    ] {
        let mut rest = text;
        while let Some(at) = rest.find(prefix) {
            rest = &rest[at + prefix.len()..];
            let Some(end) = rest.find(quote) else { break };
            let raw = rest[..end].strip_prefix("./").unwrap_or(&rest[..end]);
            rest = &rest[end + 1..];
            if looks_like_module_rel(raw) {
                push_unique(refs, raw.to_string());
            }
        }
    }
}

fn collect_hashed_quoted_refs(text: &str, refs: &mut Vec<String>) {
    for quote in ['"', '\''] {
        let mut rest = text;
        while let Some(at) = rest.find(quote) {
            rest = &rest[at + 1..];
            let Some(end) = rest.find(quote) else { break };
            let raw = rest[..end].strip_prefix("./").unwrap_or(&rest[..end]);
            rest = &rest[end + 1..];
            if looks_like_hashed_vite_asset(raw) {
                push_unique(refs, raw.to_string());
            }
        }
    }
}

fn looks_like_hashed_vite_asset(raw: &str) -> bool {
    if !looks_like_module_rel(raw) {
        return false;
    }
    let name = raw.rsplit('/').next().unwrap_or(raw);
    let Some((stem, _)) = name.rsplit_once('.') else {
        return false;
    };
    match stem.rsplit_once('-') {
        Some((head, hash))
            if !head.is_empty()
                && hash.len() >= 6
                && hash
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-')) =>
        {
            true
        }
        _ => raw.starts_with("assets/") && raw.bytes().filter(|b| *b == b'/').count() == 1,
    }
}

fn looks_like_module_rel(raw: &str) -> bool {
    looks_like_rel_path(raw)
        && (raw.ends_with(".js") || raw.ends_with(".mjs") || raw.ends_with(".css"))
}

fn looks_like_chunk_rel(raw: &str) -> bool {
    if !looks_like_rel_path(raw) {
        return false;
    }
    let ext = raw.rsplit('.').next().unwrap_or("");
    matches!(
        ext,
        "js" | "mjs" | "css" | "svg" | "woff" | "woff2" | "png" | "webp" | "json" | "wasm"
    )
}

fn looks_like_rel_path(raw: &str) -> bool {
    if raw.is_empty()
        || raw.len() > 180
        || raw.contains("..")
        || raw.contains('\\')
        || raw.contains(' ')
    {
        return false;
    }
    if raw.starts_with('/') || raw.starts_with("http") || raw.starts_with("data:") {
        return false;
    }
    raw.chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-' | '/'))
}

fn is_spa_asset_rel(rel: &str) -> bool {
    if rel.is_empty() || rel.contains("..") || rel.starts_with('/') || rel.contains('\\') {
        return false;
    }
    let ext = rel.rsplit('.').next().unwrap_or("");
    matches!(
        ext,
        "js" | "mjs"
            | "css"
            | "svg"
            | "ico"
            | "png"
            | "woff"
            | "woff2"
            | "json"
            | "webp"
            | "jpg"
            | "jpeg"
            | "gif"
            | "wasm"
    )
}

fn is_critical_spa_rel(rel: &str) -> bool {
    rel.ends_with(".js") || rel.ends_with(".mjs") || rel.ends_with(".css") || rel.ends_with(".wasm")
}

fn is_graph_source(rel: &str) -> bool {
    rel.ends_with(".js") || rel.ends_with(".mjs") || rel.ends_with(".css") || rel.ends_with(".html")
}

fn normalize_rel(raw: &str) -> Option<String> {
    let raw = raw.trim();
    if raw.is_empty() || raw.starts_with("http") || raw.starts_with("data:") {
        return None;
    }
    if raw.starts_with('/') {
        return None;
    }
    let rel = raw.strip_prefix("./").unwrap_or(raw);
    if rel.contains("..") {
        return None;
    }
    Some(rel.to_string())
}

fn push_unique(refs: &mut Vec<String>, rel: String) {
    if !rel.is_empty() && !refs.iter().any(|existing| existing == &rel) {
        refs.push(rel);
    }
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex_lower(&hasher.finalize())
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|err| err.to_string())?;
    }
    let tmp = match path.file_name() {
        Some(name) => {
            let mut os = name.to_os_string();
            os.push(".part");
            path.with_file_name(os)
        }
        None => path.with_extension("part"),
    };
    {
        let mut file = fs::File::create(&tmp).map_err(|err| err.to_string())?;
        file.write_all(bytes).map_err(|err| err.to_string())?;
        let _ = file.sync_all();
    }
    fs::rename(&tmp, path).map_err(|err| err.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chrome_is_baked_game_and_alife_are_not() {
        assert!(baked_bytes("index.html").is_some());
        assert!(BakedUi::get("game/index.html").is_none());
        assert!(BakedUi::get("alife/index.html").is_none());
        for app in ["level", "sprites", "bestiary"] {
            match baked_bytes(&format!("{app}/index.html")) {
                Some(html) if looks_like_packaged_editor(&html) => {
                    assert!(baked_is_packaged(app), "{app}");
                }
                Some(html) => {
                    let text = std::str::from_utf8(&html).unwrap_or("");
                    assert!(
                        text.contains("data-studio-placeholder") || text.contains("стенд"),
                        "{app} baked HTML must be a stand placeholder, not a hashed SPA"
                    );
                    assert!(!baked_is_packaged(app), "{app}");
                }
                None => assert!(!baked_is_packaged(app), "{app}"),
            }
        }
    }

    #[test]
    fn lazy_vite_chunks_resolve_next_to_the_entry() {
        let js = r#"__vitePreload(()=>import("./Workbench-ab12cd.js"),[])"#;
        let refs = collect_all_refs("assets/index-entry.js", js);
        assert_eq!(refs, vec!["assets/Workbench-ab12cd.js".to_string()]);
        assert_eq!(
            resolve_against("assets/entry.js", "./Workbench-xx.js"),
            "assets/Workbench-xx.js"
        );
        let css_js = r#"import"./Workbench-ab12cd.css""#;
        assert_eq!(
            collect_all_refs("assets/index-entry.js", css_js),
            vec!["assets/Workbench-ab12cd.css".to_string()]
        );
        // Live Vite `base: './'` mapDeps (see ui/level/assets/index-*.js).
        let vite = r#"const __vite__mapDeps=(i,m=__vite__mapDeps,d=(m.f||(m.f=["./App-CLJrVhF2.js","./solid-BLtY3ks7.js","./App-oQ0ezEB8.css"])))=>i.map(i=>d[i]);import{a as e}from"./solid-BLtY3ks7.js";"#;
        let refs = collect_all_refs("assets/index-dkKWR_Qv.js", vite);
        for need in [
            "assets/App-CLJrVhF2.js",
            "assets/solid-BLtY3ks7.js",
            "assets/App-oQ0ezEB8.css",
        ] {
            assert!(refs.contains(&need.to_string()), "{need} in {refs:?}");
        }
    }

    #[test]
    fn hashed_mapdeps_and_import_looking_bare_refs() {
        let js = r#"
            const __vite__mapDeps=(i,m=__vite__mapDeps,d=(m.f||(m.f=["assets/Workbench-ab12cd.js","assets/Workbench-ab12cd.css"])))=>i.map(i=>d[i]);
            __vitePreload(()=>import("./Workbench-ab12cd.js"),__vite__mapDeps([0,1]));
            import{j as e}from"solid-B7kQ2n1x.js";
            import"./vendor-xx1234.js";
        "#;
        let refs = collect_all_refs("assets/index-DnLRTkYU.js", js);
        for need in [
            "assets/Workbench-ab12cd.js",
            "assets/Workbench-ab12cd.css",
            "assets/solid-B7kQ2n1x.js",
            "assets/vendor-xx1234.js",
        ] {
            assert!(refs.contains(&need.to_string()), "{need} in {refs:?}");
        }
        let bare = collect_bare_chunk_refs(js);
        assert!(bare.iter().any(|r| r == "assets/Workbench-ab12cd.css"));
        assert!(bare.iter().any(|r| r == "solid-B7kQ2n1x.js"));
    }

    #[test]
    fn parent_escape_and_cycles_do_not_walk_forever() {
        assert!(resolve_against("assets/a.js", "../secret.js").is_empty());
        assert!(collect_all_refs("assets/a.js", r#"import("../x.js")"#).is_empty());
        assert!(collect_all_refs("assets/a.js", r#"import("./../x.js")"#).is_empty());
        let a = collect_all_refs("assets/a.js", r#"import("./b.js");import("./a.js")"#);
        assert_eq!(
            a,
            vec!["assets/b.js".to_string(), "assets/a.js".to_string()]
        );
        let again = collect_all_refs("assets/b.js", r#"import("./a.js")"#);
        assert_eq!(again, vec!["assets/a.js".to_string()]);
    }

    #[test]
    fn vite_index_refs_are_relative_hashed_assets() {
        let html = r#"<script type="module" src="./assets/index-DnLRTkYU.js"></script>
           <link rel="stylesheet" href="./assets/index-BQIuFD7-.css">
           <link rel="icon" href="./favicon.svg" />"#;
        let refs = collect_relative_refs(html);
        assert_eq!(
            refs,
            vec![
                "assets/index-DnLRTkYU.js".to_string(),
                "assets/index-BQIuFD7-.css".to_string(),
                "favicon.svg".to_string()
            ]
        );
        let all = collect_all_refs("index.html", html);
        assert_eq!(all, refs);
    }

    #[test]
    fn same_html_hash_means_no_redownload() {
        let a = sha256_hex(b"<html>");
        let b = sha256_hex(b"<html>");
        let c = sha256_hex(b"<html/>");
        assert_eq!(a, b);
        assert_ne!(a, c);
        if let Some(bytes) = baked_bytes("level/index.html") {
            let baked = baked_index_hash("level").expect("baked level");
            assert_eq!(baked, sha256_hex(&bytes));
        }
        assert_eq!(overlay_index_hash(&empty_test_cfg(), "level"), None);
    }

    #[test]
    fn authentik_login_html_is_not_an_editor() {
        let html = b"<!doctype html><title>authentik</title><form>login</form>";
        assert!(!looks_like_packaged_editor(html));
        let vite_like_absolute = br#"<!doctype html><title>authentik</title>
            <script type="module" src="/static/dist/assets/index-abc.js"></script>
            <div id="flow-container"></div>"#;
        assert!(!looks_like_packaged_editor(vite_like_absolute));
        let mut huge = b"<!doctype html><div id=\"root\"></div>\
            <script type=\"module\" src=\"./assets/x.js\"></script>"
            .to_vec();
        huge.extend(std::iter::repeat(b'x').take(MAX_REMOTE_HTML));
        assert!(!looks_like_packaged_editor(&huge));
    }

    #[test]
    fn refresh_follows_vite_chunks_then_skips_matching_hash() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let index = br#"<!doctype html><html><head>
                <script type="module" src="./assets/index-entry.js"></script>
                <link rel="stylesheet" href="./assets/index-entry.css">
                </head><body><div id="root"></div></body></html>"#;
            let entry_js = br#"
                const __vite__mapDeps=(i,m=__vite__mapDeps,d=(m.f||(m.f=["assets/Workbench-ab12cd.js","assets/only-mapdeps-xx1234.css"])))=>i.map(i=>d[i]);
                __vitePreload(()=>import("./Workbench-ab12cd.js"),__vite__mapDeps([0,1]));
                import"./index-entry.css";
                import{j as e}from"solid-B7kQ2n1x.js";
            "#;
            let chunk_js =
                br#"export const workbench=1;import"./Workbench-ab12cd.css";import("./cycle-aa11bb.js")"#;
            let cycle_js = br#"import("./Workbench-ab12cd.js")"#;
            let mut pages = std::collections::HashMap::new();
            pages.insert(
                "/stand/cursorgo/level/".into(),
                Bytes::copy_from_slice(index),
            );
            pages.insert(
                "/stand/cursorgo/level/assets/index-entry.js".into(),
                Bytes::copy_from_slice(entry_js),
            );
            pages.insert(
                "/stand/cursorgo/level/assets/index-entry.css".into(),
                Bytes::from_static(b"body{color:#111}"),
            );
            pages.insert(
                "/stand/cursorgo/level/assets/Workbench-ab12cd.js".into(),
                Bytes::copy_from_slice(chunk_js),
            );
            pages.insert(
                "/stand/cursorgo/level/assets/Workbench-ab12cd.css".into(),
                Bytes::from_static(b".wb{display:block}"),
            );
            pages.insert(
                "/stand/cursorgo/level/assets/only-mapdeps-xx1234.css".into(),
                Bytes::from_static(b".lazy{opacity:1}"),
            );
            pages.insert(
                "/stand/cursorgo/level/assets/solid-B7kQ2n1x.js".into(),
                Bytes::from_static(b"export const j=1"),
            );
            pages.insert(
                "/stand/cursorgo/level/assets/cycle-aa11bb.js".into(),
                Bytes::copy_from_slice(cycle_js),
            );
            pages.insert(
                "/stand/cursorgo/sprites/".into(),
                Bytes::from_static(b"<!doctype html><title>authentik</title><form>login</form>"),
            );
            let bestiary_remote = baked_bytes("bestiary/index.html").unwrap_or_else(|| {
                Bytes::from_static(b"<!doctype html><title>authentik</title><form>login</form>")
            });
            pages.insert("/stand/cursorgo/bestiary/".into(), bestiary_remote);
            let origin = spawn_mock_stand(pages).await;
            let root = test_root("refresh");
            let proxy = test_proxy(origin, &root);
            let session = test_session();

            assert!(DesignerTab::from_id("game").is_none());
            assert_eq!(
                refresh_app(&proxy, &session, "cursorgo", "game")
                    .await
                    .unwrap(),
                false
            );
            assert_eq!(
                refresh_app(&proxy, &session, "cursorgo", "alife")
                    .await
                    .unwrap(),
                false
            );

            assert!(
                refresh_app(&proxy, &session, "cursorgo", "level")
                    .await
                    .unwrap()
            );
            let overlay_progress = proxy.progress.snapshot();
            assert_eq!(overlay_progress.phase, "done");
            assert!(
                overlay_progress.files_done >= 7,
                "files_done={}",
                overlay_progress.files_done
            );
            assert!(
                overlay_progress.bytes_done > 0,
                "bytes_done={}",
                overlay_progress.bytes_done
            );
            let overlay = spa_overlay_dir(&proxy.cfg).join("level");
            assert!(overlay.join("index.html").is_file());
            assert!(overlay.join("assets/index-entry.js").is_file());
            assert!(overlay.join("assets/Workbench-ab12cd.js").is_file());
            assert!(overlay.join("assets/Workbench-ab12cd.css").is_file());
            assert!(overlay.join("assets/only-mapdeps-xx1234.css").is_file());
            assert!(overlay.join("assets/solid-B7kQ2n1x.js").is_file());
            assert!(overlay.join("assets/cycle-aa11bb.js").is_file());
            assert!(!spa_overlay_dir(&proxy.cfg).join("level.staging").exists());
            assert_eq!(
                std::fs::read(overlay.join("assets/Workbench-ab12cd.js")).unwrap(),
                chunk_js
            );

            assert_eq!(
                refresh_app(&proxy, &session, "cursorgo", "level")
                    .await
                    .unwrap(),
                false
            );

            assert_eq!(
                refresh_app(&proxy, &session, "cursorgo", "sprites")
                    .await
                    .unwrap(),
                false
            );
            assert!(!spa_overlay_dir(&proxy.cfg).join("sprites").exists());

            if baked_is_packaged("bestiary") {
                std::fs::create_dir_all(spa_overlay_dir(&proxy.cfg).join("bestiary")).unwrap();
                std::fs::write(
                    spa_overlay_dir(&proxy.cfg)
                        .join("bestiary")
                        .join("index.html"),
                    b"stale",
                )
                .unwrap();
                assert_eq!(
                    refresh_app(&proxy, &session, "cursorgo", "bestiary")
                        .await
                        .unwrap(),
                    false
                );
                assert!(!spa_overlay_dir(&proxy.cfg).join("bestiary").exists());
            }

            let _ = std::fs::remove_dir_all(root);
        });
    }

    fn empty_test_cfg() -> StudioConfig {
        StudioConfig::production(
            PathBuf::from("/missing-ui"),
            0,
            Some(std::env::temp_dir().join("designer-spa-no-overlay")),
        )
    }

    fn test_root(label: &str) -> PathBuf {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0);
        let root = std::env::temp_dir().join(format!(
            "designer-spa-{label}-{}-{}",
            std::process::id(),
            stamp
        ));
        std::fs::create_dir_all(root.join("ui")).unwrap();
        root
    }

    fn test_proxy(stand_host: String, root: &Path) -> Proxy {
        use crate::cache::ReadCache;
        use crate::session::LiveState;
        use std::sync::Arc;
        let mut cfg = StudioConfig::production(root.join("ui"), 0, Some(root.join("cache")));
        cfg.stand_host = stand_host;
        cfg.auth_host = "http://127.0.0.1:9".into();
        cfg.get_timeout = std::time::Duration::from_secs(3);
        cfg.write_timeout = std::time::Duration::from_secs(3);
        cfg.probe_timeout = std::time::Duration::from_secs(1);
        Proxy {
            cache: ReadCache::open(cfg.cache_dir.join("reads")).unwrap(),
            live: Arc::new(LiveState::new()),
            cfg,
            progress: crate::progress::ProgressHub::new(),
        }
    }

    fn test_session() -> Session {
        use std::sync::Arc;
        Session::new(
            "cursorgo".into(),
            "tester".into(),
            Arc::new(reqwest::cookie::Jar::default()),
        )
        .unwrap()
    }

    async fn spawn_mock_stand(pages: std::collections::HashMap<String, Bytes>) -> String {
        use axum::extract::State;
        use axum::http::{StatusCode, Uri};
        use axum::response::IntoResponse;
        use axum::routing::get;
        use axum::Router;
        use std::sync::Arc;

        #[derive(Clone)]
        struct Pages(Arc<std::collections::HashMap<String, Bytes>>);

        async fn page(uri: Uri, State(pages): State<Pages>) -> impl IntoResponse {
            match pages.0.get(uri.path()) {
                Some(body) => (StatusCode::OK, body.clone()),
                None => (StatusCode::NOT_FOUND, Bytes::new()),
            }
        }

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = Router::new()
            .fallback(get(page))
            .with_state(Pages(Arc::new(pages)));
        tokio::spawn(async move {
            axum::serve(listener, app).await.ok();
        });
        format!("http://127.0.0.1:{}", addr.port())
    }
}
