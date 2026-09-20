//! Dedicated in-memory cache for Chat AG-UI **inject artifacts**.
//!
//! This is not the stand [`crate::cache::ReadCache`] and not the SSO SSE
//! streamer. It stores Chat HTML after inject, the static inject script, and
//! rewritten HttpAgent JS documents. It **refuses** `text/event-stream`,
//! event-stream Accept, POST `RunAgentInput`, and any streaming response.

use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{Duration, Instant};

use bytes::Bytes;
use sha2::{Digest, Sha256};

use crate::inject::{
    is_html_content_type_str, is_javascript_content_type, INJECT_JS, STUDIO_AGUI_PATH,
};

const MEM_BUDGET: usize = 16 * 1024 * 1024;
const HTML_TTL: Duration = Duration::from_secs(30);
const ASSET_TTL: Duration = Duration::from_secs(300);
const IMMUTABLE_TTL: Duration = Duration::from_secs(3600);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArtifactKind {
    Html,
    Script,
    Asset,
}

#[derive(Debug, Clone)]
pub struct InjectObject {
    pub status: u16,
    pub content_type: String,
    pub body: Bytes,
    pub etag: Option<String>,
    pub last_modified: Option<String>,
    pub kind: ArtifactKind,
    stored_at: Instant,
    ttl: Duration,
}

impl InjectObject {
    pub fn html(
        status: u16,
        body: Bytes,
        etag: Option<String>,
        last_modified: Option<String>,
    ) -> Self {
        Self {
            status,
            content_type: "text/html; charset=utf-8".into(),
            body,
            etag,
            last_modified,
            kind: ArtifactKind::Html,
            stored_at: Instant::now(),
            ttl: HTML_TTL,
        }
    }

    pub fn asset(
        status: u16,
        content_type: String,
        body: Bytes,
        etag: Option<String>,
        last_modified: Option<String>,
        cache_control: Option<&str>,
    ) -> Self {
        let ttl = if cache_control.is_some_and(|c| c.to_ascii_lowercase().contains("immutable")) {
            IMMUTABLE_TTL
        } else {
            ASSET_TTL
        };
        Self {
            status,
            content_type,
            body,
            etag,
            last_modified,
            kind: ArtifactKind::Asset,
            stored_at: Instant::now(),
            ttl,
        }
    }

    pub fn script() -> Self {
        Self {
            status: 200,
            content_type: "text/javascript; charset=utf-8".into(),
            body: Bytes::from_static(INJECT_JS.as_bytes()),
            etag: None,
            last_modified: None,
            kind: ArtifactKind::Script,
            stored_at: Instant::now(),
            ttl: Duration::from_secs(86400),
        }
    }

    pub fn fresh(&self) -> bool {
        Instant::now().duration_since(self.stored_at) < self.ttl
    }
}

struct MemEntry {
    object: InjectObject,
    bytes: usize,
}

/// Thread-safe Chat inject cache. SSE never consults this.
pub struct InjectCache {
    mem: RwLock<HashMap<String, MemEntry>>,
}

impl InjectCache {
    pub fn new() -> Self {
        Self {
            mem: RwLock::new(HashMap::new()),
        }
    }

    /// Key by origin URL + normalized content-type (HTML inject vs JS asset).
    pub fn key(origin_url: &str, content_type: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(origin_url.as_bytes());
        hasher.update([0]);
        hasher.update(normalize_ct(content_type).as_bytes());
        hex_lower(&hasher.finalize())
    }

    pub fn get(&self, key: &str) -> Option<InjectObject> {
        self.mem
            .read()
            .ok()?
            .get(key)
            .map(|entry| entry.object.clone())
    }

    pub fn get_fresh(&self, key: &str) -> Option<InjectObject> {
        self.get(key).filter(|o| o.fresh())
    }

    pub fn put(&self, key: String, object: InjectObject) {
        let bytes = object.body.len();
        let mut mem = match self.mem.write() {
            Ok(guard) => guard,
            Err(_) => return,
        };
        mem.insert(key, MemEntry { object, bytes });
        evict_to_budget(&mut mem);
    }

    pub fn touch(&self, key: &str) {
        let Ok(mut mem) = self.mem.write() else {
            return;
        };
        if let Some(entry) = mem.get_mut(key) {
            entry.object.stored_at = Instant::now();
        }
    }

    pub fn len(&self) -> usize {
        self.mem.read().map(|m| m.len()).unwrap_or(0)
    }

    /// Event-stream / POST RunAgentInput / studio streamer path are never stored.
    pub fn may_store(method: &str, accept: Option<&str>, content_type: &str, path: &str) -> bool {
        let method = method.to_ascii_uppercase();
        if method != "GET" && method != "HEAD" {
            return false;
        }
        let path_only = path.split('?').next().unwrap_or(path);
        if path_only == STUDIO_AGUI_PATH || path_only.starts_with(&format!("{STUDIO_AGUI_PATH}/")) {
            return false;
        }
        if is_stream_media(accept.unwrap_or("")) || is_stream_media(content_type) {
            return false;
        }
        is_html_content_type_str(content_type) || is_javascript_content_type(content_type)
    }
}

impl Default for InjectCache {
    fn default() -> Self {
        Self::new()
    }
}

pub fn is_stream_media(value: &str) -> bool {
    let v = value.to_ascii_lowercase();
    v.contains("text/event-stream") || v.contains("application/vnd.ag-ui.event+proto")
}

fn normalize_ct(ct: &str) -> String {
    ct.split(';')
        .next()
        .unwrap_or(ct)
        .trim()
        .to_ascii_lowercase()
}

fn evict_to_budget(mem: &mut HashMap<String, MemEntry>) {
    let mut total: usize = mem.values().map(|e| e.bytes).sum();
    while total > MEM_BUDGET && !mem.is_empty() {
        let oldest = mem
            .iter()
            .min_by_key(|(_, e)| e.object.stored_at)
            .map(|(k, _)| k.clone());
        if let Some(key) = oldest {
            if let Some(gone) = mem.remove(&key) {
                total = total.saturating_sub(gone.bytes);
            }
        } else {
            break;
        }
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inject::{inject_chat_html, INJECT_MARKER};

    #[test]
    fn refuses_event_stream_post_and_streamer_path() {
        assert!(!InjectCache::may_store(
            "POST",
            Some("text/event-stream"),
            "text/event-stream",
            "/agent"
        ));
        assert!(!InjectCache::may_store(
            "POST",
            Some("application/json"),
            "application/json",
            "/agent"
        ));
        assert!(!InjectCache::may_store(
            "POST",
            Some("text/event-stream"),
            "application/json",
            STUDIO_AGUI_PATH
        ));
        assert!(!InjectCache::may_store(
            "GET",
            Some("text/event-stream"),
            "text/html",
            "/"
        ));
        assert!(!InjectCache::may_store(
            "GET",
            Some("text/html"),
            "text/html",
            STUDIO_AGUI_PATH
        ));
        assert!(!InjectCache::may_store(
            "GET",
            Some("*/*"),
            "text/event-stream",
            "/"
        ));
        assert!(!InjectCache::may_store(
            "GET",
            Some("application/vnd.ag-ui.event+proto"),
            "text/javascript",
            "/app.js"
        ));
        assert!(InjectCache::may_store(
            "GET",
            Some("text/html"),
            "text/html; charset=utf-8",
            "/"
        ));
        assert!(InjectCache::may_store(
            "GET",
            Some("*/*"),
            "text/javascript",
            "/assets/app.js"
        ));
    }

    #[test]
    fn hit_returns_injected_html_without_put_twice() {
        let cache = InjectCache::new();
        let html = inject_chat_html(
            "<!doctype html><html><head></head><body>chat</body></html>",
            "https://chat.mcpwork.space",
        );
        assert!(html.contains(INJECT_MARKER));
        let key = InjectCache::key("https://chat.mcpwork.space/", "text/html");
        cache.put(
            key.clone(),
            InjectObject::html(200, Bytes::from(html.clone()), None, None),
        );
        let hit = cache.get_fresh(&key).expect("fresh html");
        assert_eq!(hit.status, 200);
        assert!(String::from_utf8_lossy(&hit.body).contains(INJECT_MARKER));
        assert_eq!(cache.len(), 1);
        assert_eq!(hit.kind, ArtifactKind::Html);
    }

    #[test]
    fn script_is_in_memory_static() {
        let script = InjectObject::script();
        assert_eq!(script.kind, ArtifactKind::Script);
        assert_eq!(&script.body[..], INJECT_JS.as_bytes());
        assert!(script.fresh());
    }

    #[test]
    fn keys_include_content_type() {
        let html = InjectCache::key("https://chat.mcpwork.space/", "text/html");
        let js = InjectCache::key("https://chat.mcpwork.space/", "text/javascript");
        let html2 = InjectCache::key("https://chat.mcpwork.space/", "text/html; charset=utf-8");
        assert_eq!(html, html2);
        assert_ne!(html, js);
        assert_eq!(html.len(), 64);
    }
}
