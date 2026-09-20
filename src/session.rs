use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use reqwest::cookie::Jar;
use reqwest::Client;

use crate::cache::now_secs;

pub struct Session {
    pub slug: String,
    pub username: String,
    pub client: Client,
    /// Same Arc given to `Client::cookie_provider`. Kept on the session so the
    /// jar cannot be dropped while Authentik/outpost cookies are still needed.
    /// WebView cookies are a different jar (Tauri #12988 / #13045).
    #[allow(dead_code)]
    pub jar: Arc<Jar>,
}

pub struct LiveState {
    online: AtomicBool,
    last_probe: AtomicU64,
    last_sync_ok: AtomicU64,
    cached: AtomicUsize,
    session: Mutex<Option<Arc<Session>>>,
}

impl LiveState {
    pub fn new() -> Self {
        Self {
            online: AtomicBool::new(false),
            last_probe: AtomicU64::new(0),
            last_sync_ok: AtomicU64::new(0),
            cached: AtomicUsize::new(0),
            session: Mutex::new(None),
        }
    }

    pub fn set_session(&self, session: Session) {
        if let Ok(mut slot) = self.session.lock() {
            *slot = Some(Arc::new(session));
        }
    }

    pub fn clear_session(&self) {
        if let Ok(mut slot) = self.session.lock() {
            *slot = None;
        }
        self.online.store(false, Ordering::Relaxed);
    }

    pub fn session(&self) -> Option<Arc<Session>> {
        self.session.lock().ok().and_then(|g| g.clone())
    }

    #[inline]
    pub fn set_online(&self, online: bool) {
        self.online.store(online, Ordering::Relaxed);
        self.last_probe.store(now_secs(), Ordering::Relaxed);
    }

    #[inline]
    pub fn is_online(&self) -> bool {
        self.online.load(Ordering::Relaxed)
    }

    #[inline]
    pub fn mark_sync_ok(&self, cached: usize) {
        self.last_sync_ok.store(now_secs(), Ordering::Relaxed);
        self.cached.store(cached, Ordering::Relaxed);
        self.set_online(true);
    }

    #[inline]
    pub fn set_cached(&self, cached: usize) {
        self.cached.store(cached, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> StatusSnapshot {
        let slug = self.session().map(|s| s.slug.clone());
        let online = self.is_online();
        StatusSnapshot {
            online,
            mode: if online {
                "онлайн"
            } else {
                "оффлайн"
            },
            slug,
            cached_objects: self.cached.load(Ordering::Relaxed),
            last_probe: self.last_probe.load(Ordering::Relaxed),
            last_sync_ok: self.last_sync_ok.load(Ordering::Relaxed),
        }
    }
}

#[derive(serde::Serialize)]
pub struct StatusSnapshot {
    pub online: bool,
    pub mode: &'static str,
    pub slug: Option<String>,
    pub cached_objects: usize,
    pub last_probe: u64,
    pub last_sync_ok: u64,
}

pub fn build_client(jar: Arc<Jar>) -> Result<Client, String> {
    Client::builder()
        .cookie_provider(jar)
        .use_rustls_tls()
        .http2_adaptive_window(true)
        .gzip(true)
        .tcp_nodelay(true)
        .pool_idle_timeout(std::time::Duration::from_secs(30))
        .pool_max_idle_per_host(8)
        .redirect(reqwest::redirect::Policy::limited(12))
        .build()
        .map_err(|err| err.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn offline_is_explicit_until_probe_succeeds() {
        let state = LiveState::new();
        let snap = state.snapshot();
        assert!(!snap.online);
        assert_eq!(snap.mode, "оффлайн");
        state.set_online(true);
        assert_eq!(state.snapshot().mode, "онлайн");
    }

    #[test]
    fn rustls_http2_gzip_client_builds_with_cookie_jar() {
        let jar = Arc::new(Jar::default());
        assert!(build_client(jar).is_ok());
    }
}
