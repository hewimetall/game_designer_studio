use std::path::PathBuf;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct StudioConfig {
    pub stand_host: String,
    pub auth_host: String,
    pub chat_host: String,
    pub s3_host: String,
    pub flow_slug: String,
    pub cache_dir: PathBuf,
    pub ui_dir: PathBuf,
    pub bind_port: u16,
    pub get_timeout: Duration,
    pub write_timeout: Duration,
    pub probe_timeout: Duration,
}

impl StudioConfig {
    pub fn production(ui_dir: PathBuf, bind_port: u16, cache_dir: Option<PathBuf>) -> Self {
        Self {
            stand_host: "https://my.mcpwork.space".into(),
            auth_host: "https://auth.mcpwork.space".into(),
            chat_host: crate::apps::SystemTab::Chat.production_origin().into(),
            s3_host: crate::apps::SystemTab::S3.production_origin().into(),
            flow_slug: "default-authentication-flow".into(),
            cache_dir: cache_dir.unwrap_or_else(default_cache_dir),
            ui_dir,
            bind_port,
            get_timeout: Duration::from_millis(8000),
            write_timeout: Duration::from_millis(20_000),
            probe_timeout: Duration::from_millis(2000),
        }
    }

    #[inline]
    pub fn executor_url(&self) -> String {
        format!(
            "{}/api/v3/flows/executor/{}/",
            self.auth_host.trim_end_matches('/'),
            self.flow_slug
        )
    }

    #[inline]
    pub fn stand_origin(&self) -> &str {
        self.stand_host.trim_end_matches('/')
    }

    pub fn origin_for_system(&self, tab: crate::apps::SystemTab) -> &str {
        match tab {
            crate::apps::SystemTab::Chat => self.chat_host.trim_end_matches('/'),
            crate::apps::SystemTab::S3 => self.s3_host.trim_end_matches('/'),
        }
    }

    #[inline]
    pub fn auth_origin(&self) -> &str {
        self.auth_host.trim_end_matches('/')
    }

    #[inline]
    pub fn whoami_url(&self) -> String {
        format!("{}/api/v3/core/users/me/", self.auth_origin())
    }

    /// Host of `https://my.mcpwork.space` / `http://127.0.0.1:9` (port stripped).
    pub fn origin_host(origin: &str) -> Option<&str> {
        let rest = origin
            .strip_prefix("https://")
            .or_else(|| origin.strip_prefix("http://"))
            .unwrap_or(origin)
            .trim_end_matches('/');
        let host = rest.split(['/', ':']).next()?.trim();
        if host.is_empty() {
            None
        } else {
            Some(host)
        }
    }

    pub fn url_host_is_stand(&self, url: &reqwest::Url) -> bool {
        url.host_str()
            .is_some_and(|host| Some(host) == Self::origin_host(self.stand_origin()))
    }

    /// Host + port, so loopback test origins on different ports do not collide.
    pub fn url_matches_origin(url: &reqwest::Url, origin: &str) -> bool {
        let Ok(want) = reqwest::Url::parse(origin) else {
            return false;
        };
        url.host_str() == want.host_str()
            && url.port_or_known_default() == want.port_or_known_default()
    }
}

pub fn default_cache_dir() -> PathBuf {
    if let Ok(path) = std::env::var("DESIGNER_STUDIO_CACHE") {
        return PathBuf::from(path);
    }
    if let Ok(local) = std::env::var("LOCALAPPDATA") {
        return PathBuf::from(local).join("metroark-studio").join("cache");
    }
    if let Ok(xdg) = std::env::var("XDG_CACHE_HOME") {
        return PathBuf::from(xdg).join("metroark-studio");
    }
    if let Ok(home) = std::env::var("HOME") {
        return PathBuf::from(home).join(".cache").join("metroark-studio");
    }
    PathBuf::from(".metroark-studio-cache")
}

pub fn default_ui_dir() -> PathBuf {
    resolve_ui_dir(
        std::env::var_os("DESIGNER_STUDIO_UI").map(PathBuf::from),
        std::env::current_exe()
            .ok()
            .and_then(|exe| exe.parent().map(PathBuf::from)),
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("ui"),
    )
}

/// Packaged binary looks next to the exe (`dist/bin` → `dist/ui`, Tauri resources).
/// Dev uses `CARGO_MANIFEST_DIR/ui`.
pub fn resolve_ui_dir(
    env_override: Option<PathBuf>,
    exe_dir: Option<PathBuf>,
    crate_ui: PathBuf,
) -> PathBuf {
    if let Some(path) = env_override {
        return path;
    }
    if let Some(dir) = exe_dir {
        let mut candidates = vec![dir.join("ui"), dir.join("resources/ui")];
        if let Some(parent) = dir.parent() {
            candidates.push(parent.join("ui"));
            candidates.push(parent.join("Resources/ui"));
        }
        for candidate in candidates {
            if candidate.join("index.html").is_file() {
                return candidate.canonicalize().unwrap_or(candidate);
            }
        }
    }
    if crate_ui.join("index.html").is_file() || crate_ui.is_dir() {
        crate_ui
    } else {
        PathBuf::from("crates/designer_studio/ui")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authentik_executor_matches_staff_login() {
        let cfg = StudioConfig::production(PathBuf::from("ui"), 18765, None);
        assert_eq!(
            cfg.executor_url(),
            "https://auth.mcpwork.space/api/v3/flows/executor/default-authentication-flow/"
        );
        assert_eq!(cfg.stand_origin(), "https://my.mcpwork.space");
        assert_eq!(
            cfg.origin_for_system(crate::apps::SystemTab::Chat),
            "https://chat.mcpwork.space"
        );
        assert_eq!(
            cfg.origin_for_system(crate::apps::SystemTab::S3),
            "https://s3.mcpwork.space"
        );
        assert_eq!(
            cfg.whoami_url(),
            "https://auth.mcpwork.space/api/v3/core/users/me/"
        );
        assert_eq!(cfg.auth_origin(), "https://auth.mcpwork.space");
        assert_eq!(
            StudioConfig::origin_host("https://my.mcpwork.space"),
            Some("my.mcpwork.space")
        );
        assert_eq!(
            StudioConfig::origin_host("http://127.0.0.1:9"),
            Some("127.0.0.1")
        );
        let chat = reqwest::Url::parse("https://chat.mcpwork.space/ws").unwrap();
        assert!(StudioConfig::url_matches_origin(
            &chat,
            "https://chat.mcpwork.space"
        ));
        assert!(!StudioConfig::url_matches_origin(
            &chat,
            "https://auth.mcpwork.space"
        ));
        let loop_a = reqwest::Url::parse("http://127.0.0.1:1111/").unwrap();
        assert!(!StudioConfig::url_matches_origin(
            &loop_a,
            "http://127.0.0.1:2222"
        ));
    }

    #[test]
    fn packaged_ui_is_found_next_to_the_binary() {
        let root = std::env::temp_dir().join(format!(
            "designer-ui-{}-{}",
            std::process::id(),
            now_test_stamp()
        ));
        let ui = root.join("ui");
        std::fs::create_dir_all(&ui).unwrap();
        std::fs::write(ui.join("index.html"), "<title>studio</title>").unwrap();
        let found = resolve_ui_dir(
            None,
            Some(root.join("bin")),
            PathBuf::from("/missing/crate/ui"),
        );
        assert_eq!(found.canonicalize().unwrap(), ui.canonicalize().unwrap());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn env_override_wins_over_exe_dir() {
        let found = resolve_ui_dir(
            Some(PathBuf::from("/forced/ui")),
            Some(PathBuf::from("/exe")),
            PathBuf::from("/crate/ui"),
        );
        assert_eq!(found, PathBuf::from("/forced/ui"));
    }

    fn now_test_stamp() -> u128 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0)
    }
}
