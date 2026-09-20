//! Local remembered Authentik login for the chrome gate.
//!
//! File lives under `cache_dir` (user profile), not in WebView localStorage.
//! Password is only for this machine; the desk is loopback-only.

use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RememberedLogin {
    pub slug: String,
    pub username: String,
    pub password: String,
}

pub fn remember_path(cache_dir: &Path) -> PathBuf {
    cache_dir.join("remembered_login.json")
}

pub fn load(cache_dir: &Path) -> Option<RememberedLogin> {
    let text = fs::read_to_string(remember_path(cache_dir)).ok()?;
    let login: RememberedLogin = serde_json::from_str(&text).ok()?;
    let slug = login.slug.trim();
    let username = login.username.trim();
    if slug.is_empty() || username.is_empty() || login.password.is_empty() {
        return None;
    }
    Some(RememberedLogin {
        slug: slug.to_string(),
        username: username.to_string(),
        password: login.password,
    })
}

pub fn save(cache_dir: &Path, login: &RememberedLogin) -> Result<(), String> {
    fs::create_dir_all(cache_dir).map_err(|err| err.to_string())?;
    let path = remember_path(cache_dir);
    let tmp = path.with_extension("json.tmp");
    let body = serde_json::to_vec_pretty(login).map_err(|err| err.to_string())?;
    fs::write(&tmp, body).map_err(|err| err.to_string())?;
    chmod_private(&tmp);
    fs::rename(&tmp, &path).map_err(|err| err.to_string())?;
    chmod_private(&path);
    Ok(())
}

pub fn clear(cache_dir: &Path) {
    let path = remember_path(cache_dir);
    let _ = fs::remove_file(&path);
    let _ = fs::remove_file(path.with_extension("json.tmp"));
}

fn chmod_private(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = fs::metadata(path) {
            let mut perms = meta.permissions();
            perms.set_mode(0o600);
            let _ = fs::set_permissions(path, perms);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir() -> PathBuf {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let dir = std::env::temp_dir().join(format!(
            "studio-remember-{}-{}",
            std::process::id(),
            stamp
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn missing_file_is_none() {
        let dir = temp_dir();
        assert!(load(&dir).is_none());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn save_load_roundtrip() {
        let dir = temp_dir();
        let login = RememberedLogin {
            slug: "neweditor".into(),
            username: "akadmin".into(),
            password: "secret".into(),
        };
        save(&dir, &login).unwrap();
        assert_eq!(load(&dir), Some(login));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(remember_path(&dir))
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600);
        }
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn blank_fields_are_ignored() {
        let dir = temp_dir();
        std::fs::write(
            remember_path(&dir),
            r#"{"slug":"  ","username":"akadmin","password":"x"}"#,
        )
        .unwrap();
        assert!(load(&dir).is_none());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn clear_removes_file() {
        let dir = temp_dir();
        save(
            &dir,
            &RememberedLogin {
                slug: "neweditor".into(),
                username: "akadmin".into(),
                password: "secret".into(),
            },
        )
        .unwrap();
        clear(&dir);
        assert!(load(&dir).is_none());
        let _ = std::fs::remove_dir_all(dir);
    }
}
