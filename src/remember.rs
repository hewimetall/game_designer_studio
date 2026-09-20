//! Remembered Authentik login for the chrome gate.
//!
//! Slug and username live under `cache_dir` (not secrets). The password goes to
//! the OS store via [`keyring`] 3.6: Windows Credential Manager, macOS Keychain,
//! Linux Secret Service, Android Keystore (`android-keyring` + ndk-context).
//! Not WebView localStorage (origin is `http://127.0.0.1`) and not Stronghold
//! (that vault needs its own password).

use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

#[allow(dead_code)] // used by the OS keyring path; tests use an in-process vault
const SERVICE: &str = "space.metroark.designer-studio";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RememberedLogin {
    pub slug: String,
    pub username: String,
    pub password: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct DiskMeta {
    slug: String,
    username: String,
    /// Legacy plaintext from the first remember-login draft. Migrated out.
    #[serde(default, skip_serializing)]
    password: Option<String>,
}

pub fn remember_path(cache_dir: &Path) -> PathBuf {
    cache_dir.join("remembered_login.json")
}

pub fn load(cache_dir: &Path) -> Option<RememberedLogin> {
    ensure_store();
    let text = fs::read_to_string(remember_path(cache_dir)).ok()?;
    let meta: DiskMeta = serde_json::from_str(&text).ok()?;
    let slug = meta.slug.trim();
    let username = meta.username.trim();
    if slug.is_empty() || username.is_empty() {
        return None;
    }
    let mut password = get_secret(cache_dir, username).unwrap_or_default();
    if password.is_empty() {
        if let Some(legacy) = meta
            .password
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            let _ = set_secret(cache_dir, username, legacy);
            let _ = rewrite_meta(cache_dir, slug, username);
            password = legacy.to_string();
        }
    }
    Some(RememberedLogin {
        slug: slug.to_string(),
        username: username.to_string(),
        password,
    })
}

pub fn save(cache_dir: &Path, login: &RememberedLogin) -> Result<(), String> {
    ensure_store();
    let slug = login.slug.trim();
    let username = login.username.trim();
    if slug.is_empty() || username.is_empty() || login.password.is_empty() {
        return Err("пустой логин".into());
    }
    if let Some(old) = load_meta(cache_dir) {
        if old.username != username {
            delete_secret(cache_dir, &old.username);
        }
    }
    rewrite_meta(cache_dir, slug, username)?;
    set_secret(cache_dir, username, &login.password)
}

pub fn clear(cache_dir: &Path) {
    ensure_store();
    if let Some(old) = load_meta(cache_dir) {
        delete_secret(cache_dir, &old.username);
    }
    let path = remember_path(cache_dir);
    let _ = fs::remove_file(&path);
    let _ = fs::remove_file(path.with_extension("json.tmp"));
}

fn load_meta(cache_dir: &Path) -> Option<DiskMeta> {
    let text = fs::read_to_string(remember_path(cache_dir)).ok()?;
    serde_json::from_str(&text).ok()
}

fn rewrite_meta(cache_dir: &Path, slug: &str, username: &str) -> Result<(), String> {
    fs::create_dir_all(cache_dir).map_err(|err| err.to_string())?;
    let path = remember_path(cache_dir);
    let tmp = path.with_extension("json.tmp");
    let body = serde_json::to_vec_pretty(&serde_json::json!({
        "slug": slug,
        "username": username,
    }))
    .map_err(|err| err.to_string())?;
    fs::write(&tmp, body).map_err(|err| err.to_string())?;
    chmod_private(&tmp);
    fs::rename(&tmp, &path).map_err(|err| err.to_string())?;
    chmod_private(&path);
    Ok(())
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

fn ensure_store() {
    use std::sync::OnceLock;
    static START: OnceLock<()> = OnceLock::new();
    START.get_or_init(|| {
        #[cfg(test)]
        {
            keyring::set_default_credential_builder(keyring::mock::default_credential_builder());
        }
        #[cfg(all(not(test), target_os = "android"))]
        {
            let _ = android_keyring::set_android_keyring_credential_builder();
        }
    });
}

fn set_secret(cache_dir: &Path, username: &str, password: &str) -> Result<(), String> {
    #[cfg(test)]
    {
        test_vault().insert(test_key(cache_dir, username), password.to_string());
        return Ok(());
    }
    #[cfg(not(test))]
    {
        let _ = cache_dir;
        keyring::Entry::new(SERVICE, username)
            .and_then(|entry| entry.set_password(password))
            .map_err(|err| err.to_string())
    }
}

fn get_secret(cache_dir: &Path, username: &str) -> Option<String> {
    #[cfg(test)]
    {
        return test_vault().get(&test_key(cache_dir, username)).cloned();
    }
    #[cfg(not(test))]
    {
        let _ = cache_dir;
        keyring::Entry::new(SERVICE, username)
            .ok()?
            .get_password()
            .ok()
            .filter(|s| !s.is_empty())
    }
}

fn delete_secret(cache_dir: &Path, username: &str) {
    #[cfg(test)]
    {
        test_vault().remove(&test_key(cache_dir, username));
        return;
    }
    #[cfg(not(test))]
    {
        let _ = cache_dir;
        if let Ok(entry) = keyring::Entry::new(SERVICE, username) {
            let _ = entry.delete_credential();
        }
    }
}

#[cfg(test)]
fn test_key(cache_dir: &Path, username: &str) -> String {
    format!("{}::{username}", cache_dir.display())
}

#[cfg(test)]
fn test_vault() -> std::sync::MutexGuard<'static, std::collections::HashMap<String, String>> {
    use std::sync::{Mutex, OnceLock};
    static VAULT: OnceLock<Mutex<std::collections::HashMap<String, String>>> = OnceLock::new();
    VAULT
        .get_or_init(|| Mutex::new(std::collections::HashMap::new()))
        .lock()
        .unwrap_or_else(|err| err.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir() -> PathBuf {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let dir =
            std::env::temp_dir().join(format!("studio-remember-{}-{}", std::process::id(), stamp));
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
    fn save_load_roundtrip_keeps_password_out_of_the_file() {
        let dir = temp_dir();
        let login = RememberedLogin {
            slug: "neweditor".into(),
            username: "akadmin".into(),
            password: "secret".into(),
        };
        save(&dir, &login).unwrap();
        assert_eq!(load(&dir), Some(login));
        let disk = std::fs::read_to_string(remember_path(&dir)).unwrap();
        assert!(!disk.contains("secret"));
        assert!(disk.contains("akadmin"));
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
        std::fs::write(remember_path(&dir), r#"{"slug":"  ","username":"akadmin"}"#).unwrap();
        assert!(load(&dir).is_none());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn legacy_plaintext_password_is_migrated() {
        let dir = temp_dir();
        std::fs::write(
            remember_path(&dir),
            r#"{"slug":"neweditor","username":"akadmin","password":"legacy-secret"}"#,
        )
        .unwrap();
        let loaded = load(&dir).unwrap();
        assert_eq!(loaded.password, "legacy-secret");
        let disk = std::fs::read_to_string(remember_path(&dir)).unwrap();
        assert!(!disk.contains("legacy-secret"));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn clear_removes_file_and_secret() {
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
        assert!(get_secret(&dir, "akadmin").is_none());
        let _ = std::fs::remove_dir_all(dir);
    }
}
