//! Remembered Authentik login for the chrome gate.
//!
//! Slug and username live under `cache_dir` (not secrets). The live session is
//! the reqwest cookie jar (Authentik + outpost), encrypted with AES-256-GCM.
//! The 256-bit key is in the OS store via [`keyring`] 3.6: Windows Credential
//! Manager, macOS Keychain, Linux Secret Service, Android Keystore. Ciphertext
//! sits next to remember meta (`remembered_session.bin`, unix 0600).
//!
//! Passwords are not stored. This Authentik has no TOTP; the gate has no
//! second-factor field and no TOTP seed is kept.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use aes_gcm::aead::{Aead, AeadCore, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use reqwest::cookie::{CookieStore, Jar};
use reqwest::Url;
use serde::{Deserialize, Serialize};

#[allow(dead_code)] // used by the OS keyring path; tests use an in-process vault
const SERVICE: &str = "space.metroark.designer-studio";
const SESSION_KEY_USER: &str = "session-jar-aes";
const SESSION_MAGIC: &[u8; 4] = b"AKS1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RememberedLogin {
    pub slug: String,
    pub username: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct DiskMeta {
    slug: String,
    username: String,
    /// Legacy plaintext from the first remember-login draft. Stripped on load.
    #[serde(default, skip_serializing)]
    password: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct JarDump {
    cookies: Vec<JarCookie>,
}

#[derive(Debug, Serialize, Deserialize)]
struct JarCookie {
    url: String,
    header: String,
}

pub fn remember_path(cache_dir: &Path) -> PathBuf {
    cache_dir.join("remembered_login.json")
}

pub fn session_blob_path(cache_dir: &Path) -> PathBuf {
    cache_dir.join("remembered_session.bin")
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
    if meta
        .password
        .as_deref()
        .map(str::trim)
        .is_some_and(|s| !s.is_empty())
    {
        let _ = rewrite_meta(cache_dir, slug, username);
    }
    // Legacy remember stored the password in keyring. Session AES key is a
    // different account; drop leftover passwords so they are not reused.
    if get_secret(cache_dir, username).is_some() {
        delete_secret(cache_dir, username);
    }
    Some(RememberedLogin {
        slug: slug.to_string(),
        username: username.to_string(),
    })
}

pub fn save(cache_dir: &Path, login: &RememberedLogin) -> Result<(), String> {
    ensure_store();
    let slug = login.slug.trim();
    let username = login.username.trim();
    if slug.is_empty() || username.is_empty() {
        return Err("пустой логин".into());
    }
    if let Some(old) = load_meta(cache_dir) {
        delete_secret(cache_dir, &old.username);
    }
    delete_secret(cache_dir, username);
    rewrite_meta(cache_dir, slug, username)
}

pub fn clear(cache_dir: &Path) {
    ensure_store();
    if let Some(old) = load_meta(cache_dir) {
        delete_secret(cache_dir, &old.username);
    }
    let path = remember_path(cache_dir);
    let _ = fs::remove_file(&path);
    let _ = fs::remove_file(path.with_extension("json.tmp"));
    clear_session_blob(cache_dir);
}

pub fn clear_session_blob(cache_dir: &Path) {
    ensure_store();
    delete_secret(cache_dir, SESSION_KEY_USER);
    let path = session_blob_path(cache_dir);
    let _ = fs::remove_file(&path);
    let _ = fs::remove_file(path.with_extension("bin.tmp"));
}

pub fn save_session_jar(cache_dir: &Path, jar: &Jar, urls: &[String]) -> Result<(), String> {
    ensure_store();
    let mut cookies = Vec::new();
    for raw in urls {
        let Ok(url) = Url::parse(raw) else {
            continue;
        };
        let Some(header) = CookieStore::cookies(jar, &url) else {
            continue;
        };
        let Ok(text) = header.to_str() else {
            continue;
        };
        if text.trim().is_empty() {
            continue;
        }
        cookies.push(JarCookie {
            url: raw.clone(),
            header: text.to_string(),
        });
    }
    let plaintext = serde_json::to_vec(&JarDump { cookies }).map_err(|err| err.to_string())?;
    let key = random_aes_key();
    set_secret(cache_dir, SESSION_KEY_USER, &hex_encode(&key))?;
    let blob = encrypt_blob(&plaintext, &key)?;
    write_private_bytes(&session_blob_path(cache_dir), &blob)
}

pub fn load_session_jar(cache_dir: &Path) -> Option<Arc<Jar>> {
    ensure_store();
    let hex = get_secret(cache_dir, SESSION_KEY_USER)?;
    let key = hex_decode_key(&hex)?;
    let blob = fs::read(session_blob_path(cache_dir)).ok()?;
    let plaintext = decrypt_blob(&blob, &key).ok()?;
    let dump: JarDump = serde_json::from_slice(&plaintext).ok()?;
    let jar = Jar::default();
    for entry in dump.cookies {
        let Ok(url) = Url::parse(&entry.url) else {
            continue;
        };
        let domain = url.host_str().and_then(cookie_parent_domain);
        for (name, value) in parse_cookie_pairs(&entry.header) {
            let mut set = format!("{name}={value}; Path=/; Secure; HttpOnly");
            if let Some(domain) = domain {
                set.push_str(&format!("; Domain={domain}"));
            }
            jar.add_cookie_str(&set, &url);
        }
    }
    Some(Arc::new(jar))
}

fn load_meta(cache_dir: &Path) -> Option<DiskMeta> {
    let text = fs::read_to_string(remember_path(cache_dir)).ok()?;
    serde_json::from_str(&text).ok()
}

fn rewrite_meta(cache_dir: &Path, slug: &str, username: &str) -> Result<(), String> {
    fs::create_dir_all(cache_dir).map_err(|err| err.to_string())?;
    let body = serde_json::to_vec_pretty(&serde_json::json!({
        "slug": slug,
        "username": username,
    }))
    .map_err(|err| err.to_string())?;
    write_private_bytes(&remember_path(cache_dir), &body)
}

fn write_private_bytes(path: &Path, body: &[u8]) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|err| err.to_string())?;
    }
    let tmp = path.with_extension(format!(
        "{}.tmp",
        path.extension().and_then(|s| s.to_str()).unwrap_or("dat")
    ));
    fs::write(&tmp, body).map_err(|err| err.to_string())?;
    chmod_private(&tmp);
    fs::rename(&tmp, path).map_err(|err| err.to_string())?;
    chmod_private(path);
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

fn encrypt_blob(plaintext: &[u8], key_bytes: &[u8; 32]) -> Result<Vec<u8>, String> {
    let key = Key::<Aes256Gcm>::from_slice(key_bytes);
    let cipher = Aes256Gcm::new(key);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ct = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|err| err.to_string())?;
    let mut out = Vec::with_capacity(SESSION_MAGIC.len() + nonce.len() + ct.len());
    out.extend_from_slice(SESSION_MAGIC);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

fn decrypt_blob(blob: &[u8], key_bytes: &[u8; 32]) -> Result<Vec<u8>, String> {
    if blob.len() < SESSION_MAGIC.len() + 12 + 16 {
        return Err("короткий session blob".into());
    }
    if !blob.starts_with(SESSION_MAGIC) {
        return Err("неизвестный формат session blob".into());
    }
    let nonce = Nonce::from_slice(&blob[4..16]);
    let ct = &blob[16..];
    let key = Key::<Aes256Gcm>::from_slice(key_bytes);
    let cipher = Aes256Gcm::new(key);
    cipher.decrypt(nonce, ct).map_err(|err| err.to_string())
}

fn random_aes_key() -> [u8; 32] {
    let generated = Aes256Gcm::generate_key(OsRng);
    let mut key = [0u8; 32];
    key.copy_from_slice(&generated);
    key
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn hex_decode(text: &str) -> Option<Vec<u8>> {
    if text.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(text.len() / 2);
    let bytes = text.as_bytes();
    for chunk in bytes.chunks(2) {
        let hi = hex_nibble(chunk[0])?;
        let lo = hex_nibble(chunk[1])?;
        out.push((hi << 4) | lo);
    }
    Some(out)
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn hex_decode_key(text: &str) -> Option<[u8; 32]> {
    let bytes = hex_decode(text)?;
    if bytes.len() != 32 {
        return None;
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    Some(key)
}

fn parse_cookie_pairs(header: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for part in header.split(';') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let Some((name, value)) = part.split_once('=') else {
            continue;
        };
        let name = name.trim();
        if name.is_empty() {
            continue;
        }
        out.push((name.to_string(), value.to_string()));
    }
    out
}

fn cookie_parent_domain(host: &str) -> Option<&str> {
    if host.eq_ignore_ascii_case("localhost") {
        return None;
    }
    if host.parse::<std::net::IpAddr>().is_ok() {
        return None;
    }
    let mut parts = host.rsplit('.');
    let tld = parts.next()?;
    let sld = parts.next()?;
    parts.next()?;
    if tld.is_empty() || sld.is_empty() {
        return None;
    }
    Some(&host[host.len() - tld.len() - sld.len() - 1..])
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

    fn cookie_urls() -> Vec<String> {
        vec![
            "https://auth.mcpwork.space/".into(),
            "https://my.mcpwork.space/".into(),
        ]
    }

    #[test]
    fn missing_file_is_none() {
        let dir = temp_dir();
        assert!(load(&dir).is_none());
        assert!(load_session_jar(&dir).is_none());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn save_load_roundtrip_keeps_password_out_of_the_file() {
        let dir = temp_dir();
        let login = RememberedLogin {
            slug: "neweditor".into(),
            username: "akadmin".into(),
        };
        save(&dir, &login).unwrap();
        assert_eq!(load(&dir), Some(login));
        let disk = std::fs::read_to_string(remember_path(&dir)).unwrap();
        assert!(!disk.contains("secret"));
        assert!(!disk.contains("password"));
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
    fn legacy_plaintext_password_is_stripped_not_returned() {
        let dir = temp_dir();
        std::fs::write(
            remember_path(&dir),
            r#"{"slug":"neweditor","username":"akadmin","password":"legacy-secret"}"#,
        )
        .unwrap();
        let loaded = load(&dir).unwrap();
        assert_eq!(loaded.slug, "neweditor");
        assert_eq!(loaded.username, "akadmin");
        let disk = std::fs::read_to_string(remember_path(&dir)).unwrap();
        assert!(!disk.contains("legacy-secret"));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn clear_removes_file_secret_and_session_blob() {
        let dir = temp_dir();
        save(
            &dir,
            &RememberedLogin {
                slug: "neweditor".into(),
                username: "akadmin".into(),
            },
        )
        .unwrap();
        let jar = Jar::default();
        let url = Url::parse("https://auth.mcpwork.space/").unwrap();
        jar.add_cookie_str("authentik_session=secret-cookie; Path=/; Secure", &url);
        save_session_jar(&dir, &jar, &cookie_urls()).unwrap();
        clear(&dir);
        assert!(load(&dir).is_none());
        assert!(load_session_jar(&dir).is_none());
        assert!(get_secret(&dir, "akadmin").is_none());
        assert!(get_secret(&dir, SESSION_KEY_USER).is_none());
        assert!(!session_blob_path(&dir).exists());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn session_blob_roundtrip_restores_jar_cookies() {
        let dir = temp_dir();
        let jar = Jar::default();
        let auth = Url::parse("https://auth.mcpwork.space/").unwrap();
        let stand = Url::parse("https://my.mcpwork.space/").unwrap();
        jar.add_cookie_str(
            "authentik_session=abc123; Path=/; Domain=mcpwork.space; Secure; HttpOnly",
            &auth,
        );
        jar.add_cookie_str(
            "ak_outpost=out-9; Path=/; Domain=mcpwork.space; Secure; HttpOnly",
            &stand,
        );
        save_session_jar(&dir, &jar, &cookie_urls()).unwrap();

        let blob = std::fs::read(session_blob_path(&dir)).unwrap();
        let as_text = String::from_utf8_lossy(&blob);
        assert!(!as_text.contains("abc123"));
        assert!(!as_text.contains("authentik_session"));
        assert!(!as_text.contains("ak_outpost"));
        assert!(blob.starts_with(SESSION_MAGIC));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(session_blob_path(&dir))
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600);
        }

        let restored = load_session_jar(&dir).expect("restored jar");
        let auth_header = CookieStore::cookies(restored.as_ref(), &auth)
            .expect("auth cookies")
            .to_str()
            .unwrap()
            .to_string();
        let stand_header = CookieStore::cookies(restored.as_ref(), &stand)
            .expect("stand cookies")
            .to_str()
            .unwrap()
            .to_string();
        assert!(auth_header.contains("authentik_session=abc123"));
        assert!(stand_header.contains("ak_outpost=out-9"));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn corrupt_or_missing_blob_is_none() {
        let dir = temp_dir();
        assert!(load_session_jar(&dir).is_none());
        std::fs::write(session_blob_path(&dir), b"AKS1not-really-encrypted").unwrap();
        set_secret(&dir, SESSION_KEY_USER, &hex_encode(&[7u8; 32])).unwrap();
        assert!(load_session_jar(&dir).is_none());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn cookie_parent_domain_is_mcpwork_space() {
        assert_eq!(
            cookie_parent_domain("auth.mcpwork.space"),
            Some("mcpwork.space")
        );
        assert_eq!(
            cookie_parent_domain("my.mcpwork.space"),
            Some("mcpwork.space")
        );
        assert_eq!(cookie_parent_domain("127.0.0.1"), None);
        assert_eq!(cookie_parent_domain("localhost"), None);
    }
}
