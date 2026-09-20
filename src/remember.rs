//! Remembered Authentik login for the chrome gate.
//!
//! Slug and username live under `cache_dir` (not secrets). The live session is
//! the reqwest cookie jar (Authentik + outpost), encrypted with AES-256-GCM.
//! The 256-bit key is in the OS store via [`keyring`] 3.6: Windows Credential
//! Manager, macOS Keychain, Linux Secret Service, Android Keystore. Ciphertext
//! sits next to remember meta (`remembered_session.bin`, unix 0600).
//!
//! Save order keeps keyring and disk consistent: a stored key is reused, so a
//! re-save is one atomic blob replace (tmp + rename). A fresh key is stored only
//! after its blob is on disk, and the blob is removed again if the keyring
//! refuses the key — never a key without its blob or a blob without its key.
//!
//! Passwords are not stored. This Authentik has no TOTP; the gate has no
//! second-factor field and no TOTP seed is kept.
//!
//! Remembered `slug` is whatever last succeeded. A stale `neweditor` value is
//! not migrated to `cursorgo` — log in again with the live stand slug.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use aes_gcm::aead::{Aead, AeadCore, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use reqwest::cookie::{CookieStore, Jar};
use reqwest::Url;
use serde::{Deserialize, Serialize};

const SESSION_KEY_USER: &str = "session-jar-aes";
const SESSION_MAGIC: &[u8; 4] = b"AKS1";

/// Credential store behind the remembered session: one secret per account name.
/// Production is the OS keyring ([`os_keyring::KeyringStore`]); tests pass an
/// in-memory store.
pub trait SecretStore: Send + Sync {
    fn get(&self, account: &str) -> Option<String>;
    fn set(&self, account: &str, secret: &str) -> Result<(), String>;
    fn delete(&self, account: &str);
}

/// `keyring` 3.6 `Entry` under `SERVICE`: Windows Credential Manager, macOS
/// Keychain, Linux Secret Service, Android Keystore.
#[cfg_attr(test, allow(dead_code))]
mod os_keyring {
    use super::SecretStore;

    const SERVICE: &str = "space.metroark.designer-studio";

    pub(super) struct KeyringStore;

    impl KeyringStore {
        fn entry(account: &str) -> Result<keyring::Entry, String> {
            ensure_credential_builder();
            keyring::Entry::new(SERVICE, account).map_err(|err| err.to_string())
        }
    }

    impl SecretStore for KeyringStore {
        fn get(&self, account: &str) -> Option<String> {
            Self::entry(account)
                .ok()?
                .get_password()
                .ok()
                .filter(|s| !s.is_empty())
        }

        fn set(&self, account: &str, secret: &str) -> Result<(), String> {
            Self::entry(account)?
                .set_password(secret)
                .map_err(|err| err.to_string())
        }

        fn delete(&self, account: &str) {
            if let Ok(entry) = Self::entry(account) {
                let _ = entry.delete_credential();
            }
        }
    }

    fn ensure_credential_builder() {
        #[cfg(target_os = "android")]
        {
            use std::sync::OnceLock;
            static START: OnceLock<()> = OnceLock::new();
            START.get_or_init(|| {
                let _ = android_keyring::set_android_keyring_credential_builder();
            });
        }
    }
}

#[cfg(not(test))]
fn store_for(_cache_dir: &Path) -> Arc<dyn SecretStore> {
    Arc::new(os_keyring::KeyringStore)
}

/// Tests never reach the OS keyring. One in-memory store per cache dir keeps
/// parallel tests with different temp dirs independent.
#[cfg(test)]
fn store_for(cache_dir: &Path) -> Arc<dyn SecretStore> {
    MemoryStore::shared_for(cache_dir)
}

#[cfg(test)]
struct MemoryStore {
    secrets: std::sync::Mutex<std::collections::HashMap<String, String>>,
    reject_writes: bool,
}

#[cfg(test)]
impl MemoryStore {
    fn new() -> Self {
        Self {
            secrets: std::sync::Mutex::new(std::collections::HashMap::new()),
            reject_writes: false,
        }
    }

    /// A keyring that refuses writes (Linux without Secret Service, locked Keychain).
    fn rejecting_writes() -> Self {
        Self {
            reject_writes: true,
            ..Self::new()
        }
    }

    fn shared_for(cache_dir: &Path) -> Arc<dyn SecretStore> {
        use std::collections::HashMap;
        use std::sync::{Mutex, OnceLock};
        static STORES: OnceLock<Mutex<HashMap<PathBuf, Arc<MemoryStore>>>> = OnceLock::new();
        let mut stores = STORES
            .get_or_init(Default::default)
            .lock()
            .unwrap_or_else(|err| err.into_inner());
        stores
            .entry(cache_dir.to_path_buf())
            .or_insert_with(|| Arc::new(MemoryStore::new()))
            .clone()
    }
}

#[cfg(test)]
impl SecretStore for MemoryStore {
    fn get(&self, account: &str) -> Option<String> {
        self.secrets
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .get(account)
            .cloned()
    }

    fn set(&self, account: &str, secret: &str) -> Result<(), String> {
        if self.reject_writes {
            return Err("keyring отклонил запись".into());
        }
        self.secrets
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .insert(account.to_string(), secret.to_string());
        Ok(())
    }

    fn delete(&self, account: &str) {
        self.secrets
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .remove(account);
    }
}

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
    load_with(store_for(cache_dir).as_ref(), cache_dir)
}

pub fn save(cache_dir: &Path, login: &RememberedLogin) -> Result<(), String> {
    save_with(store_for(cache_dir).as_ref(), cache_dir, login)
}

pub fn clear(cache_dir: &Path) {
    clear_with(store_for(cache_dir).as_ref(), cache_dir)
}

pub fn clear_session_blob(cache_dir: &Path) {
    clear_session_blob_with(store_for(cache_dir).as_ref(), cache_dir)
}

pub fn save_session_jar(cache_dir: &Path, jar: &Jar, urls: &[String]) -> Result<(), String> {
    save_session_jar_with(store_for(cache_dir).as_ref(), cache_dir, jar, urls)
}

pub fn load_session_jar(cache_dir: &Path) -> Option<Arc<Jar>> {
    load_session_jar_with(store_for(cache_dir).as_ref(), cache_dir)
}

fn load_with(store: &dyn SecretStore, cache_dir: &Path) -> Option<RememberedLogin> {
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
    store.delete(username);
    Some(RememberedLogin {
        slug: slug.to_string(),
        username: username.to_string(),
    })
}

fn save_with(
    store: &dyn SecretStore,
    cache_dir: &Path,
    login: &RememberedLogin,
) -> Result<(), String> {
    let slug = login.slug.trim();
    let username = login.username.trim();
    if slug.is_empty() || username.is_empty() {
        return Err("пустой логин".into());
    }
    if let Some(old) = load_meta(cache_dir) {
        store.delete(&old.username);
    }
    store.delete(username);
    rewrite_meta(cache_dir, slug, username)
}

fn clear_with(store: &dyn SecretStore, cache_dir: &Path) {
    if let Some(old) = load_meta(cache_dir) {
        store.delete(&old.username);
    }
    let path = remember_path(cache_dir);
    let _ = fs::remove_file(&path);
    let _ = fs::remove_file(path.with_extension("json.tmp"));
    clear_session_blob_with(store, cache_dir);
}

fn clear_session_blob_with(store: &dyn SecretStore, cache_dir: &Path) {
    store.delete(SESSION_KEY_USER);
    let path = session_blob_path(cache_dir);
    let _ = fs::remove_file(&path);
    let _ = fs::remove_file(path.with_extension("bin.tmp"));
}

fn save_session_jar_with(
    store: &dyn SecretStore,
    cache_dir: &Path,
    jar: &Jar,
    urls: &[String],
) -> Result<(), String> {
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
    let stored_key = store
        .get(SESSION_KEY_USER)
        .and_then(|hex| hex_decode_key(&hex));
    let key = stored_key.unwrap_or_else(random_aes_key);
    let blob = encrypt_blob(&plaintext, &key)?;
    let path = session_blob_path(cache_dir);
    write_private_bytes(&path, &blob)?;
    if stored_key.is_none() {
        if let Err(err) = store.set(SESSION_KEY_USER, &hex_encode(&key)) {
            let _ = fs::remove_file(&path);
            return Err(err);
        }
    }
    Ok(())
}

fn load_session_jar_with(store: &dyn SecretStore, cache_dir: &Path) -> Option<Arc<Jar>> {
    let hex = store.get(SESSION_KEY_USER)?;
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

    fn login() -> RememberedLogin {
        RememberedLogin {
            slug: "cursorgo".into(),
            username: "akadmin".into(),
        }
    }

    fn jar_with(cookie: &str) -> (Jar, Url) {
        let jar = Jar::default();
        let auth = Url::parse("https://auth.mcpwork.space/").unwrap();
        jar.add_cookie_str(
            &format!("{cookie}; Path=/; Domain=mcpwork.space; Secure; HttpOnly"),
            &auth,
        );
        (jar, auth)
    }

    fn cookie_header(jar: &Jar, url: &Url) -> String {
        CookieStore::cookies(jar, url)
            .map(|h| h.to_str().unwrap().to_string())
            .unwrap_or_default()
    }

    #[cfg(unix)]
    fn mode_of(path: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn missing_file_is_none() {
        let dir = temp_dir();
        let store = MemoryStore::new();
        assert!(load_with(&store, &dir).is_none());
        assert!(load_session_jar_with(&store, &dir).is_none());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn save_load_roundtrip_writes_private_meta_without_password() {
        let dir = temp_dir();
        let store = MemoryStore::new();
        save_with(&store, &dir, &login()).unwrap();
        assert_eq!(load_with(&store, &dir), Some(login()));
        let disk = std::fs::read_to_string(remember_path(&dir)).unwrap();
        assert!(!disk.contains("password"));
        #[cfg(unix)]
        assert_eq!(mode_of(&remember_path(&dir)), 0o600);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn blank_fields_are_ignored() {
        let dir = temp_dir();
        std::fs::write(remember_path(&dir), r#"{"slug":"  ","username":"akadmin"}"#).unwrap();
        assert!(load_with(&MemoryStore::new(), &dir).is_none());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn legacy_plaintext_password_is_stripped_and_slug_is_not_migrated() {
        let dir = temp_dir();
        let store = MemoryStore::new();
        store.set("akadmin", "legacy-keyring-password").unwrap();
        std::fs::write(
            remember_path(&dir),
            r#"{"slug":"neweditor","username":"akadmin","password":"legacy-secret"}"#,
        )
        .unwrap();
        let loaded = load_with(&store, &dir).unwrap();
        assert_eq!(loaded.slug, "neweditor");
        assert_eq!(loaded.username, "akadmin");
        let disk = std::fs::read_to_string(remember_path(&dir)).unwrap();
        assert!(!disk.contains("legacy-secret"));
        assert!(!disk.contains("cursorgo"));
        assert!(
            store.get("akadmin").is_none(),
            "leftover keyring password from the first draft must be dropped"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn clear_removes_meta_key_and_session_blob() {
        let dir = temp_dir();
        let store = MemoryStore::new();
        save_with(&store, &dir, &login()).unwrap();
        let (jar, _) = jar_with("authentik_session=secret-cookie");
        save_session_jar_with(&store, &dir, &jar, &cookie_urls()).unwrap();
        clear_with(&store, &dir);
        assert!(load_with(&store, &dir).is_none());
        assert!(load_session_jar_with(&store, &dir).is_none());
        assert!(store.get(SESSION_KEY_USER).is_none());
        assert!(!session_blob_path(&dir).exists());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn session_blob_roundtrip_restores_jar_cookies() {
        let dir = temp_dir();
        let store = MemoryStore::new();
        let (jar, auth) = jar_with("authentik_session=abc123");
        let stand = Url::parse("https://my.mcpwork.space/").unwrap();
        jar.add_cookie_str(
            "ak_outpost=out-9; Path=/; Domain=mcpwork.space; Secure; HttpOnly",
            &stand,
        );
        save_session_jar_with(&store, &dir, &jar, &cookie_urls()).unwrap();

        let blob = std::fs::read(session_blob_path(&dir)).unwrap();
        let as_text = String::from_utf8_lossy(&blob);
        assert!(!as_text.contains("abc123"));
        assert!(!as_text.contains("authentik_session"));
        assert!(blob.starts_with(SESSION_MAGIC));
        #[cfg(unix)]
        assert_eq!(mode_of(&session_blob_path(&dir)), 0o600);

        let restored = load_session_jar_with(&store, &dir).expect("restored jar");
        assert!(cookie_header(&restored, &auth).contains("authentik_session=abc123"));
        assert!(cookie_header(&restored, &stand).contains("ak_outpost=out-9"));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn failed_blob_write_does_not_orphan_a_fresh_key() {
        let dir = temp_dir();
        let store = MemoryStore::new();
        // A regular file where the cache dir should be: create_dir_all fails.
        let blocker = dir.join("not-a-dir");
        std::fs::write(&blocker, b"x").unwrap();
        let cache_dir = blocker.join("cache");
        let (jar, _) = jar_with("authentik_session=secret-cookie");
        assert!(save_session_jar_with(&store, &cache_dir, &jar, &cookie_urls()).is_err());
        assert!(
            store.get(SESSION_KEY_USER).is_none(),
            "the AES key must reach the keyring only after the blob is on disk"
        );
        assert!(!session_blob_path(&cache_dir).exists());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn keyring_failure_after_blob_write_removes_the_blob() {
        let dir = temp_dir();
        let store = MemoryStore::rejecting_writes();
        let (jar, _) = jar_with("authentik_session=secret-cookie");
        assert!(save_session_jar_with(&store, &dir, &jar, &cookie_urls()).is_err());
        assert!(
            !session_blob_path(&dir).exists(),
            "a blob whose key never reached the keyring must be rolled back"
        );
        assert!(!session_blob_path(&dir).with_extension("bin.tmp").exists());
        assert!(store.get(SESSION_KEY_USER).is_none());
        assert!(load_session_jar_with(&store, &dir).is_none());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn resave_reuses_session_key_and_replaces_blob() {
        let dir = temp_dir();
        let store = MemoryStore::new();
        // An unusable stored key is replaced, not reused.
        store.set(SESSION_KEY_USER, "not-hex").unwrap();
        let (first, auth) = jar_with("authentik_session=first");
        save_session_jar_with(&store, &dir, &first, &cookie_urls()).unwrap();
        let key = store.get(SESSION_KEY_USER).expect("fresh key");
        assert!(
            hex_decode_key(&key).is_some(),
            "stored key is 32 hex bytes: {key}"
        );
        let first_blob = std::fs::read(session_blob_path(&dir)).unwrap();

        let (second, _) = jar_with("authentik_session=second");
        save_session_jar_with(&store, &dir, &second, &cookie_urls()).unwrap();
        assert_eq!(
            store.get(SESSION_KEY_USER).as_deref(),
            Some(key.as_str()),
            "re-save keeps the key so replacing the blob is the only step"
        );
        assert_ne!(std::fs::read(session_blob_path(&dir)).unwrap(), first_blob);
        let restored = load_session_jar_with(&store, &dir).expect("restored jar");
        let header = cookie_header(&restored, &auth);
        assert!(header.contains("authentik_session=second"), "{header}");
        assert!(!header.contains("first"), "{header}");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn corrupt_blob_is_none() {
        let dir = temp_dir();
        let store = MemoryStore::new();
        std::fs::write(session_blob_path(&dir), b"AKS1not-really-encrypted").unwrap();
        store
            .set(SESSION_KEY_USER, &hex_encode(&[7u8; 32]))
            .unwrap();
        assert!(load_session_jar_with(&store, &dir).is_none());
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
