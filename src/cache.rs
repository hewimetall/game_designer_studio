//! Read-only replica of stand GET responses.
//!
//! Hot path stays in Rust: in-memory `Bytes` (cheap clone, no JSON parse),
//! atomic disk write-through, size-capped eviction. Disk is for the next launch;
//! memory is for the current session on a weak link.

use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::RwLock;
use std::time::{SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use sha2::{Digest, Sha256};

const MEM_BUDGET: usize = 64 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct CachedObject {
    pub status: u16,
    pub content_type: String,
    pub body: Bytes,
    pub fetched_at: u64,
}

#[derive(Debug)]
struct MemEntry {
    object: CachedObject,
    bytes: usize,
}

pub struct ReadCache {
    dir: PathBuf,
    mem: RwLock<HashMap<String, MemEntry>>,
}

impl ReadCache {
    pub fn open(dir: impl Into<PathBuf>) -> std::io::Result<Self> {
        let dir = dir.into();
        fs::create_dir_all(&dir)?;
        Ok(Self {
            dir,
            mem: RwLock::new(HashMap::new()),
        })
    }

    #[inline]
    pub fn key(method: &str, path_and_query: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(method.as_bytes());
        hasher.update([0]);
        hasher.update(path_and_query.as_bytes());
        hex_lower(&hasher.finalize())
    }

    pub fn get(&self, key: &str) -> Option<CachedObject> {
        if let Ok(mem) = self.mem.read() {
            if let Some(entry) = mem.get(key) {
                return Some(entry.object.clone());
            }
        }
        let object = load_disk(&self.dir, key)?;
        self.insert_mem(key.to_string(), object.clone());
        Some(object)
    }

    pub fn put(&self, key: String, object: CachedObject) {
        store_disk(&self.dir, &key, &object);
        self.insert_mem(key, object);
    }

    pub fn len(&self) -> usize {
        self.mem.read().map(|m| m.len()).unwrap_or(0)
    }

    fn insert_mem(&self, key: String, object: CachedObject) {
        let bytes = object.body.len();
        let mut mem = match self.mem.write() {
            Ok(guard) => guard,
            Err(_) => return,
        };
        if let Some(old) = mem.remove(&key) {
            let _ = old.bytes;
        }
        mem.insert(key, MemEntry { object, bytes });
        evict_to_budget(&mut mem);
    }
}

fn evict_to_budget(mem: &mut HashMap<String, MemEntry>) {
    let mut total: usize = mem.values().map(|e| e.bytes).sum();
    while total > MEM_BUDGET && !mem.is_empty() {
        let oldest = mem
            .iter()
            .min_by_key(|(_, e)| e.object.fetched_at)
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

fn load_disk(dir: &Path, key: &str) -> Option<CachedObject> {
    let meta_path = dir.join(format!("{key}.meta"));
    let body_path = dir.join(format!("{key}.bin"));
    let meta = fs::read_to_string(meta_path).ok()?;
    let (status, content_type, fetched_at) = parse_meta(&meta)?;
    let body = Bytes::from(fs::read(body_path).ok()?);
    Some(CachedObject {
        status,
        content_type,
        body,
        fetched_at,
    })
}

fn store_disk(dir: &Path, key: &str, object: &CachedObject) {
    let tmp = dir.join(format!("{key}.bin.tmp"));
    let bin = dir.join(format!("{key}.bin"));
    let meta = dir.join(format!("{key}.meta"));
    if let Ok(mut file) = fs::File::create(&tmp) {
        if file.write_all(&object.body).is_ok() {
            let _ = file.sync_all();
            let _ = fs::rename(tmp, bin);
        } else {
            let _ = fs::remove_file(&tmp);
        }
    }
    let line = format!(
        "{}\n{}\n{}\n",
        object.status, object.content_type, object.fetched_at
    );
    let _ = fs::write(meta, line);
}

fn parse_meta(meta: &str) -> Option<(u16, String, u64)> {
    let mut lines = meta.lines();
    let status = lines.next()?.parse().ok()?;
    let content_type = lines.next()?.to_string();
    let fetched_at = lines.next()?.parse().ok()?;
    Some((status, content_type, fetched_at))
}

#[inline]
pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
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

    #[test]
    fn keys_are_stable_and_distinct() {
        let a = ReadCache::key("GET", "/stand/x/api/level?kind=Hub");
        let b = ReadCache::key("GET", "/stand/x/api/level?kind=Hub");
        let c = ReadCache::key("GET", "/stand/x/api/level?kind=Market");
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_eq!(a.len(), 64);
    }

    #[test]
    fn mem_and_disk_roundtrip() {
        let dir = std::env::temp_dir().join(format!(
            "designer-cache-{}-{}",
            std::process::id(),
            now_secs()
        ));
        let cache = ReadCache::open(&dir).unwrap();
        let key = ReadCache::key("GET", "/stand/s/api/bestiary");
        cache.put(
            key.clone(),
            CachedObject {
                status: 200,
                content_type: "application/json".into(),
                body: Bytes::from_static(b"{\"ok\":true}"),
                fetched_at: 1,
            },
        );
        let hit = cache.get(&key).unwrap();
        assert_eq!(&hit.body[..], b"{\"ok\":true}");
        drop(cache);
        let cache2 = ReadCache::open(&dir).unwrap();
        let again = cache2.get(&key).unwrap();
        assert_eq!(again.status, 200);
        let _ = fs::remove_dir_all(dir);
    }
}
