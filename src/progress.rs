//! Shared download counters. Rust owns the numbers; chrome polls or listens.
//!
//! Tauri 2's simplest native path is `AppHandle::emit` + `listen`
//! (<https://v2.tauri.app/develop/calling-frontend>,
//! <https://docs.rs/tauri/latest/tauri/trait.Emitter.html>).
//! `--no-window` and Android still talk to Axum on 127.0.0.1, so the same
//! snapshot is also served at `GET /api/studio/progress`.
//! reqwest has no built-in progress bar: count `Response::chunk` and
//! `content_length` (<https://docs.rs/reqwest/latest/reqwest/struct.Response.html>).

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::Serialize;

pub const STUDIO_PROGRESS_EVENT: &str = "studio-progress";

const EMIT_EVERY: Duration = Duration::from_millis(100);

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Progress {
    pub phase: String,
    pub files_done: u64,
    pub files_total: u64,
    pub bytes_done: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bytes_total: Option<u64>,
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl Progress {
    pub fn idle() -> Self {
        Self {
            phase: "idle".into(),
            files_done: 0,
            files_total: 0,
            bytes_done: 0,
            bytes_total: None,
            path: String::new(),
            error: None,
        }
    }
}

struct Inner {
    snap: Progress,
    bytes_at_file_start: u64,
    in_flight: bool,
    last_emit: Option<Instant>,
}

type Emitter = Arc<dyn Fn(Progress) + Send + Sync>;

pub struct ProgressHub {
    inner: Mutex<Inner>,
    emitter: Mutex<Option<Emitter>>,
}

impl std::fmt::Debug for ProgressHub {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProgressHub")
            .field("snapshot", &self.snapshot())
            .finish()
    }
}

impl ProgressHub {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(Inner {
                snap: Progress::idle(),
                bytes_at_file_start: 0,
                in_flight: false,
                last_emit: None,
            }),
            emitter: Mutex::new(None),
        })
    }

    pub fn set_emitter(&self, emit: Emitter) {
        if let Ok(mut slot) = self.emitter.lock() {
            *slot = Some(emit);
        }
    }

    pub fn snapshot(&self) -> Progress {
        self.lock().snap.clone()
    }

    pub fn begin(&self, phase: &str) {
        {
            let mut g = self.lock();
            g.snap = Progress {
                phase: phase.to_string(),
                files_done: 0,
                files_total: 0,
                bytes_done: 0,
                bytes_total: None,
                path: String::new(),
                error: None,
            };
            g.bytes_at_file_start = 0;
            g.in_flight = false;
            g.last_emit = None;
        }
        self.publish(true);
    }

    pub fn set_phase(&self, phase: &str) {
        {
            let mut g = self.lock();
            if g.snap.phase == "idle" || g.snap.phase == "done" || g.snap.phase == "error" {
                drop(g);
                self.begin(phase);
                return;
            }
            g.snap.phase = phase.to_string();
        }
        self.publish(true);
    }

    pub fn start_file(&self, path: &str) {
        {
            let mut g = self.lock();
            g.in_flight = true;
            g.bytes_at_file_start = g.snap.bytes_done;
            g.snap.path = path.to_string();
            g.snap.error = None;
            if g.snap.phase == "idle" || g.snap.phase == "done" || g.snap.phase == "error" {
                g.snap.phase = "overlay".into();
            }
            g.snap.files_total = g.snap.files_total.max(g.snap.files_done.saturating_add(1));
        }
        self.publish(true);
    }

    pub fn set_current_len(&self, len: Option<u64>) {
        {
            let mut g = self.lock();
            g.snap.bytes_total = len.map(|n| g.bytes_at_file_start.saturating_add(n));
        }
        self.publish(false);
    }

    pub fn add_bytes(&self, n: u64) {
        if n == 0 {
            return;
        }
        {
            let mut g = self.lock();
            g.snap.bytes_done = g.snap.bytes_done.saturating_add(n);
        }
        self.publish(false);
    }

    pub fn complete_file(&self) {
        {
            let mut g = self.lock();
            if g.in_flight {
                g.snap.files_done = g.snap.files_done.saturating_add(1);
                g.in_flight = false;
            }
            g.bytes_at_file_start = g.snap.bytes_done;
            g.snap.files_total = g.snap.files_total.max(g.snap.files_done);
            if g.snap.bytes_total.is_some() {
                g.snap.bytes_total = Some(g.snap.bytes_done);
            }
        }
        self.publish(true);
    }

    pub fn ensure_files_total(&self, n: u64) {
        {
            let mut g = self.lock();
            g.snap.files_total = g.snap.files_total.max(n);
        }
        self.publish(false);
    }

    pub fn add_files_total(&self, n: u64) {
        if n == 0 {
            return;
        }
        {
            let mut g = self.lock();
            g.snap.files_total = g.snap.files_total.saturating_add(n);
        }
        self.publish(false);
    }

    pub fn note_remaining(&self, remaining: u64) {
        {
            let mut g = self.lock();
            let inflight = if g.in_flight { 1 } else { 0 };
            g.snap.files_total = g
                .snap
                .files_done
                .saturating_add(remaining)
                .saturating_add(inflight);
        }
        self.publish(false);
    }

    pub fn finish(&self) {
        {
            let mut g = self.lock();
            g.in_flight = false;
            g.snap.phase = "done".into();
            g.snap.error = None;
            g.snap.files_total = g.snap.files_total.max(g.snap.files_done);
        }
        self.publish(true);
    }

    pub fn fail(&self, error: &str) {
        {
            let mut g = self.lock();
            g.in_flight = false;
            g.snap.phase = "error".into();
            g.snap.error = Some(error.to_string());
        }
        self.publish(true);
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn publish(&self, force: bool) {
        let snap = {
            let mut g = self.lock();
            if !force {
                if let Some(prev) = g.last_emit {
                    if prev.elapsed() < EMIT_EVERY {
                        return;
                    }
                }
            }
            g.last_emit = Some(Instant::now());
            g.snap.clone()
        };
        if let Ok(slot) = self.emitter.lock() {
            if let Some(emit) = slot.as_ref() {
                emit(snap);
            }
        }
    }
}

/// Tauri 2: `app.emit("studio-progress", snapshot)` reaches `listen` in the WebView.
/// After `navigate(http://127.0.0.1/)` the page is a remote origin: capability
/// `remote.urls` must allow loopback, and we also `eval` the same snapshot so
/// the ticket cannot miss a tick if `listen` attaches a frame late.
pub fn attach_tauri_emitter(handle: tauri::AppHandle, hub: &ProgressHub) {
    use tauri::{Emitter, Manager};
    let handle = handle.clone();
    hub.set_emitter(Arc::new(move |snap: Progress| {
        let _ = handle.emit(STUDIO_PROGRESS_EVENT, &snap);
        if let Some(win) = handle.get_webview_window("main") {
            if let Ok(json) = serde_json::to_string(&snap) {
                let _ = win.eval(&format!(
                    "window.applyStudioProgress&&window.applyStudioProgress({json})"
                ));
            }
        }
    }));
}

pub fn format_ru_bytes(n: u64) -> String {
    const KB: f64 = 1024.0;
    const MB: f64 = 1024.0 * 1024.0;
    if n < 1024 {
        format!("{n} Б")
    } else if (n as f64) < MB {
        format!("{} КБ", trim_decimal(n as f64 / KB))
    } else {
        format!("{} МБ", trim_decimal(n as f64 / MB))
    }
}

fn trim_decimal(v: f64) -> String {
    let s = format!("{v:.1}");
    if s.ends_with(".0") {
        s[..s.len() - 2].to_string()
    } else {
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_and_byte_counters_accumulate() {
        let hub = ProgressHub::new();
        assert_eq!(hub.snapshot().phase, "idle");
        hub.begin("overlay");
        hub.ensure_files_total(3);
        hub.start_file("assets/a.js");
        hub.set_current_len(Some(100));
        hub.add_bytes(40);
        let snap = hub.snapshot();
        assert_eq!(snap.phase, "overlay");
        assert_eq!(snap.files_done, 0);
        assert_eq!(snap.files_total, 3);
        assert_eq!(snap.bytes_done, 40);
        assert_eq!(snap.bytes_total, Some(100));
        assert_eq!(snap.path, "assets/a.js");

        hub.add_bytes(60);
        hub.complete_file();
        hub.start_file("assets/b.js");
        hub.set_current_len(Some(50));
        hub.add_bytes(50);
        hub.complete_file();
        let snap = hub.snapshot();
        assert_eq!(snap.files_done, 2);
        assert_eq!(snap.bytes_done, 150);
        assert_eq!(snap.bytes_total, Some(150));
        assert_eq!(snap.path, "assets/b.js");

        hub.note_remaining(1);
        assert_eq!(hub.snapshot().files_total, 3);
        hub.start_file("c.json");
        hub.add_bytes(10);
        hub.complete_file();
        hub.finish();
        let snap = hub.snapshot();
        assert_eq!(snap.phase, "done");
        assert_eq!(snap.files_done, 3);
        assert_eq!(snap.files_total, 3);
        assert_eq!(snap.bytes_done, 160);
        assert_eq!(format_ru_bytes(snap.bytes_done), "160 Б");
    }

    #[test]
    fn unknown_length_hides_bytes_total_but_keeps_bytes_done() {
        let hub = ProgressHub::new();
        hub.begin("sync");
        hub.add_files_total(2);
        hub.start_file("/api/levels");
        hub.set_current_len(None);
        hub.add_bytes(2048);
        hub.complete_file();
        let snap = hub.snapshot();
        assert_eq!(snap.files_done, 1);
        assert_eq!(snap.files_total, 2);
        assert_eq!(snap.bytes_done, 2048);
        assert_eq!(snap.bytes_total, None);
        hub.fail("стенд не ответил");
        let snap = hub.snapshot();
        assert_eq!(snap.phase, "error");
        assert_eq!(snap.error.as_deref(), Some("стенд не ответил"));
    }

    #[test]
    fn ru_byte_labels_match_desk_copy() {
        assert_eq!(format_ru_bytes(0), "0 Б");
        assert_eq!(format_ru_bytes(512), "512 Б");
        assert_eq!(format_ru_bytes(1024), "1 КБ");
        assert_eq!(format_ru_bytes(1400), "1.4 КБ");
        assert_eq!(format_ru_bytes(1_468_006), "1.4 МБ");
    }

    #[test]
    fn joining_phase_does_not_reset_counters() {
        let hub = ProgressHub::new();
        hub.begin("sync");
        hub.start_file("levels.json");
        hub.add_bytes(20);
        hub.complete_file();
        hub.set_phase("overlay");
        let snap = hub.snapshot();
        assert_eq!(snap.phase, "overlay");
        assert_eq!(snap.files_done, 1);
        assert_eq!(snap.bytes_done, 20);
        hub.finish();
        hub.set_phase("overlay");
        assert_eq!(hub.snapshot().files_done, 0);
        assert_eq!(hub.snapshot().phase, "overlay");
    }
}
