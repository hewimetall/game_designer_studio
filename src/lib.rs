//! Local designer desk: Tauri chrome + Rust proxy to the live stand.
//! Does not change Solid editors, Authentik, or tool_server.

mod apps;
mod assets;
mod auth;
mod cache;
mod config;
mod host;
mod progress;
mod proxy;
mod remember;
mod session;
mod slug;
mod sso;
mod stand;

pub use apps::{DesignerTab, SystemTab};
pub use config::{default_ui_dir, StudioConfig};
pub use host::{bind_local_host, LocalHost};
pub use progress::{attach_tauri_emitter, Progress, ProgressHub, STUDIO_PROGRESS_EVENT};

/// Wait until the loopback Axum chrome accepts TCP (desktop `--no-window` and Tauri).
pub fn await_loopback(addr: std::net::SocketAddr) {
    for _ in 0..100 {
        if std::net::TcpStream::connect_timeout(&addr, std::time::Duration::from_millis(50)).is_ok()
        {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
}

#[cfg(mobile)]
mod mobile;

/// JNI/Android entry used by `cargo tauri android build`. Not compiled in `cargo test --lib`.
#[cfg(mobile)]
#[tauri::mobile_entry_point]
pub fn run() {
    mobile::run_android();
}
