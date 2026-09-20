#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::path::PathBuf;

use clap::Parser;
use designer_studio_lib::{
    attach_tauri_emitter, await_loopback, bind_local_host, default_ui_dir, DesignerTab,
    ProgressHub, StudioConfig, SystemTab,
};

#[derive(Parser)]
#[command(
    name = "designer_studio",
    about = "Локальный стол METRO-ARK: Level / Sprites / Bestiary через стенд, Chat / S3 через общий SSO. Без Game и A-Life."
)]
struct Args {
    #[arg(long, default_value_t = 18765)]
    port: u16,
    #[arg(long)]
    cache_dir: Option<PathBuf>,
    /// Только loopback-прокси, без окна Tauri (проверка на Linux).
    #[arg(long)]
    no_window: bool,
}

fn main() {
    let args = Args::parse();
    let cfg = StudioConfig::production(default_ui_dir(), args.port, args.cache_dir);
    let host = match bind_local_host(cfg) {
        Ok(host) => host,
        Err(err) => {
            eprintln!("designer_studio: {err}");
            std::process::exit(1);
        }
    };
    let chrome = host.chrome_url();
    await_loopback(host.addr);
    eprintln!(
        "METRO-ARK Studio {} вкладки: {}, {}",
        chrome,
        DesignerTab::ALL
            .iter()
            .map(|tab| tab.id())
            .collect::<Vec<_>>()
            .join(", "),
        SystemTab::ALL
            .iter()
            .map(|tab| tab.id())
            .collect::<Vec<_>>()
            .join(", ")
    );

    if args.no_window {
        loop {
            std::thread::park();
        }
    }

    run_window(&chrome, host.progress);
}

fn run_window(chrome: &str, progress: std::sync::Arc<ProgressHub>) {
    use tauri::Manager;

    let chrome = chrome.to_string();
    tauri::Builder::default()
        .setup(move |app| {
            attach_tauri_emitter(app.handle().clone(), &progress);
            if let Some(window) = app.get_webview_window("main") {
                window.navigate(tauri::Url::parse(&chrome)?)?;
            }
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("designer studio window");
}
