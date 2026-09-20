//! Tauri 2 Android entry. Compiled only with `--cfg mobile` from `cargo tauri android build`.

use tauri::Manager;

use crate::{
    attach_tauri_emitter, await_loopback, bind_local_host, default_ui_dir, DesignerTab,
    StudioConfig,
};

pub fn run_android() {
    let cfg = StudioConfig::production(default_ui_dir(), 18765, None);
    let host = match bind_local_host(cfg) {
        Ok(host) => host,
        Err(err) => panic!("designer_studio: {err}"),
    };
    let chrome = host.chrome_url();
    await_loopback(host.addr);
    let progress = host.progress.clone();
    // Keep the Axum thread alive for the WebView session.
    let _host = host;
    eprintln!(
        "METRO-ARK Studio {} вкладки: {}",
        chrome,
        DesignerTab::ALL
            .iter()
            .map(|tab| tab.id())
            .collect::<Vec<_>>()
            .join(", ")
    );

    let chrome_url = chrome;
    tauri::Builder::default()
        .setup(move |app| {
            attach_tauri_emitter(app.handle().clone(), &progress);
            if let Some(window) = app.get_webview_window("main") {
                window.navigate(tauri::Url::parse(&chrome_url)?)?;
            }
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("designer studio window");
}
