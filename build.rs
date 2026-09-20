fn main() {
    let manifest = std::path::PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let png = manifest.join("icons").join("icon.png");
    let ico = manifest.join("icons").join("icon.ico");
    println!("cargo:rerun-if-changed={}", png.display());
    println!("cargo:rerun-if-changed={}", ico.display());

    if !png.is_file() {
        panic!("missing {} — required by the Tauri bundle", png.display());
    }
    if !ico.is_file() {
        panic!(
            "missing {} — required for generating a Windows Resource file during tauri-build",
            ico.display()
        );
    }

    let windows = tauri_build::WindowsAttributes::new().window_icon_path(&ico);
    tauri_build::try_build(tauri_build::Attributes::new().windows_attributes(windows))
        .expect("tauri-build");

    let chrome = std::path::Path::new("ui").join("index.html");
    if !chrome.is_file() {
        panic!(
            "missing {} — Studio chrome (login, tabs, progress) must ship in the binary",
            chrome.display()
        );
    }
    // Public hewimetall/game_designer_studio is chrome-only: Level / Sprites /
    // Bestiary SPAs are fetched from the live stand into the overlay cache.
    // Private hewimetall/game may still bake hashed Vite folders under ui/.
}
