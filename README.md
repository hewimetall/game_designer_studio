# METRO-ARK Designer Studio

Local Tauri **chrome** for a weak link: login, tabs, progress. Editors are **not** in this binary.

**Level / Sprites / Bestiary** load from the live stand `https://my.mcpwork.space/stand/<slug>/…` through the local proxy + overlay cache. No Game, no A-Life, no Bevy, no `tool_server`, no `src/web` editors.

Installers are **GitHub Releases** on this public repo (free Actions on public; NSIS/APK are not npm/NuGet packages):

**https://github.com/hewimetall/game_designer_studio/releases**

## Designer (Windows)

The NSIS installer does **not** embed WebView2 (`webviewInstallMode: skip`).

1. Download the Windows installer from [Releases](https://github.com/hewimetall/game_designer_studio/releases/latest).
2. If the window does not open, install the **Evergreen Bootstrapper** (left card) from https://developer.microsoft.com/microsoft-edge/webview2/
3. Start Studio → stand slug + Authentik login.

Android: unsigned APK on the same Releases page (sideload; not Play-signed).

You do not need npm, cargo, or a UI packaging script.

## Download URL shape

| What | URL |
| --- | --- |
| All releases | `https://github.com/hewimetall/game_designer_studio/releases` |
| Latest | `https://github.com/hewimetall/game_designer_studio/releases/latest` |
| A tagged asset | `https://github.com/hewimetall/game_designer_studio/releases/download/v0.1.0/<file>` |

## Developers

This repo is chrome-only. Hashed Vite SPAs under `ui/level`, `ui/sprites`, `ui/bestiary` must not be committed. After login the iframe hits `/stand/<slug>/<app>/`; Axum fills the overlay from the stand.

```bash
cargo +1.95 run -- --no-window   # proxy only
cargo +1.95 test --lib
```

Windows NSIS + Android APK CI runs **here** on tag `v*` (public Actions). It does not use the private `hewimetall/game` Actions budget.

Private `hewimetall/game` can submodule this URL at `crates/designer_studio`.
