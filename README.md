# METRO-ARK Designer Studio

Local Tauri **chrome** for a weak link: login, tabs, progress. Editors are **not** in this binary.

**Level / Sprites / Bestiary** load from the live stand `https://my.mcpwork.space/stand/cursorgo/…` (`/stand/<slug>/`, singular — not `/stands/`) through the local proxy + overlay cache. **Chat** and **S3** share the same Authentik SSO (`Domain=mcpwork.space`) on extra loopback ports to `chat.mcpwork.space` / `s3.mcpwork.space` — their Vite apps use `base: "/"` and would collide with studio `/api/*` on the chrome port. No Game, no A-Life, no Bevy, no `tool_server`, no `src/web` editors.

Installers are **GitHub Releases** on this public repo (free Actions on public; NSIS/APK are not npm/NuGet packages):

**https://github.com/hewimetall/game_designer_studio/releases**

## Designer (Windows)

The NSIS installer does **not** embed WebView2 (`webviewInstallMode: skip`).

1. Download the Windows installer from [Releases](https://github.com/hewimetall/game_designer_studio/releases/latest).
2. If the window does not open, install the **Evergreen Bootstrapper** (left card) from https://developer.microsoft.com/microsoft-edge/webview2/
3. Start Studio → login + password (стенд slug `cursorgo`). «Запомнить» stores the AES-encrypted cookie jar.
   If a previous «Запомнить» still shows `neweditor`, that slug does not exist — press «сменить» and log in again with `cursorgo` (no automatic migrate).

Android: unsigned APK on the same Releases page (sideload; not Play-signed).

You do not need npm, cargo, or a UI packaging script.

## Download URL shape

| What | URL |
| --- | --- |
| All releases | `https://github.com/hewimetall/game_designer_studio/releases` |
| Latest | `https://github.com/hewimetall/game_designer_studio/releases/latest` |
| A tagged asset | `https://github.com/hewimetall/game_designer_studio/releases/download/v0.1.0/<file>` |

## Developers

This repo is chrome-only. Hashed Vite SPAs under `ui/level`, `ui/sprites`, `ui/bestiary` must not be committed. After login the iframe hits `/stand/<slug>/<app>/` for editors (live slug `cursorgo`); Chat / S3 iframes hit extra `127.0.0.1` ports (same Authentik jar). Axum fills editor overlay from the stand. Solid `apiBasePath()` stays `/stand/<slug>/api`.

Chat injects a marker into Chat HTML only. The live contract is relative `POST /api/agent/{id}` (JSON 202 `{runId}`) then `GET /api/runs/{id}?since=` (`Accept: text/event-stream` via `fetch` + `getReader()`, not EventSource/HttpAgent). Inject rewrites only that `GET /api/runs/{uuid}[?since=]` to loopback `GET /api/studio/ag-ui` (path match, never Accept alone — other Chat SSE such as `GET /api/threads/{id}/runs` stays on the SSO proxy); the native Authentik cookie jar streams bytes as-is (`Accept-Encoding: identity`, 15 min). Inject cache is HTML-only; the SSE byte stream is not cached. WebSocket is unused in production (501).

Authentik login in this desk is username + password. «Запомнить» encrypts the cookie jar with AES-256-GCM (key in the OS keyring, ciphertext under `cache_dir`). A still-valid Authentik session skips the gate.

```bash
cargo +1.95 run -- --no-window   # proxy only
cargo +1.95 test --lib
```

Windows NSIS + Android APK CI runs **here** on tag `v*` (public Actions). It does not use the private `hewimetall/game` Actions budget.

Private `hewimetall/game` can submodule this URL at `crates/designer_studio`.
