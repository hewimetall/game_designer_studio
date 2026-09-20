//! Rust inject for Chat HTML only (not Level / Sprites / Bestiary / S3).
//!
//! Live `chat.mcpwork.space` is `hermes-scout-olimpic` (Next.js). The composer
//! (`app/chat.tsx`) does `POST /api/agent/{agentId}` with JSON and gets
//! `202 {"runId","threadId"}`. The run itself (`app/agui.ts` `streamRunEvents`)
//! is `GET /api/runs/{runId}?since={cursor}` with `Accept: text/event-stream`,
//! parsed by hand from `fetch().body.getReader()` (not `EventSource`, not
//! CopilotKit `HttpAgent`, not protobuf; `@ag-ui/client` is not imported).
//! Cancel is `POST /api/runs/{runId}/cancel`. Relative `/api/runs` already hits the Chat
//! loopback SSO proxy (`is_chat_run_sse_path`). The inject script still patches
//! `window.fetch` so only GET `/api/runs/{uuid}[?since=]` (relative or absolute)
//! is rewritten to [`STUDIO_AGUI_PATH`] with the native jar — that is the only
//! target [`agui_upstream_path`] forwards. `Accept: text/event-stream` alone
//! never triggers the rewrite: other Chat SSE (e.g. `GET /api/threads/{id}/runs`)
//! stays on the SSO proxy. POST `/api/agent/*` stays JSON through the SSO proxy.

use axum::http::HeaderMap;

use crate::config::StudioConfig;
use crate::proxy::Proxy;

/// Studio-owned GET `/api/runs/{uuid}` SSE streamer on the Chat loopback port.
pub const STUDIO_AGUI_PATH: &str = "/api/studio/ag-ui";
pub const STUDIO_INJECT_JS_PATH: &str = "/api/studio/ag-ui-inject.js";

/// Marker attribute tests look for on injected Chat HTML.
pub const INJECT_MARKER: &str = "data-studio-agui-inject";
pub const INJECT_SCRIPT_ID: &str = "studio-agui-inject";

/// Patch `window.fetch`: only GET `/api/runs/{uuid}` → streamer. The Accept
/// header is forwarded untouched but never decides the rewrite. POST
/// `/api/agent/*` is not rewritten. Production uses `fetch` + `getReader()`,
/// not `EventSource`.
pub const INJECT_JS: &str = r#"(function(){
  if (window.__STUDIO_AGUI_INJECT__) return;
  window.__STUDIO_AGUI_INJECT__ = true;
  try { document.documentElement.setAttribute("data-studio-agui-inject","1"); } catch (e) {}
  var EP = location.origin + "/api/studio/ag-ui";
  function mergeHeaders(a, b) {
    var out = new Headers();
    function add(src) {
      if (!src) return;
      try {
        if (typeof Headers !== "undefined" && src instanceof Headers) {
          src.forEach(function (v, k) { out.set(k, v); });
          return;
        }
      } catch (e) {}
      if (typeof src.forEach === "function") {
        src.forEach(function (v, k) { out.set(k, v); });
        return;
      }
      if (typeof src === "object") {
        for (var k in src) {
          if (Object.prototype.hasOwnProperty.call(src, k)) out.set(k, src[k]);
        }
      }
    }
    add(a);
    add(b);
    return out;
  }
  function isRunSsePath(pathname) {
    return /^\/api\/runs\/[0-9a-fA-F-]+$/.test(pathname);
  }
  function isStudioAgui(pathname) {
    return pathname === "/api/studio/ag-ui";
  }
  function isGetRunSse(url, init, req) {
    var method = (init && init.method) || (req && req.method) || "GET";
    if (String(method).toUpperCase() !== "GET") return false;
    try {
      var parsed = new URL(url, location.href);
      if (isStudioAgui(parsed.pathname)) return false;
      return isRunSsePath(parsed.pathname);
    } catch (e) {
      return false;
    }
  }
  function studioTo(url) {
    try {
      var parsed = new URL(url, location.href);
      return EP + "?to=" + encodeURIComponent(parsed.pathname + parsed.search);
    } catch (e) {
      return EP;
    }
  }
  var origFetch = window.fetch.bind(window);
  window.fetch = function (input, init) {
    var req = null;
    var url;
    if (typeof input === "string") {
      url = input;
    } else if (input && typeof input === "object" && input.url != null) {
      req = input;
      url = String(input.url);
    } else {
      url = String(input);
    }
    if (!isGetRunSse(url, init, req)) {
      return origFetch(input, init);
    }
    var next = {};
    if (init) {
      for (var k in init) {
        if (Object.prototype.hasOwnProperty.call(init, k)) next[k] = init[k];
      }
    }
    next.headers = mergeHeaders(req && req.headers, init && init.headers);
    next.headers.set("X-Studio-Agui-Url", url);
    next.method = "GET";
    if (req && req.signal && !next.signal) next.signal = req.signal;
    return origFetch(studioTo(url), next);
  };
})();"#;

pub fn inject_snippet(script_src: &str) -> String {
    format!(r#"<script id="{INJECT_SCRIPT_ID}" src="{script_src}" {INJECT_MARKER}></script>"#)
}

/// Inject Chat HTML `<script src>`. Does not rewrite quoted origin URLs.
pub fn inject_chat_html(html: &str) -> String {
    inject_agui_markup(html, STUDIO_INJECT_JS_PATH)
}

pub fn inject_agui_markup(html: &str, script_src: &str) -> String {
    if html.contains(INJECT_MARKER) {
        return html.to_string();
    }
    let tag = inject_snippet(script_src);
    insert_script(html, &tag)
}

pub fn script_src_for_request(incoming: &HeaderMap) -> String {
    let host = incoming
        .get(axum::http::header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("127.0.0.1");
    if host.starts_with("127.0.0.1") || host.starts_with("[::1]") || host.starts_with("localhost") {
        format!("http://{host}{STUDIO_INJECT_JS_PATH}")
    } else {
        STUDIO_INJECT_JS_PATH.to_string()
    }
}

pub fn is_javascript_content_type(content_type: &str) -> bool {
    let ct = content_type.to_ascii_lowercase();
    ct.contains("javascript") || ct.contains("ecmascript")
}

pub fn is_html_content_type_str(content_type: &str) -> bool {
    content_type.to_ascii_lowercase().contains("text/html")
}

/// Live chat run stream: `GET /api/runs/{uuid}` with optional `?since=`.
/// Not `/cancel`, not `/scouts/{id}`, not `POST /api/agent/{id}`.
pub fn is_chat_run_sse_path(path_and_query: &str) -> bool {
    let p = path_and_query.split('?').next().unwrap_or(path_and_query);
    let Some(rest) = p.strip_prefix("/api/runs/") else {
        return false;
    };
    if rest.is_empty() || rest.contains('/') {
        return false;
    }
    rest.chars().all(|c| c.is_ascii_hexdigit() || c == '-')
}

/// Mirrors the inject `window.fetch` patch: rewrite only GET `/api/runs/{uuid}`
/// to [`STUDIO_AGUI_PATH`]. The decision is method + path; the Accept header
/// plays no part, so other Chat SSE stays on the SSO proxy. POST `/api/agent/*`
/// is never classified as the AG-UI stream (JSON 202).
pub fn inject_rewrites_fetch(method: &str, url: &str) -> bool {
    if !method.eq_ignore_ascii_case("GET") {
        return false;
    }
    let path = fetch_url_path_and_query(url);
    let path_only = path.split('?').next().unwrap_or(path.as_str());
    if path_only == STUDIO_AGUI_PATH || path_only.starts_with(&format!("{STUDIO_AGUI_PATH}/")) {
        return false;
    }
    is_chat_run_sse_path(&path)
}

fn fetch_url_path_and_query(url: &str) -> String {
    let url = url.trim();
    if url.starts_with('/') {
        return url.to_string();
    }
    reqwest::Url::parse(url)
        .ok()
        .map(|u| Proxy::path_and_query(u.path(), u.query()))
        .unwrap_or_else(|| url.to_string())
}

pub fn agui_upstream_path(
    incoming: &HeaderMap,
    query: Option<&str>,
    chat_origin: &str,
) -> Option<String> {
    let raw = incoming
        .get("x-studio-agui-url")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .or_else(|| query_to_param(query))?;
    let path = sanitize_agui_target(&raw, chat_origin)?;
    is_chat_run_sse_path(&path).then_some(path)
}

fn query_to_param(query: Option<&str>) -> Option<String> {
    let q = query?;
    let dummy = format!("http://127.0.0.1/?{q}");
    reqwest::Url::parse(&dummy)
        .ok()?
        .query_pairs()
        .find(|(k, _)| k == "to" || k == "path")
        .map(|(_, v)| v.into_owned())
        .filter(|s| !s.is_empty())
}

pub fn sanitize_agui_target(raw: &str, chat_origin: &str) -> Option<String> {
    let raw = raw.trim();
    if raw.is_empty() || raw.contains("..") {
        return None;
    }
    if raw.starts_with('/') {
        if raw == STUDIO_AGUI_PATH
            || raw.starts_with(&format!("{STUDIO_AGUI_PATH}/"))
            || raw.starts_with(&format!("{STUDIO_AGUI_PATH}?"))
        {
            return None;
        }
        return Some(raw.to_string());
    }
    let url = reqwest::Url::parse(raw).ok()?;
    if !StudioConfig::url_matches_origin(&url, chat_origin) {
        return None;
    }
    let path = if url.path().is_empty() {
        "/"
    } else {
        url.path()
    };
    if path == STUDIO_AGUI_PATH || path.starts_with(&format!("{STUDIO_AGUI_PATH}/")) {
        return None;
    }
    Some(Proxy::path_and_query(path, url.query()))
}

fn insert_script(html: &str, snippet: &str) -> String {
    let lower = html.to_ascii_lowercase();
    if let Some(inserted) = insert_after_tag(&lower, html, "<head", snippet) {
        return inserted;
    }
    if let Some(inserted) = insert_after_tag(&lower, html, "<html", snippet) {
        return inserted;
    }
    let mut out = String::with_capacity(html.len() + snippet.len());
    out.push_str(snippet);
    out.push_str(html);
    out
}

fn insert_after_tag(lower: &str, html: &str, tag: &str, snippet: &str) -> Option<String> {
    let pos = lower.find(tag)?;
    let gt = lower[pos..].find('>')?;
    let at = pos + gt + 1;
    let mut out = String::with_capacity(html.len() + snippet.len());
    out.push_str(&html[..at]);
    out.push_str(snippet);
    out.push_str(&html[at..]);
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const CHAT: &str = "https://chat.mcpwork.space";
    const RUN: &str = "/api/runs/30289690-b756-416a-ac0d-5bc9a3396ef7";
    const RUN_SINCE: &str = "/api/runs/30289690-b756-416a-ac0d-5bc9a3396ef7?since=0";

    fn header(value: &'static str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-studio-agui-url",
            axum::http::HeaderValue::from_static(value),
        );
        headers
    }

    #[test]
    fn inject_lands_in_head_once_and_is_idempotent() {
        let html = "<!doctype html><html><head><title>chat</title></head><body>ok</body></html>";
        let once = inject_chat_html(html);
        let head = once.split("</head>").next().unwrap();
        assert!(head.contains(&inject_snippet(STUDIO_INJECT_JS_PATH)));
        assert_eq!(inject_chat_html(&once), once, "second pass is a no-op");
        assert_eq!(
            inject_agui_markup(&once, "/other.js"),
            once,
            "marker wins over a different script src"
        );
        let bare = inject_agui_markup("<p>no head</p>", "/x.js");
        assert!(bare.starts_with(&inject_snippet("/x.js")));
    }

    #[test]
    fn inject_does_not_rewrite_urls_in_html() {
        let html = r#"<html><head></head><body>
<script>new HttpAgent({ url: "https://chat.mcpwork.space/api/copilotkit" });</script>
<script>fetch("/api/agent/game",{method:"POST"});</script>
<script>fetch("/api/runs/30289690-b756-416a-ac0d-5bc9a3396ef7?since=0");</script>
<img src="https://chat.mcpwork.space/logo.png">
</body></html>"#;
        let out = inject_chat_html(html);
        assert_eq!(
            out.replacen(&inject_snippet(STUDIO_INJECT_JS_PATH), "", 1),
            html,
            "the only change to Chat HTML is the script tag"
        );
    }

    #[test]
    fn run_sse_path_matches_live_chat_contract() {
        assert!(is_chat_run_sse_path(RUN));
        assert!(is_chat_run_sse_path(RUN_SINCE));
        assert!(!is_chat_run_sse_path("/api/runs"));
        assert!(!is_chat_run_sse_path("/api/runs/"));
        assert!(!is_chat_run_sse_path(&format!("{RUN}/cancel")));
        assert!(!is_chat_run_sse_path(&format!("{RUN}/scouts/abc")));
        assert!(!is_chat_run_sse_path("/api/agent/game"));
        assert!(!is_chat_run_sse_path("/api/copilotkit"));
        assert!(!is_chat_run_sse_path("/api/threads"));
    }

    #[test]
    fn fetch_rewrite_is_get_api_runs_uuid_only() {
        assert!(inject_rewrites_fetch("GET", RUN_SINCE));
        assert!(inject_rewrites_fetch("GET", RUN));
        assert!(
            inject_rewrites_fetch("get", RUN_SINCE),
            "method comparison is case-insensitive"
        );
        assert!(inject_rewrites_fetch("GET", &format!("{CHAT}{RUN_SINCE}")));
        assert!(
            !inject_rewrites_fetch(
                "GET",
                "/api/threads/1de8f6f0-b0c5-4903-8a7b-15aaae852f62/runs"
            ),
            "other Chat SSE stays on the SSO proxy"
        );
        assert!(!inject_rewrites_fetch("GET", "/api/threads"));
        assert!(!inject_rewrites_fetch("POST", "/api/agent/game"));
        assert!(!inject_rewrites_fetch("POST", RUN));
        assert!(!inject_rewrites_fetch("POST", &format!("{RUN}/cancel")));
        assert!(!inject_rewrites_fetch("GET", &format!("{RUN}/cancel")));
        assert!(!inject_rewrites_fetch("GET", &format!("{RUN}/scouts/abc")));
        assert!(
            !inject_rewrites_fetch("GET", &format!("{STUDIO_AGUI_PATH}?to={RUN_SINCE}")),
            "the streamer itself is never rewritten again"
        );
        assert!(!inject_rewrites_fetch(
            "GET",
            &format!("{CHAT}{STUDIO_AGUI_PATH}?to={RUN}")
        ));
    }

    #[test]
    fn streamer_only_forwards_run_sse_on_chat_origin() {
        assert_eq!(
            sanitize_agui_target(RUN_SINCE, CHAT).as_deref(),
            Some(RUN_SINCE)
        );
        assert!(sanitize_agui_target(STUDIO_AGUI_PATH, CHAT).is_none());
        assert!(sanitize_agui_target("https://evil.example/x", CHAT).is_none());
        assert!(sanitize_agui_target("/ok/../secret", CHAT).is_none());

        assert_eq!(
            agui_upstream_path(
                &header("https://chat.mcpwork.space/api/runs/30289690-b756-416a-ac0d-5bc9a3396ef7?since=0"),
                None,
                CHAT
            )
            .as_deref(),
            Some(RUN_SINCE)
        );
        assert!(
            agui_upstream_path(
                &header("https://chat.mcpwork.space/api/copilotkit"),
                None,
                CHAT
            )
            .is_none(),
            "must not forward an invented CopilotKit path"
        );
        assert!(
            agui_upstream_path(
                &header("https://chat.mcpwork.space/api/agent/game"),
                None,
                CHAT
            )
            .is_none(),
            "POST /api/agent is JSON 202, not the SSE streamer"
        );
        assert!(agui_upstream_path(&HeaderMap::new(), Some("to=/agent"), CHAT).is_none());
        assert_eq!(
            agui_upstream_path(&HeaderMap::new(), Some(&format!("to={RUN_SINCE}")), CHAT)
                .as_deref(),
            Some(RUN_SINCE)
        );
    }
}
