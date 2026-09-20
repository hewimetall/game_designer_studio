//! Rust inject for Chat HTML only (not Level / Sprites / Bestiary / S3).
//!
//! Live `chat.mcpwork.space` is a Next.js Longgraph shell. The composer does
//! `POST /api/agent/{id}` with JSON and gets `202 {"runId","threadId"}`. The
//! run itself is `GET /api/runs/{uuid}?since=` with `Accept: text/event-stream`,
//! parsed from `fetch().body.getReader()` (not `EventSource`, not CopilotKit
//! `HttpAgent`, not protobuf). Relative `/api/runs` already hits the Chat
//! loopback SSO proxy (`is_chat_run_sse_path`). The inject script still patches
//! `window.fetch` so GET event-stream / GET `/api/runs/{uuid}` (relative or
//! absolute) is rewritten to [`STUDIO_AGUI_PATH`] with the native jar. POST
//! `/api/agent/*` stays JSON through the SSO proxy.

use axum::http::HeaderMap;

use crate::config::StudioConfig;
use crate::proxy::Proxy;

/// Studio-owned GET `/api/runs/{uuid}` SSE streamer on the Chat loopback port.
pub const STUDIO_AGUI_PATH: &str = "/api/studio/ag-ui";
pub const STUDIO_INJECT_JS_PATH: &str = "/api/studio/ag-ui-inject.js";

/// Marker attribute tests look for on injected Chat HTML.
pub const INJECT_MARKER: &str = "data-studio-agui-inject";
pub const INJECT_SCRIPT_ID: &str = "studio-agui-inject";

/// Patch `window.fetch`: GET event-stream or GET `/api/runs/{uuid}` → streamer.
/// POST `/api/agent/*` is not rewritten. Production uses `fetch` + `getReader()`,
/// not `EventSource`.
pub const INJECT_JS: &str = r#"(function(){
  if (window.__STUDIO_AGUI_INJECT__) return;
  window.__STUDIO_AGUI_INJECT__ = true;
  try { document.documentElement.setAttribute("data-studio-agui-inject","1"); } catch (e) {}
  var EP = location.origin + "/api/studio/ag-ui";
  function headerOf(h, name) {
    name = String(name).toLowerCase();
    if (!h) return "";
    try {
      if (typeof Headers !== "undefined" && h instanceof Headers) {
        return h.get(name) || "";
      }
    } catch (e) {}
    if (typeof h.get === "function") {
      try { return h.get(name) || ""; } catch (e) {}
    }
    if (typeof h === "object") {
      for (var k in h) {
        if (Object.prototype.hasOwnProperty.call(h, k) && String(k).toLowerCase() === name) {
          return String(h[k]);
        }
      }
    }
    return "";
  }
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
  function wantsEventStream(init, req) {
    var a = "";
    if (init) a = headerOf(init.headers, "accept");
    if (!a && req) a = headerOf(req.headers, "accept");
    return String(a).toLowerCase().indexOf("text/event-stream") >= 0;
  }
  function isGetRunSse(url, init, req) {
    var method = (init && init.method) || (req && req.method) || "GET";
    if (String(method).toUpperCase() !== "GET") return false;
    try {
      var parsed = new URL(url, location.href);
      if (isStudioAgui(parsed.pathname)) return false;
      return wantsEventStream(init, req) || isRunSsePath(parsed.pathname);
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

/// Mirrors the inject `window.fetch` patch: rewrite GET event-stream or GET
/// `/api/runs/{uuid}` to [`STUDIO_AGUI_PATH`]. POST `/api/agent/*` is never
/// classified as the AG-UI stream (JSON 202).
pub fn inject_rewrites_fetch(method: &str, url: &str, accept: Option<&str>) -> bool {
    if !method.eq_ignore_ascii_case("GET") {
        return false;
    }
    let path = fetch_url_path_and_query(url);
    let path_only = path.split('?').next().unwrap_or(path.as_str());
    if path_only == STUDIO_AGUI_PATH || path_only.starts_with(&format!("{STUDIO_AGUI_PATH}/")) {
        return false;
    }
    let wants_sse = accept
        .unwrap_or("")
        .to_ascii_lowercase()
        .contains("text/event-stream");
    wants_sse || is_chat_run_sse_path(&path)
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

pub fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 3);
    for b in s.as_bytes() {
        match *b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(*b as char);
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

pub fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Some(slice) = std::str::from_utf8(&bytes[i + 1..i + 3]).ok() {
                if let Ok(v) = u8::from_str_radix(slice, 16) {
                    out.push(v);
                    i += 3;
                    continue;
                }
            }
        }
        if bytes[i] == b'+' {
            out.push(b' ');
            i += 1;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inject_marks_html_and_is_idempotent() {
        let html = "<!doctype html><html><head><title>chat</title></head><body>ok</body></html>";
        let once = inject_chat_html(html);
        assert!(once.contains(INJECT_MARKER));
        assert!(once.contains(INJECT_SCRIPT_ID));
        assert!(once.contains("/api/studio/ag-ui-inject.js"));
        let head = once.split("</head>").next().unwrap();
        assert!(head.contains(INJECT_MARKER));
        let twice = inject_chat_html(&once);
        assert_eq!(
            twice.matches(&format!("id=\"{INJECT_SCRIPT_ID}\"")).count(),
            1
        );
        assert!(INJECT_JS.contains("__STUDIO_AGUI_INJECT__"));
        assert!(INJECT_JS.contains("window.fetch"));
        assert!(INJECT_JS.contains("X-Studio-Agui-Url"));
        assert!(INJECT_JS.contains("text/event-stream"));
        assert!(INJECT_JS.contains("isRunSsePath"));
        assert!(INJECT_JS.contains("isGetRunSse"));
        assert!(INJECT_JS.contains("?to="));
        assert!(INJECT_JS.contains("encodeURIComponent"));
        assert!(INJECT_JS.contains("api\\/runs\\/"));
        assert!(INJECT_JS.contains("toUpperCase() !== \"GET\""));
        assert!(!INJECT_JS.contains("isAbsoluteRunSse"));
        assert!(!INJECT_JS.contains("EventSource"));
        assert!(!INJECT_JS.contains("vnd.ag-ui"));
        assert!(!INJECT_JS.contains("HttpAgent"));
        assert!(!INJECT_JS.contains("copilotkit"));
        assert!(!INJECT_JS.contains("parsed.origin === location.origin"));
    }

    #[test]
    fn does_not_rewrite_quoted_origin_or_invent_copilotkit() {
        let html = r#"<html><head></head><body>
<script>new HttpAgent({ url: "https://chat.mcpwork.space/api/copilotkit" });</script>
<script>fetch("/api/agent/game",{method:"POST",headers:{"content-type":"application/json"}});</script>
<script>fetch("/api/runs/30289690-b756-416a-ac0d-5bc9a3396ef7?since=0",{headers:{accept:"text/event-stream"}});</script>
<img src="https://chat.mcpwork.space/logo.png">
</body></html>"#;
        let out = inject_chat_html(html);
        assert!(out.contains(INJECT_MARKER));
        assert!(
            out.contains(r#"url: "https://chat.mcpwork.space/api/copilotkit""#),
            "must not invent HttpAgent URL rewrites: {out}"
        );
        assert!(
            out.contains(r#"/api/agent/game"#),
            "relative POST /api/agent stays: {out}"
        );
        assert!(
            out.contains(r#"/api/runs/30289690-b756-416a-ac0d-5bc9a3396ef7?since=0"#),
            "relative GET /api/runs stays: {out}"
        );
        assert!(
            !out.contains("/api/studio/ag-ui?to="),
            "HTML must not rewrite quoted URLs: {out}"
        );
    }

    #[test]
    fn run_sse_path_matches_live_chat_contract() {
        assert!(is_chat_run_sse_path(
            "/api/runs/30289690-b756-416a-ac0d-5bc9a3396ef7"
        ));
        assert!(is_chat_run_sse_path(
            "/api/runs/30289690-b756-416a-ac0d-5bc9a3396ef7?since=0"
        ));
        assert!(!is_chat_run_sse_path("/api/runs"));
        assert!(!is_chat_run_sse_path("/api/runs/"));
        assert!(!is_chat_run_sse_path(
            "/api/runs/30289690-b756-416a-ac0d-5bc9a3396ef7/cancel"
        ));
        assert!(!is_chat_run_sse_path(
            "/api/runs/30289690-b756-416a-ac0d-5bc9a3396ef7/scouts/abc"
        ));
        assert!(!is_chat_run_sse_path("/api/agent/game"));
        assert!(!is_chat_run_sse_path("/api/copilotkit"));
        assert!(!is_chat_run_sse_path("/agent"));
        assert!(!is_chat_run_sse_path("/api/threads"));
    }

    #[test]
    fn fetch_get_runs_sse_is_rewritten_post_agent_is_not() {
        let run = "/api/runs/30289690-b756-416a-ac0d-5bc9a3396ef7?since=0";
        assert!(
            inject_rewrites_fetch("GET", run, Some("text/event-stream")),
            "production Chat: fetch GET /api/runs SSE"
        );
        assert!(
            inject_rewrites_fetch("GET", run, None),
            "GET /api/runs/{{uuid}} is the run stream even without Accept"
        );
        assert!(inject_rewrites_fetch(
            "GET",
            "https://chat.mcpwork.space/api/runs/30289690-b756-416a-ac0d-5bc9a3396ef7?since=0",
            Some("text/event-stream")
        ));
        assert!(inject_rewrites_fetch(
            "GET",
            "/api/threads/1de8f6f0-b0c5-4903-8a7b-15aaae852f62/runs",
            Some("text/event-stream")
        ));
        assert!(!inject_rewrites_fetch(
            "POST",
            "/api/agent/game",
            Some("text/event-stream")
        ));
        assert!(!inject_rewrites_fetch(
            "POST",
            "/api/agent/game",
            Some("application/json")
        ));
        assert!(!inject_rewrites_fetch(
            "POST",
            "/api/runs/30289690-b756-416a-ac0d-5bc9a3396ef7/cancel",
            Some("application/json")
        ));
        assert!(!inject_rewrites_fetch(
            "GET",
            "/api/studio/ag-ui?to=/api/runs/30289690-b756-416a-ac0d-5bc9a3396ef7?since=0",
            Some("text/event-stream")
        ));
        assert!(!inject_rewrites_fetch(
            "GET",
            "/api/threads/1de8f6f0-b0c5-4903-8a7b-15aaae852f62/runs",
            Some("application/json")
        ));
    }

    #[test]
    fn streamer_only_forwards_run_sse_on_chat_origin() {
        let origin = "https://chat.mcpwork.space";
        let run = "/api/runs/30289690-b756-416a-ac0d-5bc9a3396ef7?since=0";
        assert_eq!(sanitize_agui_target(run, origin).as_deref(), Some(run));
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-studio-agui-url",
            axum::http::HeaderValue::from_static(
                "https://chat.mcpwork.space/api/runs/30289690-b756-416a-ac0d-5bc9a3396ef7?since=0",
            ),
        );
        assert_eq!(
            agui_upstream_path(&headers, None, origin).as_deref(),
            Some(run)
        );
        headers.insert(
            "x-studio-agui-url",
            axum::http::HeaderValue::from_static("https://chat.mcpwork.space/api/copilotkit"),
        );
        assert!(
            agui_upstream_path(&headers, None, origin).is_none(),
            "must not forward invented CopilotKit path"
        );
        headers.insert(
            "x-studio-agui-url",
            axum::http::HeaderValue::from_static("https://chat.mcpwork.space/api/agent/game"),
        );
        assert!(
            agui_upstream_path(&headers, None, origin).is_none(),
            "POST /api/agent is JSON 202, not the SSE streamer"
        );
        assert!(agui_upstream_path(&HeaderMap::new(), Some("to=/agent"), origin).is_none());
        assert_eq!(
            agui_upstream_path(
                &HeaderMap::new(),
                Some("to=/api/runs/30289690-b756-416a-ac0d-5bc9a3396ef7?since=0"),
                origin
            )
            .as_deref(),
            Some(run)
        );
        assert!(sanitize_agui_target(STUDIO_AGUI_PATH, origin).is_none());
        assert!(sanitize_agui_target("https://evil.example/x", origin).is_none());
        assert!(sanitize_agui_target("/ok/../secret", origin).is_none());
        assert_eq!(
            percent_decode(&percent_encode(
                "/api/runs/30289690-b756-416a-ac0d-5bc9a3396ef7?since=0"
            )),
            "/api/runs/30289690-b756-416a-ac0d-5bc9a3396ef7?since=0"
        );
    }
}
