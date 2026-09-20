//! Rust inject for Chat AG-UI (not Level / Sprites / Bestiary / S3).
//!
//! Chat HTML is rewritten so HttpAgent / `fetch` of `text/event-stream` hits the
//! studio-owned loopback streamer instead of the live origin (WebView cookies
//! are unused). The SSE body itself is never rewritten or cached.

use axum::http::HeaderMap;

use crate::config::StudioConfig;
use crate::proxy::Proxy;

/// Studio-owned AG-UI streamer on the Chat loopback port.
pub const STUDIO_AGUI_PATH: &str = "/api/studio/ag-ui";
pub const STUDIO_INJECT_JS_PATH: &str = "/api/studio/ag-ui-inject.js";

/// Marker attribute tests look for on injected Chat HTML.
pub const INJECT_MARKER: &str = "data-studio-agui-inject";
pub const INJECT_SCRIPT_ID: &str = "studio-agui-inject";

/// In-memory static inject script (also stored in [`crate::inject_cache::InjectCache`]).
pub const INJECT_JS: &str = r#"(function(){
  if (window.__STUDIO_AGUI_INJECT__) return;
  window.__STUDIO_AGUI_INJECT__ = true;
  try { document.documentElement.setAttribute("data-studio-agui-inject","1"); } catch (e) {}
  var EP = location.origin + "/api/studio/ag-ui";
  function acceptOf(h) {
    if (!h) return "";
    try {
      if (typeof Headers !== "undefined" && h instanceof Headers) {
        return h.get("accept") || "";
      }
    } catch (e) {}
    if (typeof h.get === "function") {
      try { return h.get("accept") || h.get("Accept") || ""; } catch (e) {}
    }
    if (typeof h === "object") {
      for (var k in h) {
        if (Object.prototype.hasOwnProperty.call(h, k) && String(k).toLowerCase() === "accept") {
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
  function isAgui(url, init, req) {
    var method = (init && init.method) || (req && req.method) || "GET";
    if (String(method).toUpperCase() !== "POST") return false;
    var a = "";
    var ct = "";
    if (init) {
      a = headerOf(init.headers, "accept");
      ct = headerOf(init.headers, "content-type");
    }
    if (req) {
      if (!a) a = headerOf(req.headers, "accept");
      if (!ct) ct = headerOf(req.headers, "content-type");
    }
    a = String(a).toLowerCase();
    ct = String(ct).toLowerCase();
    var sse = a.indexOf("text/event-stream") >= 0;
    var proto = a.indexOf("application/vnd.ag-ui.event+proto") >= 0
      || ct.indexOf("application/vnd.ag-ui.event+proto") >= 0;
    var json = ct.indexOf("application/json") >= 0;
    return (sse && json) || proto;
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
    if (!isAgui(url, init, req)) {
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
    if (!next.method) next.method = (req && req.method) || "POST";
    if (next.body == null && req && req.method !== "GET" && req.method !== "HEAD") {
      next.body = req.body;
      if (typeof ReadableStream !== "undefined" && next.body instanceof ReadableStream) {
        next.duplex = "half";
      }
    }
    if (req && req.signal && !next.signal) next.signal = req.signal;
    var dest = EP;
    try {
      var parsed = new URL(url, location.href);
      dest = EP + "?to=" + encodeURIComponent(parsed.pathname + parsed.search);
    } catch (e) {}
    return origFetch(dest, next);
  };
  var OrigES = window.EventSource;
  if (OrigES) {
    function StudioES(url, cfg) {
      var u = String(url);
      if (u.indexOf("/api/studio/ag-ui") < 0 && looksAguiUrl(u)) {
        u = EP + "?to=" + encodeURIComponent(u);
      }
      return new OrigES(u, cfg);
    }
    StudioES.prototype = OrigES.prototype;
    StudioES.CONNECTING = OrigES.CONNECTING;
    StudioES.OPEN = OrigES.OPEN;
    StudioES.CLOSED = OrigES.CLOSED;
    window.EventSource = StudioES;
  }
})();"#;

pub fn inject_snippet(script_src: &str) -> String {
    format!(r#"<script id="{INJECT_SCRIPT_ID}" src="{script_src}" {INJECT_MARKER}></script>"#)
}

/// Rewrite Chat HTML: HttpAgent origin URLs + inject `<script src>`. Idempotent.
pub fn inject_chat_html(html: &str, origin: &str) -> String {
    inject_agui_markup(
        &rewrite_http_agent_urls(html, origin),
        STUDIO_INJECT_JS_PATH,
    )
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

/// Quoted absolute Chat-origin URLs that are not static assets become the
/// studio streamer path (`/api/studio/ag-ui?to=…`).
pub fn rewrite_http_agent_urls(source: &str, origin: &str) -> String {
    let origin = origin.trim_end_matches('/');
    if origin.is_empty() || !source.contains(origin) {
        return source.to_string();
    }
    let mut out = String::with_capacity(source.len());
    let mut rest = source;
    while let Some(idx) = rest.find(origin) {
        out.push_str(&rest[..idx]);
        let before = if idx > 0 { rest.as_bytes()[idx - 1] } else { 0 };
        let after_origin = &rest[idx + origin.len()..];
        if before == b'"' || before == b'\'' {
            let quote = before as char;
            let path = take_quoted_path(after_origin, quote);
            if !is_static_asset(path) {
                let path = if path.is_empty() { "/" } else { path };
                out.push_str(STUDIO_AGUI_PATH);
                out.push_str("?to=");
                out.push_str(&percent_encode(path));
                rest = &after_origin[path.len()..];
                continue;
            }
        }
        out.push_str(origin);
        rest = after_origin;
    }
    out.push_str(rest);
    out
}

pub fn is_javascript_content_type(content_type: &str) -> bool {
    let ct = content_type.to_ascii_lowercase();
    ct.contains("javascript") || ct.contains("ecmascript")
}

pub fn is_html_content_type_str(content_type: &str) -> bool {
    content_type.to_ascii_lowercase().contains("text/html")
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
    sanitize_agui_target(&raw, chat_origin)
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

/// Origin path for `POST /api/studio/ag-ui?path=…`. Rejects loops and hosts.
pub fn sanitize_agui_path(raw: &str) -> String {
    let decoded = percent_decode(raw);
    sanitize_agui_target(&decoded, "http://127.0.0.1")
        .filter(|p| p.starts_with('/'))
        .unwrap_or_else(|| "/".into())
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

fn take_quoted_path(s: &str, quote: char) -> &str {
    let end = s.find(quote).unwrap_or(s.len());
    &s[..end]
}

fn is_static_asset(path: &str) -> bool {
    let p = path.split('?').next().unwrap_or(path).to_ascii_lowercase();
    p.ends_with(".js")
        || p.ends_with(".css")
        || p.ends_with(".map")
        || p.ends_with(".png")
        || p.ends_with(".jpg")
        || p.ends_with(".jpeg")
        || p.ends_with(".gif")
        || p.ends_with(".svg")
        || p.ends_with(".webp")
        || p.ends_with(".ico")
        || p.ends_with(".woff")
        || p.ends_with(".woff2")
        || p.ends_with(".ttf")
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
        let once = inject_chat_html(html, "https://chat.mcpwork.space");
        assert!(once.contains(INJECT_MARKER));
        assert!(once.contains(INJECT_SCRIPT_ID));
        assert!(once.contains("/api/studio/ag-ui-inject.js"));
        let head = once.split("</head>").next().unwrap();
        assert!(head.contains(INJECT_MARKER));
        let twice = inject_chat_html(&once, "https://chat.mcpwork.space");
        assert_eq!(twice.matches(&format!("id=\"{INJECT_SCRIPT_ID}\"")).count(), 1);
        assert!(INJECT_JS.contains("__STUDIO_AGUI_INJECT__"));
        assert!(INJECT_JS.contains("X-Studio-Agui-Url"));
        assert!(INJECT_JS.contains("text/event-stream"));
        assert!(INJECT_JS.contains("application/json"));
        assert!(!INJECT_JS.contains("looksAguiUrl"));
    }

    #[test]
    fn rewrites_quoted_httpagent_origin_url() {
        let html = r#"<html><head></head><body>
<script>new HttpAgent({ url: "https://chat.mcpwork.space/api/copilotkit" });</script>
<img src="https://chat.mcpwork.space/logo.png">
</body></html>"#;
        let out = inject_chat_html(html, "https://chat.mcpwork.space");
        assert!(out.contains("/api/studio/ag-ui?to="));
        assert!(out.contains(&percent_encode("/api/copilotkit")));
        assert!(
            !out.contains(r#"url: "https://chat.mcpwork.space/api/copilotkit""#),
            "HttpAgent url must be rewritten: {out}"
        );
        assert!(
            out.contains(r#"https://chat.mcpwork.space/logo.png"#),
            "static assets stay on origin: {out}"
        );
    }

    #[test]
    fn percent_roundtrip_for_path() {
        let path = "/api/copilotkit?x=1 y";
        assert_eq!(percent_decode(&percent_encode(path)), path);
        assert_eq!(
            sanitize_agui_target("/agent", "https://chat.mcpwork.space").as_deref(),
            Some("/agent")
        );
        assert!(
            sanitize_agui_target(STUDIO_AGUI_PATH, "https://chat.mcpwork.space").is_none(),
            "must not invent a default AG-UI path"
        );
        assert_eq!(sanitize_agui_path("%2Fagent"), "/agent");
        assert_eq!(sanitize_agui_path("/api/studio/ag-ui?path=/x"), "/agent");
        assert!(
            sanitize_agui_target("https://evil.example/x", "https://chat.mcpwork.space").is_none()
        );
        assert!(sanitize_agui_target("/ok/../secret", "https://chat.mcpwork.space").is_none());
    }
}
