//! Official Authentik Flow Executor — same API the browser `/if/flow/` UI uses.
//!
//! Docs: <https://api.goauthentik.io/flow-executor>
//!
//! Expected stages: identification → password. This Authentik does not use
//! TOTP. The desk never prompts for a second factor, never generates a code,
//! and never stores a TOTP seed. Authenticator stages are a misconfiguration.
//!
//! One `reqwest` cookie jar for the whole hop chain. If cookies are dropped,
//! Authentik starts a new flow plan and the first challenge comes back again.

use std::sync::Arc;
use std::time::Duration;

use reqwest::cookie::Jar;
use reqwest::StatusCode;
use serde_json::{json, Value};

use crate::config::StudioConfig;
use crate::session::{build_client, Session};

const EXECUTOR_TIMEOUT: Duration = Duration::from_secs(20);

#[derive(Default)]
struct PostedStages {
    identification: bool,
    password: bool,
}

#[derive(Debug)]
enum StageMove {
    Post(Value),
    Redirect { to: Option<String> },
}

pub async fn login_with_password(
    cfg: &StudioConfig,
    slug: &str,
    username: &str,
    password: &str,
) -> Result<Session, String> {
    let jar = Arc::new(Jar::default());
    let client = build_client(jar.clone())?;
    let url = cfg.executor_url();
    // Official `query` param: keep this exact string on every GET/POST of the flow.
    let next = format!("next=/stand/{slug}/");

    let mut challenge = executor_get(&client, &url, &next).await?;
    let mut posted = PostedStages::default();
    for _ in 0..8 {
        match decide_stage(&challenge, username, password, &posted, &cfg.flow_slug)? {
            StageMove::Post(body) => {
                mark_posted(&mut posted, &body);
                challenge = executor_post(&client, &url, &next, body).await?;
            }
            StageMove::Redirect { to } => {
                follow_flow_redirect(&client, cfg, to.as_deref()).await;
                let who = verify_authentik_user(&client, cfg).await?;
                // Cheap stand GET so the outpost cookie lands. Chat/S3 settle is
                // background work after login returns JSON.
                settle_stand_cookie(&client, cfg, slug).await?;
                return Ok(Session {
                    slug: slug.to_string(),
                    username: who,
                    client,
                    jar,
                });
            }
        }
    }
    Err("Authentik: слишком много стадий".into())
}

/// Rebuild a Session from a persisted jar if Authentik still knows it.
pub async fn resume_from_jar(
    cfg: &StudioConfig,
    slug: &str,
    jar: Arc<Jar>,
) -> Result<Session, String> {
    let client = build_client(jar.clone())?;
    let who = verify_authentik_user_timed(&client, cfg, cfg.probe_timeout).await?;
    Ok(Session {
        slug: slug.to_string(),
        username: who,
        client,
        jar,
    })
}

/// Check `response_errors` / deny / restart **before** posting again.
fn decide_stage(
    challenge: &Value,
    username: &str,
    password: &str,
    posted: &PostedStages,
    flow_slug: &str,
) -> Result<StageMove, String> {
    if let Some(msg) = response_error_message(challenge) {
        return Err(msg);
    }
    let component = challenge
        .get("component")
        .and_then(Value::as_str)
        .unwrap_or("");
    match component {
        "ak-stage-identification" => {
            if posted.identification {
                return Err(
                    "Authentik flow начался заново — cookie jar не сохранился между запросами"
                        .into(),
                );
            }
            let mut body = json!({
                "component": "ak-stage-identification",
                "uid_field": username,
            });
            if challenge
                .get("password_fields")
                .and_then(Value::as_bool)
                .unwrap_or(false)
            {
                body["password"] = Value::String(password.to_string());
            }
            Ok(StageMove::Post(body))
        }
        "ak-stage-password" => {
            if posted.password {
                return Err("Authentik: password: неверный пароль".into());
            }
            Ok(StageMove::Post(json!({
                "component": "ak-stage-password",
                "password": password,
            })))
        }
        "ak-stage-access-denied" => Err(access_denied_message(challenge)),
        "xak-flow-redirect" => Ok(StageMove::Redirect {
            to: challenge
                .get("to")
                .and_then(Value::as_str)
                .map(str::to_string),
        }),
        "" => {
            if let Some(detail) = challenge.get("detail").and_then(Value::as_str) {
                Err(format!("Authentik: {detail}"))
            } else {
                Err("Authentik вернул пустой challenge".into())
            }
        }
        other if is_forbidden_totp_stage(other) => Err(totp_forbidden(other)),
        other => Err(format!(
            "неподдерживаемая стадия Authentik `{other}`. В браузере это /if/flow/{flow_slug}/"
        )),
    }
}

fn mark_posted(posted: &mut PostedStages, body: &Value) {
    match body.get("component").and_then(Value::as_str) {
        Some("ak-stage-identification") => posted.identification = true,
        Some("ak-stage-password") => posted.password = true,
        _ => {}
    }
}

fn is_forbidden_totp_stage(component: &str) -> bool {
    let c = component.to_ascii_lowercase();
    c.contains("authenticator-validate") || c.contains("authenticator-totp") || c.contains("totp")
}

/// Never prompt, never generate a code, never persist a TOTP seed.
fn totp_forbidden(component: &str) -> String {
    format!(
        "неподдерживаемая стадия Authentik `{component}`. Вход только логин и пароль."
    )
}

fn access_denied_message(challenge: &Value) -> String {
    let extra = challenge
        .get("error_message")
        .or_else(|| challenge.get("error"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty());
    match extra {
        Some(msg) => format!("Authentik отказал во входе (access denied): {msg}"),
        None => "Authentik отказал во входе (access denied)".into(),
    }
}

async fn executor_get(client: &reqwest::Client, url: &str, query: &str) -> Result<Value, String> {
    let res = client
        .get(format!("{url}?query={}", urlencoding_query(query)))
        .header("Accept", "application/json")
        .timeout(EXECUTOR_TIMEOUT)
        .send()
        .await
        .map_err(|err| err.to_string())?;
    json_or_err(res).await
}

async fn executor_post(
    client: &reqwest::Client,
    url: &str,
    query: &str,
    body: Value,
) -> Result<Value, String> {
    let res = client
        .post(format!("{url}?query={}", urlencoding_query(query)))
        .header("Accept", "application/json")
        .header("Content-Type", "application/json")
        .json(&body)
        .timeout(EXECUTOR_TIMEOUT)
        .send()
        .await
        .map_err(|err| err.to_string())?;
    json_or_err(res).await
}

async fn json_or_err(res: reqwest::Response) -> Result<Value, String> {
    let status = res.status();
    let text = res.text().await.map_err(|err| err.to_string())?;
    if text.is_empty() {
        return Err(format!(
            "Authentik пустой ответ ({status}). Обычно это 302, который не проследовали — клиент должен ходить с cookie jar и follow redirect."
        ));
    }
    serde_json::from_str(&text).map_err(|_| {
        if status.is_success() {
            format!("Authentik: не JSON ({status})")
        } else {
            format!("Authentik {status}: {text}")
        }
    })
}

/// Official success: `xak-flow-redirect.to` is where the browser would go next.
async fn follow_flow_redirect(client: &reqwest::Client, cfg: &StudioConfig, to: Option<&str>) {
    let Some(url) = resolve_flow_redirect(cfg, to) else {
        return;
    };
    let _ = client
        .get(&url)
        .header("Accept", "text/html,application/json")
        .timeout(EXECUTOR_TIMEOUT)
        .send()
        .await;
}

pub fn resolve_flow_redirect(cfg: &StudioConfig, to: Option<&str>) -> Option<String> {
    let to = to.map(str::trim).filter(|s| !s.is_empty())?;
    if to.starts_with("https://") || to.starts_with("http://") {
        return Some(to.to_string());
    }
    if to.starts_with("/stand/") {
        return Some(format!("{}{to}", cfg.stand_origin()));
    }
    Some(format!(
        "{}{}",
        cfg.auth_origin(),
        if to.starts_with('/') {
            to.to_string()
        } else {
            format!("/{to}")
        }
    ))
}

/// Completing the flow is not enough without User Login stage — `/core/users/me/` proves it.
/// Authentik wraps the user: `{ "user": { "username": "…" } }`.
async fn verify_authentik_user(
    client: &reqwest::Client,
    cfg: &StudioConfig,
) -> Result<String, String> {
    verify_authentik_user_timed(client, cfg, EXECUTOR_TIMEOUT).await
}

async fn verify_authentik_user_timed(
    client: &reqwest::Client,
    cfg: &StudioConfig,
    timeout: Duration,
) -> Result<String, String> {
    let res = client
        .get(cfg.whoami_url())
        .header("Accept", "application/json")
        .timeout(timeout)
        .send()
        .await
        .map_err(|err| format!("Authentik /users/me: {err}"))?;
    if res.status() == StatusCode::UNAUTHORIZED || res.status() == StatusCode::FORBIDDEN {
        return Err(
            "flow завершился, но сессия анонимная (нет User Login stage или cookie не сели)".into(),
        );
    }
    if !res.status().is_success() {
        return Err(format!("Authentik /users/me: {}", res.status()));
    }
    let body: Value = res.json().await.map_err(|err| err.to_string())?;
    username_from_me(&body)
}

pub fn username_from_me(body: &Value) -> Result<String, String> {
    let user = body.get("user").unwrap_or(body);
    if user.get("is_active").and_then(Value::as_bool) == Some(false) {
        return Err("Authentik: пользователь отключён".into());
    }
    let name = user
        .get("username")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| "Authentik /users/me: нет username".to_string())?;
    if name.eq_ignore_ascii_case("anonymoususer") || name.eq_ignore_ascii_case("anonymous") {
        return Err(
            "flow завершился, но сессия анонимная (нет User Login stage или cookie не сели)".into(),
        );
    }
    Ok(name.to_string())
}

/// Outpost cookie lives on my.mcpwork.space, Authentik session on auth.mcpwork.space.
/// One GET of the stand (with follow-redirect) lets the proxy-cookie land in the same jar.
async fn settle_stand_cookie(
    client: &reqwest::Client,
    cfg: &StudioConfig,
    slug: &str,
) -> Result<(), String> {
    let url = format!(
        "{}{}",
        cfg.stand_origin(),
        crate::stand::stand_root_path(slug)
    );
    let res = client
        .get(&url)
        .header("Accept", "text/html,application/json")
        .timeout(EXECUTOR_TIMEOUT)
        .send()
        .await
        .map_err(|err| format!("стенд после логина: {err}"))?;
    if res.status() == StatusCode::UNAUTHORIZED || res.status() == StatusCode::FORBIDDEN {
        return Err("Authentik пустил, стенд отказал (outpost / группа не совпала со slug)".into());
    }
    if !cfg.url_host_is_stand(res.url()) {
        return Err("Authentik пустил, стенд отправил на логин (outpost cookie не сел)".into());
    }
    Ok(())
}

pub fn response_error_message(challenge: &Value) -> Option<String> {
    let errors = challenge.get("response_errors")?;
    if errors.is_null() {
        return None;
    }
    let obj = errors.as_object()?;
    if obj.is_empty() {
        return None;
    }
    let mut parts = Vec::new();
    for (field, list) in obj {
        let text = error_string(list).unwrap_or("ошибка");
        parts.push(format!("{field}: {}", localize_ak_error(text)));
    }
    Some(format!("Authentik: {}", parts.join("; ")))
}

fn error_string(list: &Value) -> Option<&str> {
    if let Some(s) = list.as_str() {
        return Some(s);
    }
    list.as_array()
        .and_then(|rows| rows.first())
        .and_then(|row| {
            row.get("string")
                .and_then(Value::as_str)
                .or_else(|| row.as_str())
        })
}

fn localize_ak_error(text: &str) -> String {
    match text {
        "Invalid password" => "неверный пароль".into(),
        "Failed to authenticate" => "не удалось аутентифицироваться".into(),
        other => other.to_string(),
    }
}

pub fn urlencoding_query(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len() + 8);
    for byte in raw.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char)
            }
            other => out.push_str(&format!("%{other:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn cfg() -> StudioConfig {
        StudioConfig::production(PathBuf::from("ui"), 18765, None)
    }

    fn posted() -> PostedStages {
        PostedStages::default()
    }

    const FLOW: &str = "default-authentication-flow";

    #[test]
    fn next_query_is_form_encoded_and_stable() {
        let q = "next=/stand/x/";
        assert_eq!(urlencoding_query(q), "next%3D%2Fstand%2Fx%2F");
        assert_eq!(urlencoding_query(q), urlencoding_query(q));
    }

    #[test]
    fn invalid_password_is_read_before_reposting() {
        let challenge = json!({
            "component": "ak-stage-password",
            "response_errors": {
                "password": [{ "string": "Invalid password", "code": "invalid" }]
            }
        });
        assert_eq!(
            response_error_message(&challenge).as_deref(),
            Some("Authentik: password: неверный пароль")
        );
        let err = decide_stage(&challenge, "akadmin", "bad", &posted(), FLOW).unwrap_err();
        assert_eq!(err, "Authentik: password: неверный пароль");
    }

    #[test]
    fn password_stage_is_not_reposted_without_errors() {
        let challenge = json!({ "component": "ak-stage-password" });
        let mut seen = posted();
        seen.password = true;
        let err = decide_stage(&challenge, "u", "p", &seen, FLOW).unwrap_err();
        assert!(err.contains("неверный пароль"));
        assert!(matches!(
            decide_stage(&challenge, "u", "p", &posted(), FLOW).unwrap(),
            StageMove::Post(_)
        ));
    }

    #[test]
    fn identification_again_means_cookie_jar_was_dropped() {
        let challenge = json!({ "component": "ak-stage-identification" });
        let mut seen = posted();
        seen.identification = true;
        let err = decide_stage(&challenge, "u", "p", &seen, FLOW).unwrap_err();
        assert!(err.contains("cookie jar"));
    }

    #[test]
    fn deny_stage_stops_before_any_post() {
        let challenge = json!({
            "component": "ak-stage-access-denied",
            "error_message": "nope"
        });
        let err = decide_stage(&challenge, "u", "p", &posted(), FLOW).unwrap_err();
        assert!(err.contains("access denied"));
        assert!(err.contains("nope"));
    }

    #[test]
    fn empty_response_errors_are_ignored() {
        let challenge = json!({
            "component": "ak-stage-password",
            "response_errors": {}
        });
        assert!(response_error_message(&challenge).is_none());
    }

    #[test]
    fn redirect_to_stand_path_uses_stand_origin() {
        let c = cfg();
        assert_eq!(
            resolve_flow_redirect(&c, Some("/stand/neweditor/")),
            Some("https://my.mcpwork.space/stand/neweditor/".into())
        );
        assert_eq!(
            resolve_flow_redirect(&c, Some("/if/flow/default-authentication-flow/")),
            Some("https://auth.mcpwork.space/if/flow/default-authentication-flow/".into())
        );
        assert_eq!(
            resolve_flow_redirect(
                &c,
                Some("https://my.mcpwork.space/outpost.goauthentik.io/callback")
            ),
            Some("https://my.mcpwork.space/outpost.goauthentik.io/callback".into())
        );
    }

    #[test]
    fn authenticator_validate_is_a_clear_error_without_posting() {
        let challenge = json!({
            "component": "ak-stage-authenticator-validate",
            "device_challenges": [{ "device_class": "totp" }]
        });
        let err = decide_stage(&challenge, "u", "p", &posted(), FLOW).unwrap_err();
        assert!(err.contains("неподдерживаемая стадия"));
        assert!(err.contains("логин и пароль"));
        assert!(err.contains("ak-stage-authenticator-validate"));
        assert!(!err.contains("введите код"));
        assert!(!err.contains("auth.mcpwork.space"));
        assert!(matches!(
            decide_stage(&challenge, "u", "p", &posted(), FLOW),
            Err(_)
        ));
    }

    #[test]
    fn totp_enroll_errors_without_leaking_seed() {
        let challenge = json!({
            "component": "ak-stage-authenticator-totp",
            "config_url": "otpauth://totp/Authentik:akadmin?secret=JBSWY3DPEHPK3PXP",
            "secret_key": "JBSWY3DPEHPK3PXP"
        });
        let err = decide_stage(&challenge, "u", "p", &posted(), FLOW).unwrap_err();
        assert!(err.contains("неподдерживаемая стадия"));
        assert!(err.contains("ak-stage-authenticator-totp"));
        assert!(!err.contains("auth.mcpwork.space"));
        assert!(!err.contains("JBSWY3DPEHPK3PXP"));
        assert!(!err.contains("otpauth"));
        assert!(!err.contains("завести TOTP"));
        assert!(!err.contains("введите код"));
    }

    #[test]
    fn whoami_reads_nested_authentik_user() {
        let body = json!({
            "user": { "pk": 17, "username": "akadmin", "is_active": true }
        });
        assert_eq!(username_from_me(&body).unwrap(), "akadmin");
        assert!(username_from_me(&json!({ "user": { "username": "AnonymousUser" } })).is_err());
        assert!(username_from_me(&json!({ "username": "akadmin" })).is_ok());
        assert!(
            username_from_me(&json!({ "user": { "username": "x", "is_active": false } })).is_err()
        );
        assert!(username_from_me(
            &json!({ "detail": "Authentication credentials were not provided." })
        )
        .is_err());
    }

    #[test]
    fn unsupported_stage_does_not_invent_a_post() {
        let challenge = json!({ "component": "ak-stage-captcha" });
        let err = decide_stage(&challenge, "u", "p", &posted(), FLOW).unwrap_err();
        assert!(err.contains("ak-stage-captcha"));
    }

    /// `DESIGNER_STUDIO_LIVE_PASSWORD` — never hardcode secrets.
    #[test]
    fn live_login_if_env_set() {
        let Ok(password) = std::env::var("DESIGNER_STUDIO_LIVE_PASSWORD") else {
            return;
        };
        if password.is_empty() {
            return;
        }
        let username =
            std::env::var("DESIGNER_STUDIO_LIVE_USER").unwrap_or_else(|_| "akadmin".into());
        let slug =
            std::env::var("DESIGNER_STUDIO_LIVE_SLUG").unwrap_or_else(|_| "neweditor".into());
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let session = login_with_password(&cfg(), &slug, &username, &password)
                .await
                .expect("live Authentik login");
            assert_eq!(session.username, username);
            assert_eq!(session.slug, slug);
        });
    }
}
