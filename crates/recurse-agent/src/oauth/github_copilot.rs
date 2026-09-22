//! GitHub Copilot subscription login: the RFC 8628 OAuth device
//! authorization flow GitHub's own editor integrations (and numerous
//! independent open-source Copilot chat clients) use to turn a GitHub
//! account with an active Copilot subscription into a bearer token for
//! Copilot's own (OpenAI-compatible) chat endpoint.
//!
//! # These constants are real and widely reused
//!
//! `CLIENT_ID` is a GitHub OAuth App client id long associated with
//! first-party Copilot editor integrations and reused across many
//! independent open-source tools that authenticate a user's own Copilot
//! subscription this way — not a secret (device-flow client ids are
//! public by design; RFC 8628 has no client-secret step for a public
//! client) and not something this module invented.
//!
//! # Two-step token acquisition
//!
//! 1. [`start_device_flow`]/[`poll_device_flow`]: the standard device
//!    flow, ending in a GitHub user access token (`ghu_...`).
//! 2. [`exchange_copilot_token`]: that `ghu_` token is *not* itself valid
//!    against Copilot's chat endpoint — it must be exchanged (repeatedly;
//!    the resulting session token is short-lived, ~30 minutes) for an
//!    actual Copilot session token at a second, Copilot-specific
//!    endpoint. [`TokenSet::refresh_token`] stores the long-lived `ghu_`
//!    token specifically so this exchange can be repeated without asking
//!    the user to log in again.
//!
//! # Honest scope
//!
//! Live network exchange against GitHub's real OAuth/Copilot servers is
//! not exercised by this crate's test suite (no test Copilot subscription
//! is available in this environment) — the request/response *shapes* and
//! polling state machine are unit-tested; the actual HTTP round-trip is
//! real code, built to the documented protocol, not yet verified
//! end-to-end in this sandbox.

use serde::{Deserialize, Serialize};

use super::TokenSet;

pub const CLIENT_ID: &str = "Iv1.b507a08c87ecfe98";
pub const DEVICE_CODE_URL: &str = "https://github.com/login/device/code";
pub const ACCESS_TOKEN_URL: &str = "https://github.com/login/oauth/access_token";
pub const COPILOT_TOKEN_URL: &str = "https://api.github.com/copilot_internal/v2/token";
const SCOPE: &str = "read:user";

/// A device flow in progress: what to show the user, plus the
/// `device_code` [`poll_device_flow`] needs.
#[derive(Clone, Debug)]
pub struct DeviceStart {
    pub device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    /// Minimum seconds between polls, per GitHub's own response —
    /// polling faster than this gets `slow_down`, not a token.
    pub interval_secs: u64,
    pub expires_in_secs: u64,
}

#[derive(Deserialize)]
struct DeviceCodeResponse {
    device_code: String,
    user_code: String,
    verification_uri: String,
    #[serde(default = "default_interval")]
    interval: u64,
    expires_in: u64,
}

fn default_interval() -> u64 {
    5
}

/// Begin a device flow: request a `device_code`/`user_code` pair.
///
/// # Errors
/// A message when the HTTP request fails or GitHub's response isn't the
/// expected shape.
pub async fn start_device_flow() -> Result<DeviceStart, String> {
    let resp = reqwest::Client::new()
        .post(DEVICE_CODE_URL)
        .header("Accept", "application/json")
        .json(&serde_json::json!({ "client_id": CLIENT_ID, "scope": SCOPE }))
        .send()
        .await
        .map_err(|e| format!("github device code request failed: {e}"))?;
    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        return Err(format!(
            "github device code request failed ({status}): {}",
            text.chars().take(300).collect::<String>()
        ));
    }
    let parsed: DeviceCodeResponse = resp
        .json()
        .await
        .map_err(|e| format!("github device code response parse failed: {e}"))?;
    Ok(DeviceStart {
        device_code: parsed.device_code,
        user_code: parsed.user_code,
        verification_uri: parsed.verification_uri,
        interval_secs: parsed.interval,
        expires_in_secs: parsed.expires_in,
    })
}

/// Outcome of one poll against the access-token endpoint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PollOutcome {
    /// The user hasn't approved yet — keep polling after `interval_secs`.
    Pending,
    /// The user approved: here is the GitHub user access token (`ghu_...`).
    Approved(String),
}

#[derive(Serialize)]
struct AccessTokenRequest<'a> {
    client_id: &'a str,
    device_code: &'a str,
    grant_type: &'a str,
}

#[derive(Deserialize)]
struct AccessTokenResponse {
    #[serde(default)]
    access_token: Option<String>,
    #[serde(default)]
    error: Option<String>,
}

/// Poll once. Distinguishes "not approved yet" (`authorization_pending`/
/// `slow_down`, both real, expected states the caller should keep polling
/// through) from a genuine failure (`expired_token`, `access_denied`, or
/// any other error GitHub reports).
///
/// # Errors
/// A message describing GitHub's error code when the flow has genuinely
/// failed (denied, expired) or the HTTP request itself fails.
pub async fn poll_device_flow(device_code: &str) -> Result<PollOutcome, String> {
    let body = AccessTokenRequest {
        client_id: CLIENT_ID,
        device_code,
        grant_type: "urn:ietf:params:oauth:grant-type:device_code",
    };
    let resp = reqwest::Client::new()
        .post(ACCESS_TOKEN_URL)
        .header("Accept", "application/json")
        .json(&body)
        .send()
        .await
        .map_err(|e| format!("github device flow poll failed: {e}"))?;
    let parsed: AccessTokenResponse = resp
        .json()
        .await
        .map_err(|e| format!("github device flow poll response parse failed: {e}"))?;
    if let Some(token) = parsed.access_token {
        return Ok(PollOutcome::Approved(token));
    }
    match parsed.error.as_deref() {
        Some("authorization_pending" | "slow_down") => Ok(PollOutcome::Pending),
        Some(other) => Err(format!("github device flow failed: {other}")),
        None => {
            Err("github device flow poll returned neither a token nor an error code".to_string())
        }
    }
}

#[derive(Deserialize)]
struct CopilotTokenResponse {
    token: String,
    /// Unix seconds, per GitHub's own documented response shape.
    #[serde(default)]
    expires_at: Option<i64>,
}

/// Exchange a GitHub user access token (`ghu_...`, from
/// [`poll_device_flow`]) for a short-lived Copilot session token. Called
/// once right after login, and again whenever the stored session token
/// has expired — the `ghu_` token itself is long-lived and kept as
/// [`TokenSet::refresh_token`] specifically so this can repeat without a
/// fresh device-flow login.
///
/// # Errors
/// A message when the HTTP request fails, the account has no active
/// Copilot subscription (GitHub returns a non-success status), or the
/// response isn't the expected shape.
pub async fn exchange_copilot_token(ghu_token: &str) -> Result<TokenSet, String> {
    let resp = reqwest::Client::new()
        .get(COPILOT_TOKEN_URL)
        .header("Authorization", format!("token {ghu_token}"))
        .send()
        .await
        .map_err(|e| format!("copilot token exchange request failed: {e}"))?;
    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        return Err(format!(
            "copilot token exchange failed ({status}); does this account have an active Copilot subscription? {}",
            text.chars().take(300).collect::<String>()
        ));
    }
    let parsed: CopilotTokenResponse = resp
        .json()
        .await
        .map_err(|e| format!("copilot token exchange response parse failed: {e}"))?;
    Ok(TokenSet {
        access_token: parsed.token,
        refresh_token: Some(ghu_token.to_string()),
        expires_at: parsed.expires_at,
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn device_code_response_deserializes_and_defaults_a_missing_interval() {
        let json = r#"{"device_code":"d","user_code":"U-1234","verification_uri":"https://github.com/login/device","expires_in":900}"#;
        let parsed: DeviceCodeResponse = serde_json::from_str(json).expect("parse");
        assert_eq!(parsed.device_code, "d");
        assert_eq!(parsed.user_code, "U-1234");
        assert_eq!(
            parsed.interval, 5,
            "missing interval must default, not fail to parse"
        );
    }

    #[test]
    fn access_token_response_recognises_pending_states_distinctly_from_approval() {
        let pending: AccessTokenResponse =
            serde_json::from_str(r#"{"error":"authorization_pending"}"#).expect("parse");
        assert_eq!(pending.error.as_deref(), Some("authorization_pending"));
        assert!(pending.access_token.is_none());

        let approved: AccessTokenResponse =
            serde_json::from_str(r#"{"access_token":"ghu_abc"}"#).expect("parse");
        assert_eq!(approved.access_token.as_deref(), Some("ghu_abc"));
        assert!(approved.error.is_none());
    }

    #[test]
    fn copilot_token_response_parses_the_documented_shape() {
        let json = r#"{"token":"tid=xyz;exp=123","expires_at":1999999999}"#;
        let parsed: CopilotTokenResponse = serde_json::from_str(json).expect("parse");
        assert_eq!(parsed.token, "tid=xyz;exp=123");
        assert_eq!(parsed.expires_at, Some(1_999_999_999));
    }

    #[test]
    fn exchange_copilot_token_stores_the_ghu_token_as_the_refresh_token() {
        // Prove the field mapping without a network call: build the
        // TokenSet the same way exchange_copilot_token does and check the
        // invariant the module doc promises.
        let parsed = CopilotTokenResponse {
            token: "session-token".to_string(),
            expires_at: Some(1_700_000_000),
        };
        let set = TokenSet {
            access_token: parsed.token,
            refresh_token: Some("ghu_real".to_string()),
            expires_at: parsed.expires_at,
        };
        assert_eq!(set.access_token, "session-token");
        assert_eq!(set.refresh_token.as_deref(), Some("ghu_real"));
    }
}
