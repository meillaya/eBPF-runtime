// SPDX-License-Identifier: Apache-2.0 OR MIT
//! OIDC device flow authentication for the CLI (RFC 8628).
//!
//! Displays the verification URI + user code, then polls the
//! token endpoint with `slow_down` backoff until authorized,
//! expired, or denied.

use auth::device::{DeviceAuthorization, DeviceFlow, DeviceFlowState, TokenPollResponse};

use super::FleetContext;
use crate::exit_code::ExitCode;

/// Default client ID for the CLI.
const DEFAULT_CLIENT_ID: &str = "kernel-v1-cli";

/// Run the device flow login. Displays the verification URI
/// and user code, then polls until authorized.
pub async fn login(ctx: &FleetContext) -> ExitCode {
    eprintln!("Starting OIDC device flow authentication...");

    // Step 1: Request device authorization.
    let device_auth = match request_device_authorization(&ctx.api_base).await {
        Ok(auth) => auth,
        Err(e) => {
            eprintln!("Error: failed to start device flow: {e}");
            eprintln!("Suggestion: verify the control-plane is reachable at {}", ctx.api_base);
            return ExitCode::AuthFailure;
        }
    };

    // Step 2: Display verification instructions (non-interactive).
    eprintln!();
    eprintln!("To authenticate, visit:");
    eprintln!("  {}", device_auth.verification_uri);
    eprintln!();
    eprintln!("Enter code: {}", device_auth.user_code);
    eprintln!();
    if let Some(ref complete) = device_auth.verification_uri_complete {
        eprintln!("Or open: {complete}");
        eprintln!();
    }
    eprintln!("Waiting for authorization (expires in {}s)...", device_auth.expires_in_s);

    // Step 3: Poll the token endpoint using the DeviceFlow state machine.
    let mut flow = DeviceFlow::new();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    if let Err(e) = flow.start(device_auth, now) {
        eprintln!("Error: {e}");
        return ExitCode::AuthFailure;
    }

    poll_until_complete(&mut flow, &ctx.api_base).await
}

/// Poll the token endpoint until the flow completes.
async fn poll_until_complete(flow: &mut DeviceFlow, api_base: &str) -> ExitCode {
    let token_url = format!("{api_base}/oauth2/token");

    loop {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Check if we can still poll (handles expiry).
        let interval = match flow.poll(now) {
            Ok(interval) => interval,
            Err(e) => {
                eprintln!("Error: {e}");
                return ExitCode::AuthFailure;
            }
        };

        // Poll the token endpoint.
        let response = poll_token_endpoint(&token_url, flow).await;
        flow.handle_token_response(response);

        match flow.state() {
            DeviceFlowState::Authorized => {
                eprintln!("Authentication successful.");
                return ExitCode::Success;
            }
            DeviceFlowState::Expired => {
                eprintln!("Error: device code expired before authorization.");
                eprintln!("Suggestion: re-run `cli fleet login`");
                return ExitCode::AuthFailure;
            }
            DeviceFlowState::Denied => {
                eprintln!("Error: authorization denied by user.");
                return ExitCode::AuthFailure;
            }
            DeviceFlowState::Pending => {
                // Wait before next poll.
                tokio::time::sleep(std::time::Duration::from_secs(interval)).await;
            }
            _ => unreachable!(),
        }
    }
}

/// Request device authorization from the OIDC provider.
async fn request_device_authorization(
    api_base: &str,
) -> Result<DeviceAuthorization, String> {
    let url = format!("{api_base}/oauth2/device");
    let client = reqwest::Client::new();

    let resp = client
        .post(&url)
        .form(&[
            ("client_id", DEFAULT_CLIENT_ID),
            ("scope", "openid profile groups offline_access"),
        ])
        .send()
        .await
        .map_err(|e| format!("request to {url} failed: {e}"))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(format!("device authorization rejected ({status}): {body}"));
    }

    let body: DeviceAuthResponse = resp
        .json()
        .await
        .map_err(|e| format!("parsing device auth response: {e}"))?;

    Ok(DeviceAuthorization {
        device_code: body.device_code,
        user_code: body.user_code,
        verification_uri: body.verification_uri,
        verification_uri_complete: body.verification_uri_complete,
        expires_in_s: body.expires_in,
        interval_s: body.interval.unwrap_or(5),
    })
}

/// Poll the token endpoint once.
async fn poll_token_endpoint(token_url: &str, flow: &DeviceFlow) -> TokenPollResponse {
    let device_code = flow
        .authorization()
        .map(|a| a.device_code.as_str())
        .unwrap_or_default();

    let client = reqwest::Client::new();
    let resp = client
        .post(token_url)
        .form(&[
            ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
            ("device_code", device_code),
            ("client_id", DEFAULT_CLIENT_ID),
        ])
        .send()
        .await;

    match resp {
        Ok(r) if r.status().is_success() => TokenPollResponse::Authorized,
        Ok(r) => {
            // Parse OAuth2 error response.
            let body: TokenErrorResponse = r.json().await.unwrap_or(TokenErrorResponse {
                error: "authorization_pending".into(),
            });
            TokenPollResponse::from_error(&body.error)
        }
        Err(_) => TokenPollResponse::Pending,
    }
}

/// Device authorization response from the provider.
#[derive(Debug, serde::Deserialize)]
struct DeviceAuthResponse {
    device_code: String,
    user_code: String,
    verification_uri: String,
    verification_uri_complete: Option<String>,
    expires_in: u64,
    interval: Option<u64>,
}

/// Token endpoint error response.
#[derive(Debug, serde::Deserialize)]
struct TokenErrorResponse {
    error: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_auth_response_deserializes() {
        let json = r#"{
            "device_code": "abc123",
            "user_code": "WDJB-MJHT",
            "verification_uri": "https://auth.test/device",
            "verification_uri_complete": "https://auth.test/device?user_code=WDJB-MJHT",
            "expires_in": 1800,
            "interval": 5
        }"#;
        let resp: DeviceAuthResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.device_code, "abc123");
        assert_eq!(resp.user_code, "WDJB-MJHT");
        assert_eq!(resp.expires_in, 1800);
        assert_eq!(resp.interval, Some(5));
    }

    #[test]
    fn device_auth_response_optional_fields() {
        let json = r#"{
            "device_code": "abc123",
            "user_code": "WDJB-MJHT",
            "verification_uri": "https://auth.test/device",
            "expires_in": 1800
        }"#;
        let resp: DeviceAuthResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.verification_uri_complete, None);
        assert_eq!(resp.interval, None);
    }

    #[test]
    fn token_error_response_deserializes() {
        let json = r#"{"error": "slow_down"}"#;
        let resp: TokenErrorResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.error, "slow_down");
        assert_eq!(
            TokenPollResponse::from_error(&resp.error),
            TokenPollResponse::SlowDown
        );
    }

    #[test]
    fn default_client_id_is_set() {
        assert!(!DEFAULT_CLIENT_ID.is_empty());
    }
}
