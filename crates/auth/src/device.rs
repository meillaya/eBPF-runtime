// SPDX-License-Identifier: Apache-2.0 OR MIT
//! RFC 8628 device authorization flow state machine.
//!
//! Models the CLI authentication lifecycle:
//! `Idle → Pending → (SlowDown)* → Authorized / Expired /
//! Denied`.
//!
//! Polling respects `interval` and `slow_down` backoff. The
//! device code has a bounded expiry.

#![forbid(unsafe_code)]

use crate::error::{AuthError, AuthResult};

/// Device flow state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceFlowState {
    /// No device authorization started.
    Idle,
    /// Waiting for user to authorize at the verification URI.
    Pending,
    /// User authorized; token exchange ready.
    Authorized,
    /// Device code expired before user authorized.
    Expired,
    /// User explicitly denied the authorization.
    Denied,
}

impl std::fmt::Display for DeviceFlowState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            Self::Idle => "Idle",
            Self::Pending => "Pending",
            Self::Authorized => "Authorized",
            Self::Expired => "Expired",
            Self::Denied => "Denied",
        };
        f.write_str(name)
    }
}

/// The device authorization response from the provider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceAuthorization {
    pub device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    #[allow(dead_code)]
    pub verification_uri_complete: Option<String>,
    /// Lifetime of the device code in seconds.
    pub expires_in_s: u64,
    /// Minimum polling interval in seconds.
    pub interval_s: u64,
}

/// Device flow state machine with polling/backoff logic.
#[derive(Debug)]
pub struct DeviceFlow {
    state: DeviceFlowState,
    authorization: Option<DeviceAuthorization>,
    /// Current polling interval in seconds (grows on
    /// slow_down).
    current_interval_s: u64,
    /// Epoch seconds when the device code was issued.
    started_at_epoch_s: Option<u64>,
    /// Number of polling attempts made.
    poll_count: u32,
    /// Transition log for audit.
    transitions: Vec<String>,
}

impl DeviceFlow {
    /// Create a new device flow in the Idle state.
    pub fn new() -> Self {
        Self {
            state: DeviceFlowState::Idle,
            authorization: None,
            current_interval_s: 5,
            started_at_epoch_s: None,
            poll_count: 0,
            transitions: vec!["init: Idle".into()],
        }
    }

    /// Current state.
    pub fn state(&self) -> DeviceFlowState {
        self.state
    }

    /// Current polling interval in seconds.
    pub fn current_interval_s(&self) -> u64 {
        self.current_interval_s
    }

    /// Number of polling attempts.
    pub fn poll_count(&self) -> u32 {
        self.poll_count
    }

    /// The transition log.
    pub fn transitions(&self) -> &[String] {
        &self.transitions
    }

    /// The device authorization (if started).
    pub fn authorization(&self) -> Option<&DeviceAuthorization> {
        self.authorization.as_ref()
    }

    fn transition(&mut self, to: DeviceFlowState, reason: &str) {
        self.transitions
            .push(format!("{} -> {to}: {reason}", self.state));
        self.state = to;
    }

    /// Start the device flow with a device authorization
    /// response from the provider.
    pub fn start(&mut self, auth: DeviceAuthorization, now_epoch_s: u64) -> AuthResult<()> {
        if self.state != DeviceFlowState::Idle {
            return Err(AuthError::DeviceAuthorizationPending);
        }
        self.current_interval_s = auth.interval_s.max(1);
        self.started_at_epoch_s = Some(now_epoch_s);
        self.authorization = Some(auth);
        self.transition(DeviceFlowState::Pending, "device authorization started");
        Ok(())
    }

    /// Record a polling attempt. Returns the required wait
    /// interval. Enforces expiry.
    pub fn poll(&mut self, now_epoch_s: u64) -> AuthResult<u64> {
        if self.state != DeviceFlowState::Pending {
            return Err(match self.state {
                DeviceFlowState::Expired => AuthError::DeviceCodeExpired,
                DeviceFlowState::Denied => AuthError::DeviceAccessDenied,
                _ => AuthError::DeviceAuthorizationPending,
            });
        }

        // Check expiry.
        if let (Some(started), Some(auth)) = (self.started_at_epoch_s, &self.authorization) {
            if now_epoch_s >= started + auth.expires_in_s {
                self.transition(DeviceFlowState::Expired, "device code expired");
                return Err(AuthError::DeviceCodeExpired);
            }
        }

        self.poll_count += 1;
        Ok(self.current_interval_s)
    }

    /// Handle a token endpoint response during polling.
    pub fn handle_token_response(&mut self, response: TokenPollResponse) {
        match response {
            TokenPollResponse::Pending => {
                // Stay in Pending, no interval change.
            }
            TokenPollResponse::SlowDown => {
                // RFC 8628 §3.5: increase interval by 5 seconds.
                self.current_interval_s += 5;
                self.transitions.push(format!(
                    "slow_down: interval -> {}s",
                    self.current_interval_s
                ));
            }
            TokenPollResponse::Authorized => {
                self.transition(DeviceFlowState::Authorized, "user authorized");
            }
            TokenPollResponse::Expired => {
                self.transition(DeviceFlowState::Expired, "token endpoint: expired_token");
            }
            TokenPollResponse::Denied => {
                self.transition(DeviceFlowState::Denied, "token endpoint: access_denied");
            }
        }
    }
}

impl Default for DeviceFlow {
    fn default() -> Self {
        Self::new()
    }
}

/// The result of a single token endpoint poll.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenPollResponse {
    /// `authorization_pending` — keep polling.
    Pending,
    /// `slow_down` — increase interval by 5s.
    SlowDown,
    /// Success — token granted.
    Authorized,
    /// `expired_token` — device code expired.
    Expired,
    /// `access_denied` — user denied.
    Denied,
}

impl TokenPollResponse {
    /// Parse from an OAuth2 error string.
    pub fn from_error(error: &str) -> Self {
        match error {
            "authorization_pending" => Self::Pending,
            "slow_down" => Self::SlowDown,
            "expired_token" => Self::Expired,
            "access_denied" => Self::Denied,
            _ => Self::Denied,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_auth() -> DeviceAuthorization {
        DeviceAuthorization {
            device_code: "dev-code-123".into(),
            user_code: "WDJB-MJHT".into(),
            verification_uri: "https://dex.kernel-v1.test/device".into(),
            verification_uri_complete: Some(
                "https://dex.kernel-v1.test/device?user_code=WDJB-MJHT".into(),
            ),
            expires_in_s: 1800,
            interval_s: 5,
        }
    }

    #[test]
    fn happy_path_pending_to_authorized() {
        let mut flow = DeviceFlow::new();
        assert_eq!(flow.state(), DeviceFlowState::Idle);

        flow.start(test_auth(), 1000).unwrap();
        assert_eq!(flow.state(), DeviceFlowState::Pending);

        // Poll a few times.
        let interval = flow.poll(1005).unwrap();
        assert_eq!(interval, 5);
        flow.handle_token_response(TokenPollResponse::Pending);
        assert_eq!(flow.state(), DeviceFlowState::Pending);

        flow.handle_token_response(TokenPollResponse::Authorized);
        assert_eq!(flow.state(), DeviceFlowState::Authorized);
    }

    #[test]
    fn slow_down_increases_interval() {
        let mut flow = DeviceFlow::new();
        flow.start(test_auth(), 1000).unwrap();
        assert_eq!(flow.current_interval_s(), 5);

        flow.poll(1005).unwrap();
        flow.handle_token_response(TokenPollResponse::SlowDown);
        assert_eq!(flow.current_interval_s(), 10);

        flow.poll(1015).unwrap();
        flow.handle_token_response(TokenPollResponse::SlowDown);
        assert_eq!(flow.current_interval_s(), 15);
    }

    #[test]
    fn expiry_detected_on_poll() {
        let mut flow = DeviceFlow::new();
        flow.start(test_auth(), 1000).unwrap();

        // Poll after expiry (1000 + 1800 = 2800).
        let err = flow.poll(2800).unwrap_err();
        assert_eq!(err, AuthError::DeviceCodeExpired);
        assert_eq!(flow.state(), DeviceFlowState::Expired);
    }

    #[test]
    fn denied_by_user() {
        let mut flow = DeviceFlow::new();
        flow.start(test_auth(), 1000).unwrap();
        flow.poll(1005).unwrap();
        flow.handle_token_response(TokenPollResponse::Denied);
        assert_eq!(flow.state(), DeviceFlowState::Denied);

        // Further polls fail.
        let err = flow.poll(1010).unwrap_err();
        assert_eq!(err, AuthError::DeviceAccessDenied);
    }

    #[test]
    fn expired_from_token_endpoint() {
        let mut flow = DeviceFlow::new();
        flow.start(test_auth(), 1000).unwrap();
        flow.poll(1005).unwrap();
        flow.handle_token_response(TokenPollResponse::Expired);
        assert_eq!(flow.state(), DeviceFlowState::Expired);
    }

    #[test]
    fn cannot_start_twice() {
        let mut flow = DeviceFlow::new();
        flow.start(test_auth(), 1000).unwrap();
        let err = flow.start(test_auth(), 1001).unwrap_err();
        assert_eq!(err, AuthError::DeviceAuthorizationPending);
    }

    #[test]
    fn poll_count_tracked() {
        let mut flow = DeviceFlow::new();
        flow.start(test_auth(), 1000).unwrap();
        assert_eq!(flow.poll_count(), 0);
        flow.poll(1005).unwrap();
        assert_eq!(flow.poll_count(), 1);
        flow.poll(1010).unwrap();
        assert_eq!(flow.poll_count(), 2);
    }

    #[test]
    fn token_poll_response_from_error() {
        assert_eq!(
            TokenPollResponse::from_error("authorization_pending"),
            TokenPollResponse::Pending
        );
        assert_eq!(
            TokenPollResponse::from_error("slow_down"),
            TokenPollResponse::SlowDown
        );
        assert_eq!(
            TokenPollResponse::from_error("expired_token"),
            TokenPollResponse::Expired
        );
        assert_eq!(
            TokenPollResponse::from_error("access_denied"),
            TokenPollResponse::Denied
        );
        assert_eq!(
            TokenPollResponse::from_error("unknown_error"),
            TokenPollResponse::Denied
        );
    }

    #[test]
    fn transition_log_recorded() {
        let mut flow = DeviceFlow::new();
        flow.start(test_auth(), 1000).unwrap();
        flow.poll(1005).unwrap();
        flow.handle_token_response(TokenPollResponse::Authorized);
        assert!(flow.transitions().len() >= 3);
        assert!(flow.transitions()[1].contains("Pending"));
    }
}
