// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Short-lived session management with configurable TTL,
//! explicit revocation, and group-change invalidation.
//!
//! Sessions are NEVER static production tokens. Every session
//! has a bounded lifetime and is invalidated when the actor's
//! group membership changes.

#![forbid(unsafe_code)]

use std::collections::HashMap;

use crate::error::{AuthError, AuthResult};
use crate::rbac::Role;

/// Default session TTL in seconds (15 minutes).
pub const DEFAULT_SESSION_TTL_S: u64 = 900;

/// A short-lived authenticated session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Session {
    pub session_id: String,
    /// The OIDC subject (user identity).
    pub sub: String,
    /// The resolved role for this session.
    pub role: Role,
    /// Groups at session creation time (for change detection).
    pub groups: Vec<String>,
    /// Epoch seconds when the session was created.
    pub created_at_epoch_s: u64,
    /// Epoch seconds when the session expires.
    pub expires_at_epoch_s: u64,
    /// Whether the session has been explicitly revoked.
    pub revoked: bool,
}

impl Session {
    /// Whether the session is expired at `now_epoch_s`.
    pub fn is_expired(&self, now_epoch_s: u64) -> bool {
        now_epoch_s >= self.expires_at_epoch_s
    }

    /// Whether the session is still valid (not expired, not
    /// revoked).
    pub fn is_valid(&self, now_epoch_s: u64) -> bool {
        !self.revoked && !self.is_expired(now_epoch_s)
    }
}

/// In-memory session store with TTL, revocation, and
/// group-change invalidation.
#[derive(Debug)]
pub struct SessionStore {
    sessions: HashMap<String, Session>,
    /// Session TTL in seconds.
    ttl_s: u64,
    /// Monotonic session counter for ID generation.
    next_id: u64,
}

impl SessionStore {
    /// Create a session store with the given TTL.
    pub fn new(ttl_s: u64) -> Self {
        Self {
            sessions: HashMap::new(),
            ttl_s,
            next_id: 0,
        }
    }

    /// Create a session store with the default TTL (15 min).
    pub fn with_default_ttl() -> Self {
        Self::new(DEFAULT_SESSION_TTL_S)
    }

    /// The configured TTL in seconds.
    pub fn ttl_s(&self) -> u64 {
        self.ttl_s
    }

    /// Create a new session for an authenticated actor.
    pub fn create(
        &mut self,
        sub: &str,
        role: Role,
        groups: Vec<String>,
        now_epoch_s: u64,
    ) -> Session {
        let session_id = format!("sess-{}", self.next_id);
        self.next_id += 1;
        let session = Session {
            session_id: session_id.clone(),
            sub: sub.to_string(),
            role,
            groups,
            created_at_epoch_s: now_epoch_s,
            expires_at_epoch_s: now_epoch_s + self.ttl_s,
            revoked: false,
        };
        self.sessions.insert(session_id, session.clone());
        session
    }

    /// Validate a session: checks existence, expiry, and
    /// revocation.
    pub fn validate(&self, session_id: &str, now_epoch_s: u64) -> AuthResult<&Session> {
        let session = self
            .sessions
            .get(session_id)
            .ok_or_else(|| AuthError::SessionNotFound {
                session_id: session_id.to_string(),
            })?;
        if session.revoked {
            return Err(AuthError::SessionRevoked);
        }
        if session.is_expired(now_epoch_s) {
            return Err(AuthError::SessionExpired);
        }
        Ok(session)
    }

    /// Explicitly revoke a session.
    pub fn revoke(&mut self, session_id: &str) -> AuthResult<()> {
        let session =
            self.sessions
                .get_mut(session_id)
                .ok_or_else(|| AuthError::SessionNotFound {
                    session_id: session_id.to_string(),
                })?;
        session.revoked = true;
        Ok(())
    }

    /// Invalidate all sessions for a given sub whose groups
    /// have changed. Returns the number of sessions
    /// invalidated.
    pub fn invalidate_on_group_change(&mut self, sub: &str, new_groups: &[String]) -> usize {
        let mut count = 0;
        for session in self.sessions.values_mut() {
            if session.sub == sub && !session.revoked && session.groups.as_slice() != new_groups {
                session.revoked = true;
                count += 1;
            }
        }
        count
    }

    /// Revoke all sessions for a given sub.
    pub fn revoke_all_for_sub(&mut self, sub: &str) -> usize {
        let mut count = 0;
        for session in self.sessions.values_mut() {
            if session.sub == sub && !session.revoked {
                session.revoked = true;
                count += 1;
            }
        }
        count
    }

    /// Number of active (non-revoked, non-expired) sessions.
    pub fn active_count(&self, now_epoch_s: u64) -> usize {
        self.sessions
            .values()
            .filter(|s| s.is_valid(now_epoch_s))
            .count()
    }
}

impl Default for SessionStore {
    fn default() -> Self {
        Self::with_default_ttl()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_and_validate_session() {
        let mut store = SessionStore::new(900);
        let session = store.create("user-1", Role::Viewer, vec!["viewers".into()], 1000);
        assert!(store.validate(&session.session_id, 1000).is_ok());
        assert!(store.validate(&session.session_id, 1899).is_ok());
    }

    #[test]
    fn expired_session_rejected() {
        let mut store = SessionStore::new(900);
        let session = store.create("user-1", Role::Viewer, vec![], 1000);
        let err = store.validate(&session.session_id, 1900).unwrap_err();
        assert_eq!(err, AuthError::SessionExpired);
    }

    #[test]
    fn revoked_session_rejected() {
        let mut store = SessionStore::new(900);
        let session = store.create("user-1", Role::Viewer, vec![], 1000);
        store.revoke(&session.session_id).unwrap();
        let err = store.validate(&session.session_id, 1001).unwrap_err();
        assert_eq!(err, AuthError::SessionRevoked);
    }

    #[test]
    fn unknown_session_rejected() {
        let store = SessionStore::new(900);
        let err = store.validate("nonexistent", 1000).unwrap_err();
        assert!(matches!(err, AuthError::SessionNotFound { .. }));
    }

    #[test]
    fn group_change_invalidates_sessions() {
        let mut store = SessionStore::new(900);
        let s1 = store.create("user-1", Role::Analyst, vec!["analysts".into()], 1000);
        let s2 = store.create("user-2", Role::Viewer, vec!["viewers".into()], 1000);

        // user-1's groups change: analysts -> viewers.
        let invalidated = store.invalidate_on_group_change("user-1", &["viewers".into()]);
        assert_eq!(invalidated, 1);

        // user-1's session is now revoked.
        let err = store.validate(&s1.session_id, 1001).unwrap_err();
        assert_eq!(err, AuthError::SessionRevoked);

        // user-2's session is unaffected.
        assert!(store.validate(&s2.session_id, 1001).is_ok());
    }

    #[test]
    fn group_unchanged_sessions_survive() {
        let mut store = SessionStore::new(900);
        let session = store.create("user-1", Role::Analyst, vec!["analysts".into()], 1000);
        let invalidated = store.invalidate_on_group_change("user-1", &["analysts".into()]);
        assert_eq!(invalidated, 0);
        assert!(store.validate(&session.session_id, 1001).is_ok());
    }

    #[test]
    fn revoke_all_for_sub() {
        let mut store = SessionStore::new(900);
        let s1 = store.create("user-1", Role::Viewer, vec![], 1000);
        let s2 = store.create("user-1", Role::Viewer, vec![], 1001);
        let s3 = store.create("user-2", Role::Viewer, vec![], 1002);

        let count = store.revoke_all_for_sub("user-1");
        assert_eq!(count, 2);
        assert!(store.validate(&s1.session_id, 1003).is_err());
        assert!(store.validate(&s2.session_id, 1003).is_err());
        assert!(store.validate(&s3.session_id, 1003).is_ok());
    }

    #[test]
    fn active_count_tracks_validity() {
        let mut store = SessionStore::new(100);
        store.create("u1", Role::Viewer, vec![], 1000);
        store.create("u2", Role::Viewer, vec![], 1000);
        assert_eq!(store.active_count(1050), 2);
        assert_eq!(store.active_count(1100), 0);
    }

    #[test]
    fn default_ttl_is_900() {
        let store = SessionStore::with_default_ttl();
        assert_eq!(store.ttl_s(), 900);
        assert_eq!(DEFAULT_SESSION_TTL_S, 900);
    }
}
