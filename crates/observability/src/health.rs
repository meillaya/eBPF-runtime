// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Health, readiness, and error types.

use std::fmt;

use serde::{Deserialize, Serialize};

/// Overall health state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HealthState {
    Healthy,
    Degraded,
    Unhealthy,
}

impl fmt::Display for HealthState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            HealthState::Healthy => "healthy",
            HealthState::Degraded => "degraded",
            HealthState::Unhealthy => "unhealthy",
        })
    }
}

/// Health status with reasons.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthStatus {
    pub status: HealthState,
    pub reasons: Vec<String>,
}

/// Readiness state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReadinessState {
    Ready,
    NotReady,
}

impl fmt::Display for ReadinessState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            ReadinessState::Ready => "ready",
            ReadinessState::NotReady => "not_ready",
        })
    }
}

/// Readiness status with reasons.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadinessStatus {
    pub status: ReadinessState,
    pub reasons: Vec<String>,
}

/// Error kind for the observability subsystem.
#[derive(Debug)]
pub enum ObservabilityErrorKind {
    BindError(std::io::Error),
    ServeError(hyper::Error),
    MetricsError(prometheus::Error),
    LoggingError(String),
}

impl fmt::Display for ObservabilityErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ObservabilityErrorKind::BindError(e) => write!(f, "bind error: {e}"),
            ObservabilityErrorKind::ServeError(e) => write!(f, "serve error: {e}"),
            ObservabilityErrorKind::MetricsError(e) => write!(f, "metrics error: {e}"),
            ObservabilityErrorKind::LoggingError(e) => write!(f, "logging error: {e}"),
        }
    }
}

/// Observability error wrapping a kind.
#[derive(Debug)]
pub struct ObservabilityError {
    pub kind: ObservabilityErrorKind,
}

impl fmt::Display for ObservabilityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.kind)
    }
}

impl std::error::Error for ObservabilityError {}
