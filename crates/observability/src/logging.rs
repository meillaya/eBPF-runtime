// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Structured JSON logging for the observability subsystem.
//!
//! The logging never logs secrets or raw records. It uses `tracing::debug!`
//! only for metric values, never for raw event data.

use tracing_subscriber::EnvFilter;

use crate::{ObservabilityError, ObservabilityErrorKind};

/// Initialize structured JSON logging with the given level.
///
/// The output is JSON-formatted and includes metric values. It never includes
/// secrets or raw event records.
pub fn init_logging(level: tracing::Level) -> Result<(), ObservabilityError> {
    let filter = EnvFilter::new(level.to_string());
    init_with_filter(filter)
}

/// Initialize structured JSON logging with the given filter string.
///
/// The filter is a `tracing_subscriber::EnvFilter` directive string
/// (e.g. `"info,observability=debug"`).
///
/// Returns an error if the filter string is invalid.
pub fn init_logging_with_filter(filter: &str) -> Result<(), ObservabilityError> {
    let env_filter = EnvFilter::try_new(filter).map_err(|e| ObservabilityError {
        kind: ObservabilityErrorKind::LoggingError(format!("invalid filter: {e}")),
    })?;
    init_with_filter(env_filter)
}

/// Internal: build and install the JSON subscriber with the given filter.
fn init_with_filter(filter: EnvFilter) -> Result<(), ObservabilityError> {
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(filter)
        .with_target(true)
        .with_level(true)
        .with_thread_ids(false)
        .with_file(false)
        .with_line_number(false)
        .try_init()
        .map_err(|e| ObservabilityError {
            kind: ObservabilityErrorKind::LoggingError(format!(
                "failed to initialize subscriber: {e}"
            )),
        })
}
