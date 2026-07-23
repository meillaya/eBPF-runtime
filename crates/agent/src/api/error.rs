// SPDX-License-Identifier: Apache-2.0 OR MIT
//! API error types.

use http_body_util::Full;
use hyper::body::Bytes;
use hyper::{Response, StatusCode};

use super::helpers::error_response;

/// The kind of API error. Each variant maps to a typed HTTP rejection so the
/// server fails closed without crashing.
#[derive(Debug)]
pub enum ApiErrorKind {
    BindError(std::io::Error),
    ServeError(hyper::Error),
    StorageError(storage_local::StorageError),
    QueryError(String),
    WebSocketError(tokio_tungstenite::tungstenite::Error),
    NonLoopbackBindError(String),
    InvalidCursorError(String),
    OversizedFilterError(String),
    SlowConsumerError(String),
}

/// A typed API error.
#[derive(Debug)]
pub struct ApiError {
    pub kind: ApiErrorKind,
}

impl ApiError {
    pub fn query(msg: impl Into<String>) -> Self {
        Self {
            kind: ApiErrorKind::QueryError(msg.into()),
        }
    }
    pub fn invalid_cursor(msg: impl Into<String>) -> Self {
        Self {
            kind: ApiErrorKind::InvalidCursorError(msg.into()),
        }
    }
    pub fn oversized(msg: impl Into<String>) -> Self {
        Self {
            kind: ApiErrorKind::OversizedFilterError(msg.into()),
        }
    }
    pub fn slow_consumer(msg: impl Into<String>) -> Self {
        Self {
            kind: ApiErrorKind::SlowConsumerError(msg.into()),
        }
    }
    pub fn non_loopback(msg: impl Into<String>) -> Self {
        Self {
            kind: ApiErrorKind::NonLoopbackBindError(msg.into()),
        }
    }

    /// Stable string label for the error kind (used in typed JSON rejections).
    pub fn kind_str(&self) -> &'static str {
        match self.kind {
            ApiErrorKind::BindError(_) => "bind_error",
            ApiErrorKind::ServeError(_) => "serve_error",
            ApiErrorKind::StorageError(_) => "storage_error",
            ApiErrorKind::QueryError(_) => "query_error",
            ApiErrorKind::WebSocketError(_) => "websocket_error",
            ApiErrorKind::NonLoopbackBindError(_) => "non_loopback_bind_error",
            ApiErrorKind::InvalidCursorError(_) => "invalid_cursor_error",
            ApiErrorKind::OversizedFilterError(_) => "oversized_filter_error",
            ApiErrorKind::SlowConsumerError(_) => "slow_consumer_error",
        }
    }

    /// Map the error to an HTTP status code for the typed JSON rejection.
    pub fn status(&self) -> StatusCode {
        match self.kind {
            ApiErrorKind::InvalidCursorError(_)
            | ApiErrorKind::OversizedFilterError(_)
            | ApiErrorKind::QueryError(_)
            | ApiErrorKind::WebSocketError(_) => StatusCode::BAD_REQUEST,
            ApiErrorKind::SlowConsumerError(_) => StatusCode::TOO_MANY_REQUESTS,
            ApiErrorKind::NonLoopbackBindError(_) => StatusCode::FORBIDDEN,
            ApiErrorKind::StorageError(_)
            | ApiErrorKind::BindError(_)
            | ApiErrorKind::ServeError(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    /// Render the error as a typed JSON rejection response.
    pub fn into_response(self) -> Response<Full<Bytes>> {
        let status = self.status();
        let kind = self.kind_str();
        let message = format!("{self}");
        error_response(status, kind, &message)
    }
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.kind {
            ApiErrorKind::BindError(e) => write!(f, "bind error: {e}"),
            ApiErrorKind::ServeError(e) => write!(f, "serve error: {e}"),
            ApiErrorKind::StorageError(e) => write!(f, "storage error: {e}"),
            ApiErrorKind::QueryError(m) => write!(f, "query error: {m}"),
            ApiErrorKind::WebSocketError(e) => write!(f, "websocket error: {e}"),
            ApiErrorKind::NonLoopbackBindError(m) => write!(f, "non-loopback bind rejected: {m}"),
            ApiErrorKind::InvalidCursorError(m) => write!(f, "invalid cursor: {m}"),
            ApiErrorKind::OversizedFilterError(m) => write!(f, "oversized filter: {m}"),
            ApiErrorKind::SlowConsumerError(m) => write!(f, "slow consumer shed: {m}"),
        }
    }
}

impl std::error::Error for ApiError {}

impl From<storage_local::StorageError> for ApiError {
    fn from(e: storage_local::StorageError) -> Self {
        Self {
            kind: ApiErrorKind::StorageError(e),
        }
    }
}

impl From<std::io::Error> for ApiError {
    fn from(e: std::io::Error) -> Self {
        Self {
            kind: ApiErrorKind::BindError(e),
        }
    }
}

impl From<tokio_tungstenite::tungstenite::Error> for ApiError {
    fn from(e: tokio_tungstenite::tungstenite::Error) -> Self {
        Self {
            kind: ApiErrorKind::WebSocketError(e),
        }
    }
}
