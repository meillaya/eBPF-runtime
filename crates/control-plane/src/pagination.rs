// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Bounded pagination with opaque base64 cursors.
//!
//! Every paginated query uses a [`PageRequest`] with a bounded
//! limit and an optional opaque cursor. The cursor encodes the
//! last-seen sequence or offset; it is NOT a raw SQL parameter.
//! The server clamps the limit to the configured maximum.

#![forbid(unsafe_code)]

use base64::Engine;
use serde::{Deserialize, Serialize};

use crate::error::{ControlPlaneError, Result};

/// The base64 engine for cursor encoding (URL-safe, no pad).
const CURSOR_ENGINE: base64::engine::GeneralPurpose =
    base64::engine::general_purpose::URL_SAFE_NO_PAD;

/// A paginated request with bounded limit and optional cursor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PageRequest {
    /// Maximum number of items to return. Clamped to the
    /// server's `max_page_size`.
    pub limit: usize,
    /// Opaque cursor from a previous response. `None` for the
    /// first page.
    pub cursor: Option<String>,
}

impl PageRequest {
    /// Create a new page request.
    pub fn new(limit: usize, cursor: Option<String>) -> Self {
        Self { limit, cursor }
    }

    /// The first page with the given limit.
    pub fn first(limit: usize) -> Self {
        Self {
            limit,
            cursor: None,
        }
    }

    /// Decode the cursor into a sequence offset.
    pub fn cursor_offset(&self) -> Result<Option<u64>> {
        match &self.cursor {
            None => Ok(None),
            Some(raw) => {
                let decoded =
                    CURSOR_ENGINE
                        .decode(raw)
                        .map_err(|e| ControlPlaneError::InvalidCursor {
                            reason: format!("base64 decode failed: {e}"),
                        })?;
                let json =
                    String::from_utf8(decoded).map_err(|e| ControlPlaneError::InvalidCursor {
                        reason: format!("cursor is not valid UTF-8: {e}"),
                    })?;
                let inner: CursorInner =
                    serde_json::from_str(&json).map_err(|e| ControlPlaneError::InvalidCursor {
                        reason: format!("cursor JSON invalid: {e}"),
                    })?;
                Ok(Some(inner.offset))
            }
        }
    }
}

impl Default for PageRequest {
    fn default() -> Self {
        Self {
            limit: 50,
            cursor: None,
        }
    }
}

/// Internal cursor payload (serialized to JSON, then base64).
#[derive(Debug, Clone, Serialize, Deserialize)]
struct CursorInner {
    /// The offset (last-seen sequence or row index).
    offset: u64,
    /// A version tag for forward compatibility.
    v: u8,
}

/// Encode a cursor from an offset.
pub fn encode_cursor(offset: u64) -> String {
    let inner = CursorInner { offset, v: 1 };
    let json = serde_json::to_string(&inner).expect("cursor serialization cannot fail");
    CURSOR_ENGINE.encode(json.as_bytes())
}

/// A paginated response with items and an optional next cursor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PageResponse<T> {
    /// The items in this page.
    pub items: Vec<T>,
    /// Cursor for the next page. `None` if this is the last
    /// page.
    pub next_cursor: Option<String>,
    /// Total number of items matching the query (may be an
    /// estimate for large result sets).
    pub total: Option<u64>,
}

impl<T> PageResponse<T> {
    /// Create a page response.
    pub fn new(items: Vec<T>, next_cursor: Option<String>, total: Option<u64>) -> Self {
        Self {
            items,
            next_cursor,
            total,
        }
    }

    /// Whether there are more pages.
    pub fn has_more(&self) -> bool {
        self.next_cursor.is_some()
    }

    /// Map the items to a different type.
    pub fn map<U, F: FnMut(T) -> U>(self, f: F) -> PageResponse<U> {
        PageResponse {
            items: self.items.into_iter().map(f).collect(),
            next_cursor: self.next_cursor,
            total: self.total,
        }
    }
}

/// Apply a time window bound check.
pub fn validate_time_window(start_epoch_s: u64, end_epoch_s: u64, max_window_s: u64) -> Result<()> {
    if end_epoch_s < start_epoch_s {
        return Err(ControlPlaneError::InvalidCursor {
            reason: "end time before start time".into(),
        });
    }
    let window = end_epoch_s - start_epoch_s;
    if window > max_window_s {
        return Err(ControlPlaneError::WindowExceeded {
            requested_s: window,
            max_s: max_window_s,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cursor_round_trip() {
        let cursor = encode_cursor(42);
        let req = PageRequest::new(10, Some(cursor));
        let offset = req.cursor_offset().unwrap();
        assert_eq!(offset, Some(42));
    }

    #[test]
    fn no_cursor_returns_none() {
        let req = PageRequest::first(10);
        assert_eq!(req.cursor_offset().unwrap(), None);
    }

    #[test]
    fn invalid_base64_cursor_rejected() {
        let req = PageRequest::new(10, Some("!!!not-base64!!!".into()));
        assert!(req.cursor_offset().is_err());
    }

    #[test]
    fn invalid_json_cursor_rejected() {
        let bad = CURSOR_ENGINE.encode(b"not json");
        let req = PageRequest::new(10, Some(bad));
        assert!(req.cursor_offset().is_err());
    }

    #[test]
    fn page_response_has_more() {
        let resp: PageResponse<i32> =
            PageResponse::new(vec![1, 2, 3], Some(encode_cursor(3)), Some(10));
        assert!(resp.has_more());

        let last: PageResponse<i32> = PageResponse::new(vec![4], None, Some(4));
        assert!(!last.has_more());
    }

    #[test]
    fn page_response_map() {
        let resp: PageResponse<i32> =
            PageResponse::new(vec![1, 2, 3], Some(encode_cursor(3)), Some(10));
        let mapped = resp.map(|x| x * 2);
        assert_eq!(mapped.items, vec![2, 4, 6]);
        assert!(mapped.has_more());
    }

    #[test]
    fn time_window_within_bounds() {
        assert!(validate_time_window(1000, 2000, 3600).is_ok());
    }

    #[test]
    fn time_window_exceeds_bounds() {
        let err = validate_time_window(0, 100_000, 86_400).unwrap_err();
        assert!(matches!(err, ControlPlaneError::WindowExceeded { .. }));
    }

    #[test]
    fn time_window_end_before_start() {
        let err = validate_time_window(2000, 1000, 86_400).unwrap_err();
        assert!(matches!(err, ControlPlaneError::InvalidCursor { .. }));
    }

    #[test]
    fn default_page_request() {
        let req = PageRequest::default();
        assert_eq!(req.limit, 50);
        assert!(req.cursor.is_none());
    }

    #[test]
    fn cursor_zero_offset() {
        let cursor = encode_cursor(0);
        let req = PageRequest::new(10, Some(cursor));
        assert_eq!(req.cursor_offset().unwrap(), Some(0));
    }

    #[test]
    fn cursor_large_offset() {
        let cursor = encode_cursor(u64::MAX);
        let req = PageRequest::new(10, Some(cursor));
        assert_eq!(req.cursor_offset().unwrap(), Some(u64::MAX));
    }
}
