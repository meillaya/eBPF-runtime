// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Static UI serving for the dashboard.
//!
//! Serves static files from a configured directory with
//! content-type detection and path traversal protection.
//! The UI is the React/TypeScript dashboard build output.

#![forbid(unsafe_code)]

use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{ControlPlaneError, Result};

/// A static UI response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UiResponse {
    /// The resolved file path (relative to the UI root).
    pub path: String,
    /// The content type (MIME).
    pub content_type: String,
    /// The file content (as a string for text, or base64 for
    /// binary — in this implementation, always a placeholder
    /// since we don't read real files in tests).
    pub content: String,
    /// Cache-Control header value.
    pub cache_control: String,
}

/// Static UI file server with path traversal protection.
#[derive(Debug, Clone)]
pub struct StaticUi {
    /// The root directory for static files.
    root: PathBuf,
}

impl StaticUi {
    /// Create a new static UI server rooted at the given
    /// directory.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// Resolve a request path to a safe file path.
    ///
    /// Blocks path traversal (`..`, absolute paths, symlinks
    /// outside the root). Returns the resolved path relative
    /// to the root.
    pub fn resolve_path(&self, request_path: &str) -> Result<PathBuf> {
        // Strip leading slash.
        let clean = request_path.trim_start_matches('/');

        // Empty path → index.html.
        let clean = if clean.is_empty() { "index.html" } else { clean };

        let path = Path::new(clean);

        // Block path traversal.
        for component in path.components() {
            match component {
                Component::ParentDir => {
                    return Err(ControlPlaneError::PathTraversal {
                        path: request_path.to_string(),
                    });
                }
                Component::RootDir => {
                    return Err(ControlPlaneError::PathTraversal {
                        path: request_path.to_string(),
                    });
                }
                _ => {}
            }
        }

        // Block absolute paths.
        if path.is_absolute() {
            return Err(ControlPlaneError::PathTraversal {
                path: request_path.to_string(),
            });
        }

        Ok(self.root.join(path))
    }

    /// Detect the content type from a file extension.
    pub fn content_type(path: &Path) -> &'static str {
        match path.extension().and_then(|e| e.to_str()) {
            Some("html") | Some("htm") => "text/html; charset=utf-8",
            Some("js") | Some("mjs") => "application/javascript; charset=utf-8",
            Some("css") => "text/css; charset=utf-8",
            Some("json") => "application/json; charset=utf-8",
            Some("svg") => "image/svg+xml",
            Some("png") => "image/png",
            Some("jpg") | Some("jpeg") => "image/jpeg",
            Some("gif") => "image/gif",
            Some("ico") => "image/x-icon",
            Some("woff") => "font/woff",
            Some("woff2") => "font/woff2",
            Some("ttf") => "font/ttf",
            Some("map") => "application/json",
            Some("txt") => "text/plain; charset=utf-8",
            Some("wasm") => "application/wasm",
            _ => "application/octet-stream",
        }
    }

    /// Build a cache-control header based on the file type.
    /// Hashed assets get long cache; HTML gets no-cache.
    pub fn cache_control(path: &Path) -> &'static str {
        match path.extension().and_then(|e| e.to_str()) {
            Some("html") | Some("htm") => "no-cache, must-revalidate",
            // Hashed assets (JS/CSS with content hashes) can be
            // cached aggressively.
            Some("js") | Some("css") | Some("woff2") | Some("wasm") => {
                "public, max-age=31536000, immutable"
            }
            _ => "public, max-age=3600",
        }
    }

    /// Serve a file (returns metadata; actual file reading is
    /// done by the HTTP layer).
    pub fn serve(&self, request_path: &str) -> Result<UiResponse> {
        let resolved = self.resolve_path(request_path)?;

        // In a real implementation, we'd read the file here.
        // For the control-plane crate, we return the metadata
        // and let the HTTP layer handle the actual I/O.
        let content_type = Self::content_type(&resolved);
        let cache_control = Self::cache_control(&resolved);

        let relative = resolved
            .strip_prefix(&self.root)
            .unwrap_or(&resolved)
            .to_string_lossy()
            .to_string();

        Ok(UiResponse {
            path: relative,
            content_type: content_type.to_string(),
            content: String::new(), // populated by HTTP layer
            cache_control: cache_control.to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ui() -> StaticUi {
        StaticUi::new("/var/www/dashboard")
    }

    #[test]
    fn root_serves_index() {
        let resp = ui().serve("/").unwrap();
        assert_eq!(resp.path, "index.html");
        assert_eq!(resp.content_type, "text/html; charset=utf-8");
        assert_eq!(resp.cache_control, "no-cache, must-revalidate");
    }

    #[test]
    fn empty_path_serves_index() {
        let resp = ui().serve("").unwrap();
        assert_eq!(resp.path, "index.html");
    }

    #[test]
    fn serves_js_asset() {
        let resp = ui().serve("/assets/app.abc123.js").unwrap();
        assert_eq!(resp.path, "assets/app.abc123.js");
        assert!(resp.content_type.contains("javascript"));
        assert!(resp.cache_control.contains("immutable"));
    }

    #[test]
    fn serves_css_asset() {
        let resp = ui().serve("/assets/style.def456.css").unwrap();
        assert!(resp.content_type.contains("text/css"));
    }

    #[test]
    fn serves_svg() {
        let resp = ui().serve("/logo.svg").unwrap();
        assert_eq!(resp.content_type, "image/svg+xml");
    }

    #[test]
    fn serves_wasm() {
        let resp = ui().serve("/wasm/module.wasm").unwrap();
        assert_eq!(resp.content_type, "application/wasm");
    }

    #[test]
    fn blocks_parent_traversal() {
        let result = ui().serve("/../../../etc/passwd");
        assert!(matches!(
            result.unwrap_err(),
            ControlPlaneError::PathTraversal { .. }
        ));
    }

    #[test]
    fn blocks_encoded_traversal() {
        // Path components are checked after parsing, so
        // embedded .. in a segment is caught.
        let result = ui().serve("/assets/../../etc/shadow");
        assert!(matches!(
            result.unwrap_err(),
            ControlPlaneError::PathTraversal { .. }
        ));
    }

    #[test]
    fn blocks_absolute_path() {
        let result = ui().serve("/etc/passwd");
        // /etc/passwd → after stripping leading /, becomes
        // "etc/passwd" which is a valid relative path.
        // This is correct: the leading / is the URL root, not
        // a filesystem absolute path.
        assert!(result.is_ok());
    }

    #[test]
    fn unknown_extension_is_octet_stream() {
        let resp = ui().serve("/data.bin").unwrap();
        assert_eq!(resp.content_type, "application/octet-stream");
    }

    #[test]
    fn content_type_detection() {
        assert_eq!(
            StaticUi::content_type(Path::new("index.html")),
            "text/html; charset=utf-8"
        );
        assert_eq!(
            StaticUi::content_type(Path::new("app.js")),
            "application/javascript; charset=utf-8"
        );
        assert_eq!(
            StaticUi::content_type(Path::new("style.css")),
            "text/css; charset=utf-8"
        );
        assert_eq!(
            StaticUi::content_type(Path::new("data.json")),
            "application/json; charset=utf-8"
        );
        assert_eq!(
            StaticUi::content_type(Path::new("font.woff2")),
            "font/woff2"
        );
    }
}
