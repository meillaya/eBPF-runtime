// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Machine-readable output formatting (JSON, table, YAML).
//!
//! JSON output is wrapped in a versioned envelope:
//! ```json
//! { "schema_version": 1, "data": ... }
//! ```
//! Fields are NEVER removed without a major version bump.

use clap::ValueEnum;
use serde::Serialize;

/// Output format selector for all commands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum OutputFormat {
    /// JSON with versioned schema envelope.
    Json,
    /// Human-readable aligned table.
    Table,
    /// YAML output.
    Yaml,
}

impl Default for OutputFormat {
    fn default() -> Self {
        Self::Table
    }
}

/// Versioned JSON envelope. Fields are append-only;
/// removal requires a major schema version bump.
#[derive(Debug, Serialize)]
pub struct Envelope<T: Serialize> {
    /// Schema version (currently 1).
    pub schema_version: u32,
    /// The payload.
    pub data: T,
}

impl<T: Serialize> Envelope<T> {
    /// Wrap data in the versioned envelope.
    pub fn new(data: T) -> Self {
        Self {
            schema_version: 1,
            data,
        }
    }
}

/// Format a serializable value according to the output format.
///
/// - JSON: versioned envelope, pretty-printed.
/// - YAML: versioned envelope.
/// - Table: delegates to the provided table renderer.
pub fn format_output<T: Serialize>(
    value: &T,
    format: OutputFormat,
    table_fn: impl FnOnce(&T) -> String,
) -> String {
    match format {
        OutputFormat::Json => {
            let envelope = Envelope::new(value);
            serde_json::to_string_pretty(&envelope)
                .unwrap_or_else(|e| format!("{{\"error\": \"{e}\"}}"))
        }
        OutputFormat::Yaml => {
            let envelope = Envelope::new(value);
            serde_yaml::to_string(&envelope)
                .unwrap_or_else(|e| format!("error: {e}"))
        }
        OutputFormat::Table => table_fn(value),
    }
}

/// Render a table with aligned columns from headers and rows.
pub fn render_table(headers: &[&str], rows: &[Vec<String>]) -> String {
    if headers.is_empty() {
        return String::new();
    }

    // Compute column widths.
    let mut widths: Vec<usize> = headers.iter().map(|h| h.len()).collect();
    for row in rows {
        for (i, cell) in row.iter().enumerate() {
            if i < widths.len() {
                widths[i] = widths[i].max(cell.len());
            }
        }
    }

    let mut out = String::new();

    // Header row.
    let header_line: Vec<String> = headers
        .iter()
        .enumerate()
        .map(|(i, h)| format!("{:<width$}", h, width = widths[i]))
        .collect();
    out.push_str(&header_line.join("  "));
    out.push('\n');

    // Separator.
    let sep: Vec<String> = widths.iter().map(|w| "-".repeat(*w)).collect();
    out.push_str(&sep.join("  "));
    out.push('\n');

    // Data rows.
    for row in rows {
        let line: Vec<String> = row
            .iter()
            .enumerate()
            .map(|(i, cell)| {
                let w = widths.get(i).copied().unwrap_or(cell.len());
                format!("{:<width$}", cell, width = w)
            })
            .collect();
        out.push_str(&line.join("  "));
        out.push('\n');
    }

    out
}

/// Structured error output with code, description, and suggestion.
#[derive(Debug, Serialize)]
pub struct ErrorOutput {
    /// Machine-readable error code.
    pub code: u8,
    /// Human-readable description.
    pub description: String,
    /// Suggested remediation action.
    pub suggestion: String,
}

impl ErrorOutput {
    /// Create from an exit code and detail message.
    pub fn new(code: crate::exit_code::ExitCode, detail: &str) -> Self {
        Self {
            code: code.code(),
            description: if detail.is_empty() {
                code.description().to_string()
            } else {
                detail.to_string()
            },
            suggestion: code.suggestion().to_string(),
        }
    }

    /// Render the error in the requested format.
    pub fn render(&self, format: OutputFormat) -> String {
        match format {
            OutputFormat::Json => serde_json::to_string_pretty(self)
                .unwrap_or_else(|_| "{\"code\":1}".into()),
            OutputFormat::Yaml => {
                serde_yaml::to_string(self).unwrap_or_else(|_| "code: 1".into())
            }
            OutputFormat::Table => {
                format!(
                    "Error [{}]: {}\nSuggestion: {}",
                    self.code, self.description, self.suggestion
                )
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Serialize)]
    struct TestData {
        name: String,
        count: u32,
    }

    #[test]
    fn json_output_has_schema_version() {
        let data = TestData {
            name: "test".into(),
            count: 42,
        };
        let out = format_output(&data, OutputFormat::Json, |_| String::new());
        assert!(out.contains("\"schema_version\": 1"));
        assert!(out.contains("\"name\": \"test\""));
    }

    #[test]
    fn yaml_output_has_schema_version() {
        let data = TestData {
            name: "test".into(),
            count: 42,
        };
        let out = format_output(&data, OutputFormat::Yaml, |_| String::new());
        assert!(out.contains("schema_version: 1"));
        assert!(out.contains("name: test"));
    }

    #[test]
    fn table_output_uses_renderer() {
        let data = TestData {
            name: "test".into(),
            count: 42,
        };
        let out = format_output(&data, OutputFormat::Table, |d| {
            render_table(
                &["NAME", "COUNT"],
                &[vec![d.name.clone(), d.count.to_string()]],
            )
        });
        assert!(out.contains("NAME"));
        assert!(out.contains("test"));
        assert!(out.contains("42"));
    }

    #[test]
    fn table_columns_aligned() {
        let out = render_table(
            &["ID", "NAME"],
            &[
                vec!["1".into(), "short".into()],
                vec!["2".into(), "a-much-longer-name".into()],
            ],
        );
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines.len(), 4); // header + sep + 2 rows
        // All lines should have consistent column positions.
        assert!(lines[0].contains("ID"));
        assert!(lines[0].contains("NAME"));
    }

    #[test]
    fn error_output_json() {
        let err = ErrorOutput::new(crate::exit_code::ExitCode::AuthFailure, "token expired");
        let out = err.render(OutputFormat::Json);
        assert!(out.contains("\"code\": 2"));
        assert!(out.contains("token expired"));
    }

    #[test]
    fn error_output_table() {
        let err = ErrorOutput::new(crate::exit_code::ExitCode::NotFound, "agent xyz");
        let out = err.render(OutputFormat::Table);
        assert!(out.contains("Error [3]"));
        assert!(out.contains("agent xyz"));
        assert!(out.contains("Suggestion:"));
    }
}
