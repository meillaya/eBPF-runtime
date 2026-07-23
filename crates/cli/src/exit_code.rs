// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Stable exit codes for the CLI.
//!
//! These codes are a **stable contract**: scripts and CI may
//! depend on them. Never reassign an existing code. New codes
//! must be appended at the end.
//!
//! | Code | Meaning        | Suggested action                     |
//! |------|----------------|--------------------------------------|
//! | 0    | Success        | —                                    |
//! | 1    | General error  | Check stderr for details             |
//! | 2    | Auth failure   | Re-run `fleet login`                 |
//! | 3    | Not found      | Verify resource ID / cluster scope   |
//! | 4    | Timeout        | Retry or increase `--timeout`        |

/// Stable CLI exit codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ExitCode {
    /// Operation completed successfully.
    Success = 0,
    /// General error (network, parse, unexpected).
    Error = 1,
    /// Authentication or authorization failure.
    AuthFailure = 2,
    /// Requested resource not found.
    NotFound = 3,
    /// Operation timed out.
    Timeout = 4,
}

impl ExitCode {
    /// The numeric exit code value.
    pub fn code(self) -> u8 {
        self as u8
    }

    /// Human-readable description for error reporting.
    pub fn description(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Error => "general error",
            Self::AuthFailure => "authentication failure",
            Self::NotFound => "resource not found",
            Self::Timeout => "operation timed out",
        }
    }

    /// Suggested remediation action.
    pub fn suggestion(self) -> &'static str {
        match self {
            Self::Success => "",
            Self::Error => "check stderr output for details",
            Self::AuthFailure => "re-run `cli fleet login` to re-authenticate",
            Self::NotFound => "verify the resource ID and --cluster scope",
            Self::Timeout => "retry the command or increase --timeout",
        }
    }

    /// Help text listing all exit codes (for `--help` output).
    pub fn help_text() -> &'static str {
        "Exit codes:\n  \
         0  success\n  \
         1  general error\n  \
         2  authentication failure\n  \
         3  resource not found\n  \
         4  operation timed out"
    }
}

impl std::fmt::Display for ExitCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.code())
    }
}

impl From<ExitCode> for std::process::ExitCode {
    fn from(code: ExitCode) -> Self {
        std::process::ExitCode::from(code.code())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_codes_are_stable() {
        assert_eq!(ExitCode::Success.code(), 0);
        assert_eq!(ExitCode::Error.code(), 1);
        assert_eq!(ExitCode::AuthFailure.code(), 2);
        assert_eq!(ExitCode::NotFound.code(), 3);
        assert_eq!(ExitCode::Timeout.code(), 4);
    }

    #[test]
    fn all_codes_have_descriptions() {
        let codes = [
            ExitCode::Success,
            ExitCode::Error,
            ExitCode::AuthFailure,
            ExitCode::NotFound,
            ExitCode::Timeout,
        ];
        for code in codes {
            assert!(!code.description().is_empty());
        }
    }

    #[test]
    fn error_codes_have_suggestions() {
        let codes = [
            ExitCode::Error,
            ExitCode::AuthFailure,
            ExitCode::NotFound,
            ExitCode::Timeout,
        ];
        for code in codes {
            assert!(!code.suggestion().is_empty());
        }
    }

    #[test]
    fn help_text_lists_all_codes() {
        let help = ExitCode::help_text();
        assert!(help.contains("0  success"));
        assert!(help.contains("1  general error"));
        assert!(help.contains("2  authentication failure"));
        assert!(help.contains("3  resource not found"));
        assert!(help.contains("4  operation timed out"));
    }
}
