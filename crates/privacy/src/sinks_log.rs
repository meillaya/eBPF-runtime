// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Log sink adapter.

use super::*;

/// Log sink adapter. Emits each redacted event as a structured log line and
/// records it for verification. Only redacted output is ever logged.
#[derive(Debug, Default)]
pub struct LogSinkAdapter {
    pub logger: Mutex<LogCapture>,
}

impl LogSinkAdapter {
    pub fn new() -> Self {
        Self {
            logger: Mutex::new(LogCapture::new()),
        }
    }
    pub fn lines(&self) -> Vec<String> {
        self.logger.lock().lines.clone()
    }
}

impl SinkAdapter for LogSinkAdapter {
    fn write_redacted(&mut self, event: &RedactedEvent) -> Result<(), SinkError> {
        let line = serde_json::to_string(&event.to_json())
            .map_err(|e| SinkError::Serialization(e.to_string()))?;
        // Redacted output only — the raw payload is never logged.
        tracing::debug!(redacted_event = %line, "sink=log");
        self.logger.lock().lines.push(line);
        Ok(())
    }
    fn name(&self) -> &'static str {
        "log"
    }
    fn recorded_bytes(&self) -> Vec<Vec<u8>> {
        self.logger
            .lock()
            .lines
            .iter()
            .map(|l| l.as_bytes().to_vec())
            .collect()
    }
}
