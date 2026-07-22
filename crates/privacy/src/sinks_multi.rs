// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Multi-sink orchestration.

use super::*;

#[derive(Default)]
pub struct MultiSink {
    pub sinks: Vec<Box<dyn SinkAdapter>>,
}

impl MultiSink {
    pub fn new() -> Self {
        Self { sinks: Vec::new() }
    }
    pub fn add(&mut self, sink: Box<dyn SinkAdapter>) {
        self.sinks.push(sink);
    }
    /// Per-sink recorded bytes, for verification that every sink received the
    /// same redacted object and that no seeded token leaked.
    pub fn recorded(&self) -> Vec<(&'static str, Vec<Vec<u8>>)> {
        self.sinks
            .iter()
            .map(|s| (s.name(), s.recorded_bytes()))
            .collect()
    }
}

/// Write a redacted event to **all** sinks. If any sink fails the first error
/// is returned, but every other sink still receives the event (best-effort
/// fan-out with error propagation).
pub fn write_to_all_sinks(event: &RedactedEvent, sinks: &mut MultiSink) -> Result<(), SinkError> {
    let mut first_error: Option<SinkError> = None;
    for sink in sinks.sinks.iter_mut() {
        if let Err(e) = sink.write_redacted(event) {
            if first_error.is_none() {
                first_error = Some(e);
            }
        }
    }
    match first_error {
        Some(e) => Err(e),
        None => Ok(()),
    }
}

/// Deliberate raw-write entry point that **always** rejects. This exists to
/// make the no-bypass guarantee explicit and testable: the only way to reach a
/// sink is through [`crate::apply_redaction`] producing a [`RedactedEvent`].
pub fn write_normalized_to_sinks(
    _event: &agent_core::NormalizedEvent,
    _sinks: &mut MultiSink,
) -> Result<(), SinkError> {
    Err(SinkError::BypassRejected(
        "raw NormalizedEvent cannot be written to a sink; apply_redaction must produce a RedactedEvent first",
    ))
}
