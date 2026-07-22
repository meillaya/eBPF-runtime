// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Fixture SVID stream for testing.

use super::*;

pub struct FixtureSvidStream {
    responses: Vec<SpiffeResult<X509SvidResponse>>,
    index: usize,
}

impl FixtureSvidStream {
    /// Create a fixture stream from a sequence of responses.
    pub fn new(responses: Vec<SpiffeResult<X509SvidResponse>>) -> Self {
        Self {
            responses,
            index: 0,
        }
    }

    /// Create a stream that yields one response then closes.
    pub fn single(response: X509SvidResponse) -> Self {
        Self {
            responses: vec![Ok(response)],
            index: 0,
        }
    }

    /// Create a stream that yields an error immediately.
    pub fn error(err: SpiffeError) -> Self {
        Self {
            responses: vec![Err(err)],
            index: 0,
        }
    }
}

impl SvidStream for FixtureSvidStream {
    fn next_response(&mut self) -> SpiffeResult<Option<X509SvidResponse>> {
        if self.index >= self.responses.len() {
            return Ok(None); // Stream closed.
        }
        let result = self.responses[self.index].clone();
        self.index += 1;
        result.map(Some)
    }
}
