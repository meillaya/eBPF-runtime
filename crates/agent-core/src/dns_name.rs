// SPDX-License-Identifier: Apache-2.0 OR MIT
//! DNS name wire-format reader with strict loop detection.

use crate::dns_decoder::{DnsDecodeError, MAX_NAME_ITERATIONS};

pub(crate) struct Cursor<'a> {
    pub buf: &'a [u8],
    pub pos: usize,
    pub name_iterations: u32,
}

impl<'a> Cursor<'a> {
    pub(crate) fn new(buf: &'a [u8]) -> Self {
        Self {
            buf,
            pos: 0,
            name_iterations: 0,
        }
    }
    pub(crate) fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }
    pub(crate) fn read_u16(&mut self) -> Result<u16, DnsDecodeError> {
        if self.remaining() < 2 {
            return Err(DnsDecodeError::BufferUnderflow);
        }
        let value = u16::from_be_bytes([self.buf[self.pos], self.buf[self.pos + 1]]);
        self.pos += 2;
        Ok(value)
    }
    pub(crate) fn read_u32(&mut self) -> Result<u32, DnsDecodeError> {
        if self.remaining() < 4 {
            return Err(DnsDecodeError::BufferUnderflow);
        }
        let value = u32::from_be_bytes([
            self.buf[self.pos],
            self.buf[self.pos + 1],
            self.buf[self.pos + 2],
            self.buf[self.pos + 3],
        ]);
        self.pos += 4;
        Ok(value)
    }
}

pub(crate) fn read_name(
    cursor: &mut Cursor<'_>,
    max_bytes: usize,
) -> Result<String, DnsDecodeError> {
    let mut out = String::new();
    let mut jumped = false;
    let mut return_pos = cursor.pos;
    loop {
        cursor.name_iterations += 1;
        if cursor.name_iterations > MAX_NAME_ITERATIONS {
            return Err(DnsDecodeError::CompressionLoopDetected);
        }
        if cursor.remaining() < 1 {
            return Err(DnsDecodeError::BufferUnderflow);
        }
        let byte = cursor.buf[cursor.pos];
        match byte & 0xC0 {
            0x00 => {
                let length = byte;
                cursor.pos += 1;
                if length == 0 {
                    if !jumped {
                        return_pos = cursor.pos;
                    }
                    cursor.pos = return_pos;
                    if out.len() > max_bytes {
                        return Err(DnsDecodeError::NameTooLong);
                    }
                    if out.is_empty() {
                        out.push('.');
                    }
                    return Ok(out);
                }
                if cursor.remaining() < length as usize {
                    return Err(DnsDecodeError::BufferUnderflow);
                }
                if !out.is_empty() {
                    out.push('.');
                }
                if out.len() + length as usize > max_bytes {
                    return Err(DnsDecodeError::NameTooLong);
                }
                for index in 0..length as usize {
                    let ch = cursor.buf[cursor.pos + index];
                    if !(0x20..=0x7E).contains(&ch) {
                        return Err(DnsDecodeError::InvalidLabelLength);
                    }
                    out.push(ch as char);
                }
                cursor.pos += length as usize;
            }
            0xC0 => {
                if cursor.remaining() < 2 {
                    return Err(DnsDecodeError::BufferUnderflow);
                }
                let pointer =
                    u16::from_be_bytes([cursor.buf[cursor.pos], cursor.buf[cursor.pos + 1]]);
                let offset = (pointer & 0x3FFF) as usize;
                if offset >= cursor.buf.len() {
                    return Err(DnsDecodeError::CompressionLoopDetected);
                }
                if !jumped {
                    return_pos = cursor.pos + 2;
                    jumped = true;
                }
                cursor.pos = offset;
            }
            _ => return Err(DnsDecodeError::InvalidLabelLength),
        }
    }
}
