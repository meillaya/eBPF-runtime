// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Runtime for the process and file sensors.
//!
//! [`decode`] turns a ring buffer record into named fields,
//! [`process_table`] maps a thread group to its executable, and
//! [`rules_engine`] evaluates the YAML rule packs. The `ebpf-runtime`
//! binary in `cli` wires those pieces to the loader.

pub mod cli;
pub mod decode;
pub mod process_table;
pub mod rules_engine;

pub use decode::{decode, Clock, DecodeFailure, DecodedEvent};
pub use process_table::ProcessTable;
pub use rules_engine::{Alert, Engine, EngineError};
