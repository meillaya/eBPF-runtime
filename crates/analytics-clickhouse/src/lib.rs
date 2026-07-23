// SPDX-License-Identifier: Apache-2.0 OR MIT
//! ClickHouse analytics query helpers for the eBPF runtime security platform.
//!
//! This crate provides:
//! - Typed schema definitions mirroring the ClickHouse `events_v1` table
//! - Exact-query SQL builders using `FINAL` / `argMax` for deduplication
//! - Deduplication logic that exposes duplicates before exact query
//! - DLQ routing metadata types and validation
//! - Migration repeatability validation
//! - Consumer-lag metric types with bounded settings
//!
//! # BLOCKER
//!
//! No live ClickHouse instance on this host. All query logic is validated
//! via in-memory mocks and fixtures. Live ClickHouse integration re-opens
//! on the declared self-hosted runner.

#![forbid(unsafe_code)]

pub mod consumer;
pub mod dedup;
pub mod dlq;
pub mod error;
pub mod migration;
pub mod query;
pub mod schema;

/// The supported schema major version (mirrors `protocol::SCHEMA_MAJOR`).
pub const SUPPORTED_SCHEMA_MAJOR: u16 = 1;

/// The events.v1 Kafka topic.
pub const EVENTS_TOPIC: &str = "events.v1";

/// The events.dlq.v1 Kafka topic.
pub const DLQ_TOPIC: &str = "events.dlq.v1";

/// Default TTL for events_v1 in days.
pub const DEFAULT_EVENTS_TTL_DAYS: u16 = 30;

/// Default TTL for events_dlq_v1 in days.
pub const DEFAULT_DLQ_TTL_DAYS: u16 = 90;

/// Maximum payload size in bytes (64 KiB).
pub const MAX_PAYLOAD_BYTES: usize = 65536;

/// Bounded consumer lag threshold per partition.
pub const MAX_CONSUMER_LAG_PER_PARTITION: u64 = 10_000;
