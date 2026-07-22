// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Query types and query methods for LocalStorage.

use privacy::RedactedEvent;

use crate::error::StorageError;
use crate::serialize::deserialize_event;
use crate::storage::LocalStorage;

/// Filter for querying events.
#[derive(Debug, Clone, Default)]
pub struct EventQuery {
    pub event_kind: Option<i32>,
    pub created_at_from: Option<i64>,
    pub created_at_to: Option<i64>,
    pub acked: Option<bool>,
    pub limit: Option<usize>,
}

/// Filter for querying the outbox.
#[derive(Debug, Clone, Default)]
pub struct OutboxQuery {
    pub acked: Option<bool>,
    pub created_at_from: Option<i64>,
    pub created_at_to: Option<i64>,
    pub limit: Option<usize>,
}

/// A single outbox entry (batch).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboxEntry {
    pub batch_id: String,
    pub event_ids: Vec<String>,
    pub created_at: i64,
    pub acked: bool,
    pub acked_at: Option<i64>,
}

impl LocalStorage {
    /// Query events from the events table with optional filters.
    pub fn query_events(&self, query: &EventQuery) -> Result<Vec<RedactedEvent>, StorageError> {
        let conn = self.conn.lock();
        let mut sql = String::from("SELECT payload FROM events WHERE 1=1");
        let mut params: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();

        if let Some(kind) = query.event_kind {
            sql.push_str(" AND event_kind = ?");
            params.push(Box::new(kind));
        }
        if let Some(from) = query.created_at_from {
            sql.push_str(" AND created_at >= ?");
            params.push(Box::new(from));
        }
        if let Some(to) = query.created_at_to {
            sql.push_str(" AND created_at <= ?");
            params.push(Box::new(to));
        }
        if let Some(acked) = query.acked {
            sql.push_str(" AND acked = ?");
            params.push(Box::new(acked as i32));
        }
        sql.push_str(" ORDER BY created_at ASC");
        if let Some(limit) = query.limit {
            sql.push_str(" LIMIT ?");
            params.push(Box::new(limit as i64));
        }

        let param_refs: Vec<&dyn rusqlite::types::ToSql> =
            params.iter().map(|p| p.as_ref()).collect();
        let mut stmt = conn
            .prepare(&sql)
            .map_err(|e| StorageError::QueryFailed(e.to_string()))?;
        let rows = stmt
            .query_map(param_refs.as_slice(), |row| {
                let payload: Vec<u8> = row.get(0)?;
                Ok(payload)
            })
            .map_err(|e| StorageError::QueryFailed(e.to_string()))?;

        let mut events = Vec::new();
        for row in rows {
            let payload = row.map_err(|e| StorageError::QueryFailed(e.to_string()))?;
            let event = deserialize_event(&payload)
                .map_err(|e| StorageError::QueryFailed(e.to_string()))?;
            events.push(event);
        }
        Ok(events)
    }

    /// Query batches from the outbox table with optional filters.
    pub fn query_outbox(&self, query: &OutboxQuery) -> Result<Vec<OutboxEntry>, StorageError> {
        let conn = self.conn.lock();
        let mut sql = String::from("SELECT batch_id, event_ids, created_at, acked, acked_at FROM outbox WHERE 1=1");
        let mut params: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();

        if let Some(acked) = query.acked {
            sql.push_str(" AND acked = ?");
            params.push(Box::new(acked as i32));
        }
        if let Some(from) = query.created_at_from {
            sql.push_str(" AND created_at >= ?");
            params.push(Box::new(from));
        }
        if let Some(to) = query.created_at_to {
            sql.push_str(" AND created_at <= ?");
            params.push(Box::new(to));
        }
        sql.push_str(" ORDER BY created_at ASC");
        if let Some(limit) = query.limit {
            sql.push_str(" LIMIT ?");
            params.push(Box::new(limit as i64));
        }

        let param_refs: Vec<&dyn rusqlite::types::ToSql> =
            params.iter().map(|p| p.as_ref()).collect();
        let mut stmt = conn
            .prepare(&sql)
            .map_err(|e| StorageError::QueryFailed(e.to_string()))?;
        let rows = stmt
            .query_map(param_refs.as_slice(), |row| {
                let batch_id: String = row.get(0)?;
                let event_ids_json: String = row.get(1)?;
                let created_at: i64 = row.get(2)?;
                let acked: i32 = row.get(3)?;
                let acked_at: Option<i64> = row.get(4)?;
                Ok((batch_id, event_ids_json, created_at, acked, acked_at))
            })
            .map_err(|e| StorageError::QueryFailed(e.to_string()))?;

        let mut entries = Vec::new();
        for row in rows {
            let (batch_id, event_ids_json, created_at, acked, acked_at) =
                row.map_err(|e| StorageError::QueryFailed(e.to_string()))?;
            let event_ids: Vec<String> =
                serde_json::from_str(&event_ids_json).unwrap_or_default();
            entries.push(OutboxEntry {
                batch_id,
                event_ids,
                created_at,
                acked: acked != 0,
                acked_at,
            });
        }
        Ok(entries)
    }
}
