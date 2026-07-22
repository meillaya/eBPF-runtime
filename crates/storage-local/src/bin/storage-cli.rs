// SPDX-License-Identifier: Apache-2.0 OR MIT
//! storage-cli: smoke-test CLI for the storage-local crate.
//!
//! Usage:
//!   storage-cli open <db_path> --key <key_path>
//!   storage-cli insert <db_path> --key <key_path> --event <event.json>
//!   storage-cli query <db_path> --key <key_path> --kind <kind> --limit <limit>
//!   storage-cli ack <db_path> --key <key_path> --event-id <event_id>
//!   storage-cli retention <db_path> --key <key_path>

use std::path::Path;
use std::process;

use storage_local::{load_key_from_file, EventQuery, LocalStorage};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("usage: storage-cli <open|insert|query|ack|retention> <db_path> --key <key_path> [options]");
        process::exit(1);
    }

    let command = args[1].as_str();
    let result = match command {
        "open" => cmd_open(&args[2..]),
        "insert" => cmd_insert(&args[2..]),
        "query" => cmd_query(&args[2..]),
        "ack" => cmd_ack(&args[2..]),
        "retention" => cmd_retention(&args[2..]),
        other => {
            eprintln!("unknown command: {other}");
            process::exit(1);
        }
    };

    if let Err(e) = result {
        eprintln!("error: {e}");
        process::exit(1);
    }
}

fn parse_db_and_key(args: &[String]) -> Result<(String, String), String> {
    if args.is_empty() {
        return Err("missing <db_path>".to_string());
    }
    let db_path = args[0].clone();
    let key_path = get_flag(args, "--key")?;
    Ok((db_path, key_path))
}

fn get_flag(args: &[String], flag: &str) -> Result<String, String> {
    for (i, arg) in args.iter().enumerate() {
        if arg == flag {
            if i + 1 < args.len() {
                return Ok(args[i + 1].clone());
            }
            return Err(format!("missing value for {flag}"));
        }
    }
    Err(format!("missing {flag}"))
}

fn get_flag_opt(args: &[String], flag: &str) -> Option<String> {
    get_flag(args, flag).ok()
}

fn open_storage(db_path: &str, key_path: &str) -> Result<LocalStorage, String> {
    let key = load_key_from_file(Path::new(key_path)).map_err(|e| e.to_string())?;
    let storage = LocalStorage::open(Path::new(db_path), &key).map_err(|e| e.to_string())?;
    storage.run_migrations().map_err(|e| e.to_string())?;
    Ok(storage)
}

fn cmd_open(args: &[String]) -> Result<(), String> {
    let (db_path, key_path) = parse_db_and_key(args)?;
    let storage = open_storage(&db_path, &key_path)?;
    let version = storage.schema_version().map_err(|e| e.to_string())?;
    println!("schema_version: {version}");
    Ok(())
}

fn cmd_insert(args: &[String]) -> Result<(), String> {
    let (db_path, key_path) = parse_db_and_key(args)?;
    let event_path = get_flag(args, "--event")?;
    let event_json = std::fs::read_to_string(&event_path)
        .map_err(|e| format!("failed to read event file: {e}"))?;
    let event_value: serde_json::Value = serde_json::from_str(&event_json)
        .map_err(|e| format!("invalid event JSON: {e}"))?;
    let event = storage_local::redacted_event_from_json_value(&event_value)
        .map_err(|e| format!("failed to parse event: {e}"))?;
    let storage = open_storage(&db_path, &key_path)?;
    let event_id = storage.insert_event(&event).map_err(|e| e.to_string())?;
    println!("event_id: {event_id}");
    Ok(())
}

fn cmd_query(args: &[String]) -> Result<(), String> {
    let (db_path, key_path) = parse_db_and_key(args)?;
    let kind: Option<i32> = get_flag_opt(args, "--kind").and_then(|k| k.parse().ok());
    let limit: Option<usize> = get_flag_opt(args, "--limit").and_then(|l| l.parse().ok());
    let storage = open_storage(&db_path, &key_path)?;
    let query = EventQuery {
        event_kind: kind,
        limit,
        ..Default::default()
    };
    let events = storage.query_events(&query).map_err(|e| e.to_string())?;
    let json_events: Vec<serde_json::Value> = events.iter().map(|e| e.to_json()).collect();
    println!("{}", serde_json::to_string_pretty(&json_events).unwrap_or_default());
    Ok(())
}

fn cmd_ack(args: &[String]) -> Result<(), String> {
    let (db_path, key_path) = parse_db_and_key(args)?;
    let event_id = get_flag(args, "--event-id")?;
    let storage = open_storage(&db_path, &key_path)?;
    storage.ack_event(&event_id).map_err(|e| e.to_string())?;
    println!("acked: {event_id}");
    Ok(())
}

fn cmd_retention(args: &[String]) -> Result<(), String> {
    let (db_path, key_path) = parse_db_and_key(args)?;
    let storage = open_storage(&db_path, &key_path)?;
    let result = storage.apply_retention().map_err(|e| e.to_string())?;
    println!(
        "retention: deleted_events={}, deleted_batches={}, db_size_bytes={}",
        result.deleted_events, result.deleted_batches, result.db_size_bytes
    );
    Ok(())
}
