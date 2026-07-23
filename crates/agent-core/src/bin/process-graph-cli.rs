// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Smoke CLI for replaying process-generation fixtures.

use agent_core::{AncestryStatus, NodeState, ProcessGraph, ProcessGraphOpts, ProcessIdentity};
use std::env;
use std::fs;
use std::process::ExitCode;

fn field<'a>(object: &'a str, name: &str) -> Option<&'a str> {
    let needle = format!("\"{name}\"");
    let start = object.find(&needle)?;
    let tail = object
        .get(start + needle.len()..)?
        .trim_start_matches([' ', ':']);
    if tail.starts_with('"') {
        let end = tail.get(1..)?.find('"')? + 1;
        tail.get(1..end)
    } else {
        Some(tail.split([',', '}']).next()?.trim())
    }
}
fn number(object: &str, name: &str) -> Result<u64, String> {
    field(object, name)
        .ok_or_else(|| format!("missing {name}"))
        .and_then(|value| {
            value
                .parse()
                .map_err(|error| format!("invalid {name}: {error}"))
        })
}
fn boot(object: &str) -> Result<[u8; 16], String> {
    let text = field(object, "boot_id").ok_or_else(|| "missing boot_id".to_owned())?;
    let mut boot_id = [0; 16];
    if text.len() != 32 {
        return Err("boot_id must be 32 hexadecimal characters".to_owned());
    }
    for (index, slot) in boot_id.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&text[index * 2..index * 2 + 2], 16)
            .map_err(|error| format!("invalid boot_id: {error}"))?;
    }
    Ok(boot_id)
}
fn identity(object: &str, pid_name: &str, start_name: &str) -> Result<ProcessIdentity, String> {
    Ok(ProcessIdentity {
        boot_id: boot(object)?,
        pid: number(object, pid_name)?
            .try_into()
            .map_err(|_| "pid out of range".to_owned())?,
        start_time: number(object, start_name)?,
    })
}
fn json_escape(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}
fn node_json(graph: &ProcessGraph, node: &agent_core::ProcessNode) -> String {
    let parent = node.parent.map_or_else(
        || "null".to_owned(),
        |parent| {
            format!(
                "{{\"pid\":{},\"start_time\":{}}}",
                parent.pid, parent.start_time
            )
        },
    );
    let path = node.exec_path.as_deref().map_or_else(
        || "null".to_owned(),
        |path| format!("\"{}\"", json_escape(path)),
    );
    let state = match node.state {
        NodeState::Alive => "Alive",
        NodeState::Exited => "Exited",
        NodeState::Reaped => "Reaped",
    };
    let ancestry = match graph.ancestry_status(&node.identity) {
        AncestryStatus::Known => "Known",
        AncestryStatus::Missing => "Missing",
        AncestryStatus::AncestryIncomplete => "AncestryIncomplete",
        AncestryStatus::DuplicateFork => "DuplicateFork",
    };
    format!("{{\"boot_id\":\"{}\",\"pid\":{},\"start_time\":{},\"parent\":{},\"exec_path\":{},\"exit_code\":{},\"thread_flag\":{},\"state\":\"{}\",\"ancestry_status\":\"{}\"}}", node.identity.boot_id.iter().map(|byte| format!("{byte:02x}")).collect::<String>(), node.identity.pid, node.identity.start_time, parent, path, node.exit_code.map_or_else(|| "null".to_owned(), |code| code.to_string()), node.thread_flag, state, ancestry)
}
fn load(path: &str) -> Result<ProcessGraph, String> {
    let input = fs::read_to_string(path).map_err(|error| format!("cannot read {path}: {error}"))?;
    let mut graph = ProcessGraph::new(ProcessGraphOpts::default());
    for object in input
        .split('{')
        .skip(1)
        .filter_map(|chunk| chunk.split('}').next())
    {
        let kind = field(object, "type").ok_or_else(|| "missing event type".to_owned())?;
        let process_identity = identity(object, "pid", "start_time")?;
        let seq = number(object, "seq")?;
        match kind {
            "fork" => {
                let parent = identity(object, "parent_pid", "parent_start_time")?;
                graph.on_fork(process_identity, parent, seq);
            }
            "exec" => {
                let path =
                    field(object, "exec_path").ok_or_else(|| "missing exec_path".to_owned())?;
                graph.on_exec(
                    process_identity,
                    path.to_owned(),
                    field(object, "argv").unwrap_or("").as_bytes().to_vec(),
                    seq,
                );
            }
            "exit" => {
                let code = number(object, "exit_code")?
                    .try_into()
                    .map_err(|_| "exit_code out of range".to_owned())?;
                graph.on_exit(process_identity, code, seq);
            }
            other => return Err(format!("unknown event type {other}")),
        }
    }
    Ok(graph)
}
fn main() -> ExitCode {
    let mut args = env::args().skip(1);
    let command = args.next();
    let input = args.next();
    let result = match (command.as_deref(), input.as_deref()) {
        (Some("dump"), Some(path)) => { let output = args.skip_while(|arg| arg != "--output").nth(1).unwrap_or_else(|| "json".to_owned()); load(path).map(|graph| if output == "text" { graph.snapshot().iter().map(|node| format!("{} {:?}\n", node.identity.pid, node.state)).collect() } else { format!("[{}]", graph.snapshot().iter().map(|node| node_json(&graph, node)).collect::<Vec<_>>().join(",")) }) }
        (Some("path"), Some(path)) => { let pid = args.skip_while(|arg| arg != "--pid").nth(1).ok_or_else(|| "missing --pid".to_owned()).and_then(|value| value.parse::<u32>().map_err(|error| error.to_string())); load(path).and_then(|graph| { let pid = pid?; let identity = graph.snapshot().into_iter().find(|node| node.identity.pid == pid).ok_or_else(|| "pid not found".to_owned())?; graph.path(&identity.identity).map(|path| format!("[{}]", path.iter().map(|id| format!("{{\"pid\":{},\"start_time\":{}}}", id.pid, id.start_time)).collect::<Vec<_>>().join(","))).ok_or_else(|| "path unavailable".to_owned()) }) }
        _ => Err("usage: process-graph-cli dump <input.json> --output json|text | path <input.json> --pid <pid>".to_owned()),
    };
    match result {
        Ok(output) => {
            println!("{output}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}
