// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Smoke CLI for socket lifecycle and DNS user-space decoder correlation.

use std::env;
use std::fs;
use std::io::{Read, Write};
use std::process::ExitCode;

use agent_core::{
    parse_dns_message, SocketFamily, SocketIdentity, SocketTable, SocketTableOpts,
    NAMESPACE_KIND_COUNT,
};

const HELP: &str = "Usage: socket-and-dns-cli dump <input.json> | parse-dns <raw.bin>\n";

fn field(object: &str, name: &str) -> Option<String> {
    let needle = format!("\"{name}\"");
    let start = object.find(&needle)?;
    let tail = object
        .get(start + needle.len()..)?
        .trim_start_matches([' ', ':']);
    if tail.starts_with('"') {
        let end = tail.get(1..)?.find('"')?;
        Some(tail[1..=end].to_owned())
    } else if tail.starts_with('[') {
        let end = tail.find(']')?;
        Some(tail[1..end].to_owned())
    } else {
        Some(tail.split([',', '}']).next()?.trim().to_owned())
    }
}

fn u64v(object: &str, name: &str) -> Result<u64, String> {
    field(object, name)
        .ok_or_else(|| format!("missing {name}"))
        .and_then(|v| v.parse().map_err(|e| format!("invalid {name}: {e}")))
}

fn i64v(object: &str, name: &str) -> Result<i64, String> {
    field(object, name)
        .ok_or_else(|| format!("missing {name}"))
        .and_then(|v| v.parse().map_err(|e| format!("invalid {name}: {e}")))
}

fn namespace_tuple(object: &str) -> Result<[u64; NAMESPACE_KIND_COUNT], String> {
    let raw = field(object, "namespace_tuple").unwrap_or_default();
    let parts: Vec<&str> = raw.split(',').map(str::trim).collect();
    if parts.len() != NAMESPACE_KIND_COUNT {
        return Err(format!(
            "namespace_tuple needs {} entries",
            NAMESPACE_KIND_COUNT
        ));
    }
    let mut out = [0_u64; NAMESPACE_KIND_COUNT];
    for (slot, part) in out.iter_mut().zip(parts) {
        *slot = part
            .parse()
            .map_err(|e| format!("invalid tuple entry: {e}"))?;
    }
    Ok(out)
}

fn dst_ip(object: &str) -> Result<[u8; 16], String> {
    let raw = field(object, "dst_ip").unwrap_or_else(|| "0.0.0.0".to_owned());
    let parts: Vec<&str> = raw.split('.').collect();
    if parts.len() != 4 {
        return Err("dst_ip must be 4 octets".to_owned());
    }
    let mut out = [0_u8; 16];
    for (i, p) in parts.iter().enumerate() {
        out[i] = p.parse().map_err(|e| format!("invalid octet: {e}"))?;
    }
    Ok(out)
}

fn family(object: &str) -> SocketFamily {
    match field(object, "family").as_deref() {
        Some("INET6") => SocketFamily::INET6,
        Some("UNIX") => SocketFamily::UNIX,
        Some("OTHER") => SocketFamily::OTHER,
        _ => SocketFamily::INET,
    }
}

fn identity(object: &str) -> Result<SocketIdentity, String> {
    let cgroup_id = u64v(object, "cgroup_id")?;
    let tuple = namespace_tuple(object)?;
    let cookie_str = field(object, "cookie").ok_or_else(|| "missing cookie".to_owned())?;
    let cookie = if let Some(hex) = cookie_str.strip_prefix("0x") {
        u64::from_str_radix(hex, 16).map_err(|e| format!("invalid cookie: {e}"))?
    } else {
        cookie_str
            .parse()
            .map_err(|e| format!("invalid cookie: {e}"))?
    };
    Ok(SocketIdentity::new(cgroup_id, tuple, cookie))
}

fn dns_bytes(object: &str) -> Result<Vec<u8>, String> {
    let raw = field(object, "bytes").unwrap_or_default();
    let cleaned: String = raw.chars().filter(|c| !c.is_whitespace()).collect();
    let chars: Vec<char> = cleaned.chars().collect();
    let mut out = Vec::with_capacity(chars.len() / 2);
    let mut i = 0;
    while i + 1 < chars.len() {
        let hex = format!("{}{}", chars[i], chars[i + 1]);
        let value = u8::from_str_radix(&hex, 16).map_err(|e| format!("bad hex: {e}"))?;
        out.push(value);
        i += 2;
    }
    Ok(out)
}

fn apply(table: &mut SocketTable, object: &str) -> Result<(), String> {
    let kind = field(object, "type").ok_or_else(|| "missing event type".to_owned())?;
    match kind.as_str() {
        "connect_attempt" => {
            let id = identity(object)?;
            let pid_tgid = u64v(object, "pid_tgid")?;
            let dst = dst_ip(object)?;
            let dst_port = u64v(object, "dst_port")? as u16;
            let family = family(object);
            let seq = u64v(object, "seq")?;
            table.on_connect_attempt(id, pid_tgid, dst, dst_port, family, seq);
        }
        "connect_result" => {
            let id = identity(object)?;
            let result = i64v(object, "result")? as i32;
            let seq = u64v(object, "seq")?;
            table.on_connect_result(id, result, seq);
        }
        "accept" => {
            let id = identity(object)?;
            let peer_pid_tgid = u64v(object, "peer_pid_tgid")?;
            let fd = i64v(object, "fd")? as i32;
            let seq = u64v(object, "seq")?;
            table.on_accept(id, peer_pid_tgid, fd, seq);
        }
        "close" => {
            let id = identity(object)?;
            let seq = u64v(object, "seq")?;
            table.on_close(id, seq);
        }
        "dns" => {}
        other => return Err(format!("unknown event type {other}")),
    }
    Ok(())
}

fn entry_to_json(entry: &agent_core::SocketEntry) -> String {
    let family = match entry.family {
        SocketFamily::INET => "INET",
        SocketFamily::INET6 => "INET6",
        SocketFamily::UNIX => "UNIX",
        SocketFamily::OTHER => "OTHER",
    };
    let state = match entry.state {
        agent_core::SocketState::Connecting => "Connecting",
        agent_core::SocketState::Connected => "Connected",
        agent_core::SocketState::Accepting => "Accepting",
        agent_core::SocketState::Accepted => "Accepted",
        agent_core::SocketState::Closed => "Closed",
    };
    let ns = entry
        .identity
        .namespace_tuple
        .iter()
        .map(|v| v.to_string())
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "{{\"cookie\":\"{:#x}\",\"cgroup_id\":{},\"namespace_tuple\":[{}],\"generation\":{},\"family\":\"{}\",\"state\":\"{}\",\"connect_attempt_seq\":{},\"connect_result_seq\":{},\"accept_result_seq\":{},\"fd\":{}}}",
        entry.identity.cookie, entry.identity.cgroup_id, ns, entry.generation, family, state,
        entry.connect_attempt_seq, entry.connect_result_seq, entry.accept_result_seq, entry.fd
    )
}

fn dns_to_json(raw: &[u8]) -> String {
    match parse_dns_message(raw) {
        Ok(message) => {
            let questions = message
                .questions
                .iter()
                .map(|q| {
                    format!(
                        "{{\"qname\":\"{}\",\"qtype\":{},\"qclass\":{}}}",
                        q.qname.replace('\\', "\\\\").replace('"', "\\\""),
                        q.qtype,
                        q.qclass
                    )
                })
                .collect::<Vec<_>>()
                .join(",");
            format!(
                "{{\"id\":{},\"qd_count\":{},\"an_count\":{},\"truncation_reason\":\"{:?}\",\"questions\":[{questions}],\"answer_count\":{}}}",
                message.id,
                message.qd_count,
                message.an_count,
                message.truncation_reason,
                message.answers.len()
            )
        }
        Err(error) => format!(
            "{{\"error\":\"{:?}\",\"truncation_reason\":\"{:?}\"}}",
            error,
            agent_core::truncation_reason_from_error(&error)
        ),
    }
}

fn dump_command(path: &str) -> Result<String, String> {
    let input = fs::read_to_string(path).map_err(|e| format!("cannot read {path}: {e}"))?;
    let mut table = SocketTable::new(SocketTableOpts::default());
    let mut dns_messages: Vec<Vec<u8>> = Vec::new();
    for object in input.split('{').skip(1).filter_map(|c| c.split('}').next()) {
        let kind = field(object, "type").ok_or_else(|| "missing type".to_owned())?;
        if kind == "dns" {
            dns_messages.push(dns_bytes(object)?);
        } else {
            apply(&mut table, object)?;
        }
    }
    let socket_json = table
        .snapshot()
        .iter()
        .map(entry_to_json)
        .collect::<Vec<_>>()
        .join(",");
    let dns_json = dns_messages
        .iter()
        .map(|raw| dns_to_json(raw))
        .collect::<Vec<_>>()
        .join(",");
    Ok(format!(
        "{{\"socket_table\":[{socket_json}],\"dns_messages\":[{dns_json}]}}"
    ))
}

fn parse_dns_command() -> Result<String, String> {
    let mut raw = Vec::new();
    std::io::stdin()
        .read_to_end(&mut raw)
        .map_err(|e| format!("cannot read stdin: {e}"))?;
    if raw.len() > 4 * 1024 {
        return Err(format!(
            "raw DNS payload {} bytes exceeds 4 KiB cap",
            raw.len()
        ));
    }
    Ok(dns_to_json(&raw))
}

fn main() -> ExitCode {
    let mut args = env::args().skip(1);
    let command = args.next();
    let input = args.next();
    let result = match (command.as_deref(), input.as_deref()) {
        (Some("dump"), Some(path)) => dump_command(path),
        (Some("parse-dns"), _) => parse_dns_command(),
        _ => Err(format!("{HELP}invalid args: {command:?} {input:?}")),
    };
    match result {
        Ok(output) => {
            let stdout = std::io::stdout();
            let mut handle = stdout.lock();
            let _ = handle.write_all(output.as_bytes());
            let _ = handle.write_all(b"\n");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}
