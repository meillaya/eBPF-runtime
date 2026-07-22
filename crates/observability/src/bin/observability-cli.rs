// SPDX-License-Identifier: Apache-2.0 OR MIT
//! CLI smoke test for the observability subsystem.
//!
//! Usage:
//!   observability-cli serve --addr <addr>      Start the observability server
//!   observability-cli health --addr <addr>     Query the health endpoint
//!   observability-cli readiness --addr <addr>  Query the readiness endpoint
//!   observability-cli metrics --addr <addr>    Query the metrics endpoint

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::Duration;

use observability::server::ObservabilityServer;
use observability::{logging, AttachState, MetricsRegistry, PolicyMode, Program, Source};

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        eprintln!("Usage: observability-cli <serve|health|readiness|metrics> --addr <addr>");
        std::process::exit(1);
    }

    let command = args[1].as_str();
    let addr = parse_addr(&args);

    match command {
        "serve" => {
            let _ = logging::init_logging(tracing::Level::INFO);
            let registry = Arc::new(MetricsRegistry::new());

            // Initialize with all sensors attached and storage available
            // for the smoke test server.
            for program in Program::ALL {
                registry.set_program_state(program, AttachState::Attached);
            }
            registry.set_storage_available(true);
            registry.set_policy_version(1);
            registry.set_policy_mode(PolicyMode::Audit);

            // Set some baseline metrics.
            for source in Source::ALL {
                registry.increment_source_attempts(source);
            }

            let server = ObservabilityServer::new(registry, addr);
            tracing::info!(addr = %addr, "starting observability server");

            // Run the async server in a tokio runtime.
            let rt = tokio::runtime::Runtime::new().expect("create runtime");
            rt.block_on(async {
                if let Err(e) = server.serve().await {
                    eprintln!("server error: {e}");
                    std::process::exit(1);
                }
            });
        }
        "health" => {
            http_get(addr, "/healthz");
        }
        "readiness" => {
            http_get(addr, "/readyz");
        }
        "metrics" => {
            http_get(addr, "/metrics");
        }
        _ => {
            eprintln!("Unknown command: {command}");
            eprintln!("Usage: observability-cli <serve|health|readiness|metrics> --addr <addr>");
            std::process::exit(1);
        }
    }
}

/// Perform a simple HTTP GET request using a raw TCP stream.
fn http_get(addr: SocketAddr, path: &str) {
    let mut stream = match TcpStream::connect(addr) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error connecting to {addr}: {e}");
            std::process::exit(1);
        }
    };

    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("set timeout");

    let request = format!("GET {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n");
    stream.write_all(request.as_bytes()).expect("write request");

    let mut response = String::new();
    stream.read_to_string(&mut response).expect("read response");

    if let Some(pos) = response.find("\r\n\r\n") {
        let headers = &response[..pos];
        let body = &response[pos + 4..];
        let status_line = headers.lines().next().unwrap_or("HTTP/1.1 ???");
        println!("{status_line}");
        println!("{body}");
    } else {
        println!("{response}");
    }
}

/// Parse the `--addr` argument from the CLI args.
fn parse_addr(args: &[String]) -> SocketAddr {
    for i in 0..args.len() {
        if args[i] == "--addr" {
            if i + 1 < args.len() {
                return args[i + 1].parse().unwrap_or_else(|e| {
                    eprintln!("invalid address '{}': {e}", args[i + 1]);
                    std::process::exit(1);
                });
            }
        }
    }
    // Default address.
    "127.0.0.1:9464".parse().expect("valid default addr")
}
