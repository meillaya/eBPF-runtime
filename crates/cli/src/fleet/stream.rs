// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Fleet live event streaming with WebSocket + cursor reconnect.

use clap::Subcommand;
use futures_util::StreamExt;
use tokio_tungstenite::tungstenite::Message;

use super::{auth_header, FleetContext};
use crate::exit_code::ExitCode;

/// Stream subcommands.
#[derive(Debug, Clone, Subcommand)]
pub enum StreamCmd {
    /// Stream live events from the control-plane.
    Live {
        /// Filter by event kind.
        #[arg(long)]
        kind: Option<String>,
        /// Maximum events to receive (0 = unlimited).
        #[arg(long, default_value = "0")]
        limit: usize,
        /// Reconnect with cursor on disconnect.
        #[arg(long, default_value_t = true)]
        reconnect: bool,
        /// Maximum reconnect attempts (0 = unlimited).
        #[arg(long, default_value = "5")]
        max_reconnects: usize,
    },
}

/// Run a stream command.
pub async fn run(cmd: &StreamCmd, ctx: &FleetContext) -> ExitCode {
    match cmd {
        StreamCmd::Live {
            kind,
            limit,
            reconnect,
            max_reconnects,
        } => {
            stream_live(
                ctx,
                kind.as_deref(),
                *limit,
                *reconnect,
                *max_reconnects,
            )
            .await
        }
    }
}

async fn stream_live(
    ctx: &FleetContext,
    kind: Option<&str>,
    limit: usize,
    reconnect: bool,
    max_reconnects: usize,
) -> ExitCode {
    let token = match &ctx.token {
        Some(t) => t.clone(),
        None => {
            eprintln!("Error: not authenticated. Run `cli fleet login` first.");
            return ExitCode::AuthFailure;
        }
    };

    let mut cursor: Option<String> = None;
    let mut received = 0usize;
    let mut reconnects = 0usize;

    loop {
        let ws_url = build_ws_url(&ctx.api_base, &ctx.cluster, kind, cursor.as_deref());

        eprintln!("Connecting to {ws_url}...");

        let connect_result = connect_ws(&ws_url, &token).await;
        let mut ws = match connect_result {
            Ok(ws) => ws,
            Err(e) => {
                eprintln!("Error: WebSocket connection failed: {e}");
                if !reconnect || (max_reconnects > 0 && reconnects >= max_reconnects) {
                    eprintln!("Suggestion: verify the control-plane is reachable");
                    return ExitCode::Error;
                }
                reconnects += 1;
                eprintln!("Reconnecting (attempt {reconnects}/{max_reconnects})...");
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                continue;
            }
        };

        // Read messages from the stream.
        let read_result = read_stream(&mut ws, limit, &mut received, &mut cursor).await;

        match read_result {
            StreamEnd::Complete => return ExitCode::Success,
            StreamEnd::Disconnected => {
                if !reconnect || (max_reconnects > 0 && reconnects >= max_reconnects) {
                    eprintln!("Stream disconnected.");
                    return ExitCode::Error;
                }
                reconnects += 1;
                eprintln!(
                    "Reconnecting with cursor (attempt {reconnects}/{max_reconnects})..."
                );
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            }
            StreamEnd::AuthError => {
                eprintln!("Error: authentication rejected during stream");
                eprintln!("Suggestion: re-run `cli fleet login`");
                return ExitCode::AuthFailure;
            }
        }
    }
}

/// How the stream ended.
enum StreamEnd {
    /// Limit reached or clean close.
    Complete,
    /// Connection dropped; reconnect with cursor.
    Disconnected,
    /// Auth rejected.
    AuthError,
}

/// Build the WebSocket URL with cluster scope and optional filters.
fn build_ws_url(base: &str, cluster: &str, kind: Option<&str>, cursor: Option<&str>) -> String {
    let ws_base = base
        .replace("https://", "wss://")
        .replace("http://", "ws://");
    let mut url = format!("{ws_base}/api/v1/live?cluster_id={cluster}");
    if let Some(k) = kind {
        url.push_str(&format!("&kind={k}"));
    }
    if let Some(c) = cursor {
        url.push_str(&format!("&cursor={c}"));
    }
    url
}

/// Connect to the WebSocket endpoint.
async fn connect_ws(
    url: &str,
    token: &str,
) -> Result<
    tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
    String,
> {
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;

    let mut request = url
        .into_client_request()
        .map_err(|e| format!("invalid URL: {e}"))?;
    request.headers_mut().insert(
        "Authorization",
        auth_header(token).parse().map_err(|e| format!("header: {e}"))?,
    );

    let (ws, _resp) = tokio_tungstenite::connect_async(request)
        .await
        .map_err(|e| format!("connection failed: {e}"))?;

    Ok(ws)
}

/// Read from the WebSocket stream until limit, close, or disconnect.
async fn read_stream(
    ws: &mut tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
    limit: usize,
    received: &mut usize,
    cursor: &mut Option<String>,
) -> StreamEnd {
    while let Some(msg) = ws.next().await {
        match msg {
            Ok(Message::Text(text)) => {
                // Extract cursor from the message if present.
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) {
                    if let Some(c) = v.get("cursor").and_then(|c| c.as_str()) {
                        *cursor = Some(c.to_string());
                    }
                }
                println!("{text}");
                *received += 1;
                if limit > 0 && *received >= limit {
                    return StreamEnd::Complete;
                }
            }
            Ok(Message::Close(_)) => return StreamEnd::Complete,
            Ok(_) => {}
            Err(tokio_tungstenite::tungstenite::Error::ConnectionClosed) => {
                return StreamEnd::Complete;
            }
            Err(e) => {
                let msg = e.to_string();
                if msg.contains("401") || msg.contains("403") {
                    return StreamEnd::AuthError;
                }
                eprintln!("Stream error: {e}");
                return StreamEnd::Disconnected;
            }
        }
    }
    StreamEnd::Disconnected
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ws_url_builds_correctly() {
        let url = build_ws_url("https://cp.test", "cluster-1", None, None);
        assert_eq!(url, "wss://cp.test/api/v1/live?cluster_id=cluster-1");
    }

    #[test]
    fn ws_url_with_kind_and_cursor() {
        let url = build_ws_url(
            "http://localhost:8080",
            "c1",
            Some("DnsPacket"),
            Some("cur-abc"),
        );
        assert_eq!(
            url,
            "ws://localhost:8080/api/v1/live?cluster_id=c1&kind=DnsPacket&cursor=cur-abc"
        );
    }

    #[test]
    fn ws_url_http_to_ws() {
        let url = build_ws_url("http://127.0.0.1:9090", "c1", None, None);
        assert!(url.starts_with("ws://"));
        assert!(!url.contains("http://"));
    }

    #[test]
    fn ws_url_https_to_wss() {
        let url = build_ws_url("https://cp.production.test", "c1", None, None);
        assert!(url.starts_with("wss://"));
        assert!(!url.contains("https://"));
    }
}
