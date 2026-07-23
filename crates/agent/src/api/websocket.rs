// SPDX-License-Identifier: Apache-2.0 OR MIT
//! WebSocket live-event streaming.

use futures_util::{SinkExt, StreamExt};
use http_body_util::Full;
use hyper::body::{Bytes, Incoming};
use hyper::header::{CONNECTION, SEC_WEBSOCKET_ACCEPT, SEC_WEBSOCKET_KEY, UPGRADE};
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::sync::broadcast;
use tokio_tungstenite::tungstenite::handshake::derive_accept_key;
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
use tokio_tungstenite::tungstenite::protocol::{CloseFrame, Role};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;

use super::helpers::error_response;
use super::{ApiState, WS_SEND_TIMEOUT};

pub(crate) fn is_ws_upgrade(req: &Request<Incoming>) -> bool {
    let upgrade = req
        .headers()
        .get(UPGRADE)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.eq_ignore_ascii_case("websocket"))
        .unwrap_or(false);
    let connection = req
        .headers()
        .get(CONNECTION)
        .and_then(|v| v.to_str().ok())
        .map(|v| {
            v.split(',')
                .any(|tok| tok.trim().eq_ignore_ascii_case("upgrade"))
        })
        .unwrap_or(false);
    upgrade && connection
}

pub(crate) fn websocket(req: Request<Incoming>, state: &ApiState) -> Response<Full<Bytes>> {
    let key = req
        .headers()
        .get(SEC_WEBSOCKET_KEY)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    if key.is_empty() || !is_ws_upgrade(&req) {
        return error_response(
            StatusCode::BAD_REQUEST,
            "websocket_error",
            "missing or invalid WebSocket upgrade headers",
        );
    }
    let accept = derive_accept_key(key.as_bytes());
    let broadcaster = state.broadcaster.clone();
    tokio::spawn(async move {
        match hyper::upgrade::on(req).await {
            Ok(upgraded) => {
                let io = TokioIo::new(upgraded);
                let mut ws = WebSocketStream::from_raw_socket(io, Role::Server, None).await;
                serve_ws(&mut ws, broadcaster).await;
            }
            Err(e) => tracing::debug!(error = %e, "websocket upgrade failed"),
        }
    });
    Response::builder()
        .status(StatusCode::SWITCHING_PROTOCOLS)
        .header(UPGRADE, "websocket")
        .header(CONNECTION, "upgrade")
        .header(SEC_WEBSOCKET_ACCEPT, accept)
        .body(Full::new(Bytes::new()))
        .expect("static header names are valid")
}

/// Forward live events to a single WebSocket consumer. A consumer that falls
/// behind the bounded broadcast channel by more than its capacity is shed with
/// a typed close frame (1013 Try Again Later) — the server keeps running.
async fn serve_ws(
    ws: &mut WebSocketStream<TokioIo<hyper::upgrade::Upgraded>>,
    broadcaster: broadcast::Sender<String>,
) {
    let mut rx = broadcaster.subscribe();
    loop {
        tokio::select! {
            msg = rx.recv() => match msg {
                Ok(json) => {
                    // Bounded send: a consumer that does not drain its socket
                    // is shed after WS_SEND_TIMEOUT instead of stalling the
                    // server.
                    match tokio::time::timeout(WS_SEND_TIMEOUT, ws.send(Message::Text(json))).await
                    {
                        Ok(Ok(())) => {}
                        Ok(Err(_)) => break,
                        Err(_elapsed) => {
                            tracing::warn!("shedding slow websocket consumer (send timeout)");
                            let _ = ws
                                .send(Message::Close(Some(CloseFrame {
                                    code: CloseCode::Iana(1013),
                                    reason: "slow consumer shed".into(),
                                })))
                                .await;
                            break;
                        }
                    }
                }
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    tracing::warn!(lagged = n, "shedding slow websocket consumer (lagged)");
                    let _ = ws
                        .send(Message::Close(Some(CloseFrame {
                            code: CloseCode::Iana(1013),
                            reason: "slow consumer shed".into(),
                        })))
                        .await;
                    break;
                }
                Err(broadcast::error::RecvError::Closed) => break,
            },
            incoming = ws.next() => match incoming {
                Some(Ok(Message::Close(_))) | None => break,
                Some(Err(_)) => break,
                Some(Ok(_)) => {} // ignore client text/ping; the stream is server-push
            },
        }
    }
}
