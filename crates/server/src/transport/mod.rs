use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        ConnectInfo, State,
    },
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use futures_util::{SinkExt, StreamExt};
use relay_wire::transport::{INBOUND_IDLE_DEADLINE_SECS, KEEPALIVE_INTERVAL_SECS};
use relay_wire::{ClientFrame, ServerFrame, MAX_PAYLOAD_BYTES, NO_RECIPIENT_REASON, RELAY_WIRE};
use tokio::sync::{mpsc, Notify};

use crate::ratelimit::{ConnDecision, RateLimiter};
use crate::routing::{ConnHandle, RoutingTable};

/// The largest legitimate frame: a `Send` carrying `MAX_PAYLOAD_BYTES`, which
/// JSON spells as up to three digits and a comma per byte, plus the envelope.
const MAX_FRAME_BYTES: usize = MAX_PAYLOAD_BYTES * 4 + 1024;
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(KEEPALIVE_INTERVAL_SECS);
const INBOUND_IDLE_DEADLINE: Duration = Duration::from_secs(INBOUND_IDLE_DEADLINE_SECS);
const BYTE_LIMIT_RETRY_SECS: u64 = 2;
/// Charged on top of every inbound frame's payload, so frames without one
/// (pings, pongs) still draw on the byte budget.
const FRAME_OVERHEAD_BYTES: usize = 16;
/// Pong echoes waiting for the writer; past it a client pinging faster than
/// it reads loses the excess pongs.
const PONG_BACKLOG: usize = 8;
/// Bound on the graceful-close flush so an unresponsive client can't wedge the
/// connection task after we've decided to drop it.
const CLOSE_FLUSH_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Clone)]
pub struct AppState {
    pub routing: RoutingTable,
    pub server_id: Arc<String>,
    pub rate: Arc<RateLimiter>,
    /// The certificate `/health` reports, with TLS on.
    pub cert: Option<Arc<crate::tls::CertHealth>>,
}

impl AppState {
    pub fn new(routing: RoutingTable, server_id: impl Into<String>, rate: RateLimiter) -> Self {
        Self {
            routing,
            server_id: Arc::new(server_id.into()),
            rate: Arc::new(rate),
            cert: None,
        }
    }

    pub fn with_cert_health(mut self, cert: Arc<crate::tls::CertHealth>) -> Self {
        self.cert = Some(cert);
        self
    }

    /// Fresh routing table with a permissive limiter, for tests and local dev.
    pub fn permissive(server_id: impl Into<String>) -> Self {
        Self {
            routing: RoutingTable::new(),
            server_id: Arc::new(server_id.into()),
            rate: Arc::new(RateLimiter::permissive()),
            cert: None,
        }
    }
}

pub async fn ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Response {
    let ip = state.rate.client_ip(&headers, peer.ip());
    if let ConnDecision::Reject { retry_after_secs } = state.rate.check_connection(ip) {
        tracing::warn!(
            retry_after_secs,
            "ws upgrade rejected: connection rate limit"
        );
        return (
            StatusCode::TOO_MANY_REQUESTS,
            [(header::RETRY_AFTER, retry_after_secs.to_string())],
            "connection rate limit exceeded",
        )
            .into_response();
    }
    ws.max_message_size(MAX_FRAME_BYTES)
        .on_upgrade(move |socket| handle_connection(socket, state, ip))
}

async fn handle_connection(socket: WebSocket, state: AppState, ip: IpAddr) {
    let conn_id = state.routing.next_conn_id();
    tracing::debug!(conn_id, "ws connection upgraded");

    let (mut sink, mut stream) = socket.split();
    let (tx, mut rx) = mpsc::channel::<ServerFrame>(RoutingTable::outbound_capacity());
    // Control frames (pong echoes) ride a side channel into the writer:
    // the reader owns incoming frames and has no sink access.
    let (ctrl_tx, mut ctrl_rx) = mpsc::channel::<Message>(PONG_BACKLOG);
    let kill = Arc::new(Notify::new());

    state
        .routing
        .attach(ConnHandle {
            id: conn_id,
            send: tx.clone(),
            kill: kill.clone(),
        })
        .await;

    let _ = tx
        .send(ServerFrame::Hello {
            server_id: state.server_id.as_ref().clone(),
            protocol_version: RELAY_WIRE.version,
            app_version: env!("APP_VERSION").to_string(),
            min_client_version: RELAY_WIRE.min,
        })
        .await;

    let mut writer = tokio::spawn(async move {
        let mut ping = tokio::time::interval(KEEPALIVE_INTERVAL);
        ping.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                next = rx.recv() => {
                    let Some(frame) = next else { break };
                    let bytes = match serde_json::to_vec(&frame) {
                        Ok(b) => b,
                        Err(e) => {
                            tracing::warn!(?e, "server frame encode failed");
                            continue;
                        }
                    };
                    if sink.send(Message::Binary(bytes.into())).await.is_err() {
                        break;
                    }
                }
                Some(m) = ctrl_rx.recv() => {
                    if sink.send(m).await.is_err() {
                        break;
                    }
                }
                _ = ping.tick() => {
                    if sink.send(Message::Ping(Vec::new().into())).await.is_err() {
                        break;
                    }
                }
            }
        }
        let _ = sink.close().await;
    });

    // Some(retry) once we decide to shed this connection for its own byte rate.
    let mut rate_limited: Option<u64> = None;
    let mut greeted = false;
    loop {
        let msg = tokio::select! {
            _ = kill.notified() => {
                tracing::warn!(conn_id, "connection killed: outbound backlog overflow");
                break;
            }
            msg = tokio::time::timeout(INBOUND_IDLE_DEADLINE, stream.next()) => match msg {
                Err(_) => {
                    tracing::warn!(conn_id, "connection idle past the keep-alive deadline; closing");
                    break;
                }
                Ok(Some(m)) => m,
                Ok(None) => break,
            },
        };
        let msg = match msg {
            Ok(Message::Close(_)) | Err(_) => break,
            Ok(m) => m,
        };
        let payload_len = match &msg {
            Message::Binary(b) => b.len(),
            Message::Text(s) => s.len(),
            Message::Ping(p) | Message::Pong(p) => p.len(),
            Message::Close(_) => 0,
        };
        if !state.rate.consume(ip, payload_len + FRAME_OVERHEAD_BYTES) {
            tracing::warn!(conn_id, "connection shed: byte rate limit exceeded");
            rate_limited = Some(BYTE_LIMIT_RETRY_SECS);
            break;
        }
        let bytes: Vec<u8> = match msg {
            Message::Binary(b) => b.to_vec(),
            Message::Text(s) => s.as_bytes().to_vec(),
            Message::Ping(payload) => {
                // Echo the client's keepalive so it can measure RTT.
                let _ = ctrl_tx.try_send(Message::Pong(payload));
                continue;
            }
            Message::Pong(_) | Message::Close(_) => continue,
        };

        let frame: ClientFrame = match serde_json::from_slice(&bytes) {
            Ok(f) => f,
            Err(e) => {
                let _ = tx
                    .send(ServerFrame::Error {
                        tag: None,
                        reason: format!("bad frame: {e}"),
                    })
                    .await;
                continue;
            }
        };

        match frame {
            ClientFrame::Hello { wire, app_version } if !greeted => {
                if let Err(refusal) = RELAY_WIRE.check(wire) {
                    tracing::info!(conn_id, ?wire, %app_version, ?refusal, "client refused: wire version");
                    break;
                }
                tracing::debug!(conn_id, %app_version, ?wire, "client hello");
                greeted = true;
            }
            ClientFrame::Hello { .. } => {}
            _ if !greeted => {
                tracing::info!(conn_id, "client refused: no hello (wire 1 or older)");
                break;
            }
            ClientFrame::Register { tag } => {
                let to_notify = match state.routing.register(conn_id, tag).await {
                    Ok(to_notify) => to_notify,
                    Err(refusal) => {
                        tracing::debug!(conn_id, ?refusal, "register refused");
                        let _ = tx
                            .send(ServerFrame::Error {
                                tag: Some(tag),
                                reason: refusal.reason().into(),
                            })
                            .await;
                        continue;
                    }
                };
                tracing::trace!(conn_id, ?tag, "tag registered");
                if to_notify.len() > 1 {
                    for r in to_notify {
                        let _ = r.send.try_send(ServerFrame::PeerArrived { tag });
                    }
                }
            }
            ClientFrame::Unregister { tag } => {
                state.routing.unregister(conn_id, tag).await;
                tracing::trace!(conn_id, ?tag, "tag unregistered");
            }
            ClientFrame::Send { tag, payload } => {
                if payload.len() > MAX_PAYLOAD_BYTES {
                    tracing::debug!(
                        conn_id,
                        len = payload.len(),
                        "connection closed: payload over the Noise ceiling"
                    );
                    break;
                }
                let recipients = state.routing.recipients(conn_id, &tag).await;
                if recipients.is_empty() {
                    tracing::trace!(conn_id, ?tag, "send: no recipients");
                    let _ = tx
                        .send(ServerFrame::Error {
                            tag: Some(tag),
                            reason: NO_RECIPIENT_REASON.into(),
                        })
                        .await;
                    continue;
                }
                for r in recipients {
                    let out = ServerFrame::Recv {
                        tag,
                        payload: payload.clone(),
                    };
                    // A full recipient backlog means that peer can't keep up.
                    // Silently dropping would desync it, so tear it down and let
                    // it reconnect + re-sync instead.
                    if r.send.try_send(out).is_err() {
                        tracing::warn!(
                            conn_id,
                            recipient = r.id,
                            ?tag,
                            "recipient backlog full; disconnecting it to force re-sync"
                        );
                        r.kill.notify_one();
                    }
                }
            }
        }
    }

    if let Some(retry_after_secs) = rate_limited {
        let _ = tx.send(ServerFrame::RateLimited { retry_after_secs }).await;
    }
    state.routing.remove_connection(conn_id).await;
    // Drop our sender so the writer drains any final frame (RateLimited) and
    // closes cleanly; abort only if the client won't read it in time. The
    // inbound side is read and discarded until the client answers the close:
    // a socket closed with unread bytes is reset, and the reset discards the
    // final frame before the client reads it.
    drop(tx);
    let drain = async { while let Some(Ok(_)) = stream.next().await {} };
    if tokio::time::timeout(CLOSE_FLUSH_TIMEOUT, async {
        tokio::join!(&mut writer, drain)
    })
    .await
    .is_err()
    {
        writer.abort();
    }
    tracing::debug!(conn_id, "ws connection closed");
}
