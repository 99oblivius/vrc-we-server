//! Tag-routing integration tests against an ephemeral-port relay.

use std::time::Duration;

use futures::{SinkExt, StreamExt};
use relay_wire::version::VersionRange;
use relay_wire::{ClientFrame, RouteTag, ServerFrame, CLIENT_WIRE, MIN_CLIENT_WIRE, RELAY_WIRE};
use tokio_tungstenite::tungstenite::Message;

use server::{build_router, transport::AppState};

async fn start_relay() -> u16 {
    start_relay_with(AppState::permissive("test-relay")).await
}

async fn start_relay_with(state: AppState) -> u16 {
    let app = build_router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let _ = axum::serve(
            listener,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await;
    });
    // Give the listener a moment to start accepting.
    tokio::time::sleep(Duration::from_millis(20)).await;
    port
}

type Ws =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

async fn connect_raw(port: u16) -> Ws {
    let url = format!("ws://127.0.0.1:{port}/ws");
    let (ws, _) = tokio_tungstenite::connect_async(url).await.unwrap();
    ws
}

/// A connection greeted the way the client greets: `Hello` first.
async fn connect(port: u16) -> Ws {
    let mut ws = connect_raw(port).await;
    send_client(
        &mut ws,
        ClientFrame::Hello {
            wire: CLIENT_WIRE,
            app_version: "test".into(),
        },
    )
    .await;
    ws
}

/// True once the relay closes `ws` (within 2 s).
async fn closed_by_relay(ws: &mut Ws) -> bool {
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            match ws.next().await {
                Some(Ok(Message::Close(_))) | None | Some(Err(_)) => return true,
                Some(Ok(_)) => continue,
            }
        }
    })
    .await
    .unwrap_or(false)
}

async fn next_frame(
    ws: &mut tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
) -> ServerFrame {
    loop {
        let msg = ws.next().await.expect("ws stream closed").unwrap();
        if let Message::Binary(bytes) = msg {
            return serde_json::from_slice(&bytes).unwrap();
        }
    }
}

async fn next_data_frame(
    ws: &mut tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
) -> ServerFrame {
    loop {
        let f = next_frame(ws).await;
        match f {
            ServerFrame::PeerArrived { .. } | ServerFrame::Hello { .. } => continue,
            other => return other,
        }
    }
}

async fn send_client(
    ws: &mut tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
    frame: ClientFrame,
) {
    let bytes = serde_json::to_vec(&frame).unwrap();
    ws.send(Message::Binary(bytes.into())).await.unwrap();
}

#[tokio::test]
async fn two_clients_exchange_a_frame_via_shared_tag() {
    let port = start_relay().await;
    let mut a = connect(port).await;
    let mut b = connect(port).await;

    // Drain Hello on both.
    assert!(matches!(
        next_frame(&mut a).await,
        ServerFrame::Hello { .. }
    ));
    assert!(matches!(
        next_frame(&mut b).await,
        ServerFrame::Hello { .. }
    ));

    let tag = RouteTag([7u8; 16]);
    send_client(&mut a, ClientFrame::Register { tag }).await;
    send_client(&mut b, ClientFrame::Register { tag }).await;

    // Give the registrations a tick to apply (writer task is async).
    tokio::time::sleep(Duration::from_millis(50)).await;

    send_client(
        &mut a,
        ClientFrame::Send {
            tag,
            payload: b"hello from A".to_vec(),
        },
    )
    .await;

    let frame = tokio::time::timeout(Duration::from_secs(2), next_data_frame(&mut b))
        .await
        .expect("b should receive forwarded frame");
    match frame {
        ServerFrame::Recv { tag: t, payload } => {
            assert_eq!(t, tag);
            assert_eq!(payload, b"hello from A");
        }
        other => panic!("unexpected frame on b: {other:?}"),
    }
}

#[tokio::test]
async fn sender_does_not_receive_own_send() {
    let port = start_relay().await;
    let mut a = connect(port).await;
    let mut b = connect(port).await;

    assert!(matches!(
        next_frame(&mut a).await,
        ServerFrame::Hello { .. }
    ));
    assert!(matches!(
        next_frame(&mut b).await,
        ServerFrame::Hello { .. }
    ));

    let tag = RouteTag([42u8; 16]);
    send_client(&mut a, ClientFrame::Register { tag }).await;
    send_client(&mut b, ClientFrame::Register { tag }).await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    send_client(
        &mut a,
        ClientFrame::Send {
            tag,
            payload: b"echo check".to_vec(),
        },
    )
    .await;

    let _ = tokio::time::timeout(Duration::from_secs(2), next_data_frame(&mut b))
        .await
        .unwrap();

    let res = tokio::time::timeout(Duration::from_millis(200), next_data_frame(&mut a)).await;
    assert!(res.is_err(), "sender received its own broadcast: {:?}", res);
}

#[tokio::test]
async fn unregistered_tag_drops_silently() {
    let port = start_relay().await;
    let mut a = connect(port).await;
    let mut b = connect(port).await;
    assert!(matches!(
        next_frame(&mut a).await,
        ServerFrame::Hello { .. }
    ));
    assert!(matches!(
        next_frame(&mut b).await,
        ServerFrame::Hello { .. }
    ));

    let unknown_tag = RouteTag([0xABu8; 16]);
    send_client(
        &mut a,
        ClientFrame::Send {
            tag: unknown_tag,
            payload: b"into the void".to_vec(),
        },
    )
    .await;

    let res = tokio::time::timeout(Duration::from_millis(200), next_data_frame(&mut b)).await;
    assert!(
        res.is_err(),
        "unregistered-tag frame was forwarded: {:?}",
        res
    );
}

#[tokio::test]
async fn disconnect_clears_registrations() {
    let port = start_relay().await;
    let state_tag = RouteTag([1u8; 16]);

    {
        let mut a = connect(port).await;
        assert!(matches!(
            next_frame(&mut a).await,
            ServerFrame::Hello { .. }
        ));
        send_client(&mut a, ClientFrame::Register { tag: state_tag }).await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        // a drops here → WS close → server cleans up
    }

    // Wait briefly for cleanup task. Connect a fresh peer with the SAME
    // tag, so it should receive nothing: no other registrant is left.
    tokio::time::sleep(Duration::from_millis(200)).await;
    let mut b = connect(port).await;
    let mut c = connect(port).await;
    assert!(matches!(
        next_frame(&mut b).await,
        ServerFrame::Hello { .. }
    ));
    assert!(matches!(
        next_frame(&mut c).await,
        ServerFrame::Hello { .. }
    ));
    send_client(&mut b, ClientFrame::Register { tag: state_tag }).await;
    send_client(&mut c, ClientFrame::Register { tag: state_tag }).await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    send_client(
        &mut b,
        ClientFrame::Send {
            tag: state_tag,
            payload: b"post-cleanup".to_vec(),
        },
    )
    .await;

    let frame = tokio::time::timeout(Duration::from_secs(2), next_data_frame(&mut c))
        .await
        .expect("c should receive forwarded frame");
    assert!(matches!(frame, ServerFrame::Recv { .. }));
}

#[tokio::test]
async fn dropped_connection_pushes_peer_gone_to_remaining_subscribers() {
    let port = start_relay().await;
    let tag = RouteTag([0x5Au8; 16]);
    let mut watcher = connect(port).await;
    assert!(matches!(
        next_frame(&mut watcher).await,
        ServerFrame::Hello { .. }
    ));
    send_client(&mut watcher, ClientFrame::Register { tag }).await;

    {
        let mut leaver = connect(port).await;
        assert!(matches!(
            next_frame(&mut leaver).await,
            ServerFrame::Hello { .. }
        ));
        send_client(&mut leaver, ClientFrame::Register { tag }).await;
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    let mut saw_peer_arrived = false;
    let frame = loop {
        let f = tokio::time::timeout(Duration::from_secs(2), next_frame(&mut watcher))
            .await
            .expect("watcher should receive PeerGone");
        if matches!(f, ServerFrame::PeerArrived { .. }) {
            saw_peer_arrived = true;
            continue;
        }
        break f;
    };
    assert!(
        saw_peer_arrived,
        "watcher should have seen PeerArrived first"
    );
    match frame {
        ServerFrame::PeerGone { tag: t } => assert_eq!(t, tag),
        other => panic!("expected PeerGone, got {other:?}"),
    }
}

#[tokio::test]
async fn peer_gone_omitted_when_no_other_subscribers() {
    let port = start_relay().await;
    let tag = RouteTag([0x6Au8; 16]);
    let mut observer = connect(port).await;
    assert!(matches!(
        next_frame(&mut observer).await,
        ServerFrame::Hello { .. }
    ));

    {
        let mut leaver = connect(port).await;
        assert!(matches!(
            next_frame(&mut leaver).await,
            ServerFrame::Hello { .. }
        ));
        send_client(&mut leaver, ClientFrame::Register { tag }).await;
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    let res =
        tokio::time::timeout(Duration::from_millis(200), next_data_frame(&mut observer)).await;
    assert!(
        res.is_err(),
        "observer received unexpected frame: {:?}",
        res
    );
}

#[tokio::test]
async fn unregister_removes_recipient() {
    let port = start_relay().await;
    let mut a = connect(port).await;
    let mut b = connect(port).await;
    assert!(matches!(
        next_frame(&mut a).await,
        ServerFrame::Hello { .. }
    ));
    assert!(matches!(
        next_frame(&mut b).await,
        ServerFrame::Hello { .. }
    ));

    let tag = RouteTag([9u8; 16]);
    send_client(&mut a, ClientFrame::Register { tag }).await;
    send_client(&mut b, ClientFrame::Register { tag }).await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    send_client(&mut b, ClientFrame::Unregister { tag }).await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    send_client(
        &mut a,
        ClientFrame::Send {
            tag,
            payload: b"after-unregister".to_vec(),
        },
    )
    .await;

    let res = tokio::time::timeout(Duration::from_millis(200), next_data_frame(&mut b)).await;
    assert!(
        res.is_err(),
        "unregistered receiver still got the frame: {:?}",
        res
    );
}

#[tokio::test]
async fn pings_draw_on_the_byte_budget() {
    let mut state = AppState::permissive("test-relay");
    state.rate = std::sync::Arc::new(server::ratelimit::RateLimiter::new(
        server::ratelimit::RateLimitConfig {
            max_bytes_per_sec: 1,
            max_burst_bytes: 1_000,
            ..server::ratelimit::RateLimiter::permissive()
                .config()
                .clone()
        },
    ));
    let port = start_relay_with(state).await;
    let mut ws = connect(port).await;
    let _hello = next_frame(&mut ws).await;
    for _ in 0..200 {
        if ws.send(Message::Ping(Vec::new().into())).await.is_err() {
            break;
        }
    }
    let shed = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            match ws.next().await {
                Some(Ok(Message::Binary(bytes))) => {
                    if let Ok(ServerFrame::RateLimited { .. }) = serde_json::from_slice(&bytes) {
                        return true;
                    }
                }
                Some(Ok(_)) => continue,
                _ => return false,
            }
        }
    })
    .await
    .unwrap_or(false);
    assert!(
        shed,
        "a flood of empty pings is shed like any other traffic"
    );
}

#[tokio::test]
async fn a_connection_holds_at_most_the_tag_cap() {
    use server::routing::MAX_TAGS_PER_CONN;
    let port = start_relay().await;
    let mut ws = connect(port).await;
    let _hello = next_frame(&mut ws).await;
    let tag = |n: usize| {
        let mut t = [0u8; 16];
        t[..8].copy_from_slice(&(n as u64).to_le_bytes());
        RouteTag(t)
    };
    for n in 0..MAX_TAGS_PER_CONN {
        send_client(&mut ws, ClientFrame::Register { tag: tag(n) }).await;
    }
    send_client(&mut ws, ClientFrame::Register { tag: tag(0) }).await;
    send_client(
        &mut ws,
        ClientFrame::Register {
            tag: tag(MAX_TAGS_PER_CONN),
        },
    )
    .await;
    match next_data_frame(&mut ws).await {
        ServerFrame::Error {
            tag: Some(t),
            reason,
        } => {
            assert_eq!(
                t,
                tag(MAX_TAGS_PER_CONN),
                "re-registering a held tag is not refused"
            );
            assert_eq!(reason, relay_wire::TAG_LIMIT_REASON);
        }
        other => panic!("expected the tag-limit error, got {other:?}"),
    }
}

#[tokio::test]
async fn a_tag_holds_at_most_the_holder_cap() {
    use server::routing::MAX_HOLDERS_PER_TAG;
    let port = start_relay().await;
    let tag = RouteTag([9u8; 16]);
    let mut holders = Vec::new();
    for _ in 0..MAX_HOLDERS_PER_TAG {
        let mut ws = connect(port).await;
        let _hello = next_frame(&mut ws).await;
        send_client(&mut ws, ClientFrame::Register { tag }).await;
        holders.push(ws);
    }
    tokio::time::sleep(Duration::from_millis(50)).await;
    let mut extra = connect(port).await;
    let _hello = next_frame(&mut extra).await;
    send_client(&mut extra, ClientFrame::Register { tag }).await;
    match next_data_frame(&mut extra).await {
        ServerFrame::Error {
            tag: Some(t),
            reason,
        } => {
            assert_eq!(t, tag);
            assert_eq!(reason, relay_wire::TAG_FULL_REASON);
        }
        other => panic!("expected the tag-full error, got {other:?}"),
    }
}

#[tokio::test]
async fn the_largest_noise_message_is_relayed_and_a_larger_payload_closes_the_sender() {
    use relay_wire::MAX_PAYLOAD_BYTES;
    let port = start_relay().await;
    let mut a = connect(port).await;
    let mut b = connect(port).await;
    let _hello = next_frame(&mut a).await;
    let _hello = next_frame(&mut b).await;
    let tag = RouteTag([11u8; 16]);
    send_client(&mut a, ClientFrame::Register { tag }).await;
    send_client(&mut b, ClientFrame::Register { tag }).await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    // 255 per byte is JSON's widest spelling of a payload.
    send_client(
        &mut a,
        ClientFrame::Send {
            tag,
            payload: vec![255; MAX_PAYLOAD_BYTES],
        },
    )
    .await;
    match next_data_frame(&mut b).await {
        ServerFrame::Recv { payload, .. } => assert_eq!(payload.len(), MAX_PAYLOAD_BYTES),
        other => panic!("expected the relayed payload, got {other:?}"),
    }

    send_client(
        &mut a,
        ClientFrame::Send {
            tag,
            payload: vec![0; MAX_PAYLOAD_BYTES + 1],
        },
    )
    .await;
    assert!(closed_by_relay(&mut a).await);
}

#[tokio::test]
async fn the_hello_states_the_relay_wire_range() {
    let port = start_relay().await;
    let mut ws = connect(port).await;
    match next_frame(&mut ws).await {
        ServerFrame::Hello {
            protocol_version,
            min_client_version,
            ..
        } => assert_eq!(
            VersionRange {
                version: protocol_version,
                min: min_client_version,
            },
            RELAY_WIRE
        ),
        other => panic!("expected Hello, got {other:?}"),
    }
}

#[tokio::test]
async fn a_client_whose_first_frame_is_not_a_hello_is_closed() {
    let port = start_relay().await;
    let mut ws = connect_raw(port).await;
    let _hello = next_frame(&mut ws).await;
    send_client(
        &mut ws,
        ClientFrame::Register {
            tag: RouteTag([3u8; 16]),
        },
    )
    .await;
    assert!(closed_by_relay(&mut ws).await);
}

#[tokio::test]
async fn a_client_below_the_relays_minimum_is_closed() {
    let port = start_relay().await;
    let mut ws = connect_raw(port).await;
    let _hello = next_frame(&mut ws).await;
    let old = MIN_CLIENT_WIRE - 1;
    send_client(
        &mut ws,
        ClientFrame::Hello {
            wire: VersionRange {
                version: old,
                min: old,
            },
            app_version: "test".into(),
        },
    )
    .await;
    assert!(closed_by_relay(&mut ws).await);
}

#[tokio::test]
async fn a_greeted_client_stays_and_registers() {
    let port = start_relay().await;
    let mut ws = connect(port).await;
    let _hello = next_frame(&mut ws).await;
    let tag = RouteTag([4u8; 16]);
    send_client(&mut ws, ClientFrame::Register { tag }).await;
    send_client(
        &mut ws,
        ClientFrame::Send {
            tag,
            payload: b"x".to_vec(),
        },
    )
    .await;
    match tokio::time::timeout(Duration::from_secs(2), next_data_frame(&mut ws)).await {
        Ok(ServerFrame::Error { reason, .. }) => {
            assert_eq!(reason, relay_wire::NO_RECIPIENT_REASON)
        }
        other => panic!("expected the no-recipient error from a live connection, got {other:?}"),
    }
}
