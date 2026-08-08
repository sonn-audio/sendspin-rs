// ABOUTME: One accepted connection: handshake, the hello exchange, and the clock replies that
// ABOUTME: a client needs before it can schedule anything.

//! A single client connection, from WebSocket upgrade to the point where the client's clock
//! has converged.
//!
//! What this deliberately does *not* do yet is roles or audio. Bringing a real client up to a
//! synchronized clock is the milestone worth having on its own: it is the point where the
//! interop harness inverts, and everything after it can be checked against a live peer instead
//! of reasoned about.

use std::sync::Arc;

use futures_util::{SinkExt, StreamExt};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::Message as WsMessage;
use tokio_tungstenite::WebSocketStream;

use crate::handshake::ServerHandshake;
use crate::ServerConfig;
use sendspin::error::Error;
use sendspin::noise::constants::MSG_TYPE_JSON_BODY;
use sendspin::noise::keys::Psk;
use sendspin::noise::wire::{frame, Reassembler};
use sendspin::protocol::messages::{Message, ServerActivate, ServerHelloEncrypted, ServerTime};

/// What one connection learned about its client.
pub struct ConnectionSummary {
    /// The client's static public key.
    pub client_id: String,
    /// What the client called itself in `client/hello`.
    pub name: String,
    /// The roles this server activated for it.
    pub active_roles: Vec<String>,
    /// How many clock exchanges were answered before it ended.
    pub time_syncs: u64,
}

/// Serve one accepted TCP stream until the client goes away.
pub async fn serve(
    stream: TcpStream,
    config: Arc<ServerConfig>,
) -> Result<ConnectionSummary, Error> {
    let mut ws = tokio_tungstenite::accept_async(stream)
        .await
        .map_err(|e| Error::Connection(format!("WebSocket upgrade failed: {e}")))?;

    // --- cleartext handshake -------------------------------------------------------------
    let client_init = next_text(&mut ws).await?;
    // Every first connection is keyed by the Sentinel PSK, which every client holds. Choosing
    // a long-term key instead is what pairing buys, and it is not implemented here yet.
    let (handshake, server_init) =
        ServerHandshake::start(config.identity.clone(), Psk::sentinel(), &client_init)?;
    let client_id = handshake.client_id();
    log::info!(
        "Handshaking with {client_id} ({})",
        handshake.suite().as_wire_str()
    );
    send_text(&mut ws, server_init).await?;

    let (session, msg1) = handshake.message_one()?;
    send_text(&mut ws, msg1).await?;

    let msg2 = next_text(&mut ws).await?;
    let mut done = handshake.finish(session, &msg2)?;
    log::info!("Noise handshake complete with {client_id}");

    // --- encrypted from here -------------------------------------------------------------
    let mut reassembler = Reassembler::new();

    // `server/hello` is the one message whose payload shape depends on the transport rather
    // than on its `type`, so it is not a `Message` variant and has to be enveloped by hand.
    // Sending the bare payload is a message with no `type` at all, which is what a client
    // reports as a missing discriminator.
    send_json(
        &mut ws,
        &mut done.session,
        &serde_json::json!({
            "type": "server/hello",
            "payload": ServerHelloEncrypted { name: config.name.clone() },
        }),
    )
    .await?;

    // The client answers with its hello, and nothing else may come first: the spec puts it
    // immediately after `server/hello`, so anything else here is a peer out of sequence
    // rather than something to skip past.
    let Some(first) = next_encrypted(&mut ws, &mut done.session, &mut reassembler).await? else {
        return Err(Error::Connection(
            "client closed the connection before client/hello".to_string(),
        ));
    };
    let Message::ClientHello(hello) = first else {
        return Err(Error::Protocol(format!(
            "expected client/hello, got {}",
            message_name(&first)
        )));
    };
    let name = hello.name.clone();
    log::info!(
        "{client_id} is {name:?}, offering {:?}",
        hello.supported_roles
    );

    // No roles yet: this server can hold a connection open and keep a clock, and saying so
    // honestly is better than activating a role it cannot serve. A client that is granted
    // `player@v1` and then never sent audio looks broken in a way this does not.
    let active_roles: Vec<String> = Vec::new();
    send_json(
        &mut ws,
        &mut done.session,
        &Message::ServerActivate(ServerActivate {
            // Empty rather than invented: `activities` names what is actually going on, and
            // this server is neither playing, pairing nor managing. The reference server
            // sends an empty list on an idle connection too.
            activities: Vec::new(),
            active_roles: Some(active_roles.clone()),
            pairing: None,
            selected_pair_method: None,
        }),
    )
    .await?;

    // --- steady state --------------------------------------------------------------------
    let mut time_syncs = 0u64;
    while let Some(message) = next_encrypted(&mut ws, &mut done.session, &mut reassembler).await? {
        match message {
            Message::ClientTime(request) => {
                // Both stamps come off this server's own monotonic clock, and the reply goes
                // out immediately: the client subtracts them to remove the server's own
                // processing from its round-trip estimate, so any delay added between these
                // two reads is delay it will mistake for network latency.
                let received = config.clock.now_micros();
                let reply = Message::ServerTime(ServerTime {
                    client_transmitted: request.client_transmitted,
                    server_received: received,
                    server_transmitted: config.clock.now_micros(),
                });
                send_json(&mut ws, &mut done.session, &reply).await?;
                time_syncs += 1;
            }
            Message::ClientState(_) => {}
            Message::ClientGoodbye(goodbye) => {
                log::info!("{client_id} said goodbye: {:?}", goodbye.reason);
                break;
            }
            other => log::debug!("{client_id} sent {}", message_name(&other)),
        }
    }

    Ok(ConnectionSummary {
        client_id,
        name,
        active_roles,
        time_syncs,
    })
}

/// Read the next text frame, skipping the ping/pong traffic tungstenite answers for us.
async fn next_text(ws: &mut WebSocketStream<TcpStream>) -> Result<Vec<u8>, Error> {
    while let Some(frame) = ws.next().await {
        let frame = frame.map_err(|e| Error::Connection(format!("WebSocket read failed: {e}")))?;
        match frame {
            WsMessage::Text(text) => return Ok(text.as_bytes().to_vec()),
            WsMessage::Ping(_) | WsMessage::Pong(_) => continue,
            WsMessage::Close(_) => {
                return Err(Error::Connection(
                    "client closed during the handshake".to_string(),
                ))
            }
            WsMessage::Binary(_) => {
                return Err(Error::Protocol(
                    "binary frame arrived before the handshake finished".to_string(),
                ))
            }
            other => {
                return Err(Error::Protocol(format!(
                    "unexpected frame during the handshake: {other:?}"
                )))
            }
        }
    }
    Err(Error::Connection(
        "client disconnected during the handshake".to_string(),
    ))
}

/// Send a cleartext handshake frame.
async fn send_text(ws: &mut WebSocketStream<TcpStream>, bytes: Vec<u8>) -> Result<(), Error> {
    let text = String::from_utf8(bytes)
        .map_err(|e| Error::Protocol(format!("handshake frame was not UTF-8: {e}")))?;
    ws.send(WsMessage::text(text))
        .await
        .map_err(|e| Error::Connection(format!("WebSocket write failed: {e}")))
}

/// Encrypt, frame and send one JSON message.
async fn send_json<T: serde::Serialize>(
    ws: &mut WebSocketStream<TcpStream>,
    session: &mut sendspin::noise::session::NoiseSession,
    message: &T,
) -> Result<(), Error> {
    let json = serde_json::to_vec(message)
        .map_err(|e| Error::Protocol(format!("could not encode a message: {e}")))?;
    for plaintext in frame(MSG_TYPE_JSON_BODY, &json)? {
        let ciphertext = session.encrypt(&plaintext)?;
        ws.send(WsMessage::binary(ciphertext))
            .await
            .map_err(|e| Error::Connection(format!("WebSocket write failed: {e}")))?;
    }
    Ok(())
}

/// Read the next application message, decrypting and reassembling as needed.
///
/// `Ok(None)` means the client closed cleanly.
async fn next_encrypted(
    ws: &mut WebSocketStream<TcpStream>,
    session: &mut sendspin::noise::session::NoiseSession,
    reassembler: &mut Reassembler,
) -> Result<Option<Message>, Error> {
    while let Some(next) = ws.next().await {
        let next = next.map_err(|e| Error::Connection(format!("WebSocket read failed: {e}")))?;
        let bytes = match next {
            WsMessage::Binary(bytes) => bytes,
            WsMessage::Ping(_) | WsMessage::Pong(_) => continue,
            WsMessage::Close(_) => return Ok(None),
            // Once the transport is encrypted a text frame is a protocol error rather than
            // something to interpret: everything is a Noise ciphertext from here.
            WsMessage::Text(_) => {
                return Err(Error::Protocol(
                    "text frame arrived on an encrypted connection".to_string(),
                ))
            }
            other => {
                return Err(Error::Protocol(format!(
                    "unexpected frame on an encrypted connection: {other:?}"
                )))
            }
        };
        let plaintext = session.decrypt(&bytes)?;
        let Some(assembled) = reassembler.accept(&plaintext)? else {
            continue;
        };
        if assembled.msg_type != MSG_TYPE_JSON_BODY {
            log::debug!(
                "ignoring binary message type {} from a client",
                assembled.msg_type
            );
            continue;
        }
        let message: Message = serde_json::from_slice(&assembled.payload)
            .map_err(|e| Error::Protocol(format!("malformed message from the client: {e}")))?;
        return Ok(Some(message));
    }
    Ok(None)
}

/// The wire name of a message, for logs that have to say what arrived.
fn message_name(message: &Message) -> String {
    serde_json::to_value(message)
        .ok()
        .and_then(|value| {
            value
                .get("type")
                .and_then(|t| t.as_str())
                .map(str::to_string)
        })
        .unwrap_or_else(|| "an unrecognised message".to_string())
}
