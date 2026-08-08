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

use crate::group::{Group, Membership, Outgoing};
use crate::handshake::ServerHandshake;
use crate::ServerConfig;
use sendspin_proto::error::Error;
use sendspin_proto::messages::{
    Activity, Message, ServerActivate, ServerHelloEncrypted, ServerState, ServerTime,
};
use sendspin_proto::noise::constants::MSG_TYPE_JSON_BODY;
use sendspin_proto::noise::keys::Psk;
use sendspin_proto::noise::wire::{frame, Reassembler};

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
    /// How many audio chunks were pushed to it.
    pub chunks_sent: u64,
}

/// Serve one accepted TCP stream until the client goes away.
pub async fn serve(
    stream: TcpStream,
    config: Arc<ServerConfig>,
    group: Arc<Group>,
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

    // A client's `unpaired_access` is it telling the server up front whether it may be used
    // without a pairing, and this connection is Sentinel-keyed — the key every client holds,
    // which authenticates nobody. Activating roles anyway is asking for authority the client
    // has already declined: the reference client answers `goodbye(pairing_required)`, and it
    // is right to. Pairing is what lifts this, and it is not implemented here yet.
    let unpaired_ok = hello.unpaired_access.enabled;
    if !unpaired_ok {
        log::info!("{client_id} does not admit unpaired access, so no roles are activated for it");
    }

    // Only what this server actually implements, and only what the client offered. Activating
    // a role is a promise to serve it.
    let mut active_roles = if unpaired_ok {
        crate::roles::negotiate(&hello.supported_roles, &crate::roles::servable(&config))
    } else {
        Vec::new()
    };

    // The last promise on this path that was being made blind. This server sends one fixed
    // format and does not transcode, so a client that cannot decode it is not a player here —
    // whatever it offered. Granting the role anyway would hand it bytes it cannot render, and
    // silence from a speaker that reported itself healthy is a fault nobody can trace.
    if let Some(source) = config.audio.as_ref() {
        let sending = source.format();
        let offered = hello
            .player_v1_support
            .as_ref()
            .map(|support| support.supported_formats.as_slice())
            .unwrap_or(&[]);
        if active_roles.iter().any(|r| r == "player@v1")
            && !crate::roles::can_play(offered, &sending)
        {
            log::warn!(
                "{client_id} cannot play {} {}Hz {}ch {}bit, so it is not activated as a player",
                sending.codec,
                sending.sample_rate,
                sending.channels,
                sending.bit_depth
            );
            active_roles.retain(|r| r != "player@v1");
        }
    }
    let active_roles = active_roles;
    // No `audio.is_some()` here any more: `servable` already refused to offer `player@v1`
    // without a source, so a granted player role is by construction one this server can feed.
    let will_play = active_roles.iter().any(|r| r == "player@v1");
    send_json(
        &mut ws,
        &mut done.session,
        &Message::ServerActivate(ServerActivate {
            // `activities` names what is actually going on. Playback only when there is audio
            // to play and someone activated to hear it; empty otherwise, which is what the
            // reference server sends on an idle connection.
            activities: if will_play {
                vec![Activity::Playback]
            } else {
                Vec::new()
            },
            active_roles: Some(active_roles.clone()),
            pairing: None,
            selected_pair_method: None,
        }),
    )
    .await?;
    log::info!("{client_id} activated with {active_roles:?}");

    // --- steady state --------------------------------------------------------------------
    let mut time_syncs = 0u64;
    let mut chunks_sent = 0u64;

    // Joining the group is what replaced pulling audio here. A connection no longer owns a
    // timeline: it owns a *seat* at one, and the group hands every seat the same bytes.
    //
    // Every activated client takes a seat, not only players: a controller learns the group's
    // volume this way and a display learns what is playing. Whether it *plays* is separate, and
    // is what decides both if it receives audio frames and if it keeps the stream running — a
    // group holding nothing but a controller has nobody to play to.
    let mut membership = if active_roles.is_empty() {
        None
    } else {
        Some(group.join(will_play))
    };

    if let Some(member) = membership.as_mut() {
        send_json(
            &mut ws,
            &mut done.session,
            &Message::GroupUpdate(member.group_update()),
        )
        .await?;
        // A client that arrived mid-track gets the `stream/start` for the stream already in
        // flight. Without it the binary frames that follow are undecodable: it would know when
        // to play them but not what they are.
        if let Some(start) = member.catch_up() {
            log::info!("{client_id} joined a stream already in progress");
            send_json(&mut ws, &mut done.session, &Message::StreamStart(start)).await?;
        }
    }

    // Metadata is its own role, so it is sent to a client that activated it whether or not that
    // client also plays: a display in the hallway wants to know what is on without receiving a
    // single sample.
    if active_roles.iter().any(|r| r == "controller@v1") {
        if let Some(controller) = group.controller_state() {
            send_json(
                &mut ws,
                &mut done.session,
                &Message::ServerState(ServerState {
                    metadata: None,
                    controller: Some(controller),
                    color: None,
                }),
            )
            .await?;
        }
    }

    if active_roles.iter().any(|r| r == "metadata@v1") {
        if let Some(metadata) = config.metadata.as_ref().and_then(|source| source.current()) {
            send_json(
                &mut ws,
                &mut done.session,
                &Message::ServerState(ServerState {
                    metadata: Some(metadata),
                    controller: None,
                    color: None,
                }),
            )
            .await?;
        }
    }

    /// Whichever came first: something to read from the client, or something to send it.
    enum Event {
        // Boxed because a `Message` is an order of magnitude larger than the other variant,
        // and every poll of this loop would otherwise carry the widest payload the protocol
        // has on the stack whether or not one arrived.
        Incoming(Option<Box<Message>>),
        Outgoing(Option<Result<Arc<Outgoing>, u64>>),
    }

    loop {
        // Racing the read against the group's feed keeps both responsive: a client's message is
        // answered while audio is pending, and audio does not wait on a quiet client. The
        // select produces a value rather than acting in its arms, so the borrows of the socket
        // and the feed do not overlap.
        let event = match membership.as_mut() {
            Some(member) => tokio::select! {
                incoming = next_encrypted(&mut ws, &mut done.session, &mut reassembler) => {
                    Event::Incoming(incoming?.map(Box::new))
                }
                outgoing = member.next() => Event::Outgoing(outgoing),
            },
            None => Event::Incoming(
                next_encrypted(&mut ws, &mut done.session, &mut reassembler)
                    .await?
                    .map(Box::new),
            ),
        };

        let message = match event {
            Event::Outgoing(None) => break,
            Event::Outgoing(Some(Err(missed))) => {
                // This client could not keep up. Saying so is the whole point: audio is
                // realtime, so the group drops what it could not deliver rather than letting
                // one stalled socket delay everybody else's playback.
                log::warn!("{client_id} fell behind and missed {missed} frame(s)");
                continue;
            }
            Event::Outgoing(Some(Ok(out))) => {
                let plays = membership.as_ref().is_some_and(Membership::plays);
                match out.as_ref() {
                    Outgoing::Json(msg) => send_json(&mut ws, &mut done.session, msg).await?,
                    // Control messages go to the whole group; samples do not. Sending audio to a
                    // controller would be handing it bytes it has no format for and no way to
                    // play.
                    Outgoing::Binary(bytes) if plays => {
                        send_binary(&mut ws, &mut done.session, bytes).await?;
                        chunks_sent += 1;
                    }
                    Outgoing::Binary(_) => {}
                }
                continue;
            }
            Event::Incoming(incoming) => incoming,
        };
        let Some(message) = message else { break };

        match *message {
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
            Message::ClientState(state) => {
                // `available: false` is a client saying its output is in use by something else
                // — an HDMI input, a local app. Continuing to send it audio would be sending
                // into a void, and worse, it would keep the group awake on behalf of a listener
                // that is not listening. Dropping the membership stops the audio without
                // dropping the connection: the client keeps its clock sync and its roles, and
                // says so when it is free again.
                match state.is_available() {
                    Some(false) if membership.is_some() => {
                        log::info!("{client_id} reports it is busy; pausing its audio");
                        membership = None;
                    }
                    Some(true) if membership.is_none() && will_play => {
                        log::info!("{client_id} reports it is free again; resuming its audio");
                        let mut member = group.join(true);
                        send_json(
                            &mut ws,
                            &mut done.session,
                            &Message::GroupUpdate(member.group_update()),
                        )
                        .await?;
                        if let Some(start) = member.catch_up() {
                            send_json(&mut ws, &mut done.session, &Message::StreamStart(start))
                                .await?;
                        }
                        membership = Some(member);
                    }
                    _ => {}
                }
            }
            Message::ClientCommand(command) => {
                // Only from a client that was actually granted the role. Acting on a command
                // from a client this server never activated as a controller would let any peer
                // set the volume of a room it was not admitted to.
                if !active_roles.iter().any(|r| r == "controller@v1") {
                    log::warn!("{client_id} sent a command without the controller role");
                } else if let Some(controller) = command.controller.as_ref() {
                    group.handle_controller_command(controller);
                }
            }
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
        chunks_sent,
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
    session: &mut sendspin_proto::noise::session::NoiseSession,
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

/// Encrypt, frame and send one binary message, already carrying its own type byte.
async fn send_binary(
    ws: &mut WebSocketStream<TcpStream>,
    session: &mut sendspin_proto::noise::session::NoiseSession,
    body: &[u8],
) -> Result<(), Error> {
    // The audio frame's own type byte is the *inner* one, inside the framing layer's envelope;
    // the two are separate headers and collapsing them sends a chunk no client can read.
    let (msg_type, payload) = body.split_first().ok_or_else(|| {
        Error::Protocol("a binary message needs at least a type byte".to_string())
    })?;
    for plaintext in frame(*msg_type, payload)? {
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
    session: &mut sendspin_proto::noise::session::NoiseSession,
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
