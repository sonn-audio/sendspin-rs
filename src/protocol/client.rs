// ABOUTME: WebSocket client implementation for Sendspin protocol
// ABOUTME: Handles connection, message routing, and protocol state machine

use crate::error::Error;
use crate::log_sampling::should_log_sample;
use crate::protocol::messages::{
    ArtworkFormatRequest, ClientCommand, ClientGoodbye, ClientHello, ClientState, ClientStreamEnd,
    ClientStreamSource, ClientStreamStart, ClientSyncState, ClientTime, ConnectionReason,
    ControllerCommand, ControllerCommandType, GoodbyeReason, Message, PlayerFormatRequest,
    PlayerState, RepeatMode, ServerHello, SourceState, StreamEnd, StreamRequestFormat, StreamStart,
    VisualizerDataType, VisualizerFormatRequest,
};
use crate::sync::raw_clock::Clock;
use crate::sync::ClockSync;
use futures_util::{
    stream::{SplitSink, SplitStream},
    SinkExt, StreamExt,
};
use parking_lot::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::{connect_async, tungstenite::Message as WsMessage};

use super::transport::{Inbound, Outbound, Transport};
use crate::noise::pairing::{plan_pairing, PairAbort, PairAbortReason, PairingAction};
use crate::noise::trust_store::{InMemoryPairingStore, PairingRecord, PairingStore};
use crate::noise::{CipherSuite, ClientHandshake, HandshakeStep, Identity};

/// `Goodbye` is one variant (not `Send` + `Close`) so the writer processes it
/// atomically: once dequeued it flushes goodbye + close and exits, so nothing
/// *enqueued after it* reaches the wire.
enum WriteCommand {
    Send {
        payload: Outbound,
        ack: tokio::sync::oneshot::Sender<Result<(), Error>>,
    },
    Goodbye {
        reason: GoodbyeReason,
        ack: tokio::sync::oneshot::Sender<Result<(), Error>>,
    },
}

async fn writer_task<S>(
    mut sink: SplitSink<WebSocketStream<S>, WsMessage>,
    mut rx: UnboundedReceiver<WriteCommand>,
    transport: Arc<Mutex<Transport>>,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    while let Some(cmd) = rx.recv().await {
        match cmd {
            WriteCommand::Send { payload, ack } => {
                // Encode under the lock, send outside it: encryption is quick and
                // synchronous, whereas holding a lock across `send().await` would let a
                // slow socket block the reader's decryption.
                let framed = transport.lock().encode(payload);
                let result = match framed {
                    Ok(frames) => send_all(&mut sink, frames).await,
                    Err(e) => Err(e),
                };
                let failed = result.is_err();
                // Ignore SendError: the caller may have dropped its receiver.
                let _ = ack.send(result);
                if failed {
                    break;
                }
            }
            WriteCommand::Goodbye { reason, ack } => {
                let _ = ack.send(perform_goodbye(&mut sink, reason, &transport).await);
                break;
            }
        }
    }
    log::debug!("Writer task exiting");
    // On exit `rx` drops, dropping the ack sender of any still-queued command;
    // callers awaiting those acks see the cancellation and treat it as a closed
    // connection (see `WsSender::send_message`).
}

/// Write every WebSocket frame one message became — more than one after fragmentation.
async fn send_all<S>(
    sink: &mut SplitSink<WebSocketStream<S>, WsMessage>,
    frames: Vec<WsMessage>,
) -> Result<(), Error>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    for frame in frames {
        sink.send(frame)
            .await
            .map_err(|e| Error::WebSocket(e.to_string()))?;
    }
    Ok(())
}

async fn perform_goodbye<S>(
    sink: &mut SplitSink<WebSocketStream<S>, WsMessage>,
    reason: GoodbyeReason,
    transport: &Arc<Mutex<Transport>>,
) -> Result<(), Error>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let goodbye = Message::ClientGoodbye(ClientGoodbye { reason });
    let json = serde_json::to_string(&goodbye).map_err(|e| Error::Protocol(e.to_string()))?;
    let frames = transport.lock().encode(Outbound::Json(json))?;
    send_all(sink, frames).await?;
    sink.close()
        .await
        .map_err(|e| Error::WebSocket(e.to_string()))
}

/// Drive the cleartext init exchange and Noise handshake over `ws_stream`.
///
/// On success the socket is in transport mode and every subsequent message travels as an
/// encrypted binary frame. On failure the socket is closed without an application-level
/// error message: the spec gives a handshake failure nothing to say, and saying anything
/// would leak which step failed.
async fn run_noise_handshake<S>(
    ws_stream: &mut WebSocketStream<S>,
    settings: EncryptionSettings,
) -> Result<crate::noise::HandshakeResult, Error>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let EncryptionSettings {
        identity,
        suite,
        store,
    } = settings;
    let psks = crate::noise::trust_store::handshake_candidates(store.as_ref())?;
    log::debug!("Offering {} PSK candidate(s)", psks.len());
    let (mut handshake, client_init) = ClientHandshake::start(identity, suite, psks)?;

    log::debug!("Sending client/init ({} bytes)", client_init.len());
    send_cleartext(ws_stream, client_init).await?;

    let deadline = tokio::time::Instant::now()
        + tokio::time::Duration::from_secs(crate::noise::constants::HANDSHAKE_TIMEOUT_SECS);

    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            let _ = ws_stream.close(None).await;
            return Err(Error::Connection("Noise handshake timed out".to_string()));
        }
        let next = match tokio::time::timeout(remaining, ws_stream.next()).await {
            Err(_) => {
                let _ = ws_stream.close(None).await;
                return Err(Error::Connection("Noise handshake timed out".to_string()));
            }
            Ok(None) => {
                return Err(Error::Connection(
                    "connection closed during the Noise handshake".to_string(),
                ))
            }
            Ok(Some(frame)) => frame.map_err(|e| Error::WebSocket(e.to_string()))?,
        };

        // Handshake messages are cleartext text frames; the socket only turns binary once
        // both sides are in transport mode.
        let raw = match &next {
            WsMessage::Text(text) => text.as_bytes().to_vec(),
            WsMessage::Ping(_) | WsMessage::Pong(_) => continue,
            WsMessage::Close(_) => {
                return Err(Error::Connection(
                    "server closed during the Noise handshake".to_string(),
                ))
            }
            other => {
                let _ = ws_stream.close(None).await;
                return Err(Error::Protocol(format!(
                    "unexpected frame during the Noise handshake: {other:?}"
                )));
            }
        };

        match handshake.handle_message(&raw) {
            Ok(HandshakeStep::Continue { send }) => {
                if let Some(bytes) = send {
                    send_cleartext(ws_stream, bytes).await?;
                }
            }
            Ok(HandshakeStep::Complete { send, result }) => {
                send_cleartext(ws_stream, send).await?;
                return Ok(*result);
            }
            Err(e) => {
                let _ = ws_stream.close(None).await;
                return Err(e);
            }
        }
    }
}

/// Settle the request-format gate, then hand the message to consumers.
fn forward_message(
    msg: Message,
    stream_state: &Arc<StreamState>,
    message_tx: &UnboundedSender<Message>,
    message_closed: &mut bool,
) {
    // Before forwarding, so a consumer reacting to this stream/start or stream/end sees
    // current state.
    match &msg {
        Message::StreamStart(start) => stream_state.note_stream_start(start),
        Message::StreamEnd(end) => stream_state.note_stream_end(end),
        _ => {}
    }
    if !*message_closed && message_tx.send(msg).is_err() {
        log::error!("Message receiver dropped — messages will be discarded");
        *message_closed = true;
    }
}

/// Send one message through the writer, waiting until it has actually reached the socket.
///
/// The wait matters wherever ordering does — notably a re-handshake, whose reply has to be
/// on the wire under the old keys before the session is swapped.
async fn send_and_flush(
    out_tx: &UnboundedSender<WriteCommand>,
    payload: Outbound,
) -> Result<(), Error> {
    let (ack_tx, ack_rx) = tokio::sync::oneshot::channel();
    out_tx
        .send(WriteCommand::Send {
            payload,
            ack: ack_tx,
        })
        .map_err(|_| Error::WebSocket("connection closed".to_string()))?;
    ack_rx
        .await
        .map_err(|_| Error::WebSocket("connection closed".to_string()))?
}

/// Enqueue `client/goodbye` from the router and wait for it to reach the wire.
///
/// The router uses this where the spec makes the client end the connection — a revoked
/// pairing, or a server claiming authority the handshake does not support. Flushing rather
/// than firing and forgetting matters: the reason is the last thing the server learns, and a
/// dropped one turns a deliberate close into an apparent crash.
async fn send_goodbye(
    out_tx: &UnboundedSender<WriteCommand>,
    reason: GoodbyeReason,
) -> Result<(), Error> {
    let (ack_tx, ack_rx) = tokio::sync::oneshot::channel();
    out_tx
        .send(WriteCommand::Goodbye {
            reason,
            ack: ack_tx,
        })
        .map_err(|_| Error::WebSocket("connection closed".to_string()))?;
    ack_rx
        .await
        .map_err(|_| Error::WebSocket("connection closed".to_string()))?
}

/// React to a `server/activate` that asks to pair.
///
/// Returns the record to persist once the server acknowledges, or `None` when there was
/// nothing to do or the attempt was declined.
async fn handle_pairing_activation(
    activate: &super::messages::ServerActivate,
    context: &SecurityContext,
    out_tx: &UnboundedSender<WriteCommand>,
) -> Option<PairingRecord> {
    use super::messages::Activity;
    if !activate.activities.contains(&Activity::Pairing) {
        return None;
    }
    // A method is required when the activity set includes pairing; without one there is
    // nothing to check against, which is itself a reason to decline.
    let Some(method) = activate.pair_method() else {
        log::warn!("Pairing activation named no method");
        let _ = send_abort(out_tx, PairAbortReason::MethodNotSupported).await;
        return None;
    };

    let matched = *context.psk_category.lock();

    let action = match plan_pairing(method, matched, &context.server_id, context.store.as_ref()) {
        Ok(action) => action,
        Err(e) => {
            log::error!("Could not plan pairing: {e}");
            return None;
        }
    };

    match action {
        PairingAction::Finalize { message, record } => {
            log::info!("Pairing with {} via {method:?}", context.server_id);
            let json = match serde_json::to_string(&Message::ClientPairFinalize(message)) {
                Ok(json) => json,
                Err(e) => {
                    log::error!("Could not encode client/pair-finalize: {e}");
                    return None;
                }
            };
            if let Err(e) = send_and_flush(out_tx, Outbound::Json(json)).await {
                log::error!("Could not send client/pair-finalize: {e}");
                return None;
            }
            Some(record)
        }
        PairingAction::Abort(reason) => {
            log::warn!("Declining pairing: {reason:?}");
            let _ = send_abort(out_tx, reason).await;
            None
        }
    }
}

/// Send a `pair/abort`.
///
/// Every reason but `concurrent_attempt` leaves the connection open, so the server can offer
/// another method rather than being dropped.
async fn send_abort(
    out_tx: &UnboundedSender<WriteCommand>,
    reason: PairAbortReason,
) -> Result<(), Error> {
    let json = serde_json::to_string(&Message::PairAbort(PairAbort { reason }))
        .map_err(|e| Error::Protocol(e.to_string()))?;
    send_and_flush(out_tx, Outbound::Json(json)).await
}

/// Drive an in-band re-handshake and swap the transport onto the new session.
async fn handle_rehandshake(
    msg1_data: &str,
    context: &SecurityContext,
    transport: &Arc<Mutex<Transport>>,
    out_tx: &UnboundedSender<WriteCommand>,
) -> Result<(), Error> {
    let previous_hash = transport.lock().handshake_hash()?;
    let candidates = crate::noise::trust_store::handshake_candidates(context.store.as_ref())?;
    let result = crate::noise::run_rehandshake_client(
        context.suite,
        &context.identity,
        &context.server_static,
        &previous_hash,
        &context.server_id,
        &candidates,
        msg1_data,
    )?;
    let reply = String::from_utf8(result.reply)
        .map_err(|e| Error::Protocol(format!("re-handshake reply was not UTF-8: {e}")))?;

    // Message 2 goes out under the OLD keys, so it has to be on the wire before the swap —
    // hence the flush rather than a fire-and-forget send.
    send_and_flush(out_tx, Outbound::Json(reply)).await?;
    transport.lock().swap_session(result.session)?;
    *context.psk_category.lock() = result.psk_category;
    context.psk_id.lock().clone_from(&result.psk_id);
    context.store.mark_record_used(&result.psk_id)?;
    log::info!(
        "Re-handshake complete: session now keyed by {:?} ({})",
        result.psk_category,
        result.psk_id
    );
    Ok(())
}

/// Re-run `server/hello` -> `client/hello` -> `server/activate` after a re-handshake.
///
/// The spec restarts the connection here rather than resuming mid-stream, and the reference
/// server enforces it: anything else arriving in this window is a sequence violation it
/// answers by dropping the connection. That is why the caller holds the outbound gate for the
/// duration.
async fn restart_hello_exchange<S>(
    read: &mut SplitStream<WebSocketStream<S>>,
    transport: &Arc<Mutex<Transport>>,
    out_tx: &UnboundedSender<WriteCommand>,
    hello_json: &str,
) -> Result<super::messages::ServerActivate, Error>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    // The post-re-handshake hello is the encrypted shape, carrying only {name}.
    loop {
        let Some(frame) = read.next().await else {
            return Err(Error::Connection(
                "connection ended before the post-re-handshake server/hello".to_string(),
            ));
        };
        let ws_msg = frame.map_err(|e| Error::WebSocket(e.to_string()))?;
        if matches!(ws_msg, WsMessage::Close(_)) {
            return Err(Error::Connection(
                "server closed before the post-re-handshake server/hello".to_string(),
            ));
        }
        let Some(Inbound::Json(text)) = transport.lock().decode(&ws_msg)? else {
            continue;
        };
        match serde_json::from_str::<TypedPayload<super::messages::ServerHelloEncrypted>>(&text) {
            Ok(wrapper) if wrapper.r#type == "server/hello" => {
                log::debug!("Re-handshake: server/hello from {}", wrapper.payload.name);
                break;
            }
            _ => {
                log::debug!("Ignoring {text} while awaiting the post-re-handshake server/hello");
            }
        }
    }

    send_and_flush(out_tx, Outbound::Json(hello_json.to_string())).await?;
    let activate = await_server_activate(read, transport).await?;
    log::info!(
        "Re-handshake complete: activities={:?}, active_roles={:?}",
        activate.activities,
        activate.active_roles
    );
    // Handed back rather than consumed: this is the activation that carries the pairing the
    // re-handshake was run for, so swallowing it here leaves the server waiting for a
    // client/pair-finalize that never comes.
    Ok(activate)
}

/// Minimal view of the message envelope, for the one message whose payload shape depends
/// on the transport rather than on its `type`.
#[derive(serde::Deserialize)]
struct TypedPayload<T> {
    r#type: String,
    payload: T,
}

/// Record whether this activation puts the connection in a management session.
///
/// The client also has to check that the session is keyed by a Sendspin PSK: a server that
/// claims `management` while the connection is not paired is asking for authority it does not
/// have, and the spec answers that by closing with `client/goodbye` reason `unauthorized`.
/// Recording `false` here is the softer half of that — every management command then draws
/// `permission_denied` — and [`management_claim_is_unauthorized`] reports the harder half.
fn note_management_activity(context: &SecurityContext, activate: &super::messages::ServerActivate) {
    use super::messages::Activity;
    let claimed = activate.activities.contains(&Activity::Management);
    let paired = *context.psk_category.lock() == crate::noise::PskCategory::LongTerm;
    *context.management.lock() = claimed && paired;
}

/// Whether an activation claims `management` on a connection that is not paired.
fn management_claim_is_unauthorized(
    context: &SecurityContext,
    activate: &super::messages::ServerActivate,
) -> bool {
    use super::messages::Activity;
    activate.activities.contains(&Activity::Management)
        && *context.psk_category.lock() != crate::noise::PskCategory::LongTerm
}

/// Answer one `management/*` request against the store.
///
/// Outside a management session every command is `permission_denied` — including on an
/// unencrypted connection, which has no pairing to authorize anything.
fn answer_management(
    context: Option<&SecurityContext>,
    message: &Message,
) -> Result<
    Option<(
        crate::noise::ManagementResult,
        crate::noise::ManagementEffect,
    )>,
    Error,
> {
    use crate::noise::management as mgmt;
    use crate::noise::ManagementResultCode as Code;

    let in_session = context.is_some_and(|ctx| *ctx.management.lock());
    if !in_session {
        let denied = matches!(
            message,
            Message::ManagementListRecords(_)
                | Message::ManagementAddRecord(_)
                | Message::ManagementRemoveRecord(_)
                | Message::ManagementGetPairingConfig(_)
                | Message::ManagementSetPairingConfig(_)
                | Message::ManagementOpenPairingWindow(_)
        );
        return Ok(denied.then(|| {
            (
                crate::noise::ManagementResult::code(Code::PermissionDenied),
                crate::noise::ManagementEffect::None,
            )
        }));
    }
    // `in_session` is only ever true with a context.
    let context = context.expect("management session implies a security context");
    let store = context.store.as_ref();

    // `include_static` marks the two reads a server uses to plan ahead; they carry the
    // capacity and per-kind costs, the rest carry only `free`.
    let (mut answer, include_static) = match message {
        Message::ManagementListRecords(_) => (mgmt::handle_list_records(store)?, true),
        Message::ManagementGetPairingConfig(_) => (mgmt::handle_get_pairing_config(store)?, true),
        Message::ManagementAddRecord(payload) => (mgmt::handle_add_record(store, payload)?, false),
        Message::ManagementRemoveRecord(payload) => (
            mgmt::handle_remove_record(store, payload, Some(&context.psk_id.lock()))?,
            false,
        ),
        Message::ManagementSetPairingConfig(payload) => {
            (mgmt::handle_set_pairing_config(store, payload)?, false)
        }
        Message::ManagementOpenPairingWindow(_) => (mgmt::handle_open_pairing_window(), false),
        _ => return Ok(None),
    };
    mgmt::with_storage(&mut answer.0, store, include_static)?;
    Ok(Some(answer))
}

/// Map an activation onto the legacy `connection_reason`, so a connection reached over
/// either transport arbitrates the same way.
fn activity_to_reason(activate: &super::messages::ServerActivate) -> ConnectionReason {
    use super::messages::Activity;
    // Highest-ranked activity wins, matching the ladder in `should_switch`. An empty set is
    // the lowest rank there is, which `Discovery` already represents.
    let mut reason = ConnectionReason::Discovery;
    let mut rank = 0u8;
    for activity in &activate.activities {
        let (candidate, candidate_rank) = match activity {
            Activity::Management => (ConnectionReason::Management, 4),
            Activity::Playback => (ConnectionReason::Playback, 3),
            Activity::Pairing => (ConnectionReason::Pairing, 2),
            Activity::Unknown => (ConnectionReason::Unknown, 1),
        };
        if candidate_rank > rank {
            rank = candidate_rank;
            reason = candidate;
        }
    }
    reason
}

/// Read frames until `server/activate` arrives, which is the point a client may start
/// sending anything else.
async fn await_server_activate<S>(
    read: &mut SplitStream<WebSocketStream<S>>,
    transport: &Arc<Mutex<Transport>>,
) -> Result<super::messages::ServerActivate, Error>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    while let Some(frame) = read.next().await {
        let ws_msg = frame.map_err(|e| Error::WebSocket(e.to_string()))?;
        if matches!(ws_msg, WsMessage::Close(_)) {
            return Err(Error::Connection(
                "server closed before server/activate".to_string(),
            ));
        }
        let Some(Inbound::Json(text)) = transport.lock().decode(&ws_msg)? else {
            continue;
        };
        match serde_json::from_str::<Message>(&text) {
            Ok(Message::ServerActivate(activate)) => return Ok(activate),
            Ok(other) => log::debug!("Ignoring {:?} while awaiting server/activate", other),
            Err(e) => log::warn!("Unparseable message before server/activate: {e} ({text})"),
        }
    }
    Err(Error::Connection(
        "connection ended before server/activate".to_string(),
    ))
}

/// Send one cleartext handshake message as a WebSocket text frame.
async fn send_cleartext<S>(ws: &mut WebSocketStream<S>, bytes: Vec<u8>) -> Result<(), Error>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let text = String::from_utf8(bytes)
        .map_err(|e| Error::Protocol(format!("handshake message was not UTF-8: {e}")))?;
    ws.send(WsMessage::Text(text.into()))
        .await
        .map_err(|e| Error::WebSocket(e.to_string()))
}

/// Whether a connection is encrypted, and what to key it with.
///
/// The spec defines no unencrypted mode, so [`Encryption::Enabled`] is the compliant
/// choice; [`Encryption::Disabled`] reaches servers that still accept the legacy hello.
#[derive(Debug, Clone)]
pub enum Encryption {
    /// Transition mode: no Noise layer. Not a mode the current spec defines.
    Disabled,
    /// The spec's transport.
    Enabled(EncryptionSettings),
}

/// What an encrypted connection is keyed with.
#[derive(Clone)]
pub struct EncryptionSettings {
    /// This client's static keypair. Its public half is the `client_id`.
    pub identity: Identity,
    /// The suite to announce in `client/init`.
    pub suite: CipherSuite,
    /// Where this client's pairing records and pairing configuration live.
    ///
    /// The handshake candidate set is derived from it rather than supplied, because the rules
    /// are easy to get wrong: see
    /// [`handshake_candidates`](crate::noise::trust_store::handshake_candidates).
    pub store: Arc<dyn PairingStore>,
}

impl std::fmt::Debug for EncryptionSettings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EncryptionSettings")
            .field("client_id", &self.identity.client_id())
            .field("suite", &self.suite)
            .finish_non_exhaustive()
    }
}

impl EncryptionSettings {
    /// Settings for a client that has not paired yet, with an in-memory store.
    ///
    /// The store is in memory, so records do not survive the process. A client that means to
    /// stay paired needs a durable one — the identity and the records are exactly what has to
    /// outlive a reboot for a pairing to still mean anything.
    pub fn unpaired(identity: Identity) -> Result<Self, Error> {
        Ok(Self {
            identity,
            suite: CipherSuite::default(),
            store: Arc::new(InMemoryPairingStore::new()?),
        })
    }

    /// Settings over a caller-supplied store.
    pub fn with_store(identity: Identity, store: Arc<dyn PairingStore>) -> Self {
        Self {
            identity,
            suite: CipherSuite::default(),
            store,
        }
    }
}

/// What the router needs to carry on a pairing or a re-handshake mid-connection.
#[derive(Clone)]
pub(crate) struct SecurityContext {
    identity: Identity,
    suite: CipherSuite,
    server_static: [u8; 32],
    server_id: String,
    store: Arc<dyn PairingStore>,
    /// Which PSK category keys the live session.
    ///
    /// Shared and mutable because a re-handshake changes it — that is what a re-handshake is
    /// for — and the pairing check reads it at the moment an activation arrives, not at
    /// connect time.
    psk_category: Arc<Mutex<crate::noise::PskCategory>>,
    /// The `psk_id` that keyed the live session.
    ///
    /// Management needs it for two decisions that turn on *whose* record is being touched:
    /// `server/unpair` revokes the record that authenticated this connection, and a
    /// `management/remove-record` naming that same record revokes the requester. Like the
    /// category, it moves with a re-handshake.
    psk_id: Arc<Mutex<String>>,
    /// Whether `management` is in the connection's current activity set.
    ///
    /// Management commands are scoped to it: one arriving without it is answered
    /// `permission_denied` rather than obeyed. A server can add or drop the activity mid
    /// connection, so this tracks every activation rather than only the first.
    management: Arc<Mutex<bool>>,
}

/// Connection components returned by [`ProtocolClient::split()`].
/// Use the fields you need; ignore the rest.
pub struct Connection {
    /// Protocol messages from the server
    pub messages: UnboundedReceiver<Message>,
    /// Audio chunks from the server
    pub audio: UnboundedReceiver<AudioChunk>,
    /// Artwork chunks from the server
    pub artwork: UnboundedReceiver<ArtworkChunk>,
    /// Visualizer chunks from the server
    pub visualizer: UnboundedReceiver<VisualizerChunk>,
    /// Clock synchronization state
    pub clock_sync: Arc<Mutex<ClockSync>>,
    /// Sender for writing messages to the server
    pub sender: WsSender,
    /// Controller handle, if the server granted the `controller@v1` role
    pub controller: Option<Controller>,
    /// The `server/hello` received during handshake. Carries `server_id`,
    /// `connection_reason`, and `active_roles` — required for the
    /// multi-server arbitration policy described on [`ProtocolListener`].
    ///
    /// [`ProtocolListener`]: crate::protocol::listener::ProtocolListener
    pub server_hello: ServerHello,
    /// Must be held alive; dropping aborts background tasks
    pub guard: ConnectionGuard,
}

/// Bare role names as they appear in `stream/end` role lists — distinct from
/// the versioned `player@v1` names used during role negotiation.
const ROLE_PLAYER: &str = "player";
const ROLE_ARTWORK: &str = "artwork";
const ROLE_VISUALIZER: &str = "visualizer";

/// Which role streams are currently active, updated by the message router from
/// `stream/start` and `stream/end`.
#[derive(Debug, Default)]
struct StreamState {
    player_active: AtomicBool,
    artwork_active: AtomicBool,
    visualizer_active: AtomicBool,
}

impl StreamState {
    /// A `stream/start` for one role must not disturb another's stream, so
    /// absent roles are left untouched rather than cleared.
    fn note_stream_start(&self, start: &StreamStart) {
        if start.player.is_some() {
            self.player_active.store(true, Ordering::Release);
        }
        if start.artwork.is_some() {
            self.artwork_active.store(true, Ordering::Release);
        }
        if start.visualizer.is_some() {
            self.visualizer_active.store(true, Ordering::Release);
        }
    }

    /// `stream/end` with no roles ends every stream; otherwise only those listed.
    fn note_stream_end(&self, end: &StreamEnd) {
        if role_ended(end, ROLE_PLAYER) {
            self.player_active.store(false, Ordering::Release);
        }
        if role_ended(end, ROLE_ARTWORK) {
            self.artwork_active.store(false, Ordering::Release);
        }
        if role_ended(end, ROLE_VISUALIZER) {
            self.visualizer_active.store(false, Ordering::Release);
        }
    }

    fn is_player_active(&self) -> bool {
        self.player_active.load(Ordering::Acquire)
    }

    fn is_artwork_active(&self) -> bool {
        self.artwork_active.load(Ordering::Acquire)
    }

    fn is_visualizer_active(&self) -> bool {
        self.visualizer_active.load(Ordering::Acquire)
    }
}

fn role_ended(end: &StreamEnd, role: &str) -> bool {
    end.roles
        .as_ref()
        .is_none_or(|roles| roles.iter().any(|r| r == role))
}

/// Cheap to clone. `send_message` returns once the writer has reported the
/// underlying `sink.send` result, so the `Result` reflects the wire-write
/// outcome rather than queue insertion.
#[derive(Debug, Clone)]
pub struct WsSender {
    tx: UnboundedSender<WriteCommand>,
    /// The router updates this *before* forwarding the triggering `stream/start`
    /// / `stream/end`, so a consumer that reacts to those messages already
    /// observes the settled state.
    stream_state: Arc<StreamState>,
    /// Raised by the router while a re-handshake and the hello exchange that follows it are
    /// in flight.
    ///
    /// The spec is explicit that no other message flows during a re-handshake, and that the
    /// connection restarts at `server/hello` afterwards. A clock ping landing in the middle
    /// of that is not merely early — the reference server reports it as a sequence violation
    /// and drops the connection.
    handshake_gate: Arc<AtomicBool>,
}

impl WsSender {
    /// Send a message to the server.
    pub async fn send_message(&self, msg: Message) -> Result<(), Error> {
        let json = serde_json::to_string(&msg).map_err(|e| Error::Protocol(e.to_string()))?;
        // Time pings go out at 1Hz for as long as the connection lives; keep
        // that housekeeping at trace so debug shows only meaningful traffic.
        let level = if matches!(msg, Message::ClientTime(_)) {
            log::Level::Trace
        } else {
            log::Level::Debug
        };
        if self.handshake_gate.load(Ordering::Acquire) {
            // Time sync is housekeeping and resumes on its own, so skipping a sample costs
            // one interval. Anything else during the exchange is a caller error worth
            // surfacing rather than swallowing.
            if matches!(msg, Message::ClientTime(_)) {
                log::trace!("Skipping client/time: a handshake exchange is in flight");
                return Ok(());
            }
            return Err(Error::Protocol(
                "cannot send while a Noise handshake exchange is in flight".to_string(),
            ));
        }
        log::log!(level, "Sending message: {}", json);

        let (ack_tx, ack_rx) = tokio::sync::oneshot::channel();
        self.tx
            .send(WriteCommand::Send {
                payload: Outbound::Json(json),
                ack: ack_tx,
            })
            .map_err(|_| Error::WebSocket("connection closed".to_string()))?;

        // A cancelled ack means the writer dropped the command unsent — the
        // connection is gone either way.
        ack_rx
            .await
            .map_err(|_| Error::WebSocket("connection closed".to_string()))?
    }

    /// Send a raw binary frame.
    ///
    /// Uplink binary traffic is the source role's audio; downlink frames (player
    /// audio, artwork, visualizer) arrive on the receivers from
    /// [`ProtocolClient::split`] and never go through here. The frame must already
    /// carry its type byte and header — use [`Self::send_source_audio`] rather than
    /// packing one by hand.
    pub async fn send_binary(&self, frame: Vec<u8>) -> Result<(), Error> {
        let (ack_tx, ack_rx) = tokio::sync::oneshot::channel();
        self.tx
            .send(WriteCommand::Send {
                payload: Outbound::Binary(frame),
                ack: ack_tx,
            })
            .map_err(|_| Error::WebSocket("connection closed".to_string()))?;
        ack_rx
            .await
            .map_err(|_| Error::WebSocket("connection closed".to_string()))?
    }

    /// Send one captured audio frame as a source audio chunk (binary type 12).
    ///
    /// `server_timestamp_us` is when the first sample was captured, in the
    /// *server's* clock — convert with
    /// [`ClockSync::client_to_server_micros`](crate::sync::ClockSync::client_to_server_micros).
    /// Sending local time instead is the one mistake that produces audio which
    /// plays but never lines up.
    pub async fn send_source_audio(
        &self,
        server_timestamp_us: i64,
        frame: &[u8],
    ) -> Result<(), Error> {
        self.send_binary(pack_source_audio(server_timestamp_us, frame))
            .await
    }

    /// Announce the format of the input stream that follows.
    ///
    /// Sent before the first chunk of every stream, and again after a format
    /// change: the server treats it as the stream boundary.
    pub async fn send_client_stream_start(&self, source: ClientStreamSource) -> Result<(), Error> {
        self.send_message(Message::ClientStreamStart(ClientStreamStart { source }))
            .await
    }

    /// End the input stream, so the server tears down its ingest.
    pub async fn send_client_stream_end(&self) -> Result<(), Error> {
        self.send_message(Message::ClientStreamEnd(ClientStreamEnd {}))
            .await
    }

    /// Send a source state update (capture state, level, signal presence).
    pub async fn send_source_state(&self, source: SourceState) -> Result<(), Error> {
        self.send_message(Message::ClientState(ClientState {
            available: None,
            state: None,
            player: None,
            source: Some(source),
        }))
        .await
    }

    /// Report that audio appeared on, or disappeared from, the input.
    ///
    /// This is how a source whose activation is local — a turntable, a tape deck —
    /// tells the server the user has started something.
    /// Send a top-level client availability update.
    pub async fn send_sync_state(&self, state: ClientSyncState) -> Result<(), Error> {
        self.send_message(Message::ClientState(ClientState::availability(state)))
            .await
    }

    /// Tell the server this client is temporarily owned by another audio source.
    ///
    /// Release any Sendspin-owned output first so the external source can open
    /// the device without racing this client's audio stream.
    pub async fn enter_external_source(&self) -> Result<(), Error> {
        self.send_sync_state(ClientSyncState::ExternalSource).await
    }

    /// Tell the server this client's clock filter has converged enough to resume
    /// synchronized playback scheduling.
    ///
    /// Include player state when volume, mute, or static delay may have changed
    /// while the external source owned the device. Hardware/OS mixer changes
    /// must be read through platform APIs; this library only tracks its own
    /// software [`GainControl`](crate::audio::GainControl).
    pub async fn exit_external_source(&self, player: Option<PlayerState>) -> Result<(), Error> {
        self.send_message(Message::ClientState(ClientState {
            player,
            ..ClientState::availability(ClientSyncState::Synchronized)
        }))
        .await
    }

    /// Request a change to the active stream format.
    ///
    /// Sendspin servers may use this advisory message to switch codecs,
    /// sample rates, artwork dimensions, or other stream properties in
    /// response to changing network, CPU, or display conditions. Fields left
    /// as `None` are unconstrained by the client.
    ///
    /// This low-level sender does not enforce negotiated roles; callers should
    /// only use it for connections where the server granted the requested role.
    /// Use [`Connection::server_hello`] when you need to inspect the negotiated
    /// roles before sending.
    ///
    /// A requested component is rejected unless that role's stream is currently
    /// active (between its `stream/start` and `stream/end`): there is nothing to
    /// renegotiate for a role the server is not streaming.
    pub async fn request_stream_format(
        &self,
        player: Option<PlayerFormatRequest>,
        artwork: Option<ArtworkFormatRequest>,
    ) -> Result<(), Error> {
        self.request_stream_formats(player, artwork, None).await
    }

    /// Request changes to any combination of active stream formats.
    ///
    /// Each supplied component must have a corresponding active stream. The
    /// existing [`Self::request_stream_format`] method remains available for
    /// player/artwork-only callers.
    pub async fn request_stream_formats(
        &self,
        player: Option<PlayerFormatRequest>,
        artwork: Option<ArtworkFormatRequest>,
        visualizer: Option<VisualizerFormatRequest>,
    ) -> Result<(), Error> {
        if player.is_none() && artwork.is_none() && visualizer.is_none() {
            return Err(Error::Protocol(
                "stream/request-format requires a player, artwork, or visualizer request"
                    .to_string(),
            ));
        }

        if let Some(request) = visualizer.as_ref() {
            request
                .validate()
                .map_err(|message| Error::Protocol(message.to_string()))?;
        }

        if player.is_some() && !self.stream_state.is_player_active() {
            return Err(Error::Protocol(
                "stream/request-format requires an active player stream".to_string(),
            ));
        }

        if artwork.is_some() && !self.stream_state.is_artwork_active() {
            return Err(Error::Protocol(
                "stream/request-format requires an active artwork stream".to_string(),
            ));
        }

        if visualizer.is_some() && !self.stream_state.is_visualizer_active() {
            return Err(Error::Protocol(
                "stream/request-format requires an active visualizer stream".to_string(),
            ));
        }

        self.send_message(Message::StreamRequestFormat(StreamRequestFormat {
            player,
            artwork,
            visualizer,
        }))
        .await
    }

    /// Request a change to the active player/audio stream format.
    pub async fn request_player_format(&self, player: PlayerFormatRequest) -> Result<(), Error> {
        self.request_stream_format(Some(player), None).await
    }

    /// Request a change to an active artwork stream format.
    pub async fn request_artwork_format(&self, artwork: ArtworkFormatRequest) -> Result<(), Error> {
        self.request_stream_format(None, Some(artwork)).await
    }

    /// Request a change to an active visualizer stream format.
    pub async fn request_visualizer_format(
        &self,
        visualizer: VisualizerFormatRequest,
    ) -> Result<(), Error> {
        self.request_stream_formats(None, None, Some(visualizer))
            .await
    }

    fn send_goodbye(
        &self,
        reason: GoodbyeReason,
    ) -> Result<tokio::sync::oneshot::Receiver<Result<(), Error>>, Error> {
        let (ack_tx, ack_rx) = tokio::sync::oneshot::channel();
        self.tx
            .send(WriteCommand::Goodbye {
                reason,
                ack: ack_tx,
            })
            .map_err(|_| Error::WebSocket("connection closed".to_string()))?;
        Ok(ack_rx)
    }
}

/// Controller handle for sending playback commands to the server.
///
/// Only available when the server grants the `controller@v1` role.
/// Obtained via [`ProtocolClient::split()`].
#[derive(Debug, Clone)]
pub struct Controller {
    sender: WsSender,
}

impl Controller {
    async fn send_controller_command(&self, cmd: ControllerCommand) -> Result<(), Error> {
        let msg = Message::ClientCommand(ClientCommand {
            controller: Some(cmd),
        });
        self.sender.send_message(msg).await
    }

    async fn send_simple_command(&self, command: ControllerCommandType) -> Result<(), Error> {
        self.send_controller_command(ControllerCommand {
            command,
            volume: None,
            mute: None,
            position_ms: None,
            offset_ms: None,
        })
        .await
    }

    /// Resume playback
    pub async fn play(&self) -> Result<(), Error> {
        self.send_simple_command(ControllerCommandType::Play).await
    }

    /// Pause playback
    pub async fn pause(&self) -> Result<(), Error> {
        self.send_simple_command(ControllerCommandType::Pause).await
    }

    /// Stop playback
    pub async fn stop(&self) -> Result<(), Error> {
        self.send_simple_command(ControllerCommandType::Stop).await
    }

    /// Skip to next track
    pub async fn next(&self) -> Result<(), Error> {
        self.send_simple_command(ControllerCommandType::Next).await
    }

    /// Skip to previous track
    pub async fn previous(&self) -> Result<(), Error> {
        self.send_simple_command(ControllerCommandType::Previous)
            .await
    }

    /// Set group volume (0-100). Values above 100 are clamped.
    pub async fn set_volume(&self, volume: u8) -> Result<(), Error> {
        self.send_controller_command(ControllerCommand {
            command: ControllerCommandType::Volume,
            volume: Some(volume.clamp(0, 100)),
            mute: None,
            position_ms: None,
            offset_ms: None,
        })
        .await
    }

    /// Set group mute state
    pub async fn set_mute(&self, muted: bool) -> Result<(), Error> {
        self.send_controller_command(ControllerCommand {
            command: ControllerCommandType::Mute,
            volume: None,
            mute: Some(muted),
            position_ms: None,
            offset_ms: None,
        })
        .await
    }

    /// Set repeat mode
    pub async fn repeat(&self, mode: RepeatMode) -> Result<(), Error> {
        let command = match mode {
            RepeatMode::Off => ControllerCommandType::RepeatOff,
            RepeatMode::One => ControllerCommandType::RepeatOne,
            RepeatMode::All => ControllerCommandType::RepeatAll,
        };
        self.send_simple_command(command).await
    }

    /// Enable or disable shuffle
    pub async fn shuffle(&self, enabled: bool) -> Result<(), Error> {
        let command = if enabled {
            ControllerCommandType::Shuffle
        } else {
            ControllerCommandType::Unshuffle
        };
        self.send_simple_command(command).await
    }

    /// Switch to next group
    pub async fn switch(&self) -> Result<(), Error> {
        self.send_simple_command(ControllerCommandType::Switch)
            .await
    }

    /// Seek to an absolute playback position in milliseconds.
    ///
    /// Only send this when `seek` is in the server's `supported_commands`.
    /// Per the spec, the server ignores the command if `position_ms` is
    /// outside the range 0 to
    /// [`ControllerState::seek_max_ms`](crate::protocol::messages::ControllerState::seek_max_ms).
    pub async fn seek(&self, position_ms: u64) -> Result<(), Error> {
        self.send_controller_command(ControllerCommand {
            command: ControllerCommandType::Seek,
            volume: None,
            mute: None,
            position_ms: Some(position_ms),
            offset_ms: None,
        })
        .await
    }

    /// Seek by a signed offset in milliseconds from the current position
    /// (positive forward, negative backward).
    ///
    /// Only send this when `seek_relative` is in the server's
    /// `supported_commands`. The server applies the offset on a best-effort
    /// basis and clamps the result to the seekable range.
    pub async fn seek_relative(&self, offset_ms: i64) -> Result<(), Error> {
        self.send_controller_command(ControllerCommand {
            command: ControllerCommandType::SeekRelative,
            volume: None,
            mute: None,
            position_ms: None,
            offset_ms: Some(offset_ms),
        })
        .await
    }
}

/// Binary message type IDs per Sendspin spec
pub mod binary_types {
    /// Player audio chunk (types 4-7, we use 4)
    pub const PLAYER_AUDIO: u8 = 0x04;
    /// Artwork channel 0 (type 8)
    pub const ARTWORK_CHANNEL_0: u8 = 0x08;
    /// Artwork channel 1 (type 9)
    pub const ARTWORK_CHANNEL_1: u8 = 0x09;
    /// Artwork channel 2 (type 10)
    pub const ARTWORK_CHANNEL_2: u8 = 0x0A;
    /// Artwork channel 3 (type 11)
    pub const ARTWORK_CHANNEL_3: u8 = 0x0B;
    /// Source audio chunk, client to server (type 12)
    pub const SOURCE_AUDIO: u8 = 0x0C;
    /// Visualizer loudness data (type 16).
    pub const VISUALIZER_LOUDNESS: u8 = 0x10;
    /// Visualizer beat data (type 17).
    pub const VISUALIZER_BEAT: u8 = 0x11;
    /// Visualizer dominant-frequency data (type 18).
    pub const VISUALIZER_F_PEAK: u8 = 0x12;
    /// Visualizer spectrum data (type 19).
    pub const VISUALIZER_SPECTRUM: u8 = 0x13;
    /// Visualizer energy-onset data (type 20).
    pub const VISUALIZER_PEAK: u8 = 0x14;
    /// Visualizer perceived-pitch data (type 21).
    pub const VISUALIZER_PITCH: u8 = 0x15;
    /// Check if a binary type ID is for artwork (8-11)
    pub fn is_artwork(type_id: u8) -> bool {
        (ARTWORK_CHANNEL_0..=ARTWORK_CHANNEL_3).contains(&type_id)
    }

    /// Get artwork channel number from type ID (0-3)
    pub fn artwork_channel(type_id: u8) -> Option<u8> {
        if is_artwork(type_id) {
            Some(type_id - ARTWORK_CHANNEL_0)
        } else {
            None
        }
    }

    /// Check if a binary type ID is for visualizer data (16-20).
    pub fn is_visualizer(type_id: u8) -> bool {
        (VISUALIZER_LOUDNESS..=VISUALIZER_PITCH).contains(&type_id)
    }
}

/// Pack one source audio frame: type byte, big-endian capture timestamp, payload.
///
/// The mirror of [`AudioChunk::from_bytes`], and separate from the sender so the
/// layout can be tested without a connection.
pub fn pack_source_audio(server_timestamp_us: i64, frame: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(9 + frame.len());
    out.push(binary_types::SOURCE_AUDIO);
    out.extend_from_slice(&server_timestamp_us.to_be_bytes());
    out.extend_from_slice(frame);
    out
}

/// Audio chunk from server (binary type 4)
#[derive(Debug, Clone)]
pub struct AudioChunk {
    /// Server timestamp in microseconds
    pub timestamp: i64,
    /// Raw audio data bytes
    pub data: Arc<[u8]>,
}

impl AudioChunk {
    /// Parse from WebSocket binary frame (type 4 = player audio)
    pub fn from_bytes(frame: &[u8]) -> Result<Self, Error> {
        if frame.len() < 9 {
            return Err(Error::Protocol(format!(
                "Audio chunk too short: got {} bytes, need at least 9",
                frame.len()
            )));
        }

        // Per spec: player audio uses binary type 4
        if frame[0] != binary_types::PLAYER_AUDIO {
            return Err(Error::Protocol(format!(
                "Invalid audio chunk type: expected {}, got {}",
                binary_types::PLAYER_AUDIO,
                frame[0]
            )));
        }

        let timestamp = i64::from_be_bytes([
            frame[1], frame[2], frame[3], frame[4], frame[5], frame[6], frame[7], frame[8],
        ]);

        let data = Arc::from(&frame[9..]);

        Ok(Self { timestamp, data })
    }
}

/// Artwork chunk from server (binary types 8-11)
#[derive(Debug, Clone)]
pub struct ArtworkChunk {
    /// Artwork channel (0-3)
    pub channel: u8,
    /// Server timestamp in microseconds
    pub timestamp: i64,
    /// Image data bytes (JPEG, PNG, or BMP)
    /// Empty payload means clear the artwork
    pub data: Arc<[u8]>,
}

impl ArtworkChunk {
    /// Parse from WebSocket binary frame (types 8-11 = artwork channels 0-3)
    pub fn from_bytes(frame: &[u8]) -> Result<Self, Error> {
        if frame.len() < 9 {
            return Err(Error::Protocol(format!(
                "Artwork chunk too short: got {} bytes, need at least 9",
                frame.len()
            )));
        }

        let type_id = frame[0];
        let channel = binary_types::artwork_channel(type_id)
            .ok_or_else(|| Error::Protocol(format!("Invalid artwork chunk type: {}", type_id)))?;

        let timestamp = i64::from_be_bytes([
            frame[1], frame[2], frame[3], frame[4], frame[5], frame[6], frame[7], frame[8],
        ]);

        let data = Arc::from(&frame[9..]);

        Ok(Self {
            channel,
            timestamp,
            data,
        })
    }

    /// Check if this is a clear command (empty payload)
    pub fn is_clear(&self) -> bool {
        self.data.is_empty()
    }
}

/// Visualizer chunk from server (binary types 16-20).
#[derive(Debug, Clone)]
pub struct VisualizerChunk {
    /// Visualizer binary message type (16-20).
    pub type_id: u8,
    /// Server timestamp in microseconds.
    pub timestamp: i64,
    /// Raw visualization data bytes, left for the application to decode.
    pub data: Arc<[u8]>,
}

impl VisualizerChunk {
    /// Return the typed visualizer data kind represented by this chunk.
    ///
    /// Returns `None` if a chunk was constructed manually with an invalid
    /// `type_id`; frames parsed by [`Self::from_bytes`] always return `Some`.
    pub fn data_type(&self) -> Option<VisualizerDataType> {
        match self.type_id {
            binary_types::VISUALIZER_LOUDNESS => Some(VisualizerDataType::Loudness),
            binary_types::VISUALIZER_BEAT => Some(VisualizerDataType::Beat),
            binary_types::VISUALIZER_F_PEAK => Some(VisualizerDataType::FPeak),
            binary_types::VISUALIZER_SPECTRUM => Some(VisualizerDataType::Spectrum),
            binary_types::VISUALIZER_PEAK => Some(VisualizerDataType::Peak),
            binary_types::VISUALIZER_PITCH => Some(VisualizerDataType::Pitch),
            _ => None,
        }
    }

    /// Parse from a WebSocket binary frame (visualizer types 16-20).
    pub fn from_bytes(frame: &[u8]) -> Result<Self, Error> {
        if frame.len() < 9 {
            return Err(Error::Protocol(format!(
                "Visualizer chunk too short: got {} bytes, need at least 9",
                frame.len()
            )));
        }

        if !binary_types::is_visualizer(frame[0]) {
            return Err(Error::Protocol(format!(
                "Invalid visualizer chunk type: expected 16-21, got {}",
                frame[0]
            )));
        }

        let timestamp = i64::from_be_bytes([
            frame[1], frame[2], frame[3], frame[4], frame[5], frame[6], frame[7], frame[8],
        ]);

        let data = Arc::from(&frame[9..]);

        Ok(Self {
            type_id: frame[0],
            timestamp,
            data,
        })
    }
}

/// Binary frame from server (any type)
#[derive(Debug, Clone)]
pub enum BinaryFrame {
    /// Player audio (type 4)
    Audio(AudioChunk),
    /// Artwork image (types 8-11)
    Artwork(ArtworkChunk),
    /// Visualizer data (types 16-20)
    Visualizer(VisualizerChunk),
    /// Unknown binary type
    Unknown {
        /// The unknown type ID
        type_id: u8,
        /// Raw data after the type byte
        data: Arc<[u8]>,
    },
}

impl BinaryFrame {
    /// Parse any binary frame from WebSocket
    pub fn from_bytes(frame: &[u8]) -> Result<Self, Error> {
        if frame.is_empty() {
            return Err(Error::Protocol("Empty binary frame".to_string()));
        }

        let type_id = frame[0];

        match type_id {
            binary_types::PLAYER_AUDIO => Ok(BinaryFrame::Audio(AudioChunk::from_bytes(frame)?)),
            t if binary_types::is_artwork(t) => {
                Ok(BinaryFrame::Artwork(ArtworkChunk::from_bytes(frame)?))
            }
            t if binary_types::is_visualizer(t) => {
                Ok(BinaryFrame::Visualizer(VisualizerChunk::from_bytes(frame)?))
            }
            // The router warns when it sees the Unknown variant; parsing
            // itself stays quiet to avoid reporting the same frame twice.
            _ => Ok(BinaryFrame::Unknown {
                type_id,
                data: Arc::from(&frame[1..]),
            }),
        }
    }
}

/// WebSocket client for Sendspin protocol
pub struct ProtocolClient {
    out_tx: UnboundedSender<WriteCommand>,
    audio_rx: UnboundedReceiver<AudioChunk>,
    artwork_rx: UnboundedReceiver<ArtworkChunk>,
    visualizer_rx: UnboundedReceiver<VisualizerChunk>,
    message_rx: UnboundedReceiver<Message>,
    clock_sync: Arc<Mutex<ClockSync>>,
    server_hello: ServerHello,
    stream_state: Arc<StreamState>,
    /// Shared with the router; see [`WsSender::handshake_gate`].
    handshake_gate: Arc<AtomicBool>,
    /// Background task guard, aborts tasks on drop
    guard: ConnectionGuard,
}

/// Aborts background tasks on drop. Hold this alive for the lifetime of the
/// connection.
pub struct ConnectionGuard {
    sender: WsSender,
    router_handle: Option<tokio::task::JoinHandle<()>>,
    sync_handle: Option<tokio::task::JoinHandle<()>>,
    writer_handle: Option<tokio::task::JoinHandle<()>>,
}

impl ConnectionGuard {
    /// Gracefully disconnect: enqueue `client/goodbye`, await the writer's
    /// ack so the goodbye + close frames are known to have flushed (or
    /// surface the wire error if they didn't), then reap the writer.
    pub async fn disconnect(mut self, reason: GoodbyeReason) -> Result<(), Error> {
        log::debug!("Disconnecting (reason: {reason:?})");
        // Stop clock-sync first so it can't enqueue time samples behind the
        // goodbye. The reader stays up until the goodbye/close has flushed
        // (below) so the socket isn't half-closed while we're still writing.
        if let Some(h) = self.sync_handle.take() {
            h.abort();
        }

        let ack_rx = self.sender.send_goodbye(reason)?;
        let goodbye_result = ack_rx
            .await
            .map_err(|_| Error::WebSocket("connection closed".to_string()))?;

        // Reap the writer separately from awaiting its ack — the ack arrives
        // just before the task returns, so this only joins the trailing
        // teardown.
        if let Some(h) = self.writer_handle.take() {
            let _ = h.await;
        }

        // Goodbye + close are flushed; tear the reader down now.
        if let Some(h) = self.router_handle.take() {
            h.abort();
        }

        log::debug!("Disconnect complete");
        goodbye_result
    }

    /// Resolves once the connection is dead: the router task has exited
    /// (peer close, transport failure, or teardown). Cancel-safe.
    ///
    /// Liveness means the *reader*. A write-side failure alone does not
    /// fire this — on TCP it resets the read side too in short order, and
    /// sends toward a dead writer fail fast rather than hang.
    pub(crate) async fn closed(&mut self) {
        if let Some(h) = &mut self.router_handle {
            let _ = h.await;
        }
    }

    /// Non-blocking [`Self::closed`].
    pub(crate) fn is_closed(&self) -> bool {
        self.router_handle
            .as_ref()
            .is_none_or(tokio::task::JoinHandle::is_finished)
    }
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        if let Some(h) = self.router_handle.take() {
            h.abort();
        }
        if let Some(h) = self.sync_handle.take() {
            h.abort();
        }
        if let Some(h) = self.writer_handle.take() {
            h.abort();
        }
    }
}

impl Connection {
    /// See [`WsSender::enter_external_source`].
    pub async fn enter_external_source(&self) -> Result<(), Error> {
        self.sender.enter_external_source().await
    }

    /// See [`WsSender::exit_external_source`].
    pub async fn exit_external_source(&self, player: Option<PlayerState>) -> Result<(), Error> {
        self.sender.exit_external_source(player).await
    }
}

impl ProtocolClient {
    /// Connect to Sendspin server
    pub(crate) async fn connect<R>(
        request: R,
        hello: ClientHello,
        initial_state: ClientState,
        clock: Arc<dyn Clock>,
        encryption: Encryption,
    ) -> Result<Self, Error>
    where
        R: IntoClientRequest + Unpin,
    {
        let (mut ws_stream, _) = connect_async(request)
            .await
            .map_err(|e| Error::Connection(e.to_string()))?;

        let mut encrypted_server_id = None;
        let mut security: Option<SecurityContext> = None;
        let transport = match encryption {
            Encryption::Disabled => Transport::Plain,
            Encryption::Enabled(settings) => {
                let identity = settings.identity.clone();
                let suite = settings.suite;
                let store = Arc::clone(&settings.store);
                let result = run_noise_handshake(&mut ws_stream, settings).await?;
                log::info!(
                    "Noise handshake complete: server_id={}, psk={:?}",
                    result.server_id,
                    result.psk_category
                );
                store.mark_record_used(&result.psk_id)?;
                encrypted_server_id = Some(result.server_id.clone());
                security = Some(SecurityContext {
                    identity,
                    suite,
                    server_static: crate::noise::keys::b64_decode(&result.server_id)?,
                    server_id: result.server_id.clone(),
                    store,
                    psk_category: Arc::new(Mutex::new(result.psk_category)),
                    psk_id: Arc::new(Mutex::new(result.psk_id.clone())),
                    management: Arc::new(Mutex::new(false)),
                });
                Transport::encrypted(result.session)?
            }
        };

        Self::drive(
            ws_stream,
            hello,
            initial_state,
            clock,
            transport,
            encrypted_server_id,
            security,
        )
        .await
    }

    /// Drive the protocol-client state machine over an already-handshaked
    /// WebSocket stream. Shared between outbound `connect()` and inbound
    /// acceptor paths.
    pub(crate) async fn drive<S>(
        ws_stream: WebSocketStream<S>,
        hello: ClientHello,
        initial_state: ClientState,
        clock: Arc<dyn Clock>,
        transport: Transport,
        encrypted_server_id: Option<String>,
        security: Option<SecurityContext>,
    ) -> Result<Self, Error>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let (mut write, mut read) = ws_stream.split();
        let encrypted = transport.is_encrypted();
        let transport = Arc::new(Mutex::new(transport));

        // The handshake exchange (hello + state) sends directly on the sink
        // rather than through the writer task, so handshake failures are
        // returned synchronously instead of through an ack channel.
        let hello_msg = Message::ClientHello(hello);
        let hello_json =
            serde_json::to_string(&hello_msg).map_err(|e| Error::Protocol(e.to_string()))?;
        if !encrypted {
            // Transition mode: the client speaks first and the server answers with the
            // legacy hello carrying its identity, roles and purpose.
            log::debug!("Sending client/hello: {}", hello_json);
            let frames = transport
                .lock()
                .encode(Outbound::Json(hello_json.clone()))?;
            send_all(&mut write, frames).await?;
        }

        log::debug!("Waiting for server/hello...");
        let server_hello = loop {
            let Some(result) = read.next().await else {
                log::error!("Connection closed before receiving server/hello");
                return Err(Error::Connection("No server hello received".to_string()));
            };
            match result {
                Ok(ws_msg) => {
                    let decoded = transport.lock().decode(&ws_msg)?;
                    let text = match decoded {
                        Some(Inbound::Json(text)) => text,
                        Some(Inbound::Binary(bytes)) => {
                            log::warn!(
                                "Unexpected binary frame (type {}) while waiting for server/hello",
                                bytes.first().copied().unwrap_or_default()
                            );
                            continue;
                        }
                        None => match ws_msg {
                            WsMessage::Close(_) => {
                                log::error!("Server closed connection");
                                return Err(Error::Connection(
                                    "Server closed connection".to_string(),
                                ));
                            }
                            _ => continue,
                        },
                    };
                    if let Some(server_id) = encrypted_server_id.as_deref() {
                        // The encrypted hello carries only {name}: identity was settled by
                        // the Noise handshake, and roles and purpose arrive in
                        // server/activate. Parse it directly rather than through `Message`,
                        // which cannot hold two shapes under one `type` tag.
                        let hello: super::messages::ServerHelloEncrypted =
                            match serde_json::from_str::<TypedPayload<_>>(&text) {
                                Ok(wrapper) if wrapper.r#type == "server/hello" => wrapper.payload,
                                _ => {
                                    log::error!("Expected server/hello, got: {}", text);
                                    return Err(Error::Protocol(
                                        "Expected server/hello".to_string(),
                                    ));
                                }
                            };
                        log::info!("Connected to server: {} ({})", hello.name, server_id);

                        // Now it is the client's turn, and only then does the server declare
                        // what this connection is for.
                        log::debug!("Sending client/hello: {}", hello_json);
                        let frames = transport
                            .lock()
                            .encode(Outbound::Json(hello_json.clone()))?;
                        send_all(&mut write, frames).await?;

                        let activate = await_server_activate(&mut read, &transport).await?;
                        log::info!(
                            "Server activated: activities={:?}, active_roles={:?}",
                            activate.activities,
                            activate.active_roles
                        );
                        if let Some(context) = &security {
                            note_management_activity(context, &activate);
                        }
                        // Bridge onto the shape the rest of the client already reads. The
                        // rank ladder is the same for both spellings, so arbitration is
                        // unaffected by which one a server used.
                        break ServerHello {
                            server_id: server_id.to_string(),
                            name: hello.name,
                            version: crate::noise::constants::PROTOCOL_VERSION,
                            active_roles: activate.active_roles.clone().unwrap_or_default(),
                            connection_reason: activity_to_reason(&activate),
                            selected_pair_method: activate.pairing.as_ref().map(|p| p.method),
                        };
                    }
                    log::trace!("Received message: {}", text);
                    let msg: Message = serde_json::from_str(&text).map_err(|e| {
                        log::error!("Failed to parse server message: {} (payload: {})", e, text);
                        Error::Protocol(e.to_string())
                    })?;

                    match msg {
                        Message::ServerHello(server_hello) => {
                            log::debug!("Received server/hello: {:?}", server_hello);
                            log::info!(
                                "Connected to server: {} ({})",
                                server_hello.name,
                                server_hello.server_id
                            );
                            break server_hello;
                        }
                        _ => {
                            log::error!("Expected server/hello, got: {:?}", msg);
                            return Err(Error::Protocol("Expected server/hello".to_string()));
                        }
                    }
                }
                Err(e) => {
                    log::error!("WebSocket error: {}", e);
                    return Err(Error::WebSocket(e.to_string()));
                }
            }
        };

        // The builder was told which roles this client can fill; `server/activate` decided
        // which it actually got. State for the rest has no addressee.
        let mut initial_state = initial_state;
        initial_state.retain_active_roles(&server_hello.active_roles);
        let state_msg = Message::ClientState(initial_state);
        let state_json =
            serde_json::to_string(&state_msg).map_err(|e| Error::Protocol(e.to_string()))?;
        log::debug!("Sending initial client/state: {}", state_json);
        let frames = transport.lock().encode(Outbound::Json(state_json))?;
        send_all(&mut write, frames).await?;

        let (out_tx, out_rx) = unbounded_channel::<WriteCommand>();
        let (audio_tx, audio_rx) = unbounded_channel();
        let (artwork_tx, artwork_rx) = unbounded_channel();
        let (visualizer_tx, visualizer_rx) = unbounded_channel();
        let (message_tx, message_rx) = unbounded_channel();
        let clock_sync = Arc::new(Mutex::new(ClockSync::new(Arc::clone(&clock))));
        let stream_state = Arc::new(StreamState::default());

        let writer_handle = tokio::spawn(writer_task(write, out_rx, Arc::clone(&transport)));

        let clock_sync_router = Arc::clone(&clock_sync);
        let clock_router = Arc::clone(&clock);
        let stream_state_router = Arc::clone(&stream_state);
        let transport_router = Arc::clone(&transport);
        // Shared with the router, which raises it for the duration of a re-handshake and the
        // hello exchange that follows.
        let handshake_gate = Arc::new(AtomicBool::new(false));
        let handshake_gate_router = Arc::clone(&handshake_gate);
        let security_router = security.clone();
        let out_tx_router = out_tx.clone();
        let hello_json_router = hello_json.clone();
        // The router task handle is used by ConnectionGuard::closed() observers.
        let router_handle = tokio::spawn(async move {
            Self::message_router(
                read,
                audio_tx,
                artwork_tx,
                visualizer_tx,
                message_tx,
                clock_sync_router,
                clock_router,
                stream_state_router,
                transport_router,
                security_router,
                out_tx_router,
                hello_json_router,
                handshake_gate_router,
            )
            .await;
        });

        // First two samples fire 10ms apart so an offset estimate (and
        // playback start) is available almost immediately; drift converges
        // over the following 1Hz samples (see TimeFilter).
        let sync_sender = WsSender {
            tx: out_tx.clone(),
            stream_state: Arc::clone(&stream_state),
            handshake_gate: Arc::clone(&handshake_gate),
        };
        let sync_handle = tokio::spawn(async move {
            let mut sample_count: u32 = 0;
            'sync: loop {
                let t1 = clock.now_micros();
                let msg = Message::ClientTime(ClientTime {
                    client_transmitted: t1,
                });
                match sync_sender.send_message(msg).await {
                    Ok(()) => {
                        sample_count = sample_count.saturating_add(1);
                    }
                    Err(e) => {
                        log::info!("Clock sync task exiting: {}", e);
                        break 'sync;
                    }
                }
                let delay = if sample_count < 2 {
                    tokio::time::Duration::from_millis(10)
                } else {
                    tokio::time::Duration::from_secs(1)
                };
                tokio::time::sleep(delay).await;
            }
        });

        Ok(Self {
            out_tx: out_tx.clone(),
            audio_rx,
            artwork_rx,
            visualizer_rx,
            message_rx,
            clock_sync,
            server_hello,
            stream_state: Arc::clone(&stream_state),
            handshake_gate: Arc::clone(&handshake_gate),
            guard: ConnectionGuard {
                sender: WsSender {
                    tx: out_tx,
                    stream_state,
                    handshake_gate,
                },
                router_handle: Some(router_handle),
                sync_handle: Some(sync_handle),
                writer_handle: Some(writer_handle),
            },
        })
    }

    #[allow(clippy::too_many_arguments)] // internal plumbing: per-channel senders + shared state
    async fn message_router<S>(
        mut read: SplitStream<WebSocketStream<S>>,
        audio_tx: UnboundedSender<AudioChunk>,
        artwork_tx: UnboundedSender<ArtworkChunk>,
        visualizer_tx: UnboundedSender<VisualizerChunk>,
        message_tx: UnboundedSender<Message>,
        clock_sync: Arc<Mutex<ClockSync>>,
        clock: Arc<dyn Clock>,
        stream_state: Arc<StreamState>,
        transport_router: Arc<Mutex<Transport>>,
        security: Option<SecurityContext>,
        out_tx: UnboundedSender<WriteCommand>,
        hello_json: String,
        handshake_gate: Arc<AtomicBool>,
    ) where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let mut audio_closed = false;
        let mut artwork_closed = false;
        let mut visualizer_closed = false;
        let mut message_closed = false;
        let mut audio_chunk_count = 0u64;
        let mut visualizer_chunk_count = 0u64;
        // Pairing is a two-message exchange, so the record waits here between sending
        // client/pair-finalize and the server acknowledging it. Held rather than stored,
        // because persisting early leaves a record for a pairing the server never completed.
        let mut pending_pairing: Option<PairingRecord> = None;

        while let Some(msg) = read.next().await {
            let ws_msg = match msg {
                Ok(m) => m,
                Err(e) => {
                    log::error!("WebSocket error: {}", e);
                    break;
                }
            };
            if matches!(ws_msg, WsMessage::Close(_)) {
                log::info!("Server closed connection");
                break;
            }
            // A decode failure on an encrypted connection is fatal: an AEAD failure or a
            // malformed fragment sequence are both protocol errors the spec answers by
            // closing, and there is no state to resynchronise from.
            let decoded = match transport_router.lock().decode(&ws_msg) {
                Ok(decoded) => decoded,
                Err(e) => {
                    log::error!("Transport error, closing connection: {}", e);
                    break;
                }
            };
            match decoded {
                Some(Inbound::Binary(data)) => match BinaryFrame::from_bytes(&data) {
                    Ok(BinaryFrame::Audio(chunk)) => {
                        audio_chunk_count += 1;
                        if should_log_sample(audio_chunk_count) {
                            log::trace!(
                                "Received audio chunk: chunk={}, timestamp={}µs, payload_bytes={}, wire_bytes={}",
                                audio_chunk_count,
                                chunk.timestamp,
                                chunk.data.len(),
                                data.len()
                            );
                        }
                        if !audio_closed && audio_tx.send(chunk).is_err() {
                            log::error!("Audio receiver dropped — audio data will be discarded");
                            audio_closed = true;
                        }
                    }
                    Ok(BinaryFrame::Artwork(chunk)) => {
                        // Artwork arrives in short bursts on track changes, so
                        // every chunk is worth a line; audio and visualizer
                        // chunks stream continuously and are sampled instead.
                        log::trace!(
                            "Received artwork chunk: channel={}, timestamp={}µs, payload_bytes={}",
                            chunk.channel,
                            chunk.timestamp,
                            chunk.data.len()
                        );
                        if !artwork_closed && artwork_tx.send(chunk).is_err() {
                            log::error!(
                                "Artwork receiver dropped — artwork data will be discarded"
                            );
                            artwork_closed = true;
                        }
                    }
                    Ok(BinaryFrame::Visualizer(chunk)) => {
                        visualizer_chunk_count += 1;
                        if should_log_sample(visualizer_chunk_count) {
                            log::trace!(
                                "Received visualizer chunk: chunk={}, timestamp={}µs, payload_bytes={}",
                                visualizer_chunk_count,
                                chunk.timestamp,
                                chunk.data.len()
                            );
                        }
                        if !visualizer_closed && visualizer_tx.send(chunk).is_err() {
                            log::error!(
                                "Visualizer receiver dropped — visualizer data will be discarded"
                            );
                            visualizer_closed = true;
                        }
                    }
                    Ok(BinaryFrame::Unknown { type_id, .. }) => {
                        log::warn!("Received unknown binary type: {}", type_id);
                    }
                    Err(e) => {
                        log::warn!("Failed to parse binary frame: {}", e);
                    }
                },
                Some(Inbound::Json(text)) => {
                    // Capture receive time before deserialization so
                    // t4 is as close to the true arrival time as possible.
                    let t4 = clock.now_micros();
                    log::trace!("Received message body: {}", text);
                    match serde_json::from_str::<Message>(&text) {
                        Ok(msg) => {
                            // ServerTime is consumed here for clock sync
                            // and intentionally NOT forwarded to message_rx
                            // consumers — it's an internal protocol detail.
                            // It also arrives at 1Hz for as long as the
                            // connection lives, so it stays out of the debug
                            // view; ClockSync::update logs the computed sync
                            // state instead.
                            if let Message::ServerTime(ref st) = msg {
                                clock_sync.lock().update(
                                    st.client_transmitted,
                                    st.server_received,
                                    st.server_transmitted,
                                    t4,
                                );
                            } else if let Some(answer) =
                                answer_management(security.as_ref(), &msg).transpose()
                            {
                                // Every management/* request draws exactly one
                                // management/result, in order — which is what lets the
                                // server match reply to request with no identifier field.
                                match answer {
                                    Ok((result, effect)) => {
                                        let reply = Message::ManagementResult(result);
                                        match serde_json::to_string(&reply) {
                                            Ok(json) => {
                                                if let Err(e) =
                                                    send_and_flush(&out_tx, Outbound::Json(json))
                                                        .await
                                                {
                                                    log::error!("management/result: {e}");
                                                    break;
                                                }
                                            }
                                            Err(e) => {
                                                log::error!("management/result encode: {e}");
                                                break;
                                            }
                                        }
                                        // The reply is on the wire before the session ends,
                                        // so the server learns the outcome of the very
                                        // request that revoked it.
                                        if effect
                                            == crate::noise::ManagementEffect::GoodbyeUnauthorized
                                        {
                                            log::info!("Management session revoked its own record");
                                            let _ =
                                                send_goodbye(&out_tx, GoodbyeReason::Unauthorized)
                                                    .await;
                                            break;
                                        }
                                    }
                                    Err(e) => {
                                        log::error!("management request failed: {e}");
                                        break;
                                    }
                                }
                            } else if let Some(context) = security.as_ref() {
                                match &msg {
                                    Message::ServerActivate(activate) => {
                                        // A server claiming management authority it was never
                                        // granted is not a request to decline — it is a peer
                                        // asserting a trust level the handshake contradicts.
                                        if management_claim_is_unauthorized(context, activate) {
                                            log::warn!(
                                                "Server claimed management on an unpaired session"
                                            );
                                            let _ =
                                                send_goodbye(&out_tx, GoodbyeReason::Unauthorized)
                                                    .await;
                                            break;
                                        }
                                        note_management_activity(context, activate);
                                        if let Some(record) =
                                            handle_pairing_activation(activate, context, &out_tx)
                                                .await
                                        {
                                            pending_pairing = Some(record);
                                        }
                                    }
                                    Message::ServerUnpair(_) => {
                                        // Ignored mid-pairing: a `trust_level: none` session
                                        // has no record to revoke.
                                        if *context.psk_category.lock()
                                            == crate::noise::PskCategory::LongTerm
                                        {
                                            let psk_id = context.psk_id.lock().clone();
                                            if let Err(e) = crate::noise::management::handle_unpair(
                                                context.store.as_ref(),
                                                &psk_id,
                                            ) {
                                                log::error!("server/unpair: {e}");
                                            }
                                            log::info!(
                                                "Unpaired by {}: record {psk_id}",
                                                context.server_id
                                            );
                                            let _ = send_goodbye(&out_tx, GoodbyeReason::Unpaired)
                                                .await;
                                            break;
                                        }
                                    }
                                    Message::ServerPairFinalize(_) => {
                                        match pending_pairing.take() {
                                            Some(record) => {
                                                // The server has persisted its side; now it
                                                // is safe for the client to persist its own.
                                                match context.store.add_record(record.clone()) {
                                                    Ok(()) => log::info!(
                                                        "Paired with {}: record {}",
                                                        context.server_id,
                                                        record.psk_id()
                                                    ),
                                                    Err(e) => log::error!(
                                                        "Could not persist pairing record: {e}"
                                                    ),
                                                }
                                            }
                                            None => log::warn!(
                                                "server/pair-finalize arrived with no pairing in flight"
                                            ),
                                        }
                                    }
                                    Message::PairAbort(abort) => {
                                        log::warn!("Pairing aborted by server: {:?}", abort.reason);
                                        pending_pairing = None;
                                    }
                                    Message::NoiseHandshake(hs) => {
                                        // No other message may flow until the exchange and the
                                        // hello restart that follows it are done.
                                        handshake_gate.store(true, Ordering::Release);
                                        let outcome = handle_rehandshake(
                                            &hs.data,
                                            context,
                                            &transport_router,
                                            &out_tx,
                                        )
                                        .await;
                                        let outcome = match outcome {
                                            Ok(()) => {
                                                restart_hello_exchange(
                                                    &mut read,
                                                    &transport_router,
                                                    &out_tx,
                                                    &hello_json,
                                                )
                                                .await
                                            }
                                            Err(e) => Err(e),
                                        };
                                        let activate = match outcome {
                                            Ok(activate) => activate,
                                            Err(e) => {
                                                handshake_gate.store(false, Ordering::Release);
                                                log::error!("Re-handshake failed: {e}");
                                                break;
                                            }
                                        };
                                        note_management_activity(context, &activate);
                                        // Still gated: client/pair-finalize is part of this
                                        // exchange, and nothing else may interleave with it.
                                        if let Some(record) =
                                            handle_pairing_activation(&activate, context, &out_tx)
                                                .await
                                        {
                                            pending_pairing = Some(record);
                                        }
                                        handshake_gate.store(false, Ordering::Release);
                                        continue;
                                    }
                                    _ => {}
                                }
                                forward_message(
                                    msg,
                                    &stream_state,
                                    &message_tx,
                                    &mut message_closed,
                                );
                            } else {
                                log::debug!("Received message: {:?}", msg);
                                forward_message(
                                    msg,
                                    &stream_state,
                                    &message_tx,
                                    &mut message_closed,
                                );
                            }
                        }
                        Err(e) => {
                            log::warn!("Failed to parse message: {} (payload: {})", e, text);
                        }
                    }
                }
                None => {}
            }
        }
        log::debug!("Message router: WebSocket stream ended");
    }

    /// Gracefully disconnect: sends `client/goodbye`, closes the WebSocket,
    /// and aborts background tasks.
    pub async fn disconnect(self, reason: GoodbyeReason) -> Result<(), Error> {
        self.guard.disconnect(reason).await
    }

    /// See [`WsSender::enter_external_source`].
    pub async fn enter_external_source(&self) -> Result<(), Error> {
        WsSender {
            tx: self.out_tx.clone(),
            stream_state: Arc::clone(&self.stream_state),
            handshake_gate: Arc::clone(&self.handshake_gate),
        }
        .enter_external_source()
        .await
    }

    /// See [`WsSender::exit_external_source`].
    pub async fn exit_external_source(&self, player: Option<PlayerState>) -> Result<(), Error> {
        WsSender {
            tx: self.out_tx.clone(),
            stream_state: Arc::clone(&self.stream_state),
            handshake_gate: Arc::clone(&self.handshake_gate),
        }
        .exit_external_source(player)
        .await
    }

    /// Get reference to clock sync
    pub fn clock_sync(&self) -> Arc<Mutex<ClockSync>> {
        Arc::clone(&self.clock_sync)
    }

    /// The `server/hello` received during handshake. Carries `server_id`,
    /// `connection_reason`, and `active_roles` — required for the
    /// multi-server arbitration policy described on [`ProtocolListener`].
    ///
    /// [`ProtocolListener`]: crate::protocol::listener::ProtocolListener
    pub fn server_hello(&self) -> &ServerHello {
        &self.server_hello
    }

    /// Split into separate receivers for concurrent processing.
    ///
    /// This allows using `tokio::select!` to process messages and binary
    /// data concurrently. Use the fields you need; ignore the rest.
    pub fn split(self) -> Connection {
        let sender = WsSender {
            tx: self.out_tx,
            stream_state: self.stream_state,
            handshake_gate: self.handshake_gate,
        };
        let controller = self
            .server_hello
            .active_roles
            .iter()
            .any(|r| r == "controller@v1")
            .then(|| Controller {
                sender: sender.clone(),
            });
        Connection {
            messages: self.message_rx,
            audio: self.audio_rx,
            artwork: self.artwork_rx,
            visualizer: self.visualizer_rx,
            clock_sync: self.clock_sync,
            sender,
            controller,
            server_hello: self.server_hello,
            guard: self.guard,
        }
    }
}
