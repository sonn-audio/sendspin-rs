// ABOUTME: The client-side handshake driver: the init exchange, PSK selection from the
// ABOUTME: server's first message, and the transition into transport mode.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;

use super::keys::{b64_decode, Identity, Psk, PskCategory};
use super::models::{
    ClientInit, InitMessage, NoiseHandshake, NoiseMsg1Payload, ServerInit, NOISE_MSG2_PAYLOAD,
};
use super::session::{CipherSuite, NoiseSession};
use crate::error::Error;

/// What a completed handshake yields.
pub struct HandshakeResult {
    /// The session, already in transport mode.
    pub session: NoiseSession,
    /// The server's `server_id`, as taken from `server/init`.
    pub server_id: String,
    /// Which PSK matched, and therefore what this connection may be used for.
    pub psk_category: PskCategory,
    /// The matched `psk_id`, for the caller to mark the record as used.
    pub psk_id: String,
    /// The handshake hash — the prologue for a later in-band re-handshake.
    pub handshake_hash: [u8; 32],
}

impl std::fmt::Debug for HandshakeResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HandshakeResult")
            .field("server_id", &self.server_id)
            .field("psk_category", &self.psk_category)
            .field("psk_id", &self.psk_id)
            .finish_non_exhaustive()
    }
}

/// Drives the client half of the handshake without owning a transport.
///
/// The caller pumps bytes: it hands over each cleartext message as it arrives and sends
/// whatever comes back. Keeping I/O out means the whole exchange — including the failure
/// paths, which are the ones that matter and the hardest to provoke over a real socket —
/// is exercised in-process by the tests.
///
/// Every failure is terminal by spec: a handshake-phase error closes the WebSocket with no
/// application-level error message. There is nothing to report back to the peer, so these
/// methods return `Err` and the caller closes.
pub struct ClientHandshake {
    identity: Identity,
    suite: CipherSuite,
    candidates: Vec<Psk>,
    /// Raw `client/init` bytes exactly as sent — half the prologue.
    client_init_bytes: Vec<u8>,
    state: Phase,
}

enum Phase {
    /// `client/init` sent, waiting for `server/init`.
    AwaitingServerInit,
    /// Init exchange done, waiting for Noise message 1.
    AwaitingMsg1 {
        server_id: String,
        server_static: Box<[u8; 32]>,
        prologue: Vec<u8>,
    },
    /// Finished, or failed.
    Done,
}

impl ClientHandshake {
    /// Start a handshake, returning the driver and the `client/init` bytes to send.
    ///
    /// `candidates` is the set of PSKs this client is willing to be keyed with. The
    /// Sentinel PSK belongs in it for any client that can accept an unpaired connection;
    /// a key whose pairing method is currently disabled must be left out, so a handshake
    /// naming it fails as a lookup miss rather than succeeding against a disabled method.
    pub fn start(
        identity: Identity,
        suite: CipherSuite,
        candidates: Vec<Psk>,
    ) -> Result<(Self, Vec<u8>), Error> {
        let init = ClientInit::new(identity.client_id(), suite);
        let bytes = serde_json::to_vec(&InitMessage::ClientInit(init))
            .map_err(|e| Error::Protocol(format!("could not encode client/init: {e}")))?;
        let driver = Self {
            identity,
            suite,
            candidates,
            client_init_bytes: bytes.clone(),
            state: Phase::AwaitingServerInit,
        };
        Ok((driver, bytes))
    }

    /// Whether the handshake has run to completion or failed.
    pub fn is_done(&self) -> bool {
        matches!(self.state, Phase::Done)
    }

    /// Feed one cleartext handshake message, as received on the wire.
    ///
    /// `raw` must be the exact bytes: the prologue is defined over what was transmitted,
    /// not over a re-encoding of the parsed message, so re-serializing here would produce a
    /// prologue the server does not share and fail the handshake at message 2.
    ///
    /// Returns bytes to send back, if the step produces any, and the result once complete.
    pub fn handle_message(&mut self, raw: &[u8]) -> Result<HandshakeStep, Error> {
        let parsed: InitMessage = serde_json::from_slice(raw)
            .map_err(|e| Error::Protocol(format!("malformed cleartext handshake message: {e}")))?;

        match (&mut self.state, parsed) {
            (Phase::AwaitingServerInit, InitMessage::ServerInit(init)) => {
                self.on_server_init(init, raw)
            }
            (Phase::AwaitingMsg1 { .. }, InitMessage::NoiseHandshake(hs)) => self.on_msg1(hs),
            (_, other) => {
                self.state = Phase::Done;
                Err(Error::Protocol(format!(
                    "unexpected {} during the handshake",
                    match other {
                        InitMessage::ClientInit(_) => "client/init",
                        InitMessage::ServerInit(_) => "server/init",
                        InitMessage::NoiseHandshake(_) => "noise/handshake",
                    }
                )))
            }
        }
    }

    fn on_server_init(&mut self, init: ServerInit, raw: &[u8]) -> Result<HandshakeStep, Error> {
        if let Err(e) = init.check_version() {
            self.state = Phase::Done;
            return Err(e);
        }
        let server_static = match b64_decode(&init.server_id) {
            Ok(k) => k,
            Err(e) => {
                self.state = Phase::Done;
                return Err(e);
            }
        };
        // Prologue = the exact bytes of client/init followed by the exact bytes of
        // server/init, which binds the cleartext exchange to the handshake.
        let mut prologue = self.client_init_bytes.clone();
        prologue.extend_from_slice(raw);

        self.state = Phase::AwaitingMsg1 {
            server_id: init.server_id,
            server_static: Box::new(server_static),
            prologue,
        };
        Ok(HandshakeStep::Continue { send: None })
    }

    fn on_msg1(&mut self, hs: NoiseHandshake) -> Result<HandshakeStep, Error> {
        let Phase::AwaitingMsg1 {
            server_id,
            server_static,
            prologue,
        } = std::mem::replace(&mut self.state, Phase::Done)
        else {
            return Err(Error::Protocol(
                "handshake is not awaiting message 1".to_string(),
            ));
        };

        let msg1 = URL_SAFE_NO_PAD
            .decode(&hs.data)
            .map_err(|e| Error::Protocol(format!("noise/handshake data is not base64url: {e}")))?;

        // Message 1's payload is readable without the PSK, which is what makes selection
        // possible: build a throwaway responder under any key, read the psk_id, then
        // rebuild under the key that matches. The PSK is not mixed until message 2, so the
        // discarded read and the real one see identical state.
        let probe_psk = [0u8; 32];
        let mut probe = NoiseSession::responder(
            self.suite,
            &self.identity,
            &server_static,
            &prologue,
            &probe_psk,
        )?;
        let payload = probe.read_handshake(&msg1)?;
        let announced: NoiseMsg1Payload = serde_json::from_slice(&payload)
            .map_err(|e| Error::Protocol(format!("malformed Noise message 1 payload: {e}")))?;

        let matched = self
            .candidates
            .iter()
            .find(|psk| psk.psk_id() == announced.psk_id)
            .ok_or_else(|| {
                Error::Protocol(format!(
                    "no candidate PSK matches psk_id {}",
                    announced.psk_id
                ))
            })?
            .clone();

        // Under the stored-pubkey model the record names the server it belongs to; a
        // mismatch means this PSK is not this server's, whatever the id says.
        if !matched.accepts_server(&server_id) {
            return Err(Error::Protocol(format!(
                "PSK {} is bound to a different server_id",
                announced.psk_id
            )));
        }

        let mut session = NoiseSession::responder(
            self.suite,
            &self.identity,
            &server_static,
            &prologue,
            matched.key(),
        )?;
        session.read_handshake(&msg1)?;
        let msg2 = session.write_handshake(NOISE_MSG2_PAYLOAD)?;

        if !session.handshake_finished() {
            return Err(Error::Protocol(
                "Noise handshake did not complete after message 2".to_string(),
            ));
        }
        let handshake_hash = session.handshake_hash()?;
        session.into_transport_mode()?;

        let reply = serde_json::to_vec(&InitMessage::NoiseHandshake(NoiseHandshake {
            data: URL_SAFE_NO_PAD.encode(&msg2),
        }))
        .map_err(|e| Error::Protocol(format!("could not encode noise/handshake: {e}")))?;

        Ok(HandshakeStep::Complete {
            send: reply,
            result: Box::new(HandshakeResult {
                session,
                server_id,
                psk_category: matched.category(),
                psk_id: announced.psk_id,
                handshake_hash,
            }),
        })
    }
}

/// What one handshake step produced.
pub enum HandshakeStep {
    /// Still going; send `send` if present.
    Continue {
        /// Bytes to transmit as a cleartext text frame.
        send: Option<Vec<u8>>,
    },
    /// Finished. Send `send` first — it is Noise message 2, and still cleartext — then
    /// switch to encrypted binary frames.
    Complete {
        /// Noise message 2, to transmit before switching.
        send: Vec<u8>,
        /// The established session and what authenticated it.
        result: Box<HandshakeResult>,
    },
}

impl std::fmt::Debug for HandshakeStep {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Continue { send } => f
                .debug_struct("Continue")
                .field("send_bytes", &send.as_ref().map(Vec::len))
                .finish(),
            Self::Complete { send, result } => f
                .debug_struct("Complete")
                .field("send_bytes", &send.len())
                .field("result", result)
                .finish(),
        }
    }
}
