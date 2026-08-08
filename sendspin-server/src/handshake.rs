// ABOUTME: The server's half of the encrypted handshake — the mirror of the client's, with
// ABOUTME: the roles the spec assigns: the server is the Noise initiator.

//! Bringing an inbound connection up to an encrypted transport.
//!
//! The spec is explicit that the **server is the Noise initiator and the client the
//! responder**, regardless of which side opened the WebSocket. That is the one thing most
//! likely to be assumed backwards, and it is why this cannot simply reuse the client's driver
//! with the arguments swapped.
//!
//! The sequence, all in cleartext text frames:
//!
//! ```text
//! client → server   client/init      { client_id, version, suite }
//! server → client   server/init      { server_id, version }
//! server → client   noise/handshake  message 1, payload names the psk_id
//! client → server   noise/handshake  message 2, payload is the two bytes {}
//! ```
//!
//! After that the socket carries binary frames of Noise ciphertext and nothing else.
//!
//! The prologue is the **exact transmitted bytes** of `client/init` followed by `server/init`.
//! Re-serializing either one to rebuild it produces a prologue the peer does not share, and
//! the handshake fails at message 2 with nothing to say why — so both are kept as received or
//! as sent.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;

use sendspin_proto::error::Error;
use sendspin_proto::noise::keys::{b64_decode, Identity, Psk};
use sendspin_proto::noise::models::{
    ClientInit, InitMessage, NoiseHandshake, NoiseMsg1Payload, ServerInit, NOISE_MSG2_PAYLOAD,
};
use sendspin_proto::noise::session::{CipherSuite, NoiseSession};

/// What a completed handshake leaves behind.
pub struct ServerHandshakeResult {
    /// The client's static public key, base64url — its `client_id`.
    pub client_id: String,
    /// The suite the client chose and this handshake ran under.
    pub suite: CipherSuite,
    /// The transport-mode session.
    pub session: NoiseSession,
    /// The handshake hash, which pairing binds its session id to.
    pub handshake_hash: [u8; 32],
    /// The PSK this connection is keyed by.
    pub psk: Psk,
}

/// Drive the server's side, given a way to send and receive cleartext frames.
///
/// Split from the socket so the sequence can be tested without one, and so a caller that
/// already holds a websocket does not have to hand ownership over.
pub struct ServerHandshake {
    identity: Identity,
    /// PSKs this server will key a connection with, tried in the order given.
    ///
    /// A first connection is keyed by the Sentinel PSK, which every client holds. A paired
    /// client is keyed by its long-term record instead — that selection is the server's to
    /// make, and it is made by whoever builds this.
    psk: Psk,
    client_init_bytes: Vec<u8>,
    prologue: Vec<u8>,
    client_static: [u8; 32],
    suite: CipherSuite,
}

impl ServerHandshake {
    /// Read `client/init` and produce the `server/init` to send back.
    ///
    /// `raw` must be the bytes as received. Returns the bytes to transmit, which the caller
    /// must send unchanged: the prologue is built from exactly these.
    pub fn start(identity: Identity, psk: Psk, raw: &[u8]) -> Result<(Self, Vec<u8>), Error> {
        let parsed: InitMessage = serde_json::from_slice(raw)
            .map_err(|e| Error::Protocol(format!("malformed cleartext handshake message: {e}")))?;
        let InitMessage::ClientInit(init) = parsed else {
            return Err(Error::Protocol(
                "expected client/init as the first message".to_string(),
            ));
        };
        init.check_version()?;
        let client_static = b64_decode(&init.client_id)?;
        let suite = init.suite;

        let server_init = InitMessage::ServerInit(ServerInit {
            server_id: identity.client_id(),
            version: sendspin_proto::noise::constants::PROTOCOL_VERSION,
        });
        let server_init_bytes = serde_json::to_vec(&server_init)
            .map_err(|e| Error::Protocol(format!("could not encode server/init: {e}")))?;

        let mut prologue = raw.to_vec();
        prologue.extend_from_slice(&server_init_bytes);

        Ok((
            Self {
                identity,
                psk,
                client_init_bytes: raw.to_vec(),
                prologue,
                client_static,
                suite,
            },
            server_init_bytes,
        ))
    }

    /// The `client_id` this handshake is for, known from `client/init`.
    pub fn client_id(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.client_static)
    }

    /// The suite the client asked for.
    pub fn suite(&self) -> CipherSuite {
        self.suite
    }

    /// Build Noise message 1 and the session that will carry the rest.
    ///
    /// The payload names the `psk_id`, in cleartext as far as the PSK is concerned: `psk2`
    /// mixes the key only at message 2, which is exactly what lets a client read this and
    /// choose which of its keys to answer with.
    pub fn message_one(&self) -> Result<(NoiseSession, Vec<u8>), Error> {
        let mut session = NoiseSession::initiator(
            self.suite,
            self.identity.private_key(),
            &self.client_static,
            &self.prologue,
            self.psk.key(),
        )?;
        let payload = serde_json::to_vec(&NoiseMsg1Payload {
            psk_id: self.psk.psk_id(),
        })
        .map_err(|e| Error::Protocol(format!("could not encode the message 1 payload: {e}")))?;
        let msg1 = session.write_handshake(&payload)?;
        let frame = serde_json::to_vec(&InitMessage::NoiseHandshake(NoiseHandshake {
            data: URL_SAFE_NO_PAD.encode(&msg1),
        }))
        .map_err(|e| Error::Protocol(format!("could not encode noise/handshake: {e}")))?;
        Ok((session, frame))
    }

    /// Consume the client's message 2 and finish.
    pub fn finish(
        self,
        mut session: NoiseSession,
        raw: &[u8],
    ) -> Result<ServerHandshakeResult, Error> {
        let parsed: InitMessage = serde_json::from_slice(raw)
            .map_err(|e| Error::Protocol(format!("malformed cleartext handshake message: {e}")))?;
        let InitMessage::NoiseHandshake(hs) = parsed else {
            return Err(Error::Protocol(
                "expected noise/handshake message 2".to_string(),
            ));
        };
        let msg2 = URL_SAFE_NO_PAD
            .decode(&hs.data)
            .map_err(|e| Error::Protocol(format!("noise/handshake data is not base64url: {e}")))?;

        let payload = session.read_handshake(&msg2)?;
        // The spec pins this to the literal two bytes `{}` rather than an empty payload; the
        // two hash differently, so a peer sending the other has not read the same document.
        if payload != NOISE_MSG2_PAYLOAD {
            return Err(Error::Protocol(
                "Noise message 2 payload was not the expected {}".to_string(),
            ));
        }
        if !session.handshake_finished() {
            return Err(Error::Protocol(
                "Noise handshake did not complete after message 2".to_string(),
            ));
        }
        let handshake_hash = session.handshake_hash()?;
        session.into_transport_mode()?;

        Ok(ServerHandshakeResult {
            client_id: URL_SAFE_NO_PAD.encode(self.client_static),
            suite: self.suite,
            session,
            handshake_hash,
            psk: self.psk,
        })
    }

    /// The exact `client/init` bytes, kept for callers that log or attribute a connection.
    pub fn client_init_bytes(&self) -> &[u8] {
        &self.client_init_bytes
    }
}

/// The `client/init` a caller peeked at, for a server that wants to choose a PSK by client.
///
/// Parsing it twice is cheap and keeps [`ServerHandshake::start`] the only thing that owns the
/// transmitted bytes, which is what the prologue depends on.
pub fn peek_client_init(raw: &[u8]) -> Result<ClientInit, Error> {
    let parsed: InitMessage = serde_json::from_slice(raw)
        .map_err(|e| Error::Protocol(format!("malformed cleartext handshake message: {e}")))?;
    match parsed {
        InitMessage::ClientInit(init) => Ok(init),
        _ => Err(Error::Protocol(
            "expected client/init as the first message".to_string(),
        )),
    }
}
