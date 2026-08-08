// ABOUTME: The KKpsk2 Noise session — cipher suites, handshake state, and transport mode.
// ABOUTME: Pure protocol object: no I/O, no framing, no knowledge of WebSockets.

use snow::params::NoiseParams;
use snow::{HandshakeState, TransportState};

use super::constants::{KEY_LEN, MAX_TRANSPORT_PLAINTEXT};
use super::keys::Identity;
use crate::error::Error;

/// The two cipher suites Sendspin defines.
///
/// A suite names the `<DH>_<cipher>_<hash>` part of the Noise protocol name. Servers must
/// support both; a client picks one and announces it in `client/init`, so there is nothing
/// to negotiate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum CipherSuite {
    /// Software-friendly.
    #[serde(rename = "25519_ChaChaPoly_SHA256")]
    ChaChaPoly,
    /// Hardware-accelerated where AES-NI or the ARMv8 crypto extensions are present.
    #[serde(rename = "25519_AESGCM_SHA256")]
    AesGcm,
}

impl Default for CipherSuite {
    /// ChaChaPoly, because it is fast everywhere rather than fast on some hardware.
    fn default() -> Self {
        Self::ChaChaPoly
    }
}

impl CipherSuite {
    /// The suite string as it appears on the wire.
    pub fn as_wire_str(self) -> &'static str {
        match self {
            Self::ChaChaPoly => "25519_ChaChaPoly_SHA256",
            Self::AesGcm => "25519_AESGCM_SHA256",
        }
    }

    /// The full Noise protocol name this suite resolves to.
    pub fn protocol_name(self) -> String {
        format!("Noise_KKpsk2_{}", self.as_wire_str())
    }

    /// Parsed Noise parameters for this suite.
    pub fn noise_params(self) -> Result<NoiseParams, Error> {
        self.protocol_name()
            .parse()
            .map_err(|e| Error::Protocol(format!("unsupported Noise parameters: {e}")))
    }
}

/// A KKpsk2 session, in handshake or transport phase.
///
/// The **server is always the Noise initiator and the client always the responder**,
/// whichever side opened the WebSocket. This type is the client's half, so it is built as
/// a responder.
pub struct NoiseSession {
    state: SessionState,
    suite: CipherSuite,
    /// The handshake hash, captured before transport mode consumes the handshake state.
    ///
    /// Kept because it is the prologue for a later in-band re-handshake, which happens well
    /// after the handshake state itself is gone.
    handshake_hash: Option<[u8; KEY_LEN]>,
}

enum SessionState {
    Handshake(Box<HandshakeState>),
    Transport(Box<TransportState>),
    /// Transient, only observed while moving between the two.
    Poisoned,
}

impl NoiseSession {
    /// Build the client's (responder's) side of a handshake.
    ///
    /// `prologue` is the concatenated raw bytes of `client/init` and `server/init` for a
    /// first handshake, or the previous handshake's hash for a re-handshake.
    pub fn responder(
        suite: CipherSuite,
        identity: &Identity,
        server_static: &[u8; KEY_LEN],
        prologue: &[u8],
        psk: &[u8; KEY_LEN],
    ) -> Result<Self, Error> {
        let state = snow::Builder::new(suite.noise_params()?)
            .local_private_key(identity.private_key())
            .and_then(|b| b.remote_public_key(server_static))
            .and_then(|b| b.prologue(prologue))
            .and_then(|b| b.psk(2, psk))
            .and_then(|b| b.build_responder())
            .map_err(|e| Error::Protocol(format!("Noise responder setup failed: {e}")))?;
        Ok(Self {
            state: SessionState::Handshake(Box::new(state)),
            suite,
            handshake_hash: None,
        })
    }

    /// Build the server's (initiator's) side.
    ///
    /// Only the tests and a future server role need this; it exists so a handshake can be
    /// exercised end to end in-process, without a network peer.
    pub fn initiator(
        suite: CipherSuite,
        server_private: &[u8; KEY_LEN],
        client_static: &[u8; KEY_LEN],
        prologue: &[u8],
        psk: &[u8; KEY_LEN],
    ) -> Result<Self, Error> {
        let state = snow::Builder::new(suite.noise_params()?)
            .local_private_key(server_private)
            .and_then(|b| b.remote_public_key(client_static))
            .and_then(|b| b.prologue(prologue))
            .and_then(|b| b.psk(2, psk))
            .and_then(|b| b.build_initiator())
            .map_err(|e| Error::Protocol(format!("Noise initiator setup failed: {e}")))?;
        Ok(Self {
            state: SessionState::Handshake(Box::new(state)),
            suite,
            handshake_hash: None,
        })
    }

    /// The suite this session runs.
    pub fn suite(&self) -> CipherSuite {
        self.suite
    }

    /// Whether the handshake has finished and the session may move to transport mode.
    pub fn handshake_finished(&self) -> bool {
        match &self.state {
            SessionState::Handshake(hs) => hs.is_handshake_finished(),
            SessionState::Transport(_) => true,
            SessionState::Poisoned => false,
        }
    }

    /// Whether this session is carrying application traffic.
    pub fn in_transport_mode(&self) -> bool {
        matches!(self.state, SessionState::Transport(_))
    }

    /// The handshake hash `h`.
    ///
    /// Remains readable in transport mode, because that is when it is needed: it is the
    /// prologue for an in-band re-handshake, which the server may start at any point in a
    /// long-running session.
    pub fn handshake_hash(&self) -> Result<[u8; KEY_LEN], Error> {
        if let Some(hash) = self.handshake_hash {
            return Ok(hash);
        }
        let raw = match &self.state {
            SessionState::Handshake(hs) => hs.get_handshake_hash(),
            SessionState::Transport(_) => {
                return Err(Error::Protocol(
                    "handshake hash was not captured before entering transport mode".to_string(),
                ))
            }
            SessionState::Poisoned => {
                return Err(Error::Protocol("Noise session is poisoned".to_string()))
            }
        };
        raw.get(..KEY_LEN)
            .and_then(|s| s.try_into().ok())
            .ok_or_else(|| Error::Protocol("handshake hash was shorter than 32 bytes".to_string()))
    }

    /// Read a handshake message, returning its decrypted payload.
    pub fn read_handshake(&mut self, message: &[u8]) -> Result<Vec<u8>, Error> {
        let SessionState::Handshake(hs) = &mut self.state else {
            return Err(Error::Protocol(
                "handshake message arrived outside the handshake phase".to_string(),
            ));
        };
        let mut out = vec![0u8; MAX_TRANSPORT_PLAINTEXT];
        let len = hs
            .read_message(message, &mut out)
            .map_err(|e| Error::Protocol(format!("Noise handshake read failed: {e}")))?;
        out.truncate(len);
        Ok(out)
    }

    /// Write a handshake message carrying `payload`.
    pub fn write_handshake(&mut self, payload: &[u8]) -> Result<Vec<u8>, Error> {
        let SessionState::Handshake(hs) = &mut self.state else {
            return Err(Error::Protocol(
                "cannot write a handshake message outside the handshake phase".to_string(),
            ));
        };
        let mut out = vec![0u8; MAX_TRANSPORT_PLAINTEXT + 128];
        let len = hs
            .write_message(payload, &mut out)
            .map_err(|e| Error::Protocol(format!("Noise handshake write failed: {e}")))?;
        out.truncate(len);
        Ok(out)
    }

    /// Move to transport mode once the handshake has finished.
    pub fn into_transport_mode(&mut self) -> Result<(), Error> {
        // Capture the hash while the handshake state still exists: entering transport mode
        // consumes it, and a re-handshake later needs it as its prologue.
        if self.handshake_hash.is_none() {
            self.handshake_hash = self.handshake_hash().ok();
        }
        let state = std::mem::replace(&mut self.state, SessionState::Poisoned);
        match state {
            SessionState::Handshake(hs) => {
                let transport = hs.into_transport_mode().map_err(|e| {
                    Error::Protocol(format!("entering Noise transport mode failed: {e}"))
                })?;
                self.state = SessionState::Transport(Box::new(transport));
                Ok(())
            }
            SessionState::Transport(t) => {
                self.state = SessionState::Transport(t);
                Ok(())
            }
            SessionState::Poisoned => Err(Error::Protocol("Noise session is poisoned".to_string())),
        }
    }

    /// Encrypt one transport message.
    ///
    /// `plaintext` must already carry its message-type byte, and must fit a single Noise
    /// transport message — the caller fragments.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        if plaintext.len() > MAX_TRANSPORT_PLAINTEXT {
            return Err(Error::Protocol(format!(
                "plaintext of {} bytes exceeds the {MAX_TRANSPORT_PLAINTEXT}-byte transport limit",
                plaintext.len()
            )));
        }
        let SessionState::Transport(t) = &mut self.state else {
            return Err(Error::Protocol(
                "cannot encrypt before the handshake completes".to_string(),
            ));
        };
        let mut out = vec![0u8; plaintext.len() + 16];
        let len = t
            .write_message(plaintext, &mut out)
            .map_err(|e| Error::Protocol(format!("Noise encryption failed: {e}")))?;
        out.truncate(len);
        Ok(out)
    }

    /// Decrypt one transport message.
    ///
    /// An AEAD failure here is fatal to the connection: Noise's per-direction counter means
    /// a repeated or reordered ciphertext cannot authenticate, so the caller closes rather
    /// than skipping the frame.
    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
        let SessionState::Transport(t) = &mut self.state else {
            return Err(Error::Protocol(
                "cannot decrypt before the handshake completes".to_string(),
            ));
        };
        let mut out = vec![0u8; MAX_TRANSPORT_PLAINTEXT];
        let len = t
            .read_message(ciphertext, &mut out)
            .map_err(|e| Error::Protocol(format!("Noise decryption failed: {e}")))?;
        out.truncate(len);
        Ok(out)
    }
}

impl std::fmt::Debug for NoiseSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NoiseSession")
            .field("suite", &self.suite)
            .field("in_transport_mode", &self.in_transport_mode())
            .finish()
    }
}
