// ABOUTME: The three cleartext handshake messages, plus the JSON payloads carried inside
// ABOUTME: the two Noise handshake messages.

use serde::{Deserialize, Serialize};

use super::constants::PROTOCOL_VERSION;
use super::session::CipherSuite;
use crate::error::Error;

/// `client/init` — the first message on the socket, in cleartext.
///
/// Under encryption the client's identity lives here rather than in `client/hello`: this is
/// what the Noise handshake needs before there is a channel to carry a hello over.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientInit {
    /// The client's static public key, base64url with no padding.
    pub client_id: String,
    /// Core message-format version. Exact-match: must be `1`.
    pub version: u32,
    /// The suite the client picked for this connection.
    pub suite: CipherSuite,
}

/// `server/init` — the server's matching identity, in cleartext.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerInit {
    /// The server's static public key, base64url with no padding.
    pub server_id: String,
    /// Core message-format version. Exact-match: must be `1`.
    pub version: u32,
}

/// `noise/handshake` — one Noise handshake message.
///
/// Sent twice in a first handshake, as cleartext text frames. The same message carries an
/// in-band re-handshake, where both travel as ordinary encrypted JSON.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NoiseHandshake {
    /// The raw Noise handshake bytes, base64url with no padding.
    pub data: String,
}

/// The envelope the three cleartext messages share with the rest of the protocol.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "payload")]
pub enum InitMessage {
    /// Client to server.
    #[serde(rename = "client/init")]
    ClientInit(ClientInit),
    /// Server to client.
    #[serde(rename = "server/init")]
    ServerInit(ServerInit),
    /// Either direction.
    #[serde(rename = "noise/handshake")]
    NoiseHandshake(NoiseHandshake),
}

/// Payload of Noise message 1 (server to client).
///
/// Decryptable without the PSK — that is the whole point of `psk2`, and what lets the
/// client pick a key before it has to mix one in.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NoiseMsg1Payload {
    /// Identifies the PSK the server keyed this handshake with.
    pub psk_id: String,
}

impl ClientInit {
    /// Build a `client/init` for this identity and suite.
    pub fn new(client_id: String, suite: CipherSuite) -> Self {
        Self {
            client_id,
            version: PROTOCOL_VERSION,
            suite,
        }
    }

    /// Reject a version this build does not implement.
    ///
    /// Exact-match rather than a floor: the field names the one core format the sender
    /// speaks, so anything else aborts the handshake.
    pub fn check_version(&self) -> Result<(), Error> {
        check_version(self.version)
    }
}

impl ServerInit {
    /// Reject a version this build does not implement.
    pub fn check_version(&self) -> Result<(), Error> {
        check_version(self.version)
    }
}

fn check_version(version: u32) -> Result<(), Error> {
    if version == PROTOCOL_VERSION {
        Ok(())
    } else {
        Err(Error::Protocol(format!(
            "core message version {version} is not supported (this build speaks {PROTOCOL_VERSION})"
        )))
    }
}

/// The empty Noise message 2 payload, as the literal two bytes `{}`.
///
/// Spelled out because the spec is specific that it is those bytes rather than a
/// zero-length Noise payload — the two are different on the wire and hash differently.
pub const NOISE_MSG2_PAYLOAD: &[u8] = b"{}";
