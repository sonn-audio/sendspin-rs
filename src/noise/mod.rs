// ABOUTME: The Noise-encrypted transport that every current Sendspin connection runs on:
// ABOUTME: KKpsk2 handshake, PSK selection, and the encrypted binary framing above it.

//! The Sendspin Noise layer.
//!
//! Every connection established through the standard discovery mechanisms is encrypted end
//! to end. The WebSocket itself is plain `ws://`; confidentiality and integrity come from
//! this layer, inside the WebSocket payloads.
//!
//! The shape of a connection:
//!
//! 1. Client sends `client/init` in cleartext, server answers `server/init`.
//! 2. Server sends Noise message 1, carrying the `psk_id` it keyed the handshake with.
//! 3. Client picks the matching PSK and answers with Noise message 2.
//! 4. Both sides switch to transport mode. Everything after this is a WebSocket *binary*
//!    frame whose payload is a Noise transport ciphertext.
//!
//! The **server is the Noise initiator and the client the responder**, whichever side
//! opened the socket. [`ClientHandshake`] is the client's half.
//!
//! Two details are easy to get subtly wrong and are handled here rather than left to
//! callers: the prologue is the *exact transmitted bytes* of the two init messages, so it
//! is captured as raw bytes rather than re-encoded; and because `psk2` mixes the key only
//! at the end of message 2, message 1 is readable before the key is known, which is what
//! makes PSK selection possible at all.
//!
//! ```no_run
//! use sendspin::noise::{CipherSuite, ClientHandshake, Identity, Psk};
//!
//! let identity = Identity::generate()?;
//! // A client that accepts an unpaired connection keeps the Sentinel PSK as a candidate.
//! let (mut handshake, client_init) =
//!     ClientHandshake::start(identity, CipherSuite::default(), vec![Psk::sentinel()])?;
//! // Send `client_init` as a text frame, then feed each cleartext message back in.
//! # Ok::<(), sendspin::error::Error>(())
//! ```

/// Protocol constants: labels, the published Sentinel PSK, frame tags and size limits.
pub mod constants;
/// The client-side handshake driver.
pub mod handshake;
/// Identities, pre-shared keys, and `psk_id` derivation.
pub mod keys;
/// The cleartext handshake messages.
pub mod models;
/// The Pairing PSK flow.
pub mod pairing;
/// The KKpsk2 session: handshake and transport.
pub mod session;
/// The client's pairing records and pairing configuration.
pub mod trust_store;
/// Encrypted binary framing, with fragmentation and reassembly.
pub mod wire;

pub use handshake::{ClientHandshake, HandshakeResult, HandshakeStep};
pub use keys::{Identity, Psk, PskCategory};
pub use models::{ClientInit, NoiseHandshake, ServerInit};
pub use pairing::{
    ClientPairFinalize, PairAbort, PairAbortReason, PairingAction, ServerPairFinalize,
};
pub use session::{CipherSuite, NoiseSession};
pub use trust_store::{InMemoryPairingStore, PairingConfig, PairingRecord, PairingStore};
pub use wire::{Frame, Reassembler};

#[cfg(test)]
mod tests;
