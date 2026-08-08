// ABOUTME: The parts of the Sendspin Protocol that do not care which end you are: the message
// ABOUTME: vocabulary, the encrypted transport, and the clock.

//! Shared protocol core for the `sendspin` client and the `sendspin-server` crates.
//!
//! Most of this protocol is direction-agnostic, and this crate is where that stops being a
//! coincidence and becomes the structure. The message vocabulary derives both `Serialize` and
//! `Deserialize`, so the whole wire surface works either way. The Noise handshake has a
//! defined initiator and responder, but both halves live here because a client is the
//! responder in a first handshake and a *server* is the responder in nothing — while
//! re-handshakes swap the roles again. Framing, fragmentation and the clock never had a side
//! at all.
//!
//! # Why this is its own crate
//!
//! Because in Rust a non-optional dependency is compiled whether or not anything touches it.
//! With the client and the server as the only two crates, a server asking for the message
//! types also asked for `cpal`, the audio decoders and — on Linux — the ALSA headers needed to
//! build them, none of which it uses. The reference implementation keeps the equivalent in one
//! Python package and pays nothing for it, because Python resolves imports when they run
//! rather than when they build. That difference has to be paid for somewhere, and a shared
//! core is the cheapest place.
//!
//! # What is here
//!
//! - [`messages`] — every protocol message, in both directions.
//! - [`noise`] — the `KKpsk2` transport: handshake, sessions, framing, trust store, pairing,
//!   CPace and the PIN flows.
//! - [`sync`] — the monotonic clock and the filter that tracks a peer's.
//! - [`error`] — the error type all of the above return.
//!
//! Consumers of `sendspin` do not need to name this crate: it re-exports all four modules at
//! the paths they have always had.

#![warn(missing_docs)]

/// Every protocol message, in both directions.
pub mod messages;

/// The encrypted `KKpsk2` transport, and everything keyed to it.
pub mod noise;

/// Clock synchronization.
pub mod sync;

/// Error types for the Sendspin protocol.
pub mod error {
    use thiserror::Error;

    /// Error types for Sendspin operations.
    #[derive(Error, Debug)]
    pub enum Error {
        /// WebSocket-related error
        #[error("WebSocket error: {0}")]
        WebSocket(String),

        /// Protocol violation or parsing error
        #[error("Protocol error: {0}")]
        Protocol(String),

        /// Invalid message format received
        #[error("Invalid message format")]
        InvalidMessage,

        /// Connection-related error
        #[error("Connection error: {0}")]
        Connection(String),

        /// Audio output error
        #[error("Audio output error: {0}")]
        Output(String),
    }
}
