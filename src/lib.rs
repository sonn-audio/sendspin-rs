// ABOUTME: Main library entry point for sendspin-rs
// ABOUTME: Exports public API for Sendspin Protocol client and server

//! # sendspin-rs
//!
//! Hyper-efficient Rust implementation of the Sendspin Protocol for synchronized multi-room audio streaming.
//!
//! This library provides zero-copy audio pipelines, lock-free concurrency, and async I/O
//! for building high-performance audio streaming clients and servers.

#![warn(missing_docs)]

// The three modules below live in `sendspin-proto` so the server crate can use them without
// pulling in an audio stack, and are re-exported here at the paths they have always had.

/// Error types for Sendspin operations.
pub use sendspin_proto::error;
/// The encrypted `KKpsk2` transport, and everything keyed to it.
pub use sendspin_proto::noise;
/// Clock synchronization.
pub use sendspin_proto::sync;

/// Audio types and processing
pub mod audio;
/// Protocol implementation for WebSocket communication
pub mod protocol;

pub(crate) mod log_sampling;

pub use audio::GainControl;
pub use noise::{CipherSuite, ClientHandshake, Identity, Psk, PskCategory};
pub use protocol::client::{Connection, ConnectionGuard, Controller, ProtocolClient, WsSender};
pub use protocol::client_builder::ProtocolClientBuilder;
pub use protocol::listener::ProtocolListener;
pub use protocol::manager::{ConnectionManager, ManagedConnection, ManagerConfig};
pub use protocol::messages::ServerHello;
pub use sync::raw_clock::{Clock, DefaultClock};

/// Result type for sendspin operations
pub type Result<T> = std::result::Result<T, error::Error>;
