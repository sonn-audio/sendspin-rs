// ABOUTME: Protocol implementation for Sendspin WebSocket protocol
// ABOUTME: Message types, serialization, and WebSocket client

/// WebSocket client implementation
pub mod client;
/// Builder for easy construction of the client
pub mod client_builder;
/// mDNS advertisement so a server can discover a listening client
#[cfg(feature = "discovery")]
pub mod discovery;
/// Inbound WebSocket acceptor for server-initiated connections
pub mod listener;
/// Managed connection lifecycle: multi-server arbitration and auto-goodbye
pub mod manager;
/// Protocol message type definitions and serialization
/// Every protocol message, in both directions.
///
/// Re-exported from `sendspin-proto`: the vocabulary is shared with the server crate, and the
/// path here is what it has always been.
pub use sendspin_proto::messages;
/// The seam between protocol logic and the socket: plain frames, or Noise ciphertexts
pub(crate) mod transport;

pub use client::{Connection, ConnectionGuard, Controller, WsSender};
pub use listener::ProtocolListener;
pub use manager::{should_switch, ConnectionManager, ManagedConnection, ManagerConfig};
pub use messages::Message;
