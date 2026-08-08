// ABOUTME: The server side of the protocol: accept connections, speak the encrypted transport,
// ABOUTME: and keep a client's clock synchronized.

//! A Sendspin server.
//!
//! A crate of its own rather than a feature of `sendspin`, because the two have genuinely
//! different dependency appetites: a server grows resamplers, encoders and signal analysis
//! that an embedded player has no use for, and a feature flag on one crate makes every one of
//! those a decision the player's build has to carry.
//!
//! What it borrows from `sendspin` is everything that is direction-agnostic, and that turns
//! out to be most of the protocol: the message vocabulary derives both `Serialize` and
//! `Deserialize`, so the whole wire surface works in either direction, and the framing,
//! fragmentation and Noise primitives do not care which end they are on. Nothing here reaches
//! into the client crate's internals.
//!
//! # What works
//!
//! Enough to bring a real client up, keep it there and play to it: the WebSocket upgrade, the
//! encrypted `KKpsk2` handshake with this side as the Noise initiator, `server/hello` →
//! `client/hello` → `server/activate`, `client/time` answered so the client's filter can
//! converge, and `player@v1` fed with paced PCM on the server's own timeline.
//!
//! # What does not
//!
//! Groups, pairing, management, and every role but `player@v1`. A role this server does not
//! serve is not activated even when a client offers it: activating one is a promise, and a
//! client granted a role that is then never served looks broken from the outside.
//!
//! ```no_run
//! # #[tokio::main]
//! # async fn main() -> Result<(), sendspin::error::Error> {
//! use sendspin::noise::Identity;
//! use sendspin_server::{SendspinServer, ServerConfig};
//!
//! let config = ServerConfig::new(Identity::generate()?, "Living Room".to_string());
//! let server = SendspinServer::bind("0.0.0.0:8927", config).await?;
//! server.serve_forever().await
//! # }
//! ```

use std::sync::Arc;

use tokio::net::TcpListener;

use sendspin::error::Error;
use sendspin::noise::keys::Identity;
use sendspin::sync::raw_clock::{Clock, DefaultClock};

/// Where a server's audio comes from.
///
/// Deliberately a trait rather than a queue: what a server plays is its own business — a file,
/// a capture device, a mixer, a test tone — and the only thing this crate needs is PCM in a
/// stated format, on demand. Pull rather than push, so the pacing stays with the stream that
/// knows the timeline rather than with whatever is producing samples.
pub trait AudioSource: Send + Sync {
    /// The format the PCM is in. Fixed for the life of the source.
    fn format(&self) -> sendspin::protocol::messages::StreamPlayerConfig;

    /// Fill `frames` worth of PCM, or return `None` when the source is finished.
    fn next_chunk(&self, frames: usize) -> Option<Vec<u8>>;
}

pub mod connection;
pub mod handshake;
pub mod roles;
pub mod stream;

/// What a server is: an identity, a name, and a clock.
pub struct ServerConfig {
    /// The static keypair whose public half is this server's `server_id`.
    ///
    /// Persist it. A server that mints a new one on every start is a new server to every
    /// client that ever paired with it, and every one of those pairings becomes dead weight.
    pub identity: Identity,
    /// The friendly name sent in `server/hello`.
    pub name: String,
    /// Where the audio comes from, when there is any.
    ///
    /// `None` serves connections without ever starting a stream, which is what the interop
    /// check for the handshake wants. A real server has a pipeline behind this.
    pub audio: Option<Arc<dyn AudioSource>>,
    /// The timebase the clock replies are stamped from.
    ///
    /// Must be monotonic and not NTP-conditioned: a clock that steps backwards puts a step
    /// into every connected client's filter at once.
    pub clock: Arc<dyn Clock>,
}

impl ServerConfig {
    /// A config over the default monotonic clock.
    pub fn new(identity: Identity, name: String) -> Self {
        Self {
            identity,
            name,
            audio: None,
            clock: Arc::new(DefaultClock::new()),
        }
    }

    /// The same config, playing `source` to every player that connects.
    #[must_use]
    pub fn with_audio(mut self, source: Arc<dyn AudioSource>) -> Self {
        self.audio = Some(source);
        self
    }

    /// This server's `server_id`, as clients see it.
    pub fn server_id(&self) -> String {
        self.identity.client_id()
    }
}

/// A bound server, accepting connections.
pub struct SendspinServer {
    listener: TcpListener,
    config: Arc<ServerConfig>,
}

impl SendspinServer {
    /// Bind to `addr` and start listening.
    pub async fn bind(addr: &str, config: ServerConfig) -> Result<Self, Error> {
        let listener = TcpListener::bind(addr)
            .await
            .map_err(|e| Error::Connection(format!("could not bind {addr}: {e}")))?;
        Ok(Self {
            listener,
            config: Arc::new(config),
        })
    }

    /// The address actually bound, which is what to advertise when port 0 was requested.
    pub fn local_addr(&self) -> Result<std::net::SocketAddr, Error> {
        self.listener
            .local_addr()
            .map_err(|e| Error::Connection(format!("could not read the local address: {e}")))
    }

    /// This server's `server_id`.
    pub fn server_id(&self) -> String {
        self.config.server_id()
    }

    /// Accept connections until the process ends, serving each on its own task.
    ///
    /// A connection that fails is logged and dropped rather than ending the server: one client
    /// with a stale pairing, or a port scanner, must not take the room offline.
    pub async fn serve_forever(self) -> Result<(), Error> {
        loop {
            let (stream, peer) = self
                .listener
                .accept()
                .await
                .map_err(|e| Error::Connection(format!("accept failed: {e}")))?;
            let config = Arc::clone(&self.config);
            tokio::spawn(async move {
                match connection::serve(stream, config).await {
                    Ok(summary) => log::info!(
                        "{peer} ({}) disconnected after {} clock exchanges",
                        summary.name,
                        summary.time_syncs
                    ),
                    Err(e) => log::warn!("{peer} failed: {e}"),
                }
            });
        }
    }
}
