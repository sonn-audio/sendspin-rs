// ABOUTME: The server side of the protocol: accept connections, speak the encrypted transport,
// ABOUTME: and keep a client's clock synchronized.

//! A Sendspin server.
//!
//! Behind the `server` feature, and off by default for the same reason `discovery` is: an
//! embedded player has no use for a server and should not link one.
//!
//! # What works
//!
//! Enough to bring a real client up and keep it there: the WebSocket upgrade, the encrypted
//! `KKpsk2` handshake with this side as the Noise initiator, `server/hello` →
//! `client/hello` → `server/activate`, and `client/time` answered so the client's filter can
//! converge.
//!
//! # What does not
//!
//! Roles, audio, groups and pairing. This activates no roles at all, deliberately: a client
//! granted `player@v1` that is then never sent audio looks broken, while one told it has no
//! active roles is being told the truth.
//!
//! ```no_run
//! # #[tokio::main]
//! # async fn main() -> Result<(), sendspin::error::Error> {
//! use sendspin::noise::Identity;
//! use sendspin::server::{SendspinServer, ServerConfig};
//!
//! let config = ServerConfig::new(Identity::generate()?, "Living Room".to_string());
//! let server = SendspinServer::bind("0.0.0.0:8927", config).await?;
//! server.serve_forever().await
//! # }
//! ```

use std::sync::Arc;

use tokio::net::TcpListener;

use crate::error::Error;
use crate::noise::keys::Identity;
use crate::sync::raw_clock::{Clock, DefaultClock};

pub mod connection;
pub mod handshake;

/// What a server is: an identity, a name, and a clock.
pub struct ServerConfig {
    /// The static keypair whose public half is this server's `server_id`.
    ///
    /// Persist it. A server that mints a new one on every start is a new server to every
    /// client that ever paired with it, and every one of those pairings becomes dead weight.
    pub identity: Identity,
    /// The friendly name sent in `server/hello`.
    pub name: String,
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
            clock: Arc::new(DefaultClock::new()),
        }
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
