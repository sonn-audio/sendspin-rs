// ABOUTME: The server side of the protocol: accept connections, speak the encrypted transport,
// ABOUTME: and keep a client's clock synchronized.

//! A Sendspin server.
//!
//! Built on `sendspin-proto`, the shared core holding everything direction-agnostic. It does
//! not depend on the `sendspin` client: that would mean compiling `cpal`, the audio decoders
//! and the ALSA headers behind them for a server that plays nothing locally.
//!
//! # What works
//!
//! Enough to bring real clients up, keep them there and play to all of them at once: the
//! WebSocket upgrade, the encrypted `KKpsk2` handshake with this side as the Noise initiator,
//! `server/hello` → `client/hello` → `server/activate`, `client/time` answered so a client's
//! filter can converge, and [synchronized group playback](group) — every `player@v1` client
//! shares one timeline and receives byte-identical chunks, which is what makes two speakers in
//! two rooms one system rather than two.
//!
//! # What does not
//!
//! Pairing, management, transcoding, playback control, and every role but `player@v1`. A role
//! this server does not serve is not activated even when a client offers it: activating one is
//! a promise, and a client granted a role that is then never served looks broken from the
//! outside.
//!
//! ```no_run
//! # #[tokio::main]
//! # async fn main() -> Result<(), sendspin_proto::error::Error> {
//! use sendspin_proto::noise::Identity;
//! use sendspin_server::{SendspinServer, ServerConfig};
//!
//! let config = ServerConfig::new(Identity::generate()?, "Living Room".to_string());
//! let server = SendspinServer::bind("0.0.0.0:8927", config).await?;
//! server.serve_forever().await
//! # }
//! ```

use std::sync::Arc;

use tokio::net::TcpListener;

use sendspin_proto::error::Error;
use sendspin_proto::noise::keys::Identity;
use sendspin_proto::sync::raw_clock::{Clock, DefaultClock};

/// Where a server's audio comes from.
///
/// Deliberately a trait rather than a queue: what a server plays is its own business — a file,
/// a capture device, a mixer, a test tone — and the only thing this crate needs is PCM in a
/// stated format, on demand. Pull rather than push, so the pacing stays with the stream that
/// knows the timeline rather than with whatever is producing samples.
pub trait AudioSource: Send + Sync {
    /// The format the PCM is in. Fixed for the life of the source.
    fn format(&self) -> sendspin_proto::messages::StreamPlayerConfig;

    /// Fill `frames` worth of PCM, or return `None` when the source is finished.
    fn next_chunk(&self, frames: usize) -> Option<Vec<u8>>;
}

/// What the server says is playing, for clients that display it.
///
/// Pulled rather than pushed for the same reason as the audio: what a server knows about the
/// current track comes from wherever its music does, and this crate should not care. `None`
/// means nothing is playing, which is different from a track with no title.
pub trait MetadataSource: Send + Sync {
    /// The track playing now.
    fn current(&self) -> Option<sendspin_proto::messages::MetadataState>;
}

pub mod connection;
pub mod group;
pub mod handshake;
pub mod roles;
pub mod stream;

use crate::group::Group;

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
    /// What is playing, for clients that activated `metadata@v1`.
    ///
    /// `None` means the role is not offered at all, rather than offered and left empty: see
    /// [`roles::servable`].
    pub metadata: Option<Arc<dyn MetadataSource>>,
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
            metadata: None,
            clock: Arc::new(DefaultClock::new()),
        }
    }

    /// The same config, playing `source` to every player that connects.
    #[must_use]
    pub fn with_audio(mut self, source: Arc<dyn AudioSource>) -> Self {
        self.audio = Some(source);
        self
    }

    /// The same config, telling clients what is playing.
    ///
    /// Setting this is what makes `metadata@v1` servable, and so what makes the server willing
    /// to activate it.
    #[must_use]
    pub fn with_metadata(mut self, source: Arc<dyn MetadataSource>) -> Self {
        self.metadata = Some(source);
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
    /// The group every client joins.
    ///
    /// One group rather than a registry because nothing can yet *ask* to be regrouped — the
    /// controller role is what carries that request. What matters already is that the timeline
    /// lives here rather than in a connection: two clients now share one, which is the whole
    /// difference between two speakers and multi-room.
    group: Arc<Group>,
}

impl SendspinServer {
    /// Bind to `addr` and start listening.
    pub async fn bind(addr: &str, config: ServerConfig) -> Result<Self, Error> {
        let listener = TcpListener::bind(addr)
            .await
            .map_err(|e| Error::Connection(format!("could not bind {addr}: {e}")))?;
        let config = Arc::new(config);
        let group = Group::spawn(
            Arc::clone(&config),
            uuid::Uuid::new_v4().to_string(),
            Some(config.name.clone()),
        );
        Ok(Self {
            listener,
            config,
            group,
        })
    }

    /// The group clients are placed in.
    pub fn group(&self) -> &Arc<Group> {
        &self.group
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
            let group = Arc::clone(&self.group);
            tokio::spawn(async move {
                match connection::serve(stream, config, group).await {
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
