// ABOUTME: Builder exposed for public usage of the library

use crate::error::Error;
use crate::protocol::client::Encryption;
use crate::protocol::listener::ProtocolListener;
use crate::protocol::messages::{
    ArtworkV1Support, AudioFormatSpec, ClientHello, ClientState, ClientSyncState, DeviceInfo,
    PairMethod, PairMethodDescriptor, PlayerState, PlayerV1Support, SourceState, SourceV1Support,
    TrustLevel, UnpairedAccess, VisualizerV1Support,
};
use crate::protocol::transport::Transport;
use crate::sync::raw_clock::{Clock, DefaultClock};
use crate::ProtocolClient;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, ToSocketAddrs};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::WebSocketStream;
use typed_builder::TypedBuilder;

/// Intermediate builder struct before finalization
#[derive(Clone)]
pub(crate) struct ProtocolClientBuilderRaw {
    client_id: String,
    name: String,
    product_name: Option<String>,
    manufacturer: Option<String>,
    software_version: Option<String>,
    mac_address: Option<String>,
    trust_level: TrustLevel,
    supported_pair_methods: Option<Vec<PairMethodDescriptor>>,
    unpaired_access: UnpairedAccess,
    player_v1_support: Option<PlayerV1Support>,
    source_v1_support: Option<SourceV1Support>,
    artwork_v1_support: Option<ArtworkV1Support>,
    visualizer_v1_support: Option<VisualizerV1Support>,
    initial_sync_state: ClientSyncState,
    initial_player_state: Option<PlayerState>,
    encryption: Encryption,
    initial_source_state: Option<SourceState>,
    metadata: bool,
    controller: bool,
    color: bool,
}

impl From<ProtocolClientBuilderRaw> for ProtocolClientBuilder {
    fn from(raw: ProtocolClientBuilderRaw) -> Self {
        // Build supported_roles based on which supports are configured
        let mut supported_roles = Vec::new();
        let has_explicit_role = raw.player_v1_support.is_some()
            || raw.source_v1_support.is_some()
            || raw.artwork_v1_support.is_some()
            || raw.visualizer_v1_support.is_some()
            || raw.metadata
            || raw.controller
            || raw.color;

        // Default to player@v1 if no roles were explicitly configured
        let player_v1_support = if has_explicit_role {
            raw.player_v1_support
        } else {
            Some(PlayerV1Support {
                supported_formats: vec![
                    AudioFormatSpec {
                        codec: "opus".to_string(),
                        channels: 2,
                        sample_rate: 48000,
                        bit_depth: 16,
                    },
                    AudioFormatSpec {
                        codec: "pcm".to_string(),
                        channels: 2,
                        sample_rate: 48000,
                        bit_depth: 24,
                    },
                    AudioFormatSpec {
                        codec: "pcm".to_string(),
                        channels: 2,
                        sample_rate: 48000,
                        bit_depth: 16,
                    },
                ],
                buffer_capacity: 50 * 1024 * 1024,
                supported_commands: vec!["volume".to_string(), "mute".to_string()],
            })
        };

        if player_v1_support.is_some() {
            supported_roles.push("player@v1".to_string());
        }
        if raw.source_v1_support.is_some() {
            supported_roles.push("source@v1".to_string());
        }
        if raw.artwork_v1_support.is_some() {
            supported_roles.push("artwork@v1".to_string());
        }
        if raw.visualizer_v1_support.is_some() {
            supported_roles.push("visualizer@v1".to_string());
        }
        if raw.metadata {
            supported_roles.push("metadata@v1".to_string());
        }
        if raw.controller {
            supported_roles.push("controller@v1".to_string());
        }
        if raw.color {
            supported_roles.push("color@v1".to_string());
        }

        ProtocolClientBuilder {
            encryption: raw.encryption,
            client_id: raw.client_id,
            name: raw.name,
            product_name: raw.product_name,
            manufacturer: raw.manufacturer,
            software_version: raw.software_version,
            mac_address: raw.mac_address,
            trust_level: raw.trust_level,
            supported_pair_methods: raw.supported_pair_methods,
            unpaired_access: raw.unpaired_access,
            supported_roles,
            player_v1_support,
            clock: Arc::new(DefaultClock::new()),
            source_v1_support: raw.source_v1_support,
            artwork_v1_support: raw.artwork_v1_support,
            visualizer_v1_support: raw.visualizer_v1_support,
            initial_sync_state: raw.initial_sync_state,
            initial_player_state: raw.initial_player_state,
            initial_source_state: raw.initial_source_state,
        }
    }
}

#[derive(TypedBuilder, Clone)]
#[builder(build_method(into = ProtocolClientBuilder))]
/// Builder Class for ProtocolClient
pub struct ProtocolClientBuilderFields {
    client_id: String,
    name: String,
    #[builder(default = None)]
    product_name: Option<String>,
    #[builder(default = None)]
    manufacturer: Option<String>,
    #[builder(default = None)]
    software_version: Option<String>,
    #[builder(default = None)]
    mac_address: Option<String>,
    /// Trust this client extends to the server it is about to talk to. Leave at
    /// [`TrustLevel::None`] unless a pairing exchange has already established otherwise.
    #[builder(default = TrustLevel::None)]
    trust_level: TrustLevel,
    /// Pairing methods to offer. A client with no way to pair offers none, which is the
    /// default and is what this library does on its own.
    #[builder(default = None, setter(transform = |x: Vec<PairMethodDescriptor>| Some(x)))]
    supported_pair_methods: Option<Vec<PairMethodDescriptor>>,
    /// Whether unpaired servers are admitted. Defaults to `true`, because that is what a
    /// client without a trust store does; set it to `false` only if something is actually
    /// enforcing it.
    #[builder(default = UnpairedAccess::default(), setter(transform = |enabled: bool| UnpairedAccess { enabled }))]
    unpaired_access: UnpairedAccess,
    #[builder(default = None, setter(transform = |x: PlayerV1Support| Some(x)))]
    player_v1_support: Option<PlayerV1Support>,
    #[builder(default = None, setter(transform = |x: SourceV1Support| Some(x)))]
    source_v1_support: Option<SourceV1Support>,
    #[builder(default = None, setter(transform = |x: ArtworkV1Support| Some(x)))]
    artwork_v1_support: Option<ArtworkV1Support>,
    #[builder(default = None, setter(transform = |x: VisualizerV1Support| Some(x)))]
    visualizer_v1_support: Option<VisualizerV1Support>,
    /// Initial top-level operational state sent in the first `client/state`.
    /// [`ClientSyncState::ExternalSource`] when another source owns playback.
    #[builder(default = ClientSyncState::Synchronized)]
    initial_sync_state: ClientSyncState,
    #[builder(default = None, setter(transform = |x: PlayerState| Some(x)))]
    initial_player_state: Option<PlayerState>,
    /// Whether this connection runs the spec's Noise transport.
    ///
    /// Defaults to [`Encryption::Disabled`] — the transition-mode handshake — because
    /// flipping it changes which servers a client can reach. Pass
    /// [`EncryptionSettings::unpaired`](crate::protocol::client::EncryptionSettings::unpaired)
    /// to speak the compliant transport.
    #[builder(default = Encryption::Disabled)]
    encryption: Encryption,
    /// Initial source state sent in the first `client/state`. Required by the
    /// spec for a source client, the way player state is for a player.
    #[builder(default = None, setter(transform = |x: SourceState| Some(x)))]
    initial_source_state: Option<SourceState>,
    #[builder(default = false, setter(transform = || true))]
    metadata: bool,
    #[builder(default = false, setter(transform = || true))]
    controller: bool,
    #[builder(default = false, setter(transform = || true))]
    color: bool,
}

impl From<ProtocolClientBuilderFields> for ProtocolClientBuilder {
    fn from(fields: ProtocolClientBuilderFields) -> Self {
        let raw = ProtocolClientBuilderRaw {
            encryption: fields.encryption.clone(),
            client_id: fields.client_id,
            name: fields.name,
            product_name: fields.product_name,
            manufacturer: fields.manufacturer,
            software_version: fields.software_version,
            mac_address: fields.mac_address,
            trust_level: fields.trust_level,
            supported_pair_methods: fields.supported_pair_methods,
            unpaired_access: fields.unpaired_access,
            player_v1_support: fields.player_v1_support,
            source_v1_support: fields.source_v1_support,
            artwork_v1_support: fields.artwork_v1_support,
            visualizer_v1_support: fields.visualizer_v1_support,
            initial_sync_state: fields.initial_sync_state,
            initial_player_state: fields.initial_player_state,
            initial_source_state: fields.initial_source_state,
            metadata: fields.metadata,
            controller: fields.controller,
            color: fields.color,
        };
        raw.into()
    }
}

/// Builder Class for ProtocolClient
#[derive(Clone)]
pub struct ProtocolClientBuilder {
    client_id: String,
    name: String,
    product_name: Option<String>,
    manufacturer: Option<String>,
    software_version: Option<String>,
    mac_address: Option<String>,
    trust_level: TrustLevel,
    supported_pair_methods: Option<Vec<PairMethodDescriptor>>,
    unpaired_access: UnpairedAccess,
    supported_roles: Vec<String>,
    player_v1_support: Option<PlayerV1Support>,
    source_v1_support: Option<SourceV1Support>,
    artwork_v1_support: Option<ArtworkV1Support>,
    visualizer_v1_support: Option<VisualizerV1Support>,
    initial_sync_state: ClientSyncState,
    initial_player_state: Option<PlayerState>,
    encryption: Encryption,
    initial_source_state: Option<SourceState>,
    clock: Arc<dyn Clock>,
}

impl ProtocolClientBuilder {
    /// Create a new builder
    pub fn builder() -> ProtocolClientBuilderFieldsBuilder {
        ProtocolClientBuilderFields::builder()
    }

    /// Get the supported roles that will be sent in the client hello
    pub fn supported_roles(&self) -> &[String] {
        &self.supported_roles
    }

    /// Get the player v1 support configuration
    pub fn player_v1_support(&self) -> Option<&PlayerV1Support> {
        self.player_v1_support.as_ref()
    }

    /// Override the default clock with a custom implementation.
    ///
    /// By default, the builder uses [`DefaultClock`] which reads
    /// `CLOCK_MONOTONIC_RAW` on Linux (immune to NTP slew) and the
    /// platform's native raw monotonic source elsewhere. Override this
    /// for testing or for platforms with alternative high-precision clocks.
    pub fn clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = clock;
        self
    }

    /// Connect to Sendspin server.
    ///
    /// Accepts anything that implements [`IntoClientRequest`], such as a URL string
    /// for simple connections. For custom headers (for example, auth cookies), callers
    /// will typically build an `http::Request<()>` — see the [`IntoClientRequest`] docs
    /// for the full set of supported request types.
    pub async fn connect<R: IntoClientRequest + Unpin>(
        self,
        request: R,
    ) -> Result<ProtocolClient, Error> {
        let encryption = self.encryption.clone();
        let (mut hello, initial_state, clock) = self.into_parts();
        // A client's pairing advertisement has to reflect its live configuration: a method it
        // does not offer must be absent, and the reference server refuses to pair with a
        // client whose hello offered nothing. Deriving it from the store keeps the two from
        // drifting apart.
        if let Encryption::Enabled(settings) = &encryption {
            let config = settings.store.pairing_config()?;
            let mut methods = Vec::new();
            if config.pairing_psk.is_some() {
                methods.push(PairMethodDescriptor {
                    method: PairMethod::PairingPsk,
                    out_channels: None,
                    locked_out: None,
                    min_pin_length: None,
                });
            }
            if config.static_pin.is_some() {
                methods.push(PairMethodDescriptor {
                    method: PairMethod::StaticPin,
                    out_channels: None,
                    locked_out: None,
                    min_pin_length: None,
                });
            }
            if config.dynamic_pin_enabled {
                methods.push(PairMethodDescriptor {
                    method: PairMethod::DynamicPin,
                    // The server combines this with its own minimum to pick the session's
                    // length, so leaving it out would let a shorter PIN be chosen than this
                    // client agreed to accept.
                    min_pin_length: Some(config.dynamic_pin_min_length),
                    out_channels: None,
                    locked_out: None,
                });
            }
            hello.supported_pair_methods = Some(methods);
            hello.unpaired_access = UnpairedAccess {
                enabled: config.unpaired_access,
            };
        }
        ProtocolClient::connect(request, hello, initial_state, clock, encryption).await
    }

    /// Adopt an already-handshaked WebSocket stream and drive the protocol
    /// from `client/hello` onwards.
    ///
    /// Use this when you're terminating TLS, routing by HTTP path, or
    /// otherwise need to own the WebSocket layer yourself. For the common
    /// "bind a TCP socket and accept inbound peers" case, use
    /// [`Self::listen`].
    pub async fn accept<S>(self, ws_stream: WebSocketStream<S>) -> Result<ProtocolClient, Error>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let (hello, initial_state, clock) = self.into_parts();
        ProtocolClient::drive(
            ws_stream,
            hello,
            initial_state,
            clock,
            Transport::Plain,
            None,
            None,
        )
        .await
    }

    /// Bind a TCP listener and produce a [`ProtocolListener`] that accepts
    /// inbound WebSocket peers. The builder is cloned per accepted peer.
    pub async fn listen<A: ToSocketAddrs>(self, addr: A) -> Result<ProtocolListener, Error> {
        let tcp = TcpListener::bind(addr)
            .await
            .map_err(|e| Error::Connection(format!("TCP bind failed: {e}")))?;
        let local = tcp
            .local_addr()
            .map(|a| a.to_string())
            .unwrap_or_else(|_| "unknown".to_string());
        log::info!("ProtocolListener bound on {local}");
        Ok(ProtocolListener::new(tcp, self))
    }

    fn into_parts(self) -> (ClientHello, ClientState, Arc<dyn Clock>) {
        let hello = ClientHello {
            client_id: self.client_id,
            name: self.name,
            version: 1,
            supported_roles: self.supported_roles,
            trust_level: self.trust_level,
            supported_pair_methods: self.supported_pair_methods,
            unpaired_access: self.unpaired_access,
            device_info: Some(DeviceInfo {
                product_name: self.product_name,
                manufacturer: Some(self.manufacturer.unwrap_or_else(|| "Sendspin".to_string())),
                software_version: self.software_version,
                mac_address: self.mac_address,
            }),
            player_v1_support: self.player_v1_support,
            source_v1_support: self.source_v1_support,
            artwork_v1_support: self.artwork_v1_support,
            visualizer_v1_support: self.visualizer_v1_support,
        };

        let initial_state = ClientState {
            player: self.initial_player_state,
            source: self.initial_source_state,
            ..ClientState::availability(self.initial_sync_state)
        };

        (hello, initial_state, self.clock)
    }
}
