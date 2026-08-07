// ABOUTME: Protocol message type definitions and serialization
// ABOUTME: Supports all Sendspin protocol messages per spec

use serde::{Deserialize, Serialize};

/// Top-level protocol message envelope
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "payload")]
pub enum Message {
    // === Handshake messages ===
    /// Client hello handshake message
    #[serde(rename = "client/hello")]
    ClientHello(ClientHello),

    /// Server declares its active purpose on this connection (encrypted transport).
    #[serde(rename = "server/activate")]
    ServerActivate(ServerActivate),

    /// One Noise handshake message, carried inside the encrypted channel.
    ///
    /// Only appears for an in-band re-handshake; a first handshake's two messages travel as
    /// cleartext text frames, before there is a channel to put them in.
    #[serde(rename = "noise/handshake")]
    NoiseHandshake(crate::noise::models::NoiseHandshake),

    /// Client delivers the long-term PSK for this (client, server) pair.
    #[serde(rename = "client/pair-finalize")]
    ClientPairFinalize(crate::noise::pairing::ClientPairFinalize),

    /// Server has persisted its pairing record.
    #[serde(rename = "server/pair-finalize")]
    ServerPairFinalize(crate::noise::pairing::ServerPairFinalize),

    /// Either side aborts a pairing attempt.
    #[serde(rename = "pair/abort")]
    PairAbort(crate::noise::pairing::PairAbort),

    /// Server hello handshake response
    #[serde(rename = "server/hello")]
    ServerHello(ServerHello),

    // === Time synchronization ===
    /// Client time synchronization request
    #[serde(rename = "client/time")]
    ClientTime(ClientTime),

    /// Server time synchronization response
    #[serde(rename = "server/time")]
    ServerTime(ServerTime),

    // === State messages ===
    /// Client state update
    #[serde(rename = "client/state")]
    ClientState(ClientState),

    /// Server state update (metadata, controller info)
    #[serde(rename = "server/state")]
    ServerState(ServerState),

    // === Command messages ===
    /// Server command to client (player commands)
    #[serde(rename = "server/command")]
    ServerCommand(ServerCommand),

    /// Client command to server (controller commands)
    #[serde(rename = "client/command")]
    ClientCommand(ClientCommand),

    // === Stream control messages ===
    /// Stream start notification
    #[serde(rename = "stream/start")]
    StreamStart(StreamStart),

    /// Stream end notification
    #[serde(rename = "stream/end")]
    StreamEnd(StreamEnd),

    /// Stream clear notification
    #[serde(rename = "stream/clear")]
    StreamClear(StreamClear),

    /// Client request for specific stream format
    #[serde(rename = "stream/request-format")]
    StreamRequestFormat(StreamRequestFormat),

    // === Input stream control (source role) ===
    /// Client announces the format of the input stream it is about to send
    #[serde(rename = "client_stream/start")]
    ClientStreamStart(ClientStreamStart),

    /// Client ends its input stream
    #[serde(rename = "client_stream/end")]
    ClientStreamEnd(ClientStreamEnd),

    /// Server asks the source for a different input stream format
    // === Group messages ===
    /// Group update notification
    #[serde(rename = "group/update")]
    GroupUpdate(GroupUpdate),

    // === Connection lifecycle ===
    /// Client goodbye message
    #[serde(rename = "client/goodbye")]
    ClientGoodbye(ClientGoodbye),
}

// =============================================================================
// Handshake Messages
// =============================================================================

/// Client hello message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientHello {
    /// Unique client identifier
    pub client_id: String,
    /// Human-readable client name
    pub name: String,
    /// Protocol version number
    pub version: u32,
    /// List of supported roles with versions (e.g., "player@v1", "controller@v1")
    pub supported_roles: Vec<String>,
    /// Trust this client extends to this server. `none` on an unpaired connection.
    #[serde(default)]
    pub trust_level: TrustLevel,
    /// Pairing methods this client offers. Omitted by a client that cannot pair.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supported_pair_methods: Option<Vec<PairMethodDescriptor>>,
    /// Whether this client currently admits unpaired access.
    #[serde(default)]
    pub unpaired_access: UnpairedAccess,
    /// Device information (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_info: Option<DeviceInfo>,
    /// Player capabilities (if client supports player@v1 role)
    #[serde(rename = "player@v1_support", skip_serializing_if = "Option::is_none")]
    pub player_v1_support: Option<PlayerV1Support>,
    /// Source capabilities (if client supports source@v1 role)
    #[serde(rename = "source@v1_support", skip_serializing_if = "Option::is_none")]
    pub source_v1_support: Option<SourceV1Support>,
    /// Artwork capabilities (if client supports artwork@v1 role)
    #[serde(rename = "artwork@v1_support", skip_serializing_if = "Option::is_none")]
    pub artwork_v1_support: Option<ArtworkV1Support>,
    /// Visualizer capabilities (if client supports visualizer@v1 role)
    #[serde(
        rename = "visualizer@v1_support",
        skip_serializing_if = "Option::is_none"
    )]
    pub visualizer_v1_support: Option<VisualizerV1Support>,
}

/// How much a client trusts the server on the other end of a connection.
///
/// The client's own judgement, sent in `client/hello`: it governs which management
/// operations the server may perform on this client, not what the server thinks of the
/// client. `None` is the honest answer for an unpaired connection, which is every
/// connection until a pairing exchange has happened.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum TrustLevel {
    /// No trust: unpaired, or mid-pairing. Management operations are refused.
    #[default]
    None,
    /// Paired by a user, which is what admits management.
    User,
}

/// A pairing method a client offers, or a server selects.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PairMethod {
    /// A PIN the client generates and conveys to the operator.
    DynamicPin,
    /// A pre-shared key both sides already hold.
    PairingPsk,
    /// A fixed PIN, printed on the device or in its manual.
    StaticPin,
    /// A method this build does not know (forward compatibility).
    #[serde(other)]
    Unknown,
}

/// One pairing method a client offers, with the details that method needs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairMethodDescriptor {
    /// Which method.
    pub method: PairMethod,
    /// `dynamic_pin` only: how the PIN reaches the operator (e.g. `display`, `voice`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub out_channels: Option<Vec<String>>,
    /// PIN methods only: whether the method is in terminal lockout after failed attempts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub locked_out: Option<bool>,
    /// `dynamic_pin` only: shortest PIN the client will accept, in digits (4-12).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_pin_length: Option<u8>,
}

/// Whether a client admits servers it has never paired with.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct UnpairedAccess {
    /// True when an unpaired server may use this client.
    pub enabled: bool,
}

impl Default for UnpairedAccess {
    /// `true`, which is what a client with no trust store actually does.
    ///
    /// Claiming otherwise would be a promise this library cannot keep: nothing here can
    /// turn an unpaired server away. Applications that add a trust store should say so
    /// explicitly rather than inherit this.
    fn default() -> Self {
        Self { enabled: true }
    }
}

/// Device information (all fields optional per spec)
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DeviceInfo {
    /// Product name (e.g., "Sendspin-RS Player")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub product_name: Option<String>,
    /// Manufacturer name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub manufacturer: Option<String>,
    /// Software version string
    #[serde(skip_serializing_if = "Option::is_none")]
    pub software_version: Option<String>,
    /// MAC address of the network interface the connection is opened on, in lowercase colon-separated form (e.g., `aa:bb:cc:dd:ee:ff`)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mac_address: Option<String>,
}

/// Player@v1 capabilities
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlayerV1Support {
    /// List of supported audio formats
    pub supported_formats: Vec<AudioFormatSpec>,
    /// Buffer capacity in chunks
    pub buffer_capacity: u32,
    /// List of supported playback commands
    pub supported_commands: Vec<String>,
}

/// Audio format specification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AudioFormatSpec {
    /// Codec name (e.g., "pcm", "opus", "flac")
    pub codec: String,
    /// Number of audio channels
    pub channels: u8,
    /// Sample rate in Hz
    pub sample_rate: u32,
    /// Bit depth per sample
    pub bit_depth: u8,
}

/// Artwork@v1 capabilities
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtworkV1Support {
    /// Supported artwork channels (1-4 channels, array index is channel number)
    pub channels: Vec<ArtworkChannel>,
}

/// Artwork channel configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtworkChannel {
    /// Artwork source type
    pub source: ArtworkSource,
    /// Image format
    pub format: ImageFormat,
    /// Max width in pixels
    pub media_width: u32,
    /// Max height in pixels
    pub media_height: u32,
}

/// Artwork source type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ArtworkSource {
    /// Album artwork
    Album,
    /// Artist image
    Artist,
    /// No artwork (channel disabled)
    None,
}

/// Image format
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ImageFormat {
    /// JPEG format
    Jpeg,
    /// PNG format
    Png,
    /// BMP format
    Bmp,
}

/// Visualizer@v1 capabilities.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VisualizerV1Support {
    /// Visualization data types requested by the client.
    pub types: Vec<VisualizerDataType>,
    /// Maximum total size of buffered visualizer messages in bytes.
    pub buffer_capacity: u32,
    /// Maximum periodic visualization frames per second.
    pub rate_max: u32,
    /// Spectrum configuration, required when `types` includes `spectrum`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub spectrum: Option<SpectrumConfig>,
}

impl VisualizerV1Support {
    /// Validate the cross-field spectrum requirement from the Sendspin spec.
    pub fn validate(&self) -> Result<(), &'static str> {
        validate_spectrum(&self.types, self.spectrum.as_ref())
    }
}

/// Visualization data type carried by a visualizer binary message.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum VisualizerDataType {
    /// Overall A-weighted loudness.
    Loudness,
    /// Musical beat event.
    Beat,
    /// Dominant frequency and amplitude.
    FPeak,
    /// FFT magnitudes mapped to display bins.
    Spectrum,
    /// Energy onset event.
    Peak,
    /// Perceived pitch, as MIDI note in 8.8 fixed point plus a confidence.
    Pitch,
}

/// Spectrum display-bin configuration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SpectrumConfig {
    /// Number of display bins.
    pub n_disp_bins: u32,
    /// Frequency-to-bin mapping.
    pub scale: SpectrumScale,
    /// Lowest frequency in Hz.
    pub f_min: u32,
    /// Highest frequency in Hz.
    pub f_max: u32,
}

fn validate_spectrum(
    types: &[VisualizerDataType],
    spectrum: Option<&SpectrumConfig>,
) -> Result<(), &'static str> {
    let has_spectrum = types.contains(&VisualizerDataType::Spectrum);
    match (has_spectrum, spectrum.is_some()) {
        (true, false) => Err("spectrum configuration is required for spectrum data"),
        (false, true) => Err("spectrum configuration requires spectrum data"),
        _ => Ok(()),
    }
}

/// Frequency-to-bin mapping for spectrum data.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum SpectrumScale {
    /// HTK mel-frequency spacing.
    Mel,
    /// Base-10 logarithmic spacing.
    Log,
    /// Linear frequency spacing.
    Lin,
}

/// Server hello message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerHello {
    /// Unique server identifier
    pub server_id: String,
    /// Human-readable server name
    pub name: String,
    /// Protocol version number
    pub version: u32,
    /// List of roles activated by server for this client
    pub active_roles: Vec<String>,
    /// Reason for connection: 'discovery' or 'playback'
    pub connection_reason: ConnectionReason,
    /// The pairing method the server picked from the client's offer.
    ///
    /// Present when `connection_reason` is `pairing`. A client that offered no methods
    /// and receives one anyway is being asked for something it cannot do, which is worth
    /// a `goodbye(unauthorized)` rather than a silent failure to pair.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selected_pair_method: Option<PairMethod>,
}

/// Server hello on an encrypted connection.
///
/// Under encryption the server's identity has already been established by the Noise
/// handshake — `server_id` came from `server/init` and the static key authenticated it — so
/// all that is left to say is the friendly name. Roles and purpose arrive separately, in
/// [`ServerActivate`].
///
/// This shares its `type` tag with the legacy [`ServerHello`], which is why it is not a
/// variant of [`Message`]: an internally-tagged union cannot hold two shapes under one tag.
/// The handshake parses whichever one the transport implies.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerHelloEncrypted {
    /// Human-readable server name.
    pub name: String,
}

/// A purpose a connection is currently serving.
///
/// Ranked by how much it displaces, the same ladder the legacy [`ConnectionReason`] uses:
/// see [`should_switch`](crate::protocol::should_switch).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Activity {
    /// A pairing handshake.
    Pairing,
    /// Active or upcoming playback.
    Playback,
    /// A dedicated management session.
    Management,
    /// A purpose this build does not know (forward compatibility).
    ///
    /// Lowest rank, which is the safe end: an unrecognised purpose does not displace a
    /// server that is playing.
    #[serde(other)]
    Unknown,
}

/// Parameters of the pairing attempt an activation admits.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActivationPairing {
    /// The method the server picked, drawn from the client's `supported_pair_methods`.
    pub method: PairMethod,
    /// Digit count for this session. Required when `method` is `dynamic_pin`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pin_length: Option<u8>,
    /// BCP 47 language tags in descending operator preference, for a spoken PIN.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub languages: Option<Vec<String>>,
}

/// `server/activate` — what this connection is currently for.
///
/// Replaces the legacy hello's `connection_reason` and `active_roles`. It may be re-sent at
/// any time to change the activity set, and `active_roles` persists across activations that
/// omit it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerActivate {
    /// The currently-active purposes. May be empty; members are unordered and unique.
    pub activities: Vec<Activity>,
    /// Versioned roles active for this client.
    ///
    /// Required on the first activation and persists across later ones that omit it, so
    /// `None` here means "unchanged" rather than "none".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active_roles: Option<Vec<String>>,
    /// Present when `activities` includes `pairing`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pairing: Option<ActivationPairing>,
    /// The older spelling of `pairing.method`, carrying just the method.
    ///
    /// The spec replaced it with the [`pairing`](Self::pairing) object, which can also carry
    /// `pin_length` and language hints, but `aiosendspin` still sends this one. Both are
    /// accepted on receive — see [`Self::pair_method`] — because a client that insists on the
    /// newer spelling cannot pair with the reference server.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selected_pair_method: Option<PairMethod>,
}

impl ServerActivate {
    /// The pairing method this activation selected, from whichever spelling it used.
    ///
    /// Prefers the `pairing` object, since it is the one the spec defines and the only one
    /// that can carry a PIN length.
    pub fn pair_method(&self) -> Option<PairMethod> {
        self.pairing
            .as_ref()
            .map(|p| p.method)
            .or(self.selected_pair_method)
    }

    /// The dynamic PIN length for this session, when one was given.
    pub fn pin_length(&self) -> Option<u8> {
        self.pairing.as_ref().and_then(|p| p.pin_length)
    }

    /// The highest-ranked activity declared, for admission between competing connections.
    ///
    /// An empty activity set ranks lowest, below every named purpose.
    pub fn rank(&self) -> u8 {
        self.activities
            .iter()
            .map(|a| match a {
                Activity::Management => 4,
                Activity::Playback => 3,
                Activity::Pairing => 2,
                Activity::Unknown => 1,
            })
            .max()
            .unwrap_or(0)
    }
}

/// Why a server opened this connection.
///
/// Ordered by how much it displaces: see [`should_switch`](crate::protocol::should_switch).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ConnectionReason {
    /// General availability: initial discovery, or a reconnection.
    Discovery,
    /// A pairing handshake.
    Pairing,
    /// Active or upcoming playback.
    Playback,
    /// A dedicated management session.
    Management,
    /// A reason this build does not know (forward compatibility).
    ///
    /// Treated as the lowest rank, which is the safe end: an unrecognised purpose does
    /// not get to displace a server that is playing.
    #[serde(other)]
    Unknown,
}

// =============================================================================
// Time Synchronization
// =============================================================================

/// Client time sync message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientTime {
    /// Client transmission timestamp (raw monotonic microseconds)
    pub client_transmitted: i64,
}

/// Server time sync response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerTime {
    /// Original client transmission timestamp
    pub client_transmitted: i64,
    /// Server reception timestamp (server loop microseconds)
    pub server_received: i64,
    /// Server transmission timestamp (server loop microseconds)
    pub server_transmitted: i64,
}

// =============================================================================
// State Messages
// =============================================================================

/// Client state update message (wraps role-specific state)
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ClientState {
    /// Whether this client is available to take part in playback.
    ///
    /// `false` says the output is in use by something else — an HDMI input, a local app —
    /// so the server should not schedule audio here. It replaces the `state` enum below,
    /// which said the same thing in a way that could not express anything else.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub available: Option<bool>,
    /// Client operational state.
    ///
    /// Superseded by `available` and still sent alongside it: a server that only reads
    /// this field would otherwise see a client that never reports being busy. Populate
    /// both or neither; [`ClientState::is_available`] resolves them in the right order.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<ClientSyncState>,
    /// Player state (if player role active)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub player: Option<PlayerState>,
    /// Source state (if source role active)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<SourceState>,
}

impl ClientState {
    /// A state update that says whether the client is available, in both spellings.
    pub fn availability(state: ClientSyncState) -> Self {
        Self {
            available: Some(state == ClientSyncState::Synchronized),
            state: Some(state),
            player: None,
            source: None,
        }
    }

    /// Whether the sender said it is available, preferring the field that can say more.
    ///
    /// `None` when it said neither, which is not the same as "unavailable": a partial
    /// update that carries only player volume says nothing about availability, and
    /// reading that as "do not send audio" would silence the room.
    pub fn is_available(&self) -> Option<bool> {
        self.available.or_else(|| {
            self.state
                .map(|state| state == ClientSyncState::Synchronized)
        })
    }
}

/// Player state
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PlayerState {
    /// Current volume level (0-100)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub volume: Option<u8>,
    /// Whether audio is muted
    #[serde(skip_serializing_if = "Option::is_none")]
    pub muted: Option<bool>,
    /// Static delay in milliseconds (0-5000) to compensate for external speaker/amplifier latency
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub static_delay_ms: Option<u16>,
    /// Minimum startup lead time in milliseconds.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub required_lead_time_ms: Option<u32>,
    /// Requested minimum ongoing buffer duration in milliseconds.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub min_buffer_ms: Option<u32>,
    /// Supported player state commands
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub supported_commands: Option<Vec<PlayerStateCommand>>,
}

/// Commands that can appear in PlayerState.supported_commands
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PlayerStateCommand {
    /// Client supports set_static_delay command
    SetStaticDelay,
}

/// Client operational state (top-level in client/state).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ClientSyncState {
    /// Client's clock filter has converged enough to begin scheduling playback.
    Synchronized,
    /// Client is in use by an external system (e.g., different audio source, HDMI input)
    /// and is not currently participating in Sendspin playback with this server.
    ExternalSource,
}

/// Server state update message (metadata and controller info)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerState {
    /// Metadata state (track info, progress, etc.)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<MetadataState>,
    /// Controller state (supported commands, volume, etc.)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub controller: Option<ControllerState>,
    /// Color state (colors derived from the current audio)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub color: Option<ColorState>,
}

/// An RGB color as `[R, G, B]` with components 0-255.
pub type Rgb = [u8; 3];

/// Color state from server (color role).
///
/// Colors may be extracted from album artwork, provided by the music source,
/// or manually programmed by the server. All color fields are optional; the
/// server sends only the palette entries it has.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ColorState {
    /// Server clock time in microseconds for when these colors are valid
    pub timestamp: i64,
    /// Background color suitable for dark mode. The server ensures a minimum
    /// WCAG contrast ratio of 4.5:1 with white text and with `on_dark`
    /// (if also present).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub background_dark: Option<Rgb>,
    /// Background color suitable for light mode. The server ensures a minimum
    /// WCAG contrast ratio of 4.5:1 with black text and with `on_light`
    /// (if also present).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub background_light: Option<Rgb>,
    /// The dominant color. Not adjusted for contrast.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub primary: Option<Rgb>,
    /// A secondary or complementary color. Not adjusted for contrast.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub accent: Option<Rgb>,
    /// A light color suitable for use on dark backgrounds. The server ensures
    /// a minimum WCAG contrast ratio of 4.5:1 with `background_dark` (if also
    /// present) and with black text, so it can also serve as an alternative
    /// light background.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub on_dark: Option<Rgb>,
    /// A dark color suitable for use on light backgrounds. The server ensures
    /// a minimum WCAG contrast ratio of 4.5:1 with `background_light` (if also
    /// present) and with white text, so it can also serve as an alternative
    /// dark background.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub on_light: Option<Rgb>,
}

/// Metadata state from server
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetadataState {
    /// Server timestamp for progress calculation (microseconds)
    pub timestamp: i64,
    /// Track title
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// Artist name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub artist: Option<String>,
    /// Album artist
    #[serde(skip_serializing_if = "Option::is_none")]
    pub album_artist: Option<String>,
    /// Album name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub album: Option<String>,
    /// Artwork URL
    #[serde(skip_serializing_if = "Option::is_none")]
    pub artwork_url: Option<String>,
    /// Release year
    #[serde(skip_serializing_if = "Option::is_none")]
    pub year: Option<u32>,
    /// Track number (1-indexed)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub track: Option<u32>,
    /// Current track progress
    #[serde(skip_serializing_if = "Option::is_none")]
    pub progress: Option<TrackProgress>,
    /// Repeat mode
    ///
    /// Deprecated: the spec moved `repeat` to the controller `server/state`
    /// object. Prefer [`ControllerState::repeat`] instead. This field is kept
    /// only to parse the legacy dual-emit and will be removed in a future
    /// release.
    #[deprecated(since = "0.3.0", note = "use ControllerState::repeat instead")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repeat: Option<RepeatMode>,
    /// Shuffle state
    ///
    /// Deprecated: the spec moved `shuffle` to the controller `server/state`
    /// object. Prefer [`ControllerState::shuffle`] instead. This field is kept
    /// only to parse the legacy dual-emit and will be removed in a future
    /// release.
    #[deprecated(since = "0.3.0", note = "use ControllerState::shuffle instead")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shuffle: Option<bool>,
}

/// Track progress information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrackProgress {
    /// Current position in milliseconds
    pub track_progress: i64,
    /// Total duration in milliseconds (0 for unknown/live streams)
    pub track_duration: i64,
    /// Playback speed multiplier * 1000 (1000 = normal, 0 = paused)
    pub playback_speed: i32,
}

/// Repeat mode
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RepeatMode {
    /// No repeat
    Off,
    /// Repeat current track
    One,
    /// Repeat all tracks
    All,
}

/// Controller state from server
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControllerState {
    /// List of supported commands
    pub supported_commands: Vec<String>,
    /// Current volume level (0-100)
    pub volume: u8,
    /// Whether audio is muted
    pub muted: bool,
    /// Repeat mode
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repeat: Option<RepeatMode>,
    /// Shuffle state
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shuffle: Option<bool>,
    /// Maximum absolute position in milliseconds a 'seek' may target (e.g.,
    /// the end of the current track). Present whenever 'seek' is in
    /// `supported_commands`; absent when the seekable range is unknown.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seek_max_ms: Option<u64>,
}

// =============================================================================
// Command Messages
// =============================================================================

/// Server command message (wraps role-specific commands)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerCommand {
    /// Player command (if targeting player role)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub player: Option<PlayerCommand>,
    /// Source command (if targeting source role)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<SourceCommand>,
}

/// Player-specific command from server
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlayerCommand {
    /// Command to execute
    pub command: PlayerCommandType,
    /// Optional volume level (0-100)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub volume: Option<u8>,
    /// Optional mute state
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mute: Option<bool>,
    /// Optional static delay in milliseconds (0-5000)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub static_delay_ms: Option<u16>,
}

/// Player command type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PlayerCommandType {
    /// Set volume level
    Volume,
    /// Set mute state
    Mute,
    /// Set static delay
    SetStaticDelay,
    /// Unknown command (forward compatibility)
    #[serde(other)]
    Unknown,
}

/// Client command message (controller commands to server)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientCommand {
    /// Controller command
    #[serde(skip_serializing_if = "Option::is_none")]
    pub controller: Option<ControllerCommand>,
    /// Source event (if the client has the source role)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<SourceClientCommand>,
}

/// Controller command from client
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControllerCommand {
    /// Command to execute
    pub command: ControllerCommandType,
    /// Optional volume level (0-100) for volume command
    #[serde(skip_serializing_if = "Option::is_none")]
    pub volume: Option<u8>,
    /// Optional mute state for mute command
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mute: Option<bool>,
    /// Absolute playback position in milliseconds, range 0 to
    /// [`ControllerState::seek_max_ms`]. Only set for the `seek` command.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub position_ms: Option<u64>,
    /// Signed offset in milliseconds from the current position (positive
    /// forward, negative backward). Only set for the `seek_relative` command.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offset_ms: Option<i64>,
}

/// Controller command type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ControllerCommandType {
    /// Resume playback
    Play,
    /// Pause playback
    Pause,
    /// Stop playback and reset position
    Stop,
    /// Skip to next track
    Next,
    /// Skip to previous track
    Previous,
    /// Set group volume
    Volume,
    /// Set group mute state
    Mute,
    /// Disable repeat
    RepeatOff,
    /// Repeat current track
    RepeatOne,
    /// Repeat all tracks
    RepeatAll,
    /// Randomize playback order
    Shuffle,
    /// Restore original playback order
    Unshuffle,
    /// Switch to next group
    Switch,
    /// Seek to an absolute position (requires `position_ms`)
    Seek,
    /// Seek by a signed offset from the current position (requires `offset_ms`)
    SeekRelative,
}

// =============================================================================
// Stream Control Messages
// =============================================================================

/// Stream start message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamStart {
    /// When the server put this message on the wire, in *its* clock, in microseconds.
    ///
    /// The start of the window a player's `required_lead_time_ms` is measured over: the spec
    /// counts the lead from the server's transmit time of the trigger to the playback timestamp
    /// of the first chunk that can be played in full. Without it a client can state a lead
    /// requirement but never tell whether it was honoured.
    ///
    /// Optional here because a server that predates the field simply omits it, and a stream is
    /// perfectly playable without knowing when its trigger was sent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_transmitted: Option<i64>,
    /// Player stream configuration (optional - only if player role active)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub player: Option<StreamPlayerConfig>,
    /// Artwork stream configuration (optional - only if artwork role active)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub artwork: Option<StreamArtworkConfig>,
    /// Visualizer stream configuration (optional - only if visualizer role active)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub visualizer: Option<StreamVisualizerConfig>,
}

/// Stream player configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamPlayerConfig {
    /// Audio codec name
    pub codec: String,
    /// Sample rate in Hz
    pub sample_rate: u32,
    /// Number of audio channels
    pub channels: u8,
    /// Bit depth per sample
    pub bit_depth: u8,
    /// Optional codec-specific header (base64 encoded)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub codec_header: Option<String>,
}

/// Stream artwork configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamArtworkConfig {
    /// Configuration for each active artwork channel, array index is the channel number
    pub channels: Vec<StreamArtworkChannelConfig>,
}

/// Configuration for a single artwork channel in stream/start
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamArtworkChannelConfig {
    /// Artwork source type
    pub source: ArtworkSource,
    /// Format of the encoded image
    pub format: ImageFormat,
    /// Width in pixels of the encoded image
    pub width: u32,
    /// Height in pixels of the encoded image
    pub height: u32,
}

/// Stream visualizer configuration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StreamVisualizerConfig {
    /// Visualization data types the server will stream.
    pub types: Vec<VisualizerDataType>,
    /// Maximum periodic visualization frames per second.
    pub rate_max: u32,
    /// Whether the beat tracker identifies bar starts.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tracks_downbeats: Option<bool>,
    /// Spectrum configuration, present when `types` includes `spectrum`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub spectrum: Option<SpectrumConfig>,
}

impl StreamVisualizerConfig {
    /// Validate the cross-field spectrum requirement from the Sendspin spec.
    pub fn validate(&self) -> Result<(), &'static str> {
        validate_spectrum(&self.types, self.spectrum.as_ref())
    }
}

/// Stream end message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamEnd {
    /// When the server put this message on the wire, in *its* clock, in microseconds.
    ///
    /// The start of the window a player's `required_lead_time_ms` is measured over: the spec
    /// counts the lead from the server's transmit time of the trigger to the playback timestamp
    /// of the first chunk that can be played in full. Without it a client can state a lead
    /// requirement but never tell whether it was honoured.
    ///
    /// Optional here because a server that predates the field simply omits it, and a stream is
    /// perfectly playable without knowing when its trigger was sent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_transmitted: Option<i64>,
    /// Roles for which streaming has ended (optional, all if not specified)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub roles: Option<Vec<String>>,
}

/// Stream clear message (clear buffers)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamClear {
    /// When the server put this message on the wire, in *its* clock, in microseconds.
    ///
    /// The start of the window a player's `required_lead_time_ms` is measured over: the spec
    /// counts the lead from the server's transmit time of the trigger to the playback timestamp
    /// of the first chunk that can be played in full. Without it a client can state a lead
    /// requirement but never tell whether it was honoured.
    ///
    /// Optional here because a server that predates the field simply omits it, and a stream is
    /// perfectly playable without knowing when its trigger was sent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_transmitted: Option<i64>,
    /// Roles for which buffers should be cleared (optional, all if not specified)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub roles: Option<Vec<String>>,
}

/// Stream format request from client
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamRequestFormat {
    /// Requested player format
    #[serde(skip_serializing_if = "Option::is_none")]
    pub player: Option<PlayerFormatRequest>,
    /// Requested artwork format
    #[serde(skip_serializing_if = "Option::is_none")]
    pub artwork: Option<ArtworkFormatRequest>,
    /// Requested visualizer format
    #[serde(skip_serializing_if = "Option::is_none")]
    pub visualizer: Option<VisualizerFormatRequest>,
}

/// Requested visualizer stream format. Omitted fields keep their current value.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VisualizerFormatRequest {
    /// New visualization data types.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub types: Option<Vec<VisualizerDataType>>,
    /// New periodic visualization frames-per-second cap.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rate_max: Option<u32>,
    /// New ceiling on buffered visualizer bytes.
    ///
    /// The one visualizer setting a client may need to *lower* while a stream runs: a
    /// display that has taken on other work has less memory to hold frames in, and the
    /// alternative to saying so is dropping them on arrival.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub buffer_capacity: Option<u32>,
    /// New spectrum configuration.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub spectrum: Option<SpectrumConfig>,
}

impl VisualizerFormatRequest {
    /// Validate that this request changes at least one field.
    ///
    /// This is a partial update: omitted fields retain their current value, so
    /// a request may omit `spectrum` even when its new `types` includes it.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.types.is_none()
            && self.rate_max.is_none()
            && self.buffer_capacity.is_none()
            && self.spectrum.is_none()
        {
            return Err("visualizer format request must specify at least one field");
        }
        if let (Some(types), Some(spectrum)) = (self.types.as_ref(), self.spectrum.as_ref()) {
            validate_spectrum(types, Some(spectrum))
        } else {
            Ok(())
        }
    }
}

/// Player format request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlayerFormatRequest {
    /// Preferred codec
    #[serde(skip_serializing_if = "Option::is_none")]
    pub codec: Option<String>,
    /// Preferred channel count
    #[serde(skip_serializing_if = "Option::is_none")]
    pub channels: Option<u8>,
    /// Preferred sample rate
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sample_rate: Option<u32>,
    /// Preferred bit depth
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bit_depth: Option<u8>,
}

/// Artwork format request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtworkFormatRequest {
    /// Artwork channel to request
    pub channel: u8,
    /// Preferred image source
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<ArtworkSource>,
    /// Preferred image format
    #[serde(skip_serializing_if = "Option::is_none")]
    pub format: Option<ImageFormat>,
    /// Display width in pixels
    #[serde(skip_serializing_if = "Option::is_none")]
    pub media_width: Option<u32>,
    /// Display height in pixels
    #[serde(skip_serializing_if = "Option::is_none")]
    pub media_height: Option<u32>,
}

// =============================================================================
// Group Messages
// =============================================================================

/// Group update notification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupUpdate {
    /// Current playback state of the group
    #[serde(skip_serializing_if = "Option::is_none")]
    pub playback_state: Option<PlaybackState>,
    /// Group identifier
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group_id: Option<String>,
    /// Human-readable group name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group_name: Option<String>,
}

/// Group playback state
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum PlaybackState {
    /// Audio is playing
    Playing,
    /// Playback is paused, with a position to resume from
    Paused,
    /// Playback is stopped
    Stopped,
    /// A state this build does not know (forward compatibility)
    #[serde(other)]
    Unknown,
}

// =============================================================================
// Connection Lifecycle
// =============================================================================

/// Client goodbye message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientGoodbye {
    /// Reason for disconnection
    pub reason: GoodbyeReason,
}

/// Goodbye reason
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GoodbyeReason {
    /// Switching to another server
    AnotherServer,
    /// Client is shutting down
    Shutdown,
    /// Client is restarting
    Restart,
    /// User requested disconnect
    UserRequest,
    /// The server asked for something this client's trust level does not permit
    Unauthorized,
    /// The server asked for playback, but this client requires pairing first
    PairingRequired,
    /// Rejected because another connection is already admitted
    ConcurrentAttempt,
    /// This client processed `server/unpair` from the server
    Unpaired,
}

// =============================================================================
// Source Role (source@v1)
// =============================================================================
//
// A source is the mirror image of a player: it captures audio from a local input
// and streams it *to* the server, which does the resampling, mixing and
// distribution. The server drives capture with `server/command` and the client
// announces each stream's format with `client_stream/start` before the first
// binary frame, so a format change is a stream boundary rather than a guess.

/// Audio format of a source stream
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceFormat {
    /// Codec name ("pcm", "flac", "opus")
    pub codec: String,
    /// Number of channels
    pub channels: u8,
    /// Sample rate in Hz
    pub sample_rate: u32,
    /// Bit depth per sample
    pub bit_depth: u8,
}

/// Optional source capabilities
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SourceFeatures {
    /// Client reports a normalized input level
    #[serde(skip_serializing_if = "Option::is_none")]
    pub level: Option<bool>,
    /// Client reports whether a signal is present on the input
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line_sense: Option<bool>,
}

/// Transport controls a source client accepts on behalf of its input
///
/// An input that is a device of its own — a CD player, a tuner — can be told to
/// play or skip. The server sends these; what they mean is the client's business.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceControl {
    /// Start playback on the attached device
    Play,
    /// Pause playback on the attached device
    Pause,
    /// Next track on the attached device
    Next,
    /// Previous track on the attached device
    Previous,
    /// Power up / select the attached device
    Activate,
    /// Power down / deselect the attached device
    Deactivate,
    /// Unknown control (forward compatibility)
    #[serde(other)]
    Unknown,
}

/// Source@v1 capabilities, sent in `client/hello`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceV1Support {
    /// Formats this input can deliver, best first
    pub supported_formats: Vec<SourceFormat>,
    /// Transport controls the client will act on
    #[serde(skip_serializing_if = "Option::is_none")]
    pub controls: Option<Vec<SourceControl>>,
    /// Optional level/line-sense reporting
    #[serde(skip_serializing_if = "Option::is_none")]
    pub features: Option<SourceFeatures>,
}

/// Capture state of a source
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceStateType {
    /// Not capturing
    Idle,
    /// Capturing and sending audio
    Streaming,
    /// Capture failed
    Error,
    /// Unknown state (forward compatibility)
    #[serde(other)]
    Unknown,
}

/// Whether a signal is present on the input.
///
/// `Unknown` is a real value here, not a parse fallback: a source that has just
/// been started genuinely does not know yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceSignal {
    /// Presence not determined yet
    Unknown,
    /// Audio is present on the input
    Present,
    /// The input is silent
    Absent,
}

/// Source state, sent in `client/state`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceState {
    /// Capture state
    pub state: SourceStateType,
    /// Normalized input level (0.0-1.0), if `level` is supported
    #[serde(skip_serializing_if = "Option::is_none")]
    pub level: Option<f32>,
    /// Signal presence, if `line_sense` is supported
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signal: Option<SourceSignal>,
}

/// What the server asks a source to do
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceCommandType {
    /// Begin capturing and streaming
    Start,
    /// Stop capturing
    Stop,
    /// Unknown command (forward compatibility)
    #[serde(other)]
    Unknown,
}

/// Signal-detection settings the server can push down
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SourceVadSettings {
    /// Level below which the input counts as silent, in dBFS
    #[serde(skip_serializing_if = "Option::is_none")]
    pub threshold_db: Option<f32>,
    /// How long a level change must persist before it is reported, in ms
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hold_ms: Option<u64>,
}

/// Source command from the server
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SourceCommand {
    /// Start or stop capture
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command: Option<SourceCommandType>,
    /// Transport control for the attached device
    #[serde(skip_serializing_if = "Option::is_none")]
    pub control: Option<SourceControl>,
    /// Updated signal-detection settings
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vad: Option<SourceVadSettings>,
}

/// A user-initiated capture event the client reports upstream
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceClientCommandType {
    /// Audio appeared on the input
    Started,
    /// Audio disappeared from the input
    Stopped,
    /// Unknown event (forward compatibility)
    #[serde(other)]
    Unknown,
}

/// Source event, sent in `client/command`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceClientCommand {
    /// The event
    pub command: SourceClientCommandType,
}

/// Format details of the input stream a source is about to send
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientStreamSource {
    /// Codec name ("pcm", "flac", "opus")
    pub codec: String,
    /// Number of channels
    pub channels: u8,
    /// Sample rate in Hz
    pub sample_rate: u32,
    /// Bit depth per sample
    pub bit_depth: u8,
    /// Base64 codec header, for codecs that need one out of band (FLAC STREAMINFO)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub codec_header: Option<String>,
}

/// `client_stream/start` payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientStreamStart {
    /// Format of the stream that follows
    pub source: ClientStreamSource,
}

/// `client_stream/end` payload. Empty by design — which stream ended is implied by
/// the connection.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ClientStreamEnd {}

// =============================================================================
// Legacy Aliases (deprecated)
// =============================================================================

/// Legacy type alias for backwards compatibility
#[deprecated(note = "Use PlayerV1Support instead")]
pub type PlayerSupport = PlayerV1Support;
