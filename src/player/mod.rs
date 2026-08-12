// ABOUTME: The player session: what a client does once it is connected to a server, from the
// ABOUTME: first hello to the last chunk, with the sound card and the volume path attached.

//! Being a player.
//!
//! The protocol types say what a client may send; [`SyncedPlayer`](crate::audio::SyncedPlayer)
//! plays a stream to a card. This is the part between them — the session that negotiates a
//! format, opens the right output, follows the server's timeline, honours volume and mute
//! wherever the level actually lives, and fires the host's hooks at the right moments.
//!
//! It exists as a library module because otherwise every application embedding this crate
//! writes it again. Build a [`PlayerConfig`](crate::player::PlayerConfig), hand it to
//! [`Player`](crate::player::Player), and either dial a server
//! or wait for one:
//!
//! ```no_run
//! # async fn run() -> Result<(), Box<dyn std::error::Error>> {
//! use sendspin::player::{Player, PlayerConfig};
//!
//! let player = Player::new(PlayerConfig::new("kitchen".to_string(), "Kitchen".to_string()));
//! let mut status = player.status();
//! tokio::spawn(async move {
//!     while status.changed().await.is_ok() {
//!         println!("{:?}", status.borrow().connection);
//!     }
//! });
//! player.run_outbound("ws://server:8927/sendspin", None).await?;
//! # Ok(())
//! # }
//! ```

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::watch;

use crate::audio::decode::{Decoder, FlacDecoder, OpusDecoder, PcmDecoder, PcmEndian};
use crate::audio::{AudioBuffer, AudioFormat, Codec, SyncedPlayer, SyncedPlayerConfig};
use crate::hooks::{HookContext, Hooks};
use crate::protocol::client::{AudioChunk, Encryption, EncryptionSettings, WsSender};
#[cfg(feature = "discovery")]
use crate::protocol::manager::ConnectionManager;
use crate::protocol::messages::{
    AudioFormatSpec, ClientState, Message, PlaybackState, PlayerCommandType, PlayerState,
};
use crate::ProtocolClientBuilder;

/// Where a player is in its connection to a server.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ConnectionState {
    /// Not connected, and not currently trying.
    #[default]
    Disconnected,
    /// Dialling a server, or waiting for one to dial in.
    Connecting,
    /// Connected, with roles activated. Audio may or may not be flowing.
    Connected,
    /// A stream is live and being played.
    Playing,
}

/// What the player is doing, for an application that has to show it.
///
/// Published through a [`watch`] channel rather than a callback: an observer that is slow, or
/// that only wants the current value, cannot then hold up the session that produced it.
#[derive(Debug, Clone, Default)]
pub struct PlayerStatus {
    /// Where the connection stands.
    pub connection: ConnectionState,
    /// The connected server's identity, once there is one.
    pub server_id: Option<String>,
    /// The connected server's friendly name.
    pub server_name: Option<String>,
    /// The format currently being played, as negotiated for this stream.
    pub format: Option<AudioFormat>,
    /// The level in effect, whether this process, a card or a script applies it.
    pub volume: u8,
    /// Whether output is muted.
    pub muted: bool,
    /// The last thing that went wrong, kept until something else does.
    ///
    /// A player that loses its card or its server keeps running and keeps trying, so this is
    /// how an application learns that anything happened at all.
    pub last_error: Option<String>,
}

/// Everything a server learns about this client, and everything the session needs to play.
///
/// Deliberately a plain struct: what fills it — command-line flags, a configuration file, a
/// user interface — is the embedding application's business, not this crate's.
pub struct PlayerConfig {
    /// Friendly name, shown wherever a server lists its clients.
    pub name: String,
    /// Stable identity. Under the encrypted transport this must be the public half of
    /// [`encryption`](Self::encryption)'s identity, which is what the server authenticates.
    pub client_id: String,
    /// Product name reported in `client/hello`.
    pub product_name: String,
    /// Manufacturer reported in `client/hello`.
    pub manufacturer: Option<String>,
    /// The encrypted transport's identity and trust store, or `None` to speak cleartext.
    pub encryption: Option<EncryptionSettings>,
    /// Extra playback delay in milliseconds, for latency the protocol cannot see.
    pub static_delay: u16,
    /// The output device, or `None` for the platform default.
    pub device: Option<cpal::Device>,
    /// External scripts to run on stream lifecycle and volume changes.
    pub hooks: Hooks,
    /// The card's own volume control, where one is being driven.
    #[cfg(all(feature = "hardware-volume", target_os = "linux"))]
    pub mixer: Option<Arc<crate::audio::mixer::Mixer>>,
    /// The single format to offer, which decides what the server sends rather than preferring
    /// it. `None` offers everything the decoders implement at every rate in
    /// [`rates`](Self::rates).
    pub format: Option<AudioFormatSpec>,
    /// The sample rates to offer. Empty falls back to 48kHz.
    ///
    /// [`crate::audio::devices::output_rates`] reads these from the chosen card, which is what
    /// lets a server that resamples only when it must leave a matching source alone.
    pub rates: Vec<u32>,
}

impl PlayerConfig {
    /// A configuration with the platform defaults: default output device, no hooks, no mixer,
    /// cleartext transport, and every rate the default device can open.
    pub fn new(client_id: String, name: String) -> Self {
        Self {
            name,
            client_id,
            product_name: format!(
                "sendspin-rs on {} {}",
                std::env::consts::OS,
                std::env::consts::ARCH
            ),
            manufacturer: None,
            encryption: None,
            static_delay: 0,
            device: None,
            hooks: Hooks::default(),
            #[cfg(all(feature = "hardware-volume", target_os = "linux"))]
            mixer: None,
            format: None,
            rates: crate::audio::devices::output_rates(None),
        }
    }
}

/// A player: a configuration, and the session that runs on it.
pub struct Player {
    config: PlayerConfig,
    status: watch::Sender<PlayerStatus>,
}

impl Player {
    /// Build a player. Nothing happens until it is run.
    pub fn new(config: PlayerConfig) -> Self {
        let status = watch::Sender::new(PlayerStatus {
            volume: 100,
            ..PlayerStatus::default()
        });
        Self { config, status }
    }

    /// Watch what this player is doing.
    ///
    /// Every receiver sees the current value immediately and every change after it. Dropping
    /// one does not affect the session.
    pub fn status(&self) -> watch::Receiver<PlayerStatus> {
        self.status.subscribe()
    }

    /// The configuration this player was built with.
    pub fn config(&self) -> &PlayerConfig {
        &self.config
    }

    /// Dial `url` and play what it sends.
    ///
    /// With `reconnect`, dials again whenever the server goes away, and never returns. The loop
    /// is the point for a dedicated player: a server that restarts, a switch that reboots, a
    /// cable that is nudged — all of them end a connection, and every one of them should cost a
    /// few seconds of silence rather than the rest of the evening. The wait doubles up to a
    /// minute so an overnight outage is not dialled at full speed, and resets once a connection
    /// comes up.
    ///
    /// Without it, returns when the connection ends, which is what a foreground run wants.
    pub async fn run_outbound(
        &self,
        url: &str,
        reconnect: Option<Duration>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let Some(base) = reconnect else {
            return run_outbound(&self.config, &self.status, url).await;
        };

        let ceiling = Duration::from_secs(60);
        let mut wait = base;
        loop {
            match run_outbound(&self.config, &self.status, url).await {
                // A connection that came up and then ended is ordinary; start over at the short
                // delay rather than carrying a backoff earned by an earlier outage.
                Ok(()) => wait = base,
                Err(e) => {
                    log::warn!("Connection to {url} failed: {e}");
                    self.status
                        .send_modify(|status| status.last_error = Some(e.to_string()));
                    wait = (wait * 2).min(ceiling);
                }
            }
            log::info!("Reconnecting to {url} in {}s", wait.as_secs());
            tokio::time::sleep(wait).await;
        }
    }

    /// Listen on `bind` for servers that dial in, advertise over mDNS, and play whichever
    /// connection wins arbitration.
    ///
    /// The spec has a client pick one direction: advertising and dialling at once can leave it
    /// holding two connections that each believe they arbitrated correctly.
    #[cfg(feature = "discovery")]
    pub async fn run_inbound(&self, bind: &str) -> Result<(), Box<dyn std::error::Error>> {
        run_inbound(&self.config, &self.status, bind).await
    }
}

/// Build a client template carrying everything a server learns about this device in
/// `client/hello`. Shared by both directions so the two cannot drift.
fn template(config: &PlayerConfig) -> ProtocolClientBuilder {
    ProtocolClientBuilder::builder()
        .client_id(config.client_id.clone())
        .name(config.name.clone())
        .player_v1_support(player_support(config.format.as_ref(), &config.rates))
        .product_name(Some(config.product_name.clone()))
        // Passed unconditionally rather than behind an `if`: each setter moves the builder to
        // a new type, so a conditional one would need both branches to agree on it.
        .manufacturer(config.manufacturer.clone())
        .encryption(match &config.encryption {
            Some(settings) => Encryption::Enabled(settings.clone()),
            None => Encryption::Disabled,
        })
        .build()
}

/// What this client tells a server it can decode.
///
/// With no `--audio-format` this is the full set the decoders implement, in the order this
/// client would rather have them: Opus for bandwidth, then PCM. With one, it is that alone.
///
/// Each codec is offered at every rate the card can open, not at one rate the client picked.
/// A server that resamples only when it has to can then leave a 44.1kHz album alone; naming a
/// single rate would have made every album a resampled one.
fn player_support(
    pinned: Option<&crate::protocol::messages::AudioFormatSpec>,
    rates: &[u32],
) -> crate::protocol::messages::PlayerV1Support {
    use crate::protocol::messages::{AudioFormatSpec, PlayerV1Support};

    // (codec, bit depth), most wanted first.
    const CODECS: [(&str, u8); 4] = [("opus", 16), ("flac", 24), ("pcm", 24), ("pcm", 16)];

    let supported_formats = match pinned {
        Some(format) => vec![format.clone()],
        None => CODECS
            .into_iter()
            .flat_map(|(codec, bit_depth)| {
                // Opus is defined at 48kHz, so offering it at the card's other rates would
                // invite a stream this client's own decoder refuses.
                let codec_rates: Vec<u32> = if codec == "opus" {
                    rates
                        .iter()
                        .copied()
                        .filter(|rate| *rate == 48_000)
                        .collect()
                } else {
                    rates.to_vec()
                };
                codec_rates
                    .into_iter()
                    .map(move |sample_rate| AudioFormatSpec {
                        codec: codec.to_string(),
                        channels: 2,
                        sample_rate,
                        bit_depth,
                    })
            })
            .collect(),
    };
    PlayerV1Support {
        supported_formats,
        buffer_capacity: 50 * 1024 * 1024,
        supported_commands: vec!["volume".to_string(), "mute".to_string()],
    }
}

/// Dial a named server and play whatever it sends, until it goes away.
async fn run_outbound(
    config: &PlayerConfig,
    status: &watch::Sender<PlayerStatus>,
    url: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    log::info!("Connecting to {url}");
    status.send_modify(|status| status.connection = ConnectionState::Connecting);
    let client = template(config).connect(url).await?;
    let hello = client.server_hello().clone();
    log::info!(
        "Connected to {} ({}), roles {:?}",
        hello.name,
        hello.server_id,
        hello.active_roles
    );

    let context = HookContext {
        server_id: Some(hello.server_id.clone()),
        server_name: Some(hello.name.clone()),
        server_url: Some(url.to_string()),
        client_id: config.client_id.clone(),
        client_name: config.name.clone(),
    };

    let conn = client.split();
    play(
        conn.messages,
        conn.audio,
        conn.clock_sync,
        conn.sender,
        config,
        status,
        context,
    )
    .await;
    log::info!("Server closed the connection");
    Ok(())
}

/// Listen for servers, advertise over mDNS, and serve whichever connection wins arbitration.
///
/// The manager owns the accept loop and the keep-or-switch policy; this only has to play what
/// the winner sends and be ready for the next one, because a server going away is ordinary.
#[cfg(feature = "discovery")]
async fn run_inbound(
    config: &PlayerConfig,
    status: &watch::Sender<PlayerStatus>,
    bind: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let listener = template(config).listen(bind).await?;
    let port = listener.local_addr()?.port();
    let mut manager = ConnectionManager::new(listener);
    status.send_modify(|status| status.connection = ConnectionState::Connecting);

    // Withdrawn on drop, so a player that exits stops being advertised. A stale record is
    // worse than none: a server dials it, fails, and retries.
    let _advertisement =
        crate::protocol::discovery::ClientAdvertisement::new(&config.client_id, &config.name, port)
            .inspect_err(|e| log::error!("Could not advertise over mDNS: {e}"))
            .ok();
    log::info!(
        "Listening on {bind}, advertising _sendspin._tcp.local. as {:?}",
        config.name
    );

    while let Some(conn) = manager.next_connection().await {
        let server_id = conn.server_hello.server_id.clone();
        log::info!(
            "Serving {server_id} from {} (reason {:?})",
            conn.peer,
            conn.server_hello.connection_reason
        );
        let context = HookContext {
            server_id: Some(server_id.clone()),
            server_name: Some(conn.server_hello.name.clone()),
            // No URL to report: this server dialled us, so there is none to hand a script.
            server_url: None,
            client_id: config.client_id.clone(),
            client_name: config.name.clone(),
        };
        let played = play(
            conn.messages,
            conn.audio,
            conn.clock_sync,
            conn.sender,
            config,
            status,
            context,
        )
        .await;
        // A server this client actually played for wins a later discovery tie, which is what
        // the spec asks a client to remember. It is in memory only: surviving a restart needs
        // the settings directory, which is not built yet.
        if played {
            manager.set_last_played(Some(server_id.clone()));
        }
        log::info!("{server_id} disconnected — waiting for the next server");
    }
    Ok(())
}

/// Decode and play one connection's stream until it ends.
///
/// Returns whether any audio was actually played, which is what decides if this server counts
/// as "last played" for a later arbitration.
async fn play(
    mut messages: tokio::sync::mpsc::UnboundedReceiver<Message>,
    mut audio: tokio::sync::mpsc::UnboundedReceiver<AudioChunk>,
    clock_sync: Arc<parking_lot::Mutex<crate::sync::ClockSync>>,
    sender: WsSender,
    config: &PlayerConfig,
    status: &watch::Sender<PlayerStatus>,
    context: HookContext,
) -> bool {
    let hooks = &config.hooks;
    let external_volume = volume_is_elsewhere(config);
    let output_device = config.device.clone();
    let static_delay = config.static_delay;
    status.send_modify(|status| {
        status.connection = ConnectionState::Connected;
        status.server_id = context.server_id.clone();
        status.server_name = context.server_name.clone();
    });
    // Whether a stream is live, so the stop hook fires once and only after a start did.
    let mut streaming = false;
    let mut decoder: Option<Box<dyn Decoder>> = None;
    let mut format: Option<AudioFormat> = None;
    let mut player: Option<SyncedPlayer> = None;
    // Set when opening the output device fails, so a machine with no usable card is reported
    // once per stream rather than once per chunk. Fifty chunks a second is a log flood, and it
    // buries the one line that says what actually went wrong.
    let mut output_unavailable = false;
    // Reopens spent on this stream after the card reported a fault. Bounded, because a device
    // that fails the moment it opens would otherwise be reopened once per chunk forever.
    let mut output_restarts = 0_u8;
    let mut played_anything = false;
    // Held outside the player: a volume command can arrive before a stream does, and the
    // setting has to survive until there is something to apply it to. Seeded from the card
    // where there is one, so a daemon on a card sitting at 30% reports 30 rather than
    // announcing 100 and then being wrong until someone changes it.
    let (mut volume, mut muted) = starting_volume(config);
    let mut delay = static_delay;
    status.send_modify(|status| {
        status.volume = volume;
        status.muted = muted;
    });

    // Reported up front for the same reason: `server/activate` has happened, and a server that
    // is never told the level shows whatever it assumed.
    let initial = ClientState {
        available: None,
        state: None,
        player: Some(PlayerState {
            volume: Some(volume),
            muted: Some(muted),
            static_delay_ms: Some(delay),
            ..PlayerState::default()
        }),
        source: None,
    };
    if let Err(e) = sender.send_message(Message::ClientState(initial)).await {
        log::warn!("Could not report the initial player state: {e}");
    }

    loop {
        tokio::select! {
            msg = messages.recv() => {
                let Some(msg) = msg else { break };
                match msg {
                    // Named `stream` rather than `config`, which is the player's own
                    // configuration in this scope and a different thing entirely.
                    Message::StreamStart(start) => {
                        let Some(stream) = start.player else { continue };
                        log::info!(
                            "Stream starting: {} {}Hz {}ch {}bit",
                            stream.codec, stream.sample_rate, stream.channels, stream.bit_depth
                        );
                        // Every failure below must leave "no decoder, no format" rather than a
                        // stale pairing, which would misdecode the new stream's chunks.
                        decoder = None;
                        format = None;
                        player = None;
                        output_unavailable = false;
                        output_restarts = 0;
                        match build_decoder(&stream) {
                            Ok((built, fmt)) => {
                                decoder = Some(built);
                                status.send_modify(|status| {
                                    status.format = Some(fmt.clone());
                                    status.connection = ConnectionState::Playing;
                                });
                                format = Some(fmt);
                                // Only once per stream: a server may re-send `stream/start` to
                                // change format mid-stream, and an amplifier does not want
                                // waking twice.
                                if !streaming {
                                    streaming = true;
                                    hooks.on_stream_start(&context);
                                }
                            }
                            Err(e) => {
                                log::error!("Cannot play this stream: {e}");
                                status.send_modify(|status| status.last_error = Some(e));
                            }
                        }
                    }
                    Message::StreamEnd(_) => {
                        if let Some(player) = &player {
                            player.clear();
                        }
                        if streaming {
                            streaming = false;
                            hooks.on_stream_stop(&context);
                        }
                    }
                    // A clear drops what is buffered without ending the stream, so it is not a
                    // stop: firing the hook here would shut down an amplifier mid-track.
                    Message::StreamClear(_) => {
                        if let Some(player) = &player {
                            player.clear();
                        }
                    }
                    Message::ServerCommand(command) => {
                        let Some(player_command) = command.player else { continue };
                        // Only a real change counts. A server that re-sends the level it
                        // already set is saying nothing new, and acting on it would re-ramp
                        // the gain and log a line for a setting nobody moved.
                        let mut changed = false;
                        match player_command.command {
                            PlayerCommandType::Volume => {
                                if let Some(level) = player_command.volume {
                                    if level != volume {
                                        volume = level;
                                        changed = true;
                                        log::info!("Volume set to {level}");
                                    }
                                }
                            }
                            PlayerCommandType::Mute => {
                                if let Some(state) = player_command.mute {
                                    if state != muted {
                                        muted = state;
                                        changed = true;
                                        log::info!("Mute set to {state}");
                                    }
                                }
                            }
                            PlayerCommandType::SetStaticDelay => {
                                if let Some(ms) = player_command.static_delay_ms {
                                    if ms != delay {
                                        delay = ms;
                                        if let Some(player) = &player {
                                            player.set_static_delay(ms);
                                        }
                                        log::info!("Static delay set to {ms} ms");
                                    }
                                }
                            }
                            PlayerCommandType::Unknown => {}
                        }
                        // Applied after the match rather than inside it, because volume and
                        // mute reach the same place: either the operator's script owns the
                        // level, or this process's gain does. Never both — that would apply
                        // the setting twice.
                        if changed
                            && matches!(
                                player_command.command,
                                PlayerCommandType::Volume | PlayerCommandType::Mute
                            )
                        {
                            apply_volume(config, player.as_ref(), volume, muted).await;
                            status.send_modify(|status| {
                                status.volume = volume;
                                status.muted = muted;
                            });
                        }

                        // Deliberately no `client/state` in reply. The server already knows
                        // what it asked for, and a server that reconciles the state it
                        // receives by commanding again turns an echo into a loop: this client
                        // reported 100 on connect while the group sat at 12, and the two
                        // chased each other hundreds of times a second. The reference client
                        // does not answer a command either — a client reports state it
                        // changed itself, not state it was told to have.
                    }
                    Message::GroupUpdate(group)
                        if group.playback_state == Some(PlaybackState::Playing) =>
                    {
                        played_anything = true;
                    }
                    _ => {}
                }
            }
            chunk = audio.recv() => {
                let Some(chunk) = chunk else { break };
                let (Some(decoder), Some(fmt)) = (decoder.as_ref(), format.as_ref()) else {
                    // Audio before `stream/start` has no format to be read with. Dropping it
                    // is right, and saying so is what tells an operator why it is silent.
                    log::debug!("Dropping a chunk that arrived before stream/start");
                    continue;
                };
                let samples = match decoder.decode(&chunk.data) {
                    Ok(samples) => samples,
                    Err(e) => {
                        log::warn!("Dropping an undecodable chunk: {e}");
                        continue;
                    }
                };
                if output_unavailable {
                    continue;
                }
                if player.is_none() {
                    // Built on the first chunk rather than on `stream/start`, so a stream that
                    // is announced but never carries audio does not open the device.
                    match SyncedPlayer::new(
                        fmt.clone(),
                        Arc::clone(&clock_sync),
                        SyncedPlayerConfig {
                            // Unity whenever something else owns the level — a script or the
                            // card's own mixer — or the attenuation would land twice.
                            volume: if external_volume { 100 } else { volume },
                            muted: !external_volume && muted,
                            device: output_device.clone(),
                            ..SyncedPlayerConfig::new()
                        },
                    ) {
                        Ok(built) => {
                            built.set_static_delay(delay);
                            log::info!("Audio output open");
                            player = Some(built);
                        }
                        Err(e) => {
                            log::error!("Could not open the audio output: {e}");
                            status.send_modify(|status| status.last_error = Some(e.to_string()));
                            output_unavailable = true;
                            continue;
                        }
                    }
                }
                let Some(active) = player.as_ref() else {
                    continue;
                };
                played_anything = true;
                active.enqueue(AudioBuffer {
                    timestamp: chunk.timestamp,
                    samples,
                    format: fmt.clone(),
                });
                let failure = active.take_error();

                // A card that reports a fault has stopped: everything enqueued after it is
                // played by nobody, so this reopens rather than only complaining. CoreAudio
                // raises "Device sample rate changed" the first time a device is opened at a
                // rate it was not already running — our own change, handed back as a fault —
                // and the reopen then succeeds against a card already at the new rate.
                if let Some(e) = failure {
                    const MAX_OUTPUT_RESTARTS: u8 = 3;
                    player = None;
                    status.send_modify(|status| status.last_error = Some(e.clone()));
                    if output_restarts < MAX_OUTPUT_RESTARTS {
                        output_restarts += 1;
                        log::warn!(
                            "Audio output error: {e}. Reopening the device \
                             ({output_restarts}/{MAX_OUTPUT_RESTARTS})"
                        );
                    } else {
                        // Repeated failure is a card that cannot play this stream, not a rate
                        // change settling. Stop until the next `stream/start` offers a new one.
                        output_unavailable = true;
                        log::error!(
                            "Audio output error: {e}. Reopened {MAX_OUTPUT_RESTARTS} times \
                             without it holding; staying silent until the next stream"
                        );
                    }
                }
            }
            else => break,
        }
    }
    // A server that disappears mid-stream never sends `stream/end`, and an amplifier left
    // powered because the network dropped is exactly what the stop hook is for.
    if streaming {
        hooks.on_stream_stop(&context);
    }
    status.send_modify(|status| {
        status.connection = ConnectionState::Disconnected;
        status.server_id = None;
        status.server_name = None;
        status.format = None;
    });
    played_anything
}

/// The level to start from: the card's, where a mixer is driving it, and full otherwise.
fn starting_volume(config: &PlayerConfig) -> (u8, bool) {
    #[cfg(all(feature = "hardware-volume", target_os = "linux"))]
    if let Some(mixer) = &config.mixer {
        match mixer.read() {
            Ok((volume, muted)) => {
                log::info!("Hardware volume starts at {volume}% (muted: {muted})");
                return (volume, muted);
            }
            // Not fatal: the level is still settable, this only means the initial report is a
            // guess rather than a reading.
            Err(e) => log::warn!("Could not read the hardware volume: {e}"),
        }
    }
    let _ = config;
    (100, false)
}

/// Whether something other than this process's own gain owns the level.
fn volume_is_elsewhere(config: &PlayerConfig) -> bool {
    if config.hooks.volume_is_external() {
        return true;
    }
    #[cfg(all(feature = "hardware-volume", target_os = "linux"))]
    if config.mixer.is_some() {
        return true;
    }
    false
}

/// Put `volume` and `muted` wherever this daemon's level actually lives.
///
/// Exactly one of the three owns it, which is the point: a script, the sound card, or this
/// process's own gain. Applying it in two places attenuates twice, and the second one is
/// inaudible in the wrong direction.
async fn apply_volume(
    config: &PlayerConfig,
    player: Option<&SyncedPlayer>,
    volume: u8,
    muted: bool,
) {
    if config.hooks.volume_is_external() {
        config.hooks.set_volume(volume, muted).await;
        return;
    }

    #[cfg(all(feature = "hardware-volume", target_os = "linux"))]
    if let Some(mixer) = config.mixer.clone() {
        // On a blocking thread: ALSA's mixer calls are synchronous, and one that stalls on a
        // USB card being re-plugged must not stall the runtime the audio path shares.
        let result = tokio::task::spawn_blocking(move || mixer.set(volume, muted)).await;
        match result {
            Ok(Ok(())) => {}
            Ok(Err(e)) => log::warn!("Could not set the hardware volume: {e}"),
            Err(e) => log::warn!("The hardware volume task failed: {e}"),
        }
        return;
    }

    if let Some(player) = player {
        player.set_volume(volume);
        player.set_mute(muted);
    }
}

/// Build the decoder a `stream/start` calls for, or say why this stream cannot be played.
fn build_decoder(
    config: &crate::protocol::messages::StreamPlayerConfig,
) -> Result<(Box<dyn Decoder>, AudioFormat), String> {
    use base64::prelude::{Engine as _, BASE64_STANDARD};

    let codec = match config.codec.as_str() {
        "pcm" => Codec::Pcm,
        "opus" => Codec::Opus,
        "flac" => Codec::Flac,
        other => return Err(format!("codec {other:?} is not one this client advertised")),
    };
    if config.bit_depth != 16 && config.bit_depth != 24 {
        return Err(format!("bit depth {} is not 16 or 24", config.bit_depth));
    }
    // FLAC carries `fLaC` plus STREAMINFO here, base64 in the message and raw to the decoder.
    let header = match config.codec_header.as_deref() {
        Some(b64) => Some(
            BASE64_STANDARD
                .decode(b64)
                .map_err(|e| format!("codec header is not valid base64: {e}"))?,
        ),
        None => None,
    };
    let decoder: Box<dyn Decoder> = match codec {
        Codec::Pcm => Box::new(PcmDecoder::with_endian(config.bit_depth, PcmEndian::Little)),
        Codec::Opus => Box::new(
            OpusDecoder::new(config.sample_rate, config.channels)
                .map_err(|e| format!("Opus stream format is not usable: {e}"))?,
        ),
        Codec::Flac => Box::new(match header.as_deref() {
            Some(header) => FlacDecoder::with_header(header)
                .map_err(|e| format!("FLAC codec header is not usable: {e}"))?,
            None => FlacDecoder::new(),
        }),
        other => return Err(format!("codec {other:?} has no decoder here")),
    };
    Ok((
        decoder,
        AudioFormat {
            codec,
            sample_rate: config.sample_rate,
            channels: config.channels,
            bit_depth: config.bit_depth,
            codec_header: header,
        },
    ))
}
