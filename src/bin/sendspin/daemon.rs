// ABOUTME: The headless player: bring a connection up either direction, then decode and play
// ABOUTME: what arrives on it until the server goes away.

//! `sendspin daemon`.
//!
//! Two ways in, and the choice is the operator's: `--url` dials a server, and its absence
//! listens for one and advertises over mDNS. Everything after the connection is the same, so
//! the playback loop is written once and handed whichever connection won.

use std::sync::Arc;

use sendspin::audio::decode::{Decoder, FlacDecoder, OpusDecoder, PcmDecoder, PcmEndian};
use sendspin::audio::{AudioBuffer, AudioFormat, Codec, SyncedPlayer, SyncedPlayerConfig};
use sendspin::noise::file_store::{load_or_create_identity, FilePairingStore};
use sendspin::noise::trust_store::{PairingConfig, PairingStore};
use sendspin::protocol::client::{AudioChunk, Encryption, EncryptionSettings, WsSender};
use sendspin::protocol::manager::ConnectionManager;
use sendspin::protocol::messages::{
    ClientState, Message, PlaybackState, PlayerCommandType, PlayerState,
};
use sendspin::ProtocolClientBuilder;

use crate::cli::{default_product_name, hostname, DaemonArgs};
use sendspin::hooks::{HookContext, Hooks};

/// What this daemon presents to a server, resolved once so both directions cannot drift.
struct Device {
    name: String,
    client_id: String,
    product_name: String,
    manufacturer: Option<String>,
    /// `None` in transition mode. Carries the identity and the store together, because the
    /// encrypted transport needs both and neither is any use alone.
    encryption: Option<EncryptionSettings>,
    static_delay: u16,
    /// The chosen output device, or `None` for the platform default.
    device: Option<cpal::Device>,
    /// The operator's external scripts.
    hooks: Hooks,
    /// The card's own volume control, when `--hardware-volume` named one and it opened.
    #[cfg(all(feature = "hardware-volume", target_os = "linux"))]
    mixer: Option<Arc<sendspin::audio::mixer::Mixer>>,
    /// The single format offered to the server, when `--audio-format` pinned one.
    ///
    /// Pinning narrows `client/hello` to one entry rather than reordering a list, because a
    /// server picks from what it is offered: an operator who names a format wants that format,
    /// not a preference the server may overrule.
    format: Option<sendspin::protocol::messages::AudioFormatSpec>,
    /// The sample rates the output device can open, read once at startup.
    ///
    /// Read once rather than per connection: the card does not change while the daemon runs,
    /// and a hello is not the place to discover that it cannot be enumerated.
    rates: Vec<u32>,
}

/// Run the daemon until the process is stopped.
pub async fn run(args: DaemonArgs) -> Result<(), Box<dyn std::error::Error>> {
    let static_delay = args.static_delay()?;
    let name = args.name.clone().unwrap_or_else(hostname);
    let product_name = args
        .product_name
        .clone()
        .unwrap_or_else(default_product_name);

    // Resolved before anything connects: a device that does not exist or a format it cannot
    // play is a startup error next to the flag that caused it, not silence once a server
    // starts sending.
    let device = args
        .audio_device
        .as_deref()
        .map(crate::audio::find_device)
        .transpose()?;
    let format = args
        .audio_format
        .as_deref()
        .map(crate::audio::parse_format)
        .transpose()?;
    if let (Some(device), Some(format)) = (device.as_ref(), format.as_ref()) {
        crate::audio::verify_device_supports(device, format)?;
    }
    let hooks = Hooks::new(
        args.hook_start.clone(),
        args.hook_stop.clone(),
        args.hook_set_volume.as_deref(),
    )?;
    if hooks.volume_is_external() {
        log::info!("Volume is the --hook-set-volume script's; the audio path stays at unity");
    }
    // Underscore-prefixed because without the `hardware-volume` feature there is no field to
    // put it in; `open_mixer` still runs, to report the flag as unavailable rather than
    // ignoring it.
    let _mixer = open_mixer(&args, hooks.volume_is_external())?;
    if let Some(format) = format.as_ref() {
        log::info!(
            "Offering only {}:{}:{}:{}",
            format.codec,
            format.sample_rate,
            format.bit_depth,
            format.channels
        );
    }

    // The encrypted transport decides the `client_id` rather than taking one: it is the public
    // half of the stored keypair. Only transition mode leaves the name to the operator.
    let (client_id, encryption) = if args.no_encryption {
        if args.settings_dir.is_some() {
            log::warn!("--settings-dir is unused with --no-encryption: nothing is persisted");
        }
        let client_id = args
            .id
            .clone()
            .unwrap_or_else(|| format!("sendspin-rs-{}", hostname()));
        log::warn!(
            "Running in transition mode: no Noise layer, and no pairing. A server that \
             requires the encrypted transport will refuse this connection."
        );
        (client_id, None)
    } else {
        let dir = args.settings_dir()?;
        if args.id.is_some() {
            log::warn!(
                "--id is ignored under the encrypted transport: the client_id is the public \
                 half of the identity in {}",
                dir.display()
            );
        }
        let identity = load_or_create_identity(dir.join("identity.key"))?;
        let store = FilePairingStore::open(dir.join("pairing.json"))?;
        let records = store.records()?.len();
        log::info!("Settings: {} ({records} pairing record(s))", dir.display());

        // Written through rather than applied per run, so the choice is the operator's once
        // and not a flag they have to remember on every restart.
        let config = store.pairing_config()?;
        if args.allow_unpaired && !config.unpaired_access {
            store.set_pairing_config(PairingConfig {
                unpaired_access: true,
                ..config
            })?;
            log::info!("Unpaired access enabled and saved");
        } else if !store.pairing_config()?.unpaired_access && records == 0 {
            // Worth saying plainly: with no pairing and no unpaired access, a server activates
            // no roles at all, and a silent player looks like a broken one.
            log::warn!(
                "No pairing yet and unpaired access is off, so no server will activate a \
                 role. Pair this client, or pass --allow-unpaired."
            );
        }
        let mut settings = EncryptionSettings::with_store(identity.clone(), Arc::new(store));
        // The dynamic PIN has to reach the operator through this device, and only the host
        // application knows how. A daemon with no display or speaker has the log and nothing
        // else, so it says so rather than emitting a PIN nobody was told to look for.
        settings.emit_pin = Some(Arc::new(|pin: &str| {
            log::warn!("Pairing PIN (type this into the server): {pin}");
        }));
        (identity.client_id(), Some(settings))
    };

    log::info!("Client id: {client_id}");
    log::info!("Name: {name}");

    let rates = crate::audio::output_rates(device.as_ref());
    if format.is_none() {
        log::info!(
            "Offering: {}",
            rates
                .iter()
                .map(|rate| format!("{rate}Hz"))
                .collect::<Vec<_>>()
                .join(", ")
        );
    }

    let device = Device {
        name,
        client_id,
        product_name,
        manufacturer: args.manufacturer.clone(),
        encryption,
        static_delay,
        device,
        format,
        rates,
        hooks,
        #[cfg(all(feature = "hardware-volume", target_os = "linux"))]
        mixer: _mixer,
    };

    match args.url.clone() {
        Some(url) => run_outbound_forever(&args, &url, &device).await,
        None => run_inbound(&args, &device).await,
    }
}

/// Dial `url`, play, and dial again when the server goes away.
///
/// The loop is the point. A dedicated player is not a program someone is watching: a server
/// that restarts, a switch that reboots, a cable that is nudged — all of them end a connection,
/// and every one of them should cost a few seconds of silence rather than the rest of the
/// evening. `--reconnect-secs 0` opts out, for a foreground run where an exit is wanted.
async fn run_outbound_forever(
    args: &DaemonArgs,
    url: &str,
    device: &Device,
) -> Result<(), Box<dyn std::error::Error>> {
    if args.reconnect_secs == 0 {
        return run_outbound(args, url, device).await;
    }

    let base = std::time::Duration::from_secs(args.reconnect_secs);
    // A minute is long enough that an overnight outage is quiet, and short enough that nobody
    // waits noticeably once the server is back.
    let ceiling = std::time::Duration::from_secs(60);
    let mut wait = base;
    loop {
        match run_outbound(args, url, device).await {
            // A connection that came up and then ended is ordinary; start over at the short
            // delay rather than carrying a backoff earned by an earlier outage.
            Ok(()) => wait = base,
            Err(e) => {
                log::warn!("Connection to {url} failed: {e}");
                wait = (wait * 2).min(ceiling);
            }
        }
        log::info!("Reconnecting to {url} in {}s", wait.as_secs());
        tokio::time::sleep(wait).await;
    }
}

/// Build a client template carrying everything a server learns about this device in
/// `client/hello`. Shared by both directions so the two cannot drift.
fn template(device: &Device) -> ProtocolClientBuilder {
    ProtocolClientBuilder::builder()
        .client_id(device.client_id.clone())
        .name(device.name.clone())
        .player_v1_support(player_support(device.format.as_ref(), &device.rates))
        .product_name(Some(device.product_name.clone()))
        // Passed unconditionally rather than behind an `if`: each setter moves the builder to
        // a new type, so a conditional one would need both branches to agree on it.
        .manufacturer(device.manufacturer.clone())
        .encryption(match &device.encryption {
            Some(settings) => Encryption::Enabled(settings.clone()),
            None => Encryption::Disabled,
        })
        .build()
}

/// Open the card's mixer when `--hardware-volume` asked for one.
///
/// A card with no gain stage is common — plenty of DACs have none — so a mixer that will not
/// open is reported and stepped over rather than fatal: software attenuation still works, and
/// refusing to start would be the wrong trade for a device that can still play.
#[cfg(all(feature = "hardware-volume", target_os = "linux"))]
fn open_mixer(
    args: &DaemonArgs,
    volume_is_external: bool,
) -> Result<Option<Arc<sendspin::audio::mixer::Mixer>>, String> {
    let Some(card) = args.hardware_volume.as_deref() else {
        return Ok(None);
    };
    if volume_is_external {
        log::warn!("--hardware-volume is ignored: --hook-set-volume already owns the level");
        return Ok(None);
    }
    match sendspin::audio::mixer::Mixer::open(card) {
        Ok(mixer) => {
            log::info!("Hardware volume: {} on {}", mixer.element(), mixer.card());
            Ok(Some(Arc::new(mixer)))
        }
        Err(e) => {
            log::warn!("Falling back to software volume: {e}");
            Ok(None)
        }
    }
}

/// Without the feature, the flag is accepted and reported as unavailable rather than rejected:
/// a systemd unit shared across builds should not fail to start on the one built without it.
#[cfg(not(all(feature = "hardware-volume", target_os = "linux")))]
fn open_mixer(args: &DaemonArgs, _volume_is_external: bool) -> Result<Option<()>, String> {
    if args.hardware_volume.is_some() {
        log::warn!(
            "--hardware-volume needs the `hardware-volume` feature on Linux; using software \
             volume instead"
        );
    }
    Ok(None)
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
    pinned: Option<&sendspin::protocol::messages::AudioFormatSpec>,
    rates: &[u32],
) -> sendspin::protocol::messages::PlayerV1Support {
    use sendspin::protocol::messages::{AudioFormatSpec, PlayerV1Support};

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
    _args: &DaemonArgs,
    url: &str,
    device: &Device,
) -> Result<(), Box<dyn std::error::Error>> {
    log::info!("Connecting to {url}");
    let client = template(device).connect(url).await?;
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
        client_id: device.client_id.clone(),
        client_name: device.name.clone(),
    };

    let conn = client.split();
    play(
        conn.messages,
        conn.audio,
        conn.clock_sync,
        conn.sender,
        device,
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
async fn run_inbound(args: &DaemonArgs, device: &Device) -> Result<(), Box<dyn std::error::Error>> {
    let bind = args.bind_address();
    let listener = template(device).listen(&bind).await?;
    let port = listener.local_addr()?.port();
    let mut manager = ConnectionManager::new(listener);

    // Withdrawn on drop, so a daemon that exits stops being advertised. A stale record is
    // worse than none: a server dials it, fails, and retries.
    let _advertisement = sendspin::protocol::discovery::ClientAdvertisement::new(
        &device.client_id,
        &device.name,
        port,
    )
    .inspect_err(|e| log::error!("Could not advertise over mDNS: {e}"))
    .ok();
    if args.interface.is_some() {
        log::warn!(
            "--interface restricts the listening socket only; the mDNS advertisement still \
             goes out on every interface"
        );
    }
    log::info!(
        "Listening on {bind}, advertising _sendspin._tcp.local. as {:?}",
        device.name
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
            client_id: device.client_id.clone(),
            client_name: device.name.clone(),
        };
        let played = play(
            conn.messages,
            conn.audio,
            conn.clock_sync,
            conn.sender,
            device,
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
    clock_sync: Arc<parking_lot::Mutex<sendspin::sync::ClockSync>>,
    sender: WsSender,
    device: &Device,
    context: HookContext,
) -> bool {
    let hooks = &device.hooks;
    let external_volume = volume_is_elsewhere(device);
    let output_device = device.device.clone();
    let static_delay = device.static_delay;
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
    let (mut volume, mut muted) = starting_volume(device);
    let mut delay = static_delay;

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
                    Message::StreamStart(start) => {
                        let Some(config) = start.player else { continue };
                        log::info!(
                            "Stream starting: {} {}Hz {}ch {}bit",
                            config.codec, config.sample_rate, config.channels, config.bit_depth
                        );
                        // Every failure below must leave "no decoder, no format" rather than a
                        // stale pairing, which would misdecode the new stream's chunks.
                        decoder = None;
                        format = None;
                        player = None;
                        output_unavailable = false;
                        output_restarts = 0;
                        match build_decoder(&config) {
                            Ok((built, fmt)) => {
                                decoder = Some(built);
                                format = Some(fmt);
                                // Only once per stream: a server may re-send `stream/start` to
                                // change format mid-stream, and an amplifier does not want
                                // waking twice.
                                if !streaming {
                                    streaming = true;
                                    hooks.on_stream_start(&context);
                                }
                            }
                            Err(e) => log::error!("Cannot play this stream: {e}"),
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
                            apply_volume(device, player.as_ref(), volume, muted).await;
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
    played_anything
}

/// The level to start from: the card's, where a mixer is driving it, and full otherwise.
fn starting_volume(device: &Device) -> (u8, bool) {
    #[cfg(all(feature = "hardware-volume", target_os = "linux"))]
    if let Some(mixer) = &device.mixer {
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
    let _ = device;
    (100, false)
}

/// Whether something other than this process's own gain owns the level.
fn volume_is_elsewhere(device: &Device) -> bool {
    if device.hooks.volume_is_external() {
        return true;
    }
    #[cfg(all(feature = "hardware-volume", target_os = "linux"))]
    if device.mixer.is_some() {
        return true;
    }
    false
}

/// Put `volume` and `muted` wherever this daemon's level actually lives.
///
/// Exactly one of the three owns it, which is the point: a script, the sound card, or this
/// process's own gain. Applying it in two places attenuates twice, and the second one is
/// inaudible in the wrong direction.
async fn apply_volume(device: &Device, player: Option<&SyncedPlayer>, volume: u8, muted: bool) {
    if device.hooks.volume_is_external() {
        device.hooks.set_volume(volume, muted).await;
        return;
    }

    #[cfg(all(feature = "hardware-volume", target_os = "linux"))]
    if let Some(mixer) = device.mixer.clone() {
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
    config: &sendspin::protocol::messages::StreamPlayerConfig,
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
