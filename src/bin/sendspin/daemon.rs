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
use crate::hooks::{HookContext, Hooks};

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
    /// The single format offered to the server, when `--audio-format` pinned one.
    ///
    /// Pinning narrows `client/hello` to one entry rather than reordering a list, because a
    /// server picks from what it is offered: an operator who names a format wants that format,
    /// not a preference the server may overrule.
    format: Option<sendspin::protocol::messages::AudioFormatSpec>,
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

    let device = Device {
        name,
        client_id,
        product_name,
        manufacturer: args.manufacturer.clone(),
        encryption,
        static_delay,
        device,
        format,
        hooks,
    };

    match args.url.clone() {
        Some(url) => run_outbound(&args, &url, &device).await,
        None => run_inbound(&args, &device).await,
    }
}

/// Build a client template carrying everything a server learns about this device in
/// `client/hello`. Shared by both directions so the two cannot drift.
fn template(device: &Device) -> ProtocolClientBuilder {
    ProtocolClientBuilder::builder()
        .client_id(device.client_id.clone())
        .name(device.name.clone())
        .player_v1_support(player_support(device.format.as_ref()))
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

/// What this client tells a server it can decode.
///
/// With no `--audio-format` this is the full set the decoders implement, in the order this
/// client would rather have them: Opus for bandwidth, then PCM. With one, it is that alone.
fn player_support(
    pinned: Option<&sendspin::protocol::messages::AudioFormatSpec>,
) -> sendspin::protocol::messages::PlayerV1Support {
    use sendspin::protocol::messages::{AudioFormatSpec, PlayerV1Support};

    let supported_formats = match pinned {
        Some(format) => vec![format.clone()],
        None => vec![
            AudioFormatSpec {
                codec: "opus".to_string(),
                channels: 2,
                sample_rate: 48_000,
                bit_depth: 16,
            },
            AudioFormatSpec {
                codec: "flac".to_string(),
                channels: 2,
                sample_rate: 48_000,
                bit_depth: 24,
            },
            AudioFormatSpec {
                codec: "pcm".to_string(),
                channels: 2,
                sample_rate: 48_000,
                bit_depth: 24,
            },
            AudioFormatSpec {
                codec: "pcm".to_string(),
                channels: 2,
                sample_rate: 48_000,
                bit_depth: 16,
            },
        ],
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
    let mut played_anything = false;
    // Held outside the player: a volume command can arrive before a stream does, and the
    // setting has to survive until there is something to apply it to.
    let mut volume = 100u8;
    let mut muted = false;
    let mut delay = static_delay;

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
                        match player_command.command {
                            PlayerCommandType::Volume => {
                                if let Some(level) = player_command.volume {
                                    volume = level;
                                    log::info!("Volume set to {level}");
                                }
                            }
                            PlayerCommandType::Mute => {
                                if let Some(state) = player_command.mute {
                                    muted = state;
                                    log::info!("Mute set to {state}");
                                }
                            }
                            PlayerCommandType::SetStaticDelay => {
                                if let Some(ms) = player_command.static_delay_ms {
                                    delay = ms;
                                    if let Some(player) = &player {
                                        player.set_static_delay(ms);
                                    }
                                    log::info!("Static delay set to {ms} ms");
                                }
                            }
                            PlayerCommandType::Unknown => {}
                        }
                        // Applied after the match rather than inside it, because volume and
                        // mute reach the same place: either the operator's script owns the
                        // level, or this process's gain does. Never both — that would apply
                        // the setting twice.
                        if matches!(
                            player_command.command,
                            PlayerCommandType::Volume | PlayerCommandType::Mute
                        ) {
                            if hooks.volume_is_external() {
                                hooks.set_volume(volume, muted).await;
                            } else if let Some(player) = &player {
                                player.set_volume(volume);
                                player.set_mute(muted);
                            }
                        }

                        // A command is only obeyed if the server can see it was: the spec has
                        // the client report its own state rather than the server assuming.
                        let state = ClientState {
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
                        if let Err(e) = sender.send_message(Message::ClientState(state)).await {
                            log::warn!("Could not report player state: {e}");
                        }
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
                let player = match player.as_ref() {
                    Some(player) => player,
                    None => {
                        // Built on the first chunk rather than on `stream/start`, so a stream
                        // that is announced but never carries audio does not open the device.
                        match SyncedPlayer::new(
                            fmt.clone(),
                            Arc::clone(&clock_sync),
                            SyncedPlayerConfig {
                                // Unity when a script owns the level, or the attenuation
                                // would land twice.
                                volume: if hooks.volume_is_external() { 100 } else { volume },
                                muted: !hooks.volume_is_external() && muted,
                                device: output_device.clone(),
                                ..SyncedPlayerConfig::new()
                            },
                        ) {
                            Ok(built) => {
                                built.set_static_delay(delay);
                                log::info!("Audio output open");
                                player.insert(built)
                            }
                            Err(e) => {
                                log::error!("Could not open the audio output: {e}");
                                output_unavailable = true;
                                continue;
                            }
                        }
                    }
                };
                played_anything = true;
                player.enqueue(AudioBuffer {
                    timestamp: chunk.timestamp,
                    samples,
                    format: fmt.clone(),
                });
                if let Some(e) = player.take_error() {
                    log::error!("Audio output error: {e}");
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
