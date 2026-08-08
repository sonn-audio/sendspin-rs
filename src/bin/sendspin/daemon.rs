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
use sendspin::protocol::client::{AudioChunk, WsSender};
use sendspin::protocol::manager::ConnectionManager;
use sendspin::protocol::messages::{
    ClientState, Message, PlaybackState, PlayerCommandType, PlayerState,
};
use sendspin::ProtocolClientBuilder;

use crate::cli::{default_product_name, hostname, DaemonArgs};

/// Run the daemon until the process is stopped.
pub async fn run(args: DaemonArgs) -> Result<(), Box<dyn std::error::Error>> {
    let static_delay = args.static_delay()?;
    let name = args.name.clone().unwrap_or_else(hostname);
    let client_id = args
        .id
        .clone()
        .unwrap_or_else(|| format!("sendspin-rs-{}", hostname()));
    let product_name = args
        .product_name
        .clone()
        .unwrap_or_else(default_product_name);

    log::info!("Client id: {client_id}");
    log::info!("Name: {name}");
    // Said once, plainly, because it decides which servers this daemon can reach: a server
    // with `allow_unencrypted` off refuses the cleartext hello outright. Turning it on needs
    // an identity that survives a restart — under the encrypted transport the `client_id` *is*
    // the public half of that key — so it waits on a settings directory to keep one in.
    log::warn!(
        "Running in transition mode: no Noise layer. Servers that require the encrypted \
         transport will refuse this connection."
    );

    match args.url.clone() {
        Some(url) => {
            run_outbound(&args, &url, &name, &client_id, &product_name, static_delay).await
        }
        None => run_inbound(&args, &name, &client_id, &product_name, static_delay).await,
    }
}

/// Build a client template carrying everything a server learns about this device in
/// `client/hello`. Shared by both directions so the two cannot drift.
fn template(
    name: &str,
    client_id: &str,
    product_name: &str,
    manufacturer: Option<&str>,
) -> ProtocolClientBuilder {
    ProtocolClientBuilder::builder()
        .client_id(client_id.to_string())
        .name(name.to_string())
        .product_name(Some(product_name.to_string()))
        // Passed unconditionally rather than behind an `if`: each setter moves the builder to
        // a new type, so a conditional one would need both branches to agree on it.
        .manufacturer(manufacturer.map(str::to_string))
        .build()
}

/// Dial a named server and play whatever it sends, until it goes away.
async fn run_outbound(
    args: &DaemonArgs,
    url: &str,
    name: &str,
    client_id: &str,
    product_name: &str,
    static_delay: u16,
) -> Result<(), Box<dyn std::error::Error>> {
    log::info!("Connecting to {url}");
    let client = template(name, client_id, product_name, args.manufacturer.as_deref())
        .connect(url)
        .await?;
    let hello = client.server_hello().clone();
    log::info!(
        "Connected to {} ({}), roles {:?}",
        hello.name,
        hello.server_id,
        hello.active_roles
    );

    let conn = client.split();
    play(
        conn.messages,
        conn.audio,
        conn.clock_sync,
        conn.sender,
        static_delay,
    )
    .await;
    log::info!("Server closed the connection");
    Ok(())
}

/// Listen for servers, advertise over mDNS, and serve whichever connection wins arbitration.
///
/// The manager owns the accept loop and the keep-or-switch policy; this only has to play what
/// the winner sends and be ready for the next one, because a server going away is ordinary.
async fn run_inbound(
    args: &DaemonArgs,
    name: &str,
    client_id: &str,
    product_name: &str,
    static_delay: u16,
) -> Result<(), Box<dyn std::error::Error>> {
    let bind = args.bind_address();
    let listener = template(name, client_id, product_name, args.manufacturer.as_deref())
        .listen(&bind)
        .await?;
    let port = listener.local_addr()?.port();
    let mut manager = ConnectionManager::new(listener);

    // Withdrawn on drop, so a daemon that exits stops being advertised. A stale record is
    // worse than none: a server dials it, fails, and retries.
    let _advertisement =
        sendspin::protocol::discovery::ClientAdvertisement::new(client_id, name, port)
            .inspect_err(|e| log::error!("Could not advertise over mDNS: {e}"))
            .ok();
    if args.interface.is_some() {
        log::warn!(
            "--interface restricts the listening socket only; the mDNS advertisement still \
             goes out on every interface"
        );
    }
    log::info!("Listening on {bind}, advertising _sendspin._tcp.local. as {name:?}");

    while let Some(conn) = manager.next_connection().await {
        let server_id = conn.server_hello.server_id.clone();
        log::info!(
            "Serving {server_id} from {} (reason {:?})",
            conn.peer,
            conn.server_hello.connection_reason
        );
        let played = play(
            conn.messages,
            conn.audio,
            conn.clock_sync,
            conn.sender,
            static_delay,
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
    static_delay: u16,
) -> bool {
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
                            }
                            Err(e) => log::error!("Cannot play this stream: {e}"),
                        }
                    }
                    Message::StreamEnd(_) | Message::StreamClear(_) => {
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
                                    if let Some(player) = &player {
                                        player.set_volume(level);
                                    }
                                    log::info!("Volume set to {level}");
                                }
                            }
                            PlayerCommandType::Mute => {
                                if let Some(state) = player_command.mute {
                                    muted = state;
                                    if let Some(player) = &player {
                                        player.set_mute(state);
                                    }
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
                            SyncedPlayerConfig { volume, muted, ..SyncedPlayerConfig::new() },
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
