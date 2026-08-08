// ABOUTME: Runs the Noise handshake against a real Sendspin server and reports what
// ABOUTME: happened, so the encrypted transport is validated against the reference.

//! Interop check for the encrypted transport.
//!
//! Loopback tests prove this crate's two halves agree with each other. They cannot prove
//! the spec is being read the same way the reference implementation reads it — the
//! prologue byte-for-byte, the `psk_id` derivation, the cleartext framing, the point at
//! which the socket switches to binary. This example answers that by driving a handshake
//! against an actual server and printing each step.
//!
//! ```text
//! cargo run --example noise_interop -- --server ws://127.0.0.1:8927/sendspin
//! cargo run --example noise_interop -- --full   # whole client, not just the handshake
//! ```

use clap::Parser;
use futures_util::{SinkExt, StreamExt};
use sendspin::noise::trust_store::{
    psk_to_wire, InMemoryPairingStore, PairingConfig, PairingStore,
};
use sendspin::noise::wire::Reassembler;
use sendspin::noise::{CipherSuite, ClientHandshake, HandshakeStep, Identity, Psk};
use sendspin::protocol::client::{Encryption, EncryptionSettings};
use std::sync::Arc;
use tokio_tungstenite::tungstenite::Message as WsMessage;

#[derive(Parser, Debug)]
#[command(about = "Validate the Noise handshake against a Sendspin server", long_about = None)]
struct Args {
    /// WebSocket URL of the server.
    #[arg(short, long, default_value = "ws://127.0.0.1:8927/sendspin")]
    server: String,

    /// Cipher suite to announce.
    #[arg(long, default_value = "chacha")]
    suite: String,

    /// Seconds to keep reading encrypted frames after the handshake.
    #[arg(long, default_value = "5")]
    listen_secs: u64,

    /// Drive the whole ProtocolClient over the encrypted transport, rather than only the
    /// handshake: client/hello, server/activate, clock sync and role messages included.
    #[arg(long)]
    full: bool,

    /// Byte to fill a deterministic private key with, so client_id is stable across runs.
    ///
    /// Only for interop testing — a real client generates its identity once and persists
    /// it. A fixed key is exactly what you must not ship.
    #[arg(long)]
    seed: Option<u8>,

    /// Codec the source streams: `pcm`, `flac` or `opus`.
    ///
    /// The server transcodes centrally, so this is the source's choice alone — which makes
    /// it the one knob that decides whether the encoders are exercised at all.
    #[arg(long, default_value = "pcm")]
    codec: String,

    /// Drive the `source@v1` role: pair, reconnect on the long-term PSK, then stream
    /// captured audio up to the server when it asks for it.
    ///
    /// The role is pairing-gated — a server will not activate it on a Sentinel-keyed
    /// connection — so this implies the pairing flow and needs `PAIR_WITH` on the server.
    #[arg(long)]
    source: bool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    let args = Args::parse();
    let suite = match args.suite.as_str() {
        "aes" | "aesgcm" | "25519_AESGCM_SHA256" => CipherSuite::AesGcm,
        _ => CipherSuite::ChaChaPoly,
    };

    let identity = match args.seed {
        Some(byte) => Identity::from_private_key([byte; 32]),
        None => Identity::generate()?,
    };
    println!("client_id : {}", identity.client_id());
    println!("suite     : {}", suite.as_wire_str());

    if args.source {
        return run_source_client(&args, identity, suite).await;
    }
    if args.full {
        return run_full_client(&args, identity, suite).await;
    }

    let (mut ws, _) = tokio_tungstenite::connect_async(&args.server).await?;
    println!("connected : {}", args.server);

    // A client with no pairing record offers only the Sentinel PSK, which is what a
    // server keys a first connection with.
    let (mut handshake, client_init) =
        ClientHandshake::start(identity, suite, vec![Psk::sentinel()])?;
    println!("--> client/init ({} bytes)", client_init.len());
    ws.send(WsMessage::text(String::from_utf8(client_init)?))
        .await?;

    let mut result = None;
    while let Some(frame) = ws.next().await {
        let frame = frame?;
        let raw = match &frame {
            // Cleartext handshake messages are text frames.
            WsMessage::Text(t) => t.as_bytes().to_vec(),
            WsMessage::Close(c) => {
                println!("<-- close: {c:?}");
                println!("\nFAILED: server closed during the handshake");
                return Ok(());
            }
            WsMessage::Ping(_) | WsMessage::Pong(_) => continue,
            WsMessage::Binary(b) => {
                println!(
                    "<-- unexpected binary frame during handshake ({} bytes)",
                    b.len()
                );
                break;
            }
            other => {
                println!("<-- unexpected frame: {other:?}");
                break;
            }
        };
        let preview = String::from_utf8_lossy(&raw);
        let preview = preview.chars().take(160).collect::<String>();
        println!("<-- {preview}");

        match handshake.handle_message(&raw) {
            Ok(HandshakeStep::Continue { send }) => {
                if let Some(bytes) = send {
                    println!("--> ({} bytes)", bytes.len());
                    ws.send(WsMessage::text(String::from_utf8(bytes)?)).await?;
                }
            }
            Ok(HandshakeStep::Complete { send, result: done }) => {
                println!("--> noise/handshake msg2 ({} bytes)", send.len());
                ws.send(WsMessage::text(String::from_utf8(send)?)).await?;
                result = Some(done);
                break;
            }
            Err(e) => {
                println!("\nFAILED at handshake step: {e}");
                return Ok(());
            }
        }
    }

    let Some(mut done) = result else {
        println!("\nFAILED: handshake never completed");
        return Ok(());
    };

    println!("\nHANDSHAKE OK");
    println!("  server_id    : {}", done.server_id);
    println!("  psk          : {:?} ({})", done.psk_category, done.psk_id);
    println!("  transport    : {}", done.session.in_transport_mode());

    // Everything from here is a binary frame carrying a Noise ciphertext. Decrypting the
    // server's first message is the real proof: it means both sides derived the same
    // transport keys from the same prologue and PSK.
    println!("\nreading encrypted frames for {}s...", args.listen_secs);
    let mut reasm = Reassembler::new();
    let deadline = tokio::time::Instant::now() + tokio::time::Duration::from_secs(args.listen_secs);
    let mut decrypted_count = 0usize;

    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        let next = match tokio::time::timeout(remaining, ws.next()).await {
            Err(_) => break,
            Ok(None) => {
                println!("socket closed by server");
                break;
            }
            Ok(Some(frame)) => frame?,
        };
        match next {
            WsMessage::Binary(bytes) => match done.session.decrypt(&bytes) {
                Ok(plaintext) => match reasm.accept(&plaintext) {
                    Ok(Some(frame)) => {
                        decrypted_count += 1;
                        let body = if frame.msg_type == 0 {
                            String::from_utf8_lossy(&frame.payload)
                                .chars()
                                .take(220)
                                .collect::<String>()
                        } else {
                            format!("<{} bytes>", frame.payload.len())
                        };
                        println!("  DECRYPTED type={} {}", frame.msg_type, body);
                    }
                    Ok(None) => println!("  (fragment buffered)"),
                    Err(e) => {
                        println!("  framing error: {e}");
                        break;
                    }
                },
                Err(e) => {
                    println!("  DECRYPT FAILED: {e}");
                    break;
                }
            },
            WsMessage::Close(c) => {
                println!("  close: {c:?}");
                break;
            }
            WsMessage::Ping(_) | WsMessage::Pong(_) => {}
            other => println!("  unexpected frame after handshake: {other:?}"),
        }
    }

    println!();
    if decrypted_count > 0 {
        println!("INTEROP OK: {decrypted_count} encrypted message(s) decrypted from the reference server");
    } else {
        println!("handshake succeeded but no application message was decrypted");
    }
    Ok(())
}

/// Drive `source@v1` against the reference server.
///
/// The role is pairing-gated, and a server filters it out of `active_roles` on a
/// Sentinel-keyed connection. So this runs the flow a real source runs: connect once to
/// pair, come back on the long-term PSK, and only then expect the role. What it proves that
/// a loopback test cannot is that the reference *decodes* what this client packs — the
/// chunk header, binary type 12, and the server-clock timestamp.
async fn run_source_client(
    args: &Args,
    identity: Identity,
    suite: CipherSuite,
) -> Result<(), Box<dyn std::error::Error>> {
    use sendspin::audio::SourceCapture;
    use sendspin::protocol::messages::{
        ClientStreamSource, GoodbyeReason, Message, SourceCommandType, SourceFeatures,
        SourceSignal, SourceState, SourceV1Support,
    };
    use sendspin::ProtocolClientBuilder;

    const SAMPLE_RATE: u32 = 48_000;
    const CHANNELS: u8 = 2;
    const BIT_DEPTH: u8 = 16;
    /// 20 ms of audio fed to the encoder per tick.
    const FRAMES_PER_TICK: usize = (SAMPLE_RATE as usize) / 50;

    // The capture helper owns the timeline: anchor once, advance by sample count, and
    // subtract the codec's lookahead. Doing that here instead would be duplicating the one
    // piece of arithmetic a source most needs the library to get right.
    let mut capture = SourceCapture::new(&args.codec, SAMPLE_RATE, BIT_DEPTH, CHANNELS)?;
    let codec_header = capture.codec_header();
    println!("codec     : {}", args.codec);

    let store = build_pairing_store(args)?;

    // Pass 1: pair. The server re-handshakes onto a long-term PSK and this client
    // persists a record bound to the server's id.
    println!("\n=== pass 1: pairing ===");
    let paired_settings = encryption_settings(&identity, &store, suite);
    let pairing_client = ProtocolClientBuilder::builder()
        .client_id(identity.client_id())
        .name("Rust Interop Source".to_string())
        .encryption(Encryption::Enabled(paired_settings))
        .source_v1_support(SourceV1Support {
            features: Some(SourceFeatures {
                line_sense: Some(true),
            }),
        })
        .initial_source_state(SourceState {
            signal: Some(SourceSignal::Absent),
        })
        .build()
        .connect(&args.server)
        .await?;
    println!(
        "  roles     : {:?}",
        pairing_client.server_hello().active_roles
    );

    let conn = pairing_client.split();
    let deadline = tokio::time::Instant::now() + tokio::time::Duration::from_secs(args.listen_secs);
    while tokio::time::Instant::now() < deadline && store.records()?.is_empty() {
        tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;
    }
    let records = store.records()?;
    println!("  records   : {}", records.len());
    conn.guard.disconnect(GoodbyeReason::Restart).await?;
    if records.is_empty() {
        println!("\nFAILED: never paired, so source@v1 can never activate");
        println!("        (start the server with PAIR_WITH=<client_id>:<pairing_psk>)");
        return Ok(());
    }

    // Pass 2: reconnect on the long-term PSK. Only now can the role activate.
    println!("\n=== pass 2: source@v1 on the long-term PSK ===");
    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
    let client = ProtocolClientBuilder::builder()
        .client_id(identity.client_id())
        .name("Rust Interop Source".to_string())
        .encryption(Encryption::Enabled(encryption_settings(
            &identity, &store, suite,
        )))
        .source_v1_support(SourceV1Support {
            features: Some(SourceFeatures {
                line_sense: Some(true),
            }),
        })
        .initial_source_state(SourceState {
            signal: Some(SourceSignal::Absent),
        })
        .build()
        .connect(&args.server)
        .await?;

    let active = client.server_hello().active_roles.clone();
    println!("  roles     : {active:?}");
    let activated = active.iter().any(|r| r == "source@v1");
    if !activated {
        println!("\nFAILED: server did not activate source@v1 on a paired connection");
        return Ok(());
    }

    let conn = client.split();
    let mut messages = conn.messages;
    let clock_sync = conn.clock_sync;
    let sender = conn.sender;

    let mut streaming = false;
    let mut phase = 0.0f32;
    let mut chunks_sent = 0usize;
    let mut bytes_sent = 0usize;
    let mut skipped_unsynced = 0usize;
    let mut saw_start = false;
    let mut saw_stop = false;
    let mut ticker = tokio::time::interval(tokio::time::Duration::from_millis(20));

    println!("\nstreaming for up to {}s...", args.listen_secs);
    let deadline = tokio::time::Instant::now() + tokio::time::Duration::from_secs(args.listen_secs);
    loop {
        if tokio::time::Instant::now() >= deadline {
            break;
        }
        tokio::select! {
            _ = tokio::time::sleep_until(deadline) => break,
            msg = messages.recv() => {
                let Some(msg) = msg else {
                    println!("  message stream ended");
                    break;
                };
                let Message::ServerCommand(command) = msg else { continue };
                let Some(source) = command.source else { continue };
                match source.command {
                    // Both commands are idempotent by spec: a start while already
                    // streaming must not restart the stream.
                    SourceCommandType::Start if !streaming => {
                        saw_start = true;
                        println!("  <-- server/command start");
                        sender
                            .send_client_stream_start(ClientStreamSource {
                                codec: args.codec.clone(),
                                channels: CHANNELS,
                                sample_rate: SAMPLE_RATE,
                                bit_depth: BIT_DEPTH,
                                // FLAC carries STREAMINFO here; PCM and Opus need none.
                                codec_header: codec_header.clone(),
                            })
                            .await?;
                        sender
                            .send_source_state(SourceState { signal: Some(SourceSignal::Present) })
                            .await?;
                        println!(
                            "  --> client_stream/start ({} 48000/16/2, header {})",
                            args.codec,
                            codec_header.as_ref().map_or(0, String::len)
                        );
                        streaming = true;
                    }
                    SourceCommandType::Stop if streaming => {
                        saw_stop = true;
                        println!("  <-- server/command stop");
                        // Flush before the end marker: a codec with a fixed frame size is
                        // still holding the tail, and dropping it loses real audio.
                        for (timestamp_us, frame) in capture.finish()? {
                            bytes_sent += frame.len();
                            sender.send_source_audio(timestamp_us, &frame).await?;
                            chunks_sent += 1;
                        }
                        sender.send_client_stream_end().await?;
                        sender
                            .send_source_state(SourceState { signal: Some(SourceSignal::Absent) })
                            .await?;
                        println!("  --> client_stream/end after {chunks_sent} chunks");
                        // The stop is the last thing this check needs; anything further
                        // would only be idle time.
                        break;
                    }
                    _ => {}
                }
            }
            _ = ticker.tick() => {
                if !streaming {
                    continue;
                }
                // Capture time goes out in the *server's* clock. Until the filter has
                // converged there is no conversion, and a frame stamped with local time
                // would never line up, so there is nothing worth sending.
                let capture_us = clock_sync.lock().clock().now_micros();
                let Some(server_us) = clock_sync.lock().client_to_server_micros(capture_us) else {
                    skipped_unsynced += 1;
                    continue;
                };
                let pcm = tone_chunk(&mut phase, SAMPLE_RATE, CHANNELS, FRAMES_PER_TICK);
                for (timestamp_us, frame) in capture.feed(&pcm, server_us)? {
                    bytes_sent += frame.len();
                    sender.send_source_audio(timestamp_us, &frame).await?;
                    chunks_sent += 1;
                }
            }
        }
    }

    println!("\nserver/command start : {saw_start}");
    println!("server/command stop  : {saw_stop}");
    println!("chunks sent          : {chunks_sent} ({bytes_sent} bytes)");
    println!("skipped pre-sync     : {skipped_unsynced}");

    println!();
    if saw_start && chunks_sent > 0 {
        println!("SOURCE INTEROP OK: role activated, capture streamed to the reference server");
        println!("  check the server log for SOURCE_INTEROP_OK and the decoded byte count");
    } else if saw_start {
        println!("FAILED: stream started but no chunk was ever sent (clock sync never converged?)");
    } else {
        println!("FAILED: server never asked this source to start");
    }
    Ok(())
}

/// A pairing store seeded so the harness can be told which key to pair with.
///
/// Real clients keep one CSPRNG key for the life of the device; a deterministic one exists
/// here only so `PAIR_WITH` on the server side has something to name.
fn build_pairing_store(args: &Args) -> Result<Arc<dyn PairingStore>, Box<dyn std::error::Error>> {
    let pairing_psk = args.seed.map(|byte| [byte ^ 0xA5; 32]);
    let config = match pairing_psk {
        Some(psk) => PairingConfig {
            pairing_psk: Some(psk),
            unpaired_access: true,
            record_mode_psk_id: None,
            ..PairingConfig::disabled()
        },
        None => PairingConfig::generate()?,
    };
    if let Some(psk) = pairing_psk {
        println!("pairing_psk: {}", psk_to_wire(&psk));
    }
    Ok(Arc::new(InMemoryPairingStore::with_config(config)))
}

/// Encryption settings sharing one store, so a second connection sees the record the
/// first one persisted.
fn encryption_settings(
    identity: &Identity,
    store: &Arc<dyn PairingStore>,
    suite: CipherSuite,
) -> EncryptionSettings {
    let mut settings = EncryptionSettings::with_store(identity.clone(), Arc::clone(store));
    settings.suite = suite;
    settings
}

/// One 20 ms chunk of a 440 Hz tone, interleaved, little-endian 16-bit.
fn tone_chunk(phase: &mut f32, sample_rate: u32, channels: u8, frames: usize) -> Vec<u8> {
    let mut pcm = Vec::with_capacity(frames * channels as usize * 2);
    let step = std::f32::consts::TAU * 440.0 / sample_rate as f32;
    for _ in 0..frames {
        let sample = ((phase.sin() * 0.2) * f32::from(i16::MAX)) as i16;
        for _ in 0..channels {
            pcm.extend_from_slice(&sample.to_le_bytes());
        }
        *phase += step;
    }
    pcm
}

/// Bring up a complete client over the encrypted transport and watch what the server
/// sends. This exercises the paths the handshake-only check cannot reach: the shrunk
/// `server/hello`, `client/hello` going out encrypted, `server/activate`, and the clock
/// sync that follows.
async fn run_full_client(
    args: &Args,
    identity: Identity,
    suite: CipherSuite,
) -> Result<(), Box<dyn std::error::Error>> {
    use sendspin::ProtocolClientBuilder;

    let store = build_pairing_store(args)?;
    let settings = encryption_settings(&identity, &store, suite);

    let client = ProtocolClientBuilder::builder()
        .client_id(identity.client_id())
        .name("Rust Interop Client".to_string())
        .encryption(Encryption::Enabled(settings))
        .build()
        .connect(&args.server)
        .await?;

    let hello = client.server_hello().clone();
    println!("\nCLIENT UP");
    println!("  server    : {} ({})", hello.name, hello.server_id);
    println!("  version   : {}", hello.version);
    println!("  roles     : {:?}", hello.active_roles);
    println!("  reason    : {:?}", hello.connection_reason);

    let conn = client.split();
    let mut messages = conn.messages;
    let clock_sync = conn.clock_sync;
    let _guard = conn.guard;

    println!("\nwatching messages for {}s...", args.listen_secs);
    let deadline = tokio::time::Instant::now() + tokio::time::Duration::from_secs(args.listen_secs);
    let mut seen = 0usize;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        match tokio::time::timeout(remaining, messages.recv()).await {
            Err(_) => break,
            Ok(None) => {
                println!("  message stream ended");
                break;
            }
            Ok(Some(msg)) => {
                seen += 1;
                println!("  {msg:?}");
            }
        }
    }

    let synced = clock_sync.lock().is_synchronized();
    println!("\nmessages seen : {seen}");
    println!("clock synced  : {synced}");

    let records = store.records()?;
    println!("pairing records: {}", records.len());
    for record in &records {
        println!(
            "  {} -> {}",
            record.psk_id(),
            record.server_id().unwrap_or("<shared>")
        );
    }
    if records.is_empty() {
        println!("\nFULL CLIENT INTEROP OK: encrypted connection came up end to end");
    } else {
        println!("\nPAIRING INTEROP OK: paired and persisted a long-term record");
    }
    Ok(())
}
