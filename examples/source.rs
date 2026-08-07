// ABOUTME: A source@v1 client: captures a local input and streams it to the server,
// ABOUTME: which resamples, mixes and distributes it to players.

//! A minimal `source@v1` client.
//!
//! A source is a player in reverse. The role is deliberately small: the client advertises at
//! most that it can sense signal, the server drives capture with `server/command`, and the
//! client announces its format in `client_stream/start` before the first chunk. There is no
//! format negotiation — the server takes whatever a source announces and transcodes centrally.
//!
//! This example synthesizes a tone rather than opening a capture device, so it runs anywhere.

use clap::Parser;
use sendspin::protocol::messages::{ClientStreamSource, ClientStreamStart};
use sendspin::protocol::messages::{
    Message, SourceCommandType, SourceFeatures, SourceSignal, SourceState, SourceV1Support,
};
use sendspin::{ProtocolClientBuilder, WsSender};

#[derive(Parser, Debug)]
#[command(about = "Stream a local input to a Sendspin server", long_about = None)]
struct Args {
    /// WebSocket URL of the server.
    #[arg(short, long, default_value = "ws://localhost:8927/sendspin")]
    server: String,

    /// Client name.
    #[arg(short, long, default_value = "Rust Line-In")]
    name: String,
}

const SAMPLE_RATE: u32 = 48_000;
const CHANNELS: u8 = 2;
const BIT_DEPTH: u8 = 16;
/// 20 ms of audio per chunk.
const FRAMES_PER_CHUNK: usize = (SAMPLE_RATE as usize) / 50;

fn format() -> ClientStreamSource {
    ClientStreamSource {
        codec: "pcm".to_string(),
        channels: CHANNELS,
        sample_rate: SAMPLE_RATE,
        bit_depth: BIT_DEPTH,
        // PCM needs no header; FLAC would carry fLaC + STREAMINFO here.
        codec_header: None,
    }
}

async fn start_stream(sender: &WsSender) -> Result<(), Box<dyn std::error::Error>> {
    sender
        .send_message(Message::ClientStreamStart(ClientStreamStart {
            source: format(),
        }))
        .await?;
    sender
        .send_source_state(SourceState {
            signal: Some(SourceSignal::Present),
        })
        .await?;
    println!("stream started");
    Ok(())
}

async fn stop_stream(sender: &WsSender) -> Result<(), Box<dyn std::error::Error>> {
    sender.send_client_stream_end().await?;
    sender
        .send_source_state(SourceState {
            signal: Some(SourceSignal::Absent),
        })
        .await?;
    println!("stream ended");
    Ok(())
}

/// One 20 ms chunk of a 440 Hz tone, interleaved stereo, little-endian 16-bit.
fn tone_chunk(phase: &mut f32) -> Vec<u8> {
    let mut pcm = Vec::with_capacity(FRAMES_PER_CHUNK * CHANNELS as usize * 2);
    let step = std::f32::consts::TAU * 440.0 / SAMPLE_RATE as f32;
    for _ in 0..FRAMES_PER_CHUNK {
        let sample = ((phase.sin() * 0.2) * i16::MAX as f32) as i16;
        for _ in 0..CHANNELS {
            pcm.extend_from_slice(&sample.to_le_bytes());
        }
        *phase += step;
    }
    pcm
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    let args = Args::parse();

    let client = ProtocolClientBuilder::builder()
        .client_id(uuid::Uuid::new_v4().to_string())
        .name(args.name.clone())
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

    println!("connected to {}", client.server_hello().name);

    let conn = client.split();
    let mut messages = conn.messages;
    let clock_sync = conn.clock_sync;
    let sender = conn.sender;
    let _guard = conn.guard;

    let mut streaming = false;
    let mut phase = 0.0f32;
    let mut ticker = tokio::time::interval(tokio::time::Duration::from_millis(20));

    loop {
        tokio::select! {
            msg = messages.recv() => {
                let Some(msg) = msg else { break };
                if let Message::ServerCommand(command) = msg {
                    let Some(source) = command.source else { continue };
                    match source.command {
                        // Both commands are idempotent by spec: a start while already
                        // streaming must not restart the stream.
                        SourceCommandType::Start if !streaming => {
                            start_stream(&sender).await?;
                            streaming = true;
                        }
                        SourceCommandType::Stop if streaming => {
                            stop_stream(&sender).await?;
                            streaming = false;
                        }
                        _ => {}
                    }
                }
            }
            _ = ticker.tick() => {
                if !streaming {
                    continue;
                }
                // Capture time goes out in the *server's* clock. While the filter is still
                // settling there is no conversion yet, and a frame stamped with local time
                // would never line up, so there is nothing worth sending.
                let capture_us = clock_sync.lock().clock().now_micros();
                let Some(server_us) = clock_sync.lock().client_to_server_micros(capture_us) else {
                    continue;
                };
                sender.send_source_audio(server_us, &tone_chunk(&mut phase)).await?;
            }
        }
    }
    Ok(())
}
