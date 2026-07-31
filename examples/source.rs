// ABOUTME: End-to-end source@v1 example
// ABOUTME: Streams a synthesised tone to the server on demand, with level and line-sense reporting

//! A source is a player in reverse: the server tells it when to capture, and it
//! sends timestamped audio upstream for the server to resample, mix and
//! distribute. This example uses a sine generator rather than a sound card so it
//! runs anywhere, and mirrors the reference CLI's `--input sine` mode.
//!
//! ```sh
//! RUST_LOG=info cargo run --example source -- --server ws://localhost:8927/sendspin
//! ```

use clap::Parser;
use sendspin::protocol::messages::{
    Message, SourceClientCommandType, SourceCommandType, SourceFeatures, SourceFormat,
    SourceSignal, SourceState, SourceStateType, SourceV1Support,
};
use sendspin::ProtocolClientBuilder;
use std::f64::consts::TAU;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Sendspin source client
#[derive(Parser, Debug)]
#[command(name = "source")]
#[command(about = "Stream a test tone to a Sendspin server as a source@v1 client", long_about = None)]
struct Args {
    /// WebSocket URL of the Sendspin server
    #[arg(short, long, default_value = "ws://localhost:8927/sendspin")]
    server: String,

    /// Client name
    #[arg(short, long, default_value = "Sendspin-RS Source")]
    name: String,

    /// Client ID (random UUID when omitted)
    #[arg(short = 'i', long = "id")]
    id: Option<String>,

    /// Tone frequency in Hz
    #[arg(long, default_value_t = 440.0)]
    tone_hz: f64,

    /// Frame size in milliseconds
    #[arg(long, default_value_t = 20)]
    frame_ms: u64,

    /// Stream without waiting for the server to ask (for servers that only select
    /// a source once it reports audio)
    #[arg(long)]
    start_streaming: bool,
}

const SAMPLE_RATE: u32 = 48_000;
const CHANNELS: u8 = 2;
const BIT_DEPTH: u8 = 16;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    let args = Args::parse();
    let client_id = args.id.unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

    let format = SourceFormat {
        codec: "pcm".to_string(),
        channels: CHANNELS,
        sample_rate: SAMPLE_RATE,
        bit_depth: BIT_DEPTH,
    };

    println!("Connecting to {}...", args.server);
    let client = ProtocolClientBuilder::builder()
        .client_id(client_id)
        .name(args.name)
        .source_v1_support(SourceV1Support {
            supported_formats: vec![format.clone()],
            controls: None,
            features: Some(SourceFeatures {
                level: Some(true),
                line_sense: Some(true),
            }),
        })
        // A source reports state from its first message, the way a player does.
        .initial_source_state(SourceState {
            state: SourceStateType::Idle,
            level: Some(0.0),
            signal: Some(SourceSignal::Unknown),
        })
        .build()
        .connect(&args.server)
        .await?;
    println!("Connected as {:?}", client.server_hello().active_roles);

    let connection = client.split();
    let mut messages = connection.messages;
    let clock_sync = connection.clock_sync;
    let sender = connection.sender;
    let _guard = connection.guard;

    let mut streaming = args.start_streaming;
    if streaming {
        start_stream(&sender, &format).await?;
    }

    let frame_samples = (SAMPLE_RATE as u64 * args.frame_ms / 1000) as usize;
    let phase_step = TAU * args.tone_hz / SAMPLE_RATE as f64;
    let mut phase = 0.0f64;
    let mut ticker = tokio::time::interval(Duration::from_millis(args.frame_ms));

    loop {
        tokio::select! {
            message = messages.recv() => {
                let Some(message) = message else { break };
                match message {
                    Message::ServerTime(server_time) => {
                        let t4 = now_micros();
                        clock_sync.lock().update(
                            server_time.client_transmitted,
                            server_time.server_received,
                            server_time.server_transmitted,
                            t4,
                        );
                    }
                    Message::ServerCommand(command) => {
                        let Some(source) = command.source else { continue };
                        if let Some(vad) = source.vad {
                            println!("VAD settings: {:?}", vad);
                        }
                        if let Some(control) = source.control {
                            // A real source would forward this to whatever device is
                            // wired to the input.
                            println!("Control for the attached device: {:?}", control);
                        }
                        match source.command {
                            Some(SourceCommandType::Start) if !streaming => {
                                println!("Server asked us to start");
                                start_stream(&sender, &format).await?;
                                streaming = true;
                            }
                            Some(SourceCommandType::Stop) if streaming => {
                                println!("Server asked us to stop");
                                streaming = false;
                                sender.send_input_stream_end().await?;
                                sender.send_source_state(SourceState {
                                    state: SourceStateType::Idle,
                                    level: Some(0.0),
                                    signal: Some(SourceSignal::Absent),
                                }).await?;
                                sender.send_source_event(SourceClientCommandType::Stopped).await?;
                            }
                            _ => {}
                        }
                    }
                    Message::InputStreamRequestFormat(request) => {
                        // This example only produces one format; re-announcing the
                        // stream is the honest answer, not silently ignoring it.
                        println!("Server requested {:?}; keeping ours", request.source);
                        start_stream(&sender, &format).await?;
                    }
                    other => println!("Message: {:?}", other),
                }
            }
            _ = ticker.tick() => {
                if !streaming {
                    continue;
                }
                // Capture time in the *server's* clock. While the filter is still
                // settling there is no conversion yet, so there is nothing worth
                // sending: a frame stamped with local time would never line up.
                let Some(server_us) = clock_sync.lock().client_to_server_micros(now_micros()) else {
                    continue;
                };
                let frame = tone_frame(&mut phase, phase_step, frame_samples);
                sender.send_source_audio(server_us, &frame).await?;
            }
        }
    }

    Ok(())
}

async fn start_stream(
    sender: &sendspin::WsSender,
    format: &SourceFormat,
) -> Result<(), Box<dyn std::error::Error>> {
    sender
        .send_input_stream_start(sendspin::protocol::messages::InputStreamSource {
            codec: format.codec.clone(),
            channels: format.channels,
            sample_rate: format.sample_rate,
            bit_depth: format.bit_depth,
            codec_header: None,
        })
        .await?;
    sender
        .send_source_state(SourceState {
            state: SourceStateType::Streaming,
            level: Some(0.5),
            signal: Some(SourceSignal::Present),
        })
        .await?;
    sender
        .send_source_event(SourceClientCommandType::Started)
        .await?;
    Ok(())
}

/// One frame of 16-bit little-endian interleaved stereo.
fn tone_frame(phase: &mut f64, phase_step: f64, samples: usize) -> Vec<u8> {
    let amplitude = 0.3 * f64::from(i16::MAX);
    let mut out = Vec::with_capacity(samples * usize::from(CHANNELS) * 2);
    for _ in 0..samples {
        let sample = (amplitude * phase.sin()) as i16;
        *phase += phase_step;
        if *phase > TAU {
            *phase -= TAU;
        }
        for _ in 0..CHANNELS {
            out.extend_from_slice(&sample.to_le_bytes());
        }
    }
    out
}

fn now_micros() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_micros() as i64)
        .unwrap_or_default()
}
