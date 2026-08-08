// ABOUTME: Runs the Sendspin server so a real client can be pointed at it, which is the only
// ABOUTME: way to find out whether the server half reads the spec the same way.

//! A minimal Sendspin server.
//!
//! ```text
//! cargo run -p sendspin-server --example server -- --bind 127.0.0.1:8927
//! ```
//!
//! Then point `aiosendspin`'s own client at it — see `scripts/interop/reference_client.py`.
//! It accepts connections, completes the encrypted handshake, exchanges hellos and answers
//! clock requests. No roles and no audio yet, deliberately.

use std::sync::Arc;

use clap::Parser;
use parking_lot::Mutex;
use sendspin::noise::Identity;
use sendspin::protocol::messages::StreamPlayerConfig;
use sendspin_server::{AudioSource, SendspinServer, ServerConfig};

/// A 440 Hz tone, for a server that has to play *something* to be worth pointing a client at.
///
/// Deliberately generated rather than read from a file: both ends of an interop run can then
/// state the same expected frame count without shipping a fixture.
struct Tone {
    sample_rate: u32,
    channels: u8,
    /// Frames left to produce, or `None` for a tone that never ends.
    remaining: Mutex<Option<u64>>,
    phase: Mutex<f32>,
}

impl AudioSource for Tone {
    fn format(&self) -> StreamPlayerConfig {
        StreamPlayerConfig {
            codec: "pcm".to_string(),
            sample_rate: self.sample_rate,
            channels: self.channels,
            bit_depth: 16,
            codec_header: None,
        }
    }

    fn next_chunk(&self, frames: usize) -> Option<Vec<u8>> {
        let mut remaining = self.remaining.lock();
        let frames = match remaining.as_mut() {
            Some(0) => return None,
            Some(left) => {
                let take = frames.min(usize::try_from(*left).unwrap_or(frames));
                *left -= take as u64;
                take
            }
            None => frames,
        };

        let mut phase = self.phase.lock();
        let step = std::f32::consts::TAU * 440.0 / self.sample_rate as f32;
        let mut pcm = Vec::with_capacity(frames * usize::from(self.channels) * 2);
        for _ in 0..frames {
            let sample = ((phase.sin() * 0.2) * f32::from(i16::MAX)) as i16;
            for _ in 0..self.channels {
                pcm.extend_from_slice(&sample.to_le_bytes());
            }
            *phase += step;
        }
        Some(pcm)
    }
}

#[derive(Parser, Debug)]
#[command(about = "Run a Sendspin server", long_about = None)]
struct Args {
    /// Address to bind.
    #[arg(long, default_value = "127.0.0.1:8927")]
    bind: String,

    /// Friendly name sent in `server/hello`.
    #[arg(long, default_value = "Rust Interop Server")]
    name: String,

    /// Play a 440 Hz tone to any client that activates `player@v1`, for this many seconds.
    ///
    /// 0 plays nothing, which is what the handshake-only interop check wants; a negative value
    /// plays until the client leaves.
    #[arg(long, default_value_t = 0.0)]
    pub tone_secs: f64,

    /// Byte to fill a deterministic private key with, so `server_id` is stable across runs.
    ///
    /// Only for interop testing. A real server generates its identity once and persists it;
    /// a fixed key is exactly what you must not ship.
    #[arg(long)]
    seed: Option<u8>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let args = Args::parse();

    let identity = match args.seed {
        Some(byte) => Identity::from_private_key([byte; 32]),
        None => Identity::generate()?,
    };
    let mut config = ServerConfig::new(identity, args.name.clone());
    if args.tone_secs != 0.0 {
        let sample_rate = 48_000u32;
        let remaining = if args.tone_secs < 0.0 {
            None
        } else {
            Some((args.tone_secs * f64::from(sample_rate)) as u64)
        };
        config = config.with_audio(Arc::new(Tone {
            sample_rate,
            channels: 2,
            remaining: Mutex::new(remaining),
            phase: Mutex::new(0.0),
        }));
        println!("TONE_SECONDS={}", args.tone_secs);
    }
    let server = SendspinServer::bind(&args.bind, config).await?;

    println!("SERVER_ID={}", server.server_id());
    println!("URL=ws://{}/sendspin", server.local_addr()?);
    println!("READY");

    server.serve_forever().await?;
    Ok(())
}
