// ABOUTME: Being a source from an application's point of view: capture a real input, stream it
// ABOUTME: when the server asks, and decide for yourself whether there is signal on the line.

//! An embedded source.
//!
//! ```sh
//! cargo run --example embedded_source -- --server ws://127.0.0.1:8927/sendspin --capture-device 0
//! ```
//!
//! Nothing here comes from `src/bin`.
//!
//! ## The signal policy is this example's, not the library's
//!
//! `line_sense` says whether anything is actually playing into the input, and only this end can
//! know. The crate deliberately does not decide it, and neither does the reference
//! implementation's source client — both report what the application tells them. So the policy
//! below is a choice, made here where it is visible:
//!
//! - Compare a short window's peak against a threshold, not a single sample: one loud sample in
//!   a quiet passage is not a signal, and one quiet sample in a loud one is not silence.
//! - Two thresholds rather than one. Rising through the upper one means present; falling below
//!   the lower one means absent; between them nothing changes. A single threshold makes a
//!   passage sitting near it flap between states several times a second.
//! - Wait before declaring absence. Music has rests, and a source that reports silence during
//!   one invites a server to drop it mid-track.
//!
//! Every one of those numbers is an installation's business — a turntable's noise floor is not
//! a capture card's — which is exactly why they are not in the library.

use std::time::{Duration, Instant};

use clap::Parser;
use sendspin::audio::devices::{find_input_device, input_devices};
use sendspin::noise::trust_store::PairingConfig;
use sendspin::noise::Identity;
use sendspin::protocol::client::EncryptionSettings;
use sendspin::protocol::messages::SourceSignal;
use sendspin::source::{Source, SourceConfig};

/// Peak level, 0.0 to 1.0, at or above which the line counts as carrying audio.
const PRESENT_ABOVE: f32 = 0.02;
/// Peak level below which it counts as quiet. Lower than `PRESENT_ABOVE` on purpose.
const ABSENT_BELOW: f32 = 0.01;
/// How long the line has to stay quiet before absence is reported.
const QUIET_BEFORE_ABSENT: Duration = Duration::from_secs(3);

#[derive(Parser, Debug)]
#[command(about = "Stream a capture device to a Sendspin server, using the library directly", long_about = None)]
struct Args {
    /// WebSocket URL of the server.
    #[arg(short, long, default_value = "ws://127.0.0.1:8927/sendspin")]
    server: String,

    /// Friendly name to introduce this source as.
    #[arg(short, long, default_value = "Embedded Source")]
    name: String,

    /// Capture device, by index or name. Omit for the platform default input.
    #[arg(long)]
    capture_device: Option<String>,

    /// List the capture devices this machine has, and exit.
    #[arg(long)]
    list_capture_devices: bool,

    /// Sample rate to capture at.
    #[arg(long, default_value_t = 48_000)]
    sample_rate: u32,

    /// Channel count to capture.
    #[arg(long, default_value_t = 2)]
    channels: u8,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let args = Args::parse();

    if args.list_capture_devices {
        for device in input_devices()? {
            match device.description {
                Some(description) => println!("  [{}] {} — {description}", device.index, device.id),
                None => println!("  [{}] {}", device.index, device.id),
            }
        }
        return Ok(());
    }

    let device = args
        .capture_device
        .as_deref()
        .map(find_input_device)
        .transpose()?;

    let identity = Identity::generate()?;
    let encryption = EncryptionSettings::unpaired(identity.clone())?;
    encryption.store.set_pairing_config(PairingConfig {
        unpaired_access: true,
        ..encryption.store.pairing_config()?
    })?;

    let config = SourceConfig {
        device,
        sample_rate: args.sample_rate,
        channels: args.channels,
        encryption: Some(encryption),
        // Advertised because this example does report it. A source that claims the feature and
        // never calls `set_signal` leaves the server waiting on a promise.
        line_sense: true,
        ..SourceConfig::new(identity.client_id(), args.name.clone())
    };

    let source = Source::new(config);

    let mut status = source.status();
    tokio::spawn(async move {
        loop {
            {
                let now = status.borrow_and_update();
                print!("[{:?}]", now.connection);
                if let Some(name) = &now.server_name {
                    print!(" server={name}");
                }
                if let Some(format) = &now.format {
                    print!(
                        " sending={} {}Hz {}ch {}bit",
                        format.codec, format.sample_rate, format.channels, format.bit_depth
                    );
                }
                if let Some(signal) = &now.signal {
                    print!(" signal={signal:?}");
                }
                if let Some(error) = &now.last_error {
                    print!(" last_error={error:?}");
                }
                println!();
            }
            if status.changed().await.is_err() {
                break;
            }
        }
    });

    // The policy lives here, fed by the level the library measures. This is the whole point of
    // the split: the crate says how loud the input is, the application says what that means.
    let mut levels = source.levels();
    let signals = source.signal_reporter();
    tokio::spawn(async move {
        let mut gate = SignalGate::new();
        while levels.changed().await.is_ok() {
            let peak = *levels.borrow_and_update();
            if let Some(signal) = gate.observe(peak, Instant::now()) {
                signals.report(signal);
            }
        }
    });

    source.run_outbound(&args.server, None).await?;
    Ok(())
}

/// One window's worth of level, turned into a decision.
///
/// Kept as a type so the hysteresis is one thing that can be tested rather than three
/// conditions spread through a loop.
#[derive(Debug)]
struct SignalGate {
    present: bool,
    quiet_since: Option<Instant>,
}

impl SignalGate {
    fn new() -> Self {
        Self {
            present: false,
            quiet_since: None,
        }
    }

    /// Feed one window's peak level, and get back a state to report when it changed.
    fn observe(&mut self, peak: f32, now: Instant) -> Option<SourceSignal> {
        if peak >= PRESENT_ABOVE {
            self.quiet_since = None;
            if !self.present {
                self.present = true;
                return Some(SourceSignal::Present);
            }
            return None;
        }
        if peak < ABSENT_BELOW && self.present {
            let since = *self.quiet_since.get_or_insert(now);
            if now.duration_since(since) >= QUIET_BEFORE_ABSENT {
                self.present = false;
                self.quiet_since = None;
                return Some(SourceSignal::Absent);
            }
        }
        None
    }
}
