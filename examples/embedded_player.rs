// ABOUTME: Being a player from an application's point of view: build a config, run it, and
// ABOUTME: watch what it does — using the library alone, with no help from the `sendspin` binary.

//! An embedded player.
//!
//! This is the shape an application takes when it wants to *be* a Sendspin player rather than
//! speak the protocol by hand: choose an output, describe the client, run it, and watch its
//! status to show the user what is happening.
//!
//! ```sh
//! cargo run --example embedded_player -- --server ws://127.0.0.1:8927/sendspin
//! ```
//!
//! Nothing here comes from `src/bin`. If it ever needs to, the player is not a library.

use clap::Parser;
use sendspin::audio::devices::{find_device, output_rates};
use sendspin::noise::trust_store::PairingConfig;
use sendspin::noise::Identity;
use sendspin::player::{Player, PlayerConfig};
use sendspin::protocol::client::EncryptionSettings;

#[derive(Parser, Debug)]
#[command(about = "Play from a Sendspin server, using the library directly", long_about = None)]
struct Args {
    /// WebSocket URL of the server.
    #[arg(short, long, default_value = "ws://127.0.0.1:8927/sendspin")]
    server: String,

    /// Friendly name to introduce this player as.
    #[arg(short, long, default_value = "Embedded Player")]
    name: String,

    /// Output device, by index or name. Omit for the platform default.
    #[arg(long)]
    audio_device: Option<String>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("warn")).init();
    let args = Args::parse();

    let device = args.audio_device.as_deref().map(find_device).transpose()?;

    // Generated per run, so this example leaves nothing behind. A real device persists its
    // key — the identity *is* the client's name to a server, and one that changes every start
    // is a new client every start, with whatever pairing it had left behind.
    let identity = Identity::generate()?;
    let mut config = PlayerConfig::new(identity.client_id(), args.name.clone());
    // Speaking the encrypted transport, which is what the spec asks for and what a server may
    // require. `EncryptionSettings::unpaired` keeps the trust store in memory: enough to reach
    // a server that allows unpaired access, and deliberately not enough to remember a pairing.
    let encryption = EncryptionSettings::unpaired(identity)?;
    // Admit a server this player has never paired with. Off by default, and rightly so — an
    // unpaired session is authenticated by nothing — but a demonstration that refuses every
    // server until someone completes a pairing demonstrates very little.
    encryption.store.set_pairing_config(PairingConfig {
        unpaired_access: true,
        ..encryption.store.pairing_config()?
    })?;
    config.encryption = Some(encryption);
    // Offer what this card can actually open, so a server that resamples only when it must can
    // leave a matching source alone.
    config.rates = output_rates(device.as_ref());
    config.device = device;

    let player = Player::new(config);

    // The status is a `watch` channel: this observer can be as slow as it likes without ever
    // holding up the session, and it sees the current value the moment it subscribes.
    let mut status = player.status();
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
                        " stream={:?} {}Hz {}ch {}bit",
                        format.codec, format.sample_rate, format.channels, format.bit_depth
                    );
                }
                print!(
                    " volume={}{}",
                    now.volume,
                    if now.muted { " muted" } else { "" }
                );
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

    // `None` returns when the connection ends; a `Some(interval)` would keep redialling, which
    // is what a dedicated appliance wants.
    player.run_outbound(&args.server, None).await?;
    Ok(())
}
