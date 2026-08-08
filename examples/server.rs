// ABOUTME: Runs the Sendspin server so a real client can be pointed at it, which is the only
// ABOUTME: way to find out whether the server half reads the spec the same way.

//! A minimal Sendspin server.
//!
//! ```text
//! cargo run --features server --example server -- --port 8927
//! ```
//!
//! Then point `aiosendspin`'s own client at it — see `scripts/interop/reference_client.py`.
//! It accepts connections, completes the encrypted handshake, exchanges hellos and answers
//! clock requests. No roles and no audio yet, deliberately.

use clap::Parser;
use sendspin::noise::Identity;
use sendspin::server::{SendspinServer, ServerConfig};

#[derive(Parser, Debug)]
#[command(about = "Run a Sendspin server", long_about = None)]
struct Args {
    /// Address to bind.
    #[arg(long, default_value = "127.0.0.1:8927")]
    bind: String,

    /// Friendly name sent in `server/hello`.
    #[arg(long, default_value = "Rust Interop Server")]
    name: String,

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
    let config = ServerConfig::new(identity, args.name.clone());
    let server = SendspinServer::bind(&args.bind, config).await?;

    println!("SERVER_ID={}", server.server_id());
    println!("URL=ws://{}/sendspin", server.local_addr()?);
    println!("READY");

    server.serve_forever().await?;
    Ok(())
}
