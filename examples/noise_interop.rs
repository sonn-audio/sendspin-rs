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
//! ```

use clap::Parser;
use futures_util::{SinkExt, StreamExt};
use sendspin::noise::wire::Reassembler;
use sendspin::noise::{CipherSuite, ClientHandshake, HandshakeStep, Identity, Psk};
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
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    let args = Args::parse();
    let suite = match args.suite.as_str() {
        "aes" | "aesgcm" | "25519_AESGCM_SHA256" => CipherSuite::AesGcm,
        _ => CipherSuite::ChaChaPoly,
    };

    let identity = Identity::generate()?;
    println!("client_id : {}", identity.client_id());
    println!("suite     : {}", suite.as_wire_str());

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
