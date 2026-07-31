# sendspin-rs
=======

> [!WARNING]  
> THIS IS A WIP. Please help!

Hyper-efficient Rust implementation of the [Sendspin Protocol](https://github.com/Sendspin/spec) for synchronized multi-room audio streaming.

## Features

- **Zero-copy audio pipeline** - Minimal allocations, maximum performance
- **Lock-free concurrency** - No contention on audio thread
- **Async I/O** - Efficient WebSocket handling with Tokio
- **Type-safe protocol** - Leverage Rust's type system for correctness
- **Source role** - Stream a local audio input *to* the server (`source@v1`)

## Performance Targets

- Audio latency: <10ms end-to-end jitter
- CPU usage: <2% on modern hardware (4-core)
- Memory: <20MB stable
- Thread synchronization: Lock-free audio pipeline

## Current Status

**Phase 1: Foundation** ✅ (Complete)
- Core audio types (Sample, AudioFormat, AudioBuffer)
- Protocol message types with serde serialization
- WebSocket client with handshake
- PCM decoder (16-bit and 24-bit)
- Clock synchronization (NTP-style)

**Phase 2: Audio Pipeline** 🚧 (Next)
- Audio output (cpal integration)
- Lock-free scheduler
- End-to-end player


## Installing build dependencies

### Debian/Ubuntu/Mint

```
sudo apt install libasound2-dev
```

### Fedora/Centos

```
dnf install alsa-lib-devel
```

## Quick Start

Add to your `Cargo.toml`:

```toml
[dependencies]
sendspin = "0.1"
```

### Basic Client Example

```rust
use sendspin::ProtocolClientBuilder;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = ProtocolClientBuilder::builder()
        .client_id(uuid::Uuid::new_v4().to_string())
        .name("My Player".to_string())
        .build()
        .connect("ws://localhost:8080/sendspin")
        .await?;

    // Client is now connected and ready to receive audio

    Ok(())
}
```

See `examples/` directory for more examples.

## Sources (`source@v1`)

A source is a player in reverse: it captures a local input — line-in, a turntable
preamp, an HDMI capture card — and streams it to the server, which does the
resampling, mixing and distribution. The device stays simple.

```rust
let client = ProtocolClientBuilder::builder()
    .client_id("kitchen-linein".to_string())
    .name("Kitchen Line-In".to_string())
    .source_v1_support(SourceV1Support {
        supported_formats: vec![SourceFormat {
            codec: "pcm".to_string(), channels: 2, sample_rate: 48_000, bit_depth: 16,
        }],
        controls: None,
        features: Some(SourceFeatures { level: Some(true), line_sense: Some(true) }),
    })
    .initial_source_state(SourceState {
        state: SourceStateType::Idle, level: Some(0.0), signal: Some(SourceSignal::Unknown),
    })
    .build()
    .connect(url)
    .await?;
```

The server drives capture with `server/command` (`start`/`stop`, optional signal
thresholds, and transport controls for the attached device). Each stream is
announced with `input_stream/start` before its first frame, so a format change is
a stream boundary rather than something the server has to infer:

```rust
sender.send_input_stream_start(InputStreamSource { /* codec, rate, depth */ }).await?;
sender.send_source_state(SourceState { state: SourceStateType::Streaming, .. }).await?;

// Capture timestamps go out in the *server's* clock.
let server_us = clock_sync.lock().client_to_server_micros(capture_us).unwrap();
sender.send_source_audio(server_us, &pcm_frame).await?;
```

Level and signal presence (`line_sense`) let a source whose activation is local —
nobody can start a turntable remotely — tell the server the user has begun
playing, via `send_source_event`. See `examples/source.rs` for a complete client.

## Architecture

See [docs/rust-thoughts.md](docs/rust-thoughts.md) for detailed architecture and implementation notes.

## Development

```bash
# Build
cargo build

# Run tests
cargo test

# Run examples
cargo run --example basic_client

# Build with optimizations
cargo build --release
```

### Verification (cargo-make)

```bash
# Install cargo-make (one time)
cargo install cargo-make

# Run the full verification suite
cargo make verify
```

`cargo make verify` runs: tests, Clippy, doc build, doctests, and formatting checks.

## Testing

```bash
# Run all tests
cargo test

# Run specific test
cargo test test_sample_from_i16

# Run with logging
RUST_LOG=debug cargo test
```

## License

MIT OR Apache-2.0

## Contributing

Contributions welcome! Please open an issue or PR.
