# sendspin-rs

Hyper-efficient Rust implementation of the [Sendspin Protocol](https://github.com/Sendspin/spec)
for synchronized multi-room audio streaming.

> [!WARNING]
> Pre-1.0 and under active development. The API is not yet stable, and pairing is not
> implemented yet — see [Status](#status).

## What this is

A client library. You bring the application; this crate speaks the protocol, keeps your
clock locked to the server's, and drives the audio device.

- **Lock-free audio path** — decode and playback communicate over lock-free queues, so a
  slow network task cannot stall the audio callback. The callback never allocates, never
  blocks, and never takes a contended lock: clock reads use `try_lock` and skip rather than
  wait.
- **Sample-accurate synchronization** — a two-dimensional Kalman filter over clock offset
  and drift, and a correction planner that holds steady-state error inside the spec's
  ±0.5 ms *target* rather than its ±1 ms floor.
- **Async I/O** — Tokio and `tokio-tungstenite`, with the audio thread deliberately outside
  the runtime.
- **End-to-end encrypted** — the spec's `KKpsk2` Noise transport, in both defined cipher
  suites, validated against the reference implementation's own server.
- **Type-safe protocol** — messages are enums and structs, not maps. Where a server may
  introduce a value this build has not seen, it deserializes to an `Unknown` variant rather
  than failing the message: a client should not throw away a whole `group/update`, or a whole
  handshake, over one field it could have ignored.

## Roles

| Role | Direction | Supported |
| --- | --- | --- |
| `player@v1` | receives audio | Yes — PCM (16/24-bit), FLAC, Opus |
| `artwork@v1` | receives images | Yes — 4 channels |
| `visualizer@v1` | receives analysis | Yes — loudness, beat, f_peak, spectrum, peak, pitch |
| `controller@v1` | sends commands | Yes — full 15-command surface incl. `seek` / `seek_relative` |
| `metadata@v1` | receives track info | Yes |
| `color@v1` | receives palette | Yes |
| `source@v1` | captures and sends audio | Yes — see [Sources](#sources-sourcev1) |

## Status

**Working:** the encrypted `KKpsk2` transport — `client/init`, the Noise handshake, PSK
selection, fragmentation, and `server/activate` — on both cipher suites; the legacy
transition-mode handshake as an opt-out; clock synchronization; all seven roles above;
synchronized playback with drift correction; volume and mute with a perceptual curve and
anti-click ramp; static-delay compensation; both connection directions (client-initiated,
and server-initiated via `ProtocolListener`); and multi-server arbitration by connection
purpose via `ConnectionManager`.

Encryption is verified against `aiosendspin`'s own server rather than only against itself —
see [scripts/interop](scripts/interop). Loopback tests cannot tell you whether the spec is
being read the same way the reference reads it, which is exactly where a transport layer
fails.

**Not implemented:** pairing and everything keyed to it — the trust store, the PSK and PIN
pairing flows, and the `management/*` messages. A client reaches a server today on the
Sentinel PSK, which is what the protocol keys a first connection with; pairing is what
promotes that to a trusted session. The PIN methods additionally need CPace, for which no
usable Rust crate exists.

**Encryption is opt-in for now**, because turning it on changes which servers a client can
reach. Pass it explicitly:

```rust
use sendspin::noise::Identity;
use sendspin::protocol::client::{Encryption, EncryptionSettings};

let identity = Identity::generate()?;   // persist the private key; the public half is the client_id
let client = ProtocolClientBuilder::builder()
    .client_id(identity.client_id())
    .name("My Player".to_string())
    .encryption(Encryption::Enabled(EncryptionSettings::unpaired(identity)))
    .build()
    .connect("ws://localhost:8927/sendspin")
    .await?;
```

**Known divergences,** both deliberate: the visualizer `pitch` type on binary slot 21, which
`aiosendspin` ships and the spec still reserves; and the `client_id` / `version` fields in
`client/hello` plus the legacy `state` enum in `client/state`, which the spec has moved or
dropped but current servers still read. The latter go away with the encrypted transport.

## Performance

The audio path is designed around the protocol's synchronization requirements. Two of these
are enforced in code and covered by tests:

| Bound | Value | Source |
| --- | --- | --- |
| Steady-state sync error | within ±0.5 ms | spec `SHOULD` target (the `MUST` floor is ±1 ms) |
| Effective playback speed | within ±0.5% | spec `MUST` |

These are design targets for resource use, not measured results — no benchmark suite exists
yet, and they should be treated as intent until one does:

- CPU: <2% on a modern 4-core machine
- Memory: <20 MB stable

## Installing build dependencies

ALSA development headers are needed on Linux for `cpal`.

### Debian/Ubuntu/Mint

```
sudo apt install libasound2-dev
```

### Fedora/CentOS

```
dnf install alsa-lib-devel
```

## Quick start

```toml
[dependencies]
sendspin = "0.3"
tokio = { version = "1", features = ["full"] }
```

Connect and complete the handshake:

```rust
use sendspin::ProtocolClientBuilder;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = ProtocolClientBuilder::builder()
        .client_id(uuid::Uuid::new_v4().to_string())
        .name("My Player".to_string())
        .build()
        .connect("ws://localhost:8927/sendspin")
        .await?;

    // Split into the independently-owned halves: message stream, audio frames,
    // clock, and a sender. The guard sends client/goodbye when dropped.
    let conn = client.split();

    Ok(())
}
```

A client that wants audio declares `player@v1_support` and an initial `PlayerState` on the
builder; `examples/player.rs` is the end-to-end version, including handing decoded buffers
to `SyncedPlayer`.

## Examples

```bash
cargo run --example basic_client          # connect and handshake
cargo run --example player                # full synchronized player
cargo run --example controller_only       # send transport commands, no audio
cargo run --example source                # capture a local input and stream it up
cargo run --example server_initiated_metadata  # accept inbound connections, print metadata
cargo run --example minimal_test          # smallest possible client
cargo run --example secure_socket --features native-tls   # wss:// transport
```

All of them take `--server`; pass `--help` for the rest. `RUST_LOG=debug` turns on protocol
tracing, and `RUST_LOG=trace` adds the per-callback sync detail.

## Sources (`source@v1`)

A source is a player in reverse: it captures a local input — line-in, a turntable preamp, an
HDMI capture card — and streams it to the server, which does the resampling, mixing and
distribution. The device stays simple.

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

The server drives capture with `server/command` (`start`/`stop`, optional signal thresholds,
and transport controls for the attached device). Each stream is announced with
`client_stream/start` before its first frame, so a format change is a stream boundary rather
than something the server has to infer:

```rust
sender.send_input_stream_start(InputStreamSource { /* codec, rate, depth */ }).await?;
sender.send_source_state(SourceState { state: SourceStateType::Streaming, .. }).await?;

// Capture timestamps go out in the *server's* clock.
let server_us = clock_sync.lock().client_to_server_micros(capture_us).unwrap();
sender.send_source_audio(server_us, &pcm_frame).await?;
```

Level and signal presence (`line_sense`) let a source whose activation is local — nobody can
start a turntable remotely — tell the server the user has begun playing, via
`send_source_event`. See `examples/source.rs` for a complete client.

`aiosendspin` gained the role in #322, which superseded the earlier #286.

## Architecture

See [docs/rust-thoughts.md](docs/rust-thoughts.md) for design notes.

The short version: `ProtocolClient` owns the WebSocket and, on `split()`, hands back a
`Connection` of independent parts — a message stream, a decoded-audio channel, a shared
`ClockSync`, a `WsSender`, and a `ConnectionGuard` that says goodbye on drop. `SyncedPlayer`
owns the output device and the correction loop, and is fed decoded `AudioBuffer`s.

## Development

```bash
cargo build
cargo test
cargo build --release
```

### Verification (cargo-make)

```bash
cargo install cargo-make   # one time
cargo make verify
```

`cargo make verify` runs tests, Clippy, the doc build, doctests, and formatting checks.
Run it before opening a PR — CI runs the same set.

```bash
cargo test correction          # filter by name
RUST_LOG=debug cargo test      # with logging
```

## License

MIT OR Apache-2.0

## Contributing

Contributions welcome. Please open an issue or PR. If a change touches the wire format or
the audio path, say which spec section it follows; that is the reasoning a reviewer needs
and the hardest thing to reconstruct later.
