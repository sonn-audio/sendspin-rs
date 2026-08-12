# sendspin-rs

Hyper-efficient Rust implementation of the [Sendspin Protocol](https://github.com/Sendspin/spec)
for synchronized multi-room audio streaming.

> [!WARNING]
> Pre-1.0 and under active development. The API is not yet stable — see [Status](#status).

## What this is

A client library. You bring the application; this crate speaks the protocol, keeps your
clock locked to the server's, and drives the audio device.

Being a player or a source is a library entry point rather than something to reassemble from
the parts: [`Player`](#being-a-player) captures the whole session from the first hello to the
last chunk, and [`Source`](#sources-sourcev1) does the same in reverse. The command-line
program is a thin layer over exactly that, so an application embedding the crate gets the
player the daemon has rather than a second copy of it.

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

Pairing works too: the trust store, all three pairing methods — Pairing PSK, static PIN and
dynamic PIN — and the `management/*` messages. All three complete end to end against
`aiosendspin`'s server, which for the PIN methods means the whole CPace exchange over the
wire; CPace is implemented in-crate against draft-21 and its vectors, because no usable Rust
crate exists. A client still reaches a server on the Sentinel PSK, which is what the protocol
keys a first connection with; pairing is what promotes that to a trusted session.

The one thing the crate cannot do by itself is the operator gesture the PIN methods are gated
on — a button, a reset pinhole, a power-cycle pattern. `PairingWindow` is a handle the host
application raises, and the dynamic PIN reaches the operator through
`EncryptionSettings::emit_pin`, because only the host knows whether this device has a display,
a speaker or a row of LEDs.

**The workspace has three crates.** [`sendspin-proto`](sendspin-proto) holds what is
direction-agnostic — the message vocabulary, the `KKpsk2` transport and the clock. This crate
is the client, [`sendspin-server`](sendspin-server) the server; both build on the core and
neither depends on the other. That shape exists so a server does not compile `cpal` and the
audio decoders to get message types, and so an embedded player never links a resampler. The
`noise`, `sync`, `error` and `protocol::messages` paths here are re-exports of the core, so
nothing using this crate has to know.

The server plays synchronized audio to a group of clients and is still early otherwise — see
its README for what works.

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

Where the spec and the reference disagree about *where* a field lives, both are read rather
than one being picked. The pairing method in `server/activate` (spec: a `pairing` object;
reference: a bare `selected_pair_method`) and the dynamic PIN's negotiated `pin_length` (spec:
in that same activation; reference: on `server/pair-init`) are each accepted from either
place, preferring the spec's. Reading only one of the two turns away every server that speaks
the other.

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

## The `sendspin` command

Behind the `cli` feature, so a device embedding this crate as a library never links an
argument parser or a logger to get a player. Five subcommands: `daemon` plays, `serve`
serves, and `audio-devices`, `servers` and `clients` list what a machine and a network have.

The daemon is the main one:

```bash
cargo run --features cli --bin sendspin -- daemon --name "Kitchen"
```

With no `--url` it listens on port 8928 for server-initiated connections and advertises
`_sendspin._tcp.local.`, which is what a fixed appliance on a network with a discovering
server wants. With `--url` it dials that server instead. Volume, mute and static delay
arrive as `server/command` and are reported back in `client/state`; multi-server arbitration
is `ConnectionManager`'s, so a server that takes over is served and the previous one is let
go.

The flag names track `sendspin-cli`'s, so an operator who knows one does not have to learn
the other.

It speaks the encrypted transport and can pair. The identity key and the pairing records
live in `--settings-dir` (`$XDG_CONFIG_HOME/sendspin`, else `~/.config/sendspin`), owner-only,
so a pairing survives a restart — which is the only way one means anything. Because the
`client_id` under Noise is the public half of that key, it comes from the identity rather
than from `--id`; `--no-encryption` falls back to the legacy cleartext transport for a server
that has not implemented Noise, and cannot pair.

`sendspin audio-devices list` prints the output devices; `--audio-device` takes an index from
that list or a name (exact id or description first, then a prefix, so `--audio-device HDA`
works). `--audio-format codec:sample_rate:bit_depth:channels` pins the stream: it becomes the
*only* format offered, so the server sends that rather than merely preferring it, and it is
checked against the device at startup. A device that does not exist or cannot play the format
is an error there and then, with the list of what was available — not silence once a server
starts sending.

One thing to know before a first run: with no pairing and no `--allow-unpaired`, a server
activates no roles and nothing plays. That is the conservative reading of the protocol — an
unpaired session is authenticated by nothing — so it is the operator's call, made once and
saved. The daemon says so at startup rather than looking broken.

`--hook-start` and `--hook-stop` run a command line through a shell when a stream begins and
ends, with the connection's details in `SENDSPIN_EVENT`, `SENDSPIN_SERVER_ID`,
`SENDSPIN_SERVER_NAME`, `SENDSPIN_SERVER_URL`, `SENDSPIN_CLIENT_ID` and `SENDSPIN_CLIENT_NAME`
— for waking an amplifier or closing a relay the protocol knows nothing about. The stop hook
also fires when a server disappears mid-stream, since an amplifier left powered by a dropped
network is exactly what it is for.

`--hook-set-volume` hands the effective volume (0-100, and 0 when muted) to a script as its
last argument. Setting it moves attenuation out of this process: the audio path stays at unity
gain and the script owns the level, so it is never applied twice. That one runs without a
shell and is split at startup, because it takes a value from the network on every change.

`--hardware-volume` drives the sound card's own volume control instead of attenuating in
software, behind the `hardware-volume` feature (Linux/ALSA). Software attenuation throws away
bits — a 16-bit stream at 30% has lost its bottom two before it reaches the DAC — and it shows
a number a knob on the front panel does not move. It picks `Digital`, `Master` or `PCM` in that
order, which is where I2S DAC HATs, generic cards and the Raspberry Pi's headphone output
respectively put theirs, and reads the card's current level at startup so the first
`client/state` reports what is actually set. A card with no gain stage falls back to software
volume with a warning rather than refusing to start.

How a percentage becomes a level depends on the card, and the card is asked rather than
guessed at. One that reports a dB range gets a logarithmic mapping over it, because that is
what makes 50% sound like half; one that reports no dB information at all gets its raw range,
because nothing here can discover what its steps are worth. Mapping a percentage straight onto
the register of a card calibrated in dB puts 30% around 60 dB down, which is inaudible where
the listener asked for "a bit quiet". The choice is logged once with the numbers behind it, and
an application embedding the crate can overrule it for a card whose dB information is wrong.

A card whose level is turned by something else — a knob, another program — is noticed within a
second and reported, rather than being overwritten the next time this client writes a level.

Exactly one thing owns the level at a time: the `--hook-set-volume` script, the card's mixer,
or this process's gain, in that order of precedence. Applying it in two places would attenuate
twice.

### `sendspin serve`

The other half of the workspace, behind the `serve` feature so a player build does not compile
a server to be a player:

```bash
cargo run --features serve --bin sendspin -- serve --demo --name "Study"
```

It binds a port, persists an identity so its `server_id` survives a restart, advertises
`_sendspin-server._tcp.local.`, and plays either a 440 Hz test tone (`--demo`) or a file
(`--source track.flac`). WAV and FLAC only, and it says so when handed anything else: a
general-purpose decoder means ffmpeg, and every player build would carry it for a server
feature it can live without.

`--client`, which dials a listening client, and `--workers` are not covered — the first needs
the server crate to open a connection rather than only accept one, the second is a process
model this does not share.

### Finding things

```bash
sendspin servers list     # Sendspin servers on the network
sendspin clients list     # clients waiting to be connected to
```

Both browse mDNS for a window (`--seconds`, three by default) rather than returning on the
first answer, because a browse cannot know it has heard everything. The URL is printed on its
own line, since that line is exactly what `--url` takes.

### As a dedicated player

For the case this is really built for — a Raspberry Pi wired to speakers, no screen, nobody
watching — `packaging/systemd/` has a unit file and the reasoning behind its choices. Two
things matter there and are handled: with `--url` the daemon redials on its own
(`--reconnect-secs`, five seconds by default, backing off to a minute), so a server that
restarts costs a few seconds of silence rather than the evening; and the settings directory
comes from `$STATE_DIRECTORY` when systemd provides one, so the daemon works as a system
service with no `HOME` at all.

One limit worth knowing: **`--interface` binds the listening socket only.** It does not yet
restrict which interface mDNS advertises on, because the advertisement API takes no
interface.

Still to come: MPRIS, and PulseAudio as a hardware-volume backend alongside ALSA.

## Quick start

```toml
[dependencies]
sendspin = "0.3"
tokio = { version = "1", features = ["full"] }
```

### Being a player

Describe the client, run it, and watch what it does. Everything between the first hello and
the last chunk — negotiating a format, opening the right output for it, following the server's
timeline, honouring volume wherever the level actually lives — is the session's job, not
yours:

```rust
use sendspin::player::{Player, PlayerConfig};

let mut config = PlayerConfig::new(client_id, "Kitchen".to_string());
config.device = Some(sendspin::audio::devices::find_device("0")?);
config.rates = sendspin::audio::devices::output_rates(config.device.as_ref());

let player = Player::new(config);
let mut status = player.status();
tokio::spawn(async move {
    while status.changed().await.is_ok() {
        println!("{:?}", status.borrow().connection);
    }
});
player.run_outbound("ws://server:8927/sendspin", None).await?;
```

`status()` is a `watch` of connection state, negotiated format, volume, mute and the last
error — a slow observer can never hold up the session that produced it. `set_volume` and
`set_static_delay` move what the application owns, and both are reported to the server, because
a client that quietly moves its own level or its own timing leaves the server showing something
that is not the sound.

`PlayerConfig` also carries what only an application can know: a starting volume to restore,
which codecs to offer and in what order, and the buffer and lead time a particular installation
needs. Nothing there is a flag on the command line; the library taking them is the point.

Waiting to be dialled instead of dialling is `run_inbound`, behind the `discovery` feature.

### Being a source

The same shape in reverse — see [Sources](#sources-sourcev1).

### Underneath

Both of the above are built on the protocol layer, which is there when an application wants
something neither role covers:

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
builder; `examples/player.rs` is the end-to-end version at this level, including handing
decoded buffers to `SyncedPlayer` yourself.

## Features

| Feature | Default | What it adds |
| --- | --- | --- |
| `player` | yes | Being a player: the session that ties the protocol to an output device |
| `source` | yes | Being a source: the session that captures an input and streams it up |
| `discovery` | no | mDNS — advertising a listening client, and browsing for either side |
| `cli` | no | The `sendspin` command: daemon, device and discovery listings |
| `serve` | no | `sendspin serve`, and with it the server crate |
| `hardware-volume` | no | Driving the card's own mixer instead of attenuating in software (Linux/ALSA) |
| `native-tls` | no | `wss://` transport |

An appliance that only plays builds with `default-features = false, features = ["player"]`.
Worth saying plainly: `player` and `source` gate code, not dependencies — cpal and the codecs
are compiled either way — so dropping one buys compile time and a smaller API, not a smaller
binary. `cli`, `serve` and `hardware-volume` do keep real dependencies out.

## Examples

```bash
cargo run --example embedded_player       # be a player, using the library alone
cargo run --example embedded_source       # capture a real input and stream it up
cargo run --example basic_client          # connect and handshake
cargo run --example player                # a player built from the protocol layer
cargo run --example controller_only       # send transport commands, no audio
cargo run --example source                # a source built from the protocol layer, on a test tone
cargo run --example server_initiated_metadata  # accept inbound connections, print metadata
cargo run --example minimal_test          # smallest possible client
cargo run --example secure_socket --features native-tls   # wss:// transport
cargo run --example noise_interop         # drive the encrypted handshake and report on it
```

The first two are the ones to read when embedding this crate; the rest work a layer down, at
the protocol itself. `embedded_source` also carries a signal-detection policy — a threshold
with hysteresis — which lives there rather than in the library on purpose: see
[Sources](#sources-sourcev1).

All of them take `--server`; pass `--help` for the rest. `RUST_LOG=debug` turns on protocol
tracing, and `RUST_LOG=trace` adds the per-callback sync detail.

## Sources (`source@v1`)

A source is a player in reverse: it captures a local input — line-in, a turntable preamp, an
HDMI capture card — and streams it to the server, which resamples, mixes and distributes it.

The role is deliberately small. A source advertises at most that it can sense signal; there is
no format negotiation, because the server transcodes centrally and takes whatever a source
announces. `Source` mirrors `Player`, so an application that has embedded one recognises the
other:

```rust
use sendspin::source::{Source, SourceConfig};

let mut config = SourceConfig::new(client_id, "Kitchen Line-In".to_string());
config.device = Some(sendspin::audio::devices::find_input_device("0")?);
config.sample_rate = 48_000;

let source = Source::new(config);
source.run_outbound("ws://server:8927/sendspin", None).await?;
```

The server drives capture with `server/command` (`start` / `stop`, both idempotent), and the
session does the rest: opening the input only while a server wants audio — an input held open
is one nothing else on the machine can use — announcing the format in `client_stream/start`
before the first frame, stamping each block in the *server's* clock, and flushing what the
encoder was still holding when the stream ends.

**Signal presence is the application's.** `line_sense` says whether anything is actually
playing into the input, and only that end can know. This crate does not decide it, and neither
does the reference implementation's source client — it reports what its application tells it.
A threshold chosen here would be an invention wearing the protocol's name. What the library
does instead is publish the fact: `levels()` carries the peak of each captured block, on its
own channel so an application watching for a format change is not woken fifty times a second
by a number it is not reading.

```rust
let mut levels = source.levels();
let signals = source.signal_reporter();   // usable from another task
```

`examples/embedded_source.rs` shows one policy over that: two thresholds rather than one, so a
passage sitting near the line does not flap; and a wait before declaring silence, because music
has rests and a source that reports one invites a server to drop it mid-track. Every number in
it is an installation's business, which is exactly why they are not in the library.

`examples/source.rs` works a layer down, driving the protocol directly on a synthesised tone.

## Architecture

See [docs/rust-thoughts.md](docs/rust-thoughts.md) for design notes.

The short version, from the bottom up. `ProtocolClient` owns the WebSocket and, on `split()`,
hands back a `Connection` of independent parts — a message stream, a decoded-audio channel, a
shared `ClockSync`, a `WsSender`, and a `ConnectionGuard` that says goodbye on drop.
`SyncedPlayer` owns the output device and the correction loop, and is fed decoded
`AudioBuffer`s; `SourceCapture` does the arithmetic for the other direction.

`player` and `source` are the layer above, and are what most applications want: the session
that ties those pieces together, from the first hello to the last chunk. `src/bin/sendspin`
is a thin command-line layer over the same modules — it resolves flags and reports what could
not be honoured, and implements no protocol of its own. If something a player needs is only
reachable from the binary, that is a bug in the split.

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
