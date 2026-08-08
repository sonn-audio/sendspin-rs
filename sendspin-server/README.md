# sendspin-server

The server side of the [Sendspin Protocol](https://github.com/Sendspin/spec), in Rust.

Built on [`sendspin-proto`](../sendspin-proto), the shared core holding everything
direction-agnostic: the message vocabulary, the `KKpsk2` transport and the clock. This crate
does **not** depend on the `sendspin` client — that would mean compiling `cpal`, the audio
decoders and the ALSA headers behind them for a server that plays nothing locally, because a
non-optional dependency in Rust is built whether or not anything touches it.

## Status

Early, and honest about it.

**Working:** the WebSocket upgrade; the encrypted `KKpsk2` handshake with this side as the
Noise *initiator* (the spec is explicit about that, and it is the thing most likely to be
assumed backwards); `server/hello` → `client/hello` → `server/activate`; `client/time`
answered so a client's clock filter converges; role negotiation; and **synchronized group
playback** — `player@v1` clients share one timeline, receive byte-identical chunks, and a
client joining mid-track is seated in the stream already playing rather than given its own.
`metadata@v1` is served too, and `client/state` is honoured: a client reporting `available:
false` — its output taken by an HDMI input or a local app — stops being sent audio without
losing its connection, its clock sync or its roles, and resumes when it says it is free.

`controller@v1` is served too: volume and mute are the group's own state, applied here and
pushed to every player as a `server/command`, while play, pause, next and seek are handed to the
application — what "next track" means belongs to whatever produces the audio, not to this crate.
A command outside the advertised `supported_commands` is refused rather than attempted.

A role is only activated when this server can actually keep the promise. `metadata@v1` is not
granted by a server started without a metadata source, because a client told it has the role
and then sent nothing cannot tell that apart from a server that crashed.

Validated against `aiosendspin`'s own client rather than only against this project's — see
[`scripts/interop`](../scripts/interop). A real reference client connects, handshakes, reaches
`is_time_synchronized()`, and receives 150 chunks / 576000 bytes of a three-second tone on both
cipher suites, paced over three seconds rather than dumped.

Synchronization is checked with *two* reference clients on one server, because a single client
cannot detect the failure that matters: it has no way to tell whether the audio it receives is
its own stream or a shared one. `two_clients.py` starts a second client a second late and
compares both by playback timestamp — 155 shared chunks, byte-identical, the late joiner
entering exactly 1s into the existing timeline. `controller.py` covers the other direction: a
reference controller sends a volume, sees the state come back changed, sends a command the
server never advertised, and confirms nothing moved and the connection survived.

**Not yet:** pairing, management, transcoding, resampling, and the `artwork`, `visualizer`,
`color` and `source` roles. Limits worth stating plainly rather than discovering:

- **One group, and nothing can ask to be regrouped.** Every client lands in the same group.
  Moving a client between groups is a `controller@v1` request, and that role is not served yet.
- **The stream itself does not pause.** A controller's play/pause reaches the application, but
  this crate does not yet stop and re-anchor the timeline for it, and `stream/clear` is never
  sent. A stream still starts when a player joins and ends when the source runs out.
- **PCM only.** The client's advertised formats are not honoured yet; a client that cannot
  decode PCM 16-bit will not get something it can.
- **No pairing**, so every connection is keyed by the Sentinel PSK. A client whose
  `unpaired_access` is off is correctly given no roles at all — that field is the client
  telling the server up front whether it may be used without a pairing, and the reference
  client answers `goodbye(pairing_required)` if it is ignored.

## Running it

```bash
cargo run -p sendspin-server --example server -- --bind 127.0.0.1:8927 --seed 3
```

```rust,no_run
use sendspin::noise::Identity;
use sendspin_server::{SendspinServer, ServerConfig};

# async fn run() -> Result<(), sendspin::error::Error> {
let config = ServerConfig::new(Identity::generate()?, "Living Room".to_string());
let server = SendspinServer::bind("0.0.0.0:8927", config).await?;
server.serve_forever().await
# }
```

Persist the identity. A server that mints a new keypair on every start is a new server to
every client that ever paired with it, and every one of those pairings becomes dead weight.
