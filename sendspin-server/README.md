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

Validated against `aiosendspin`'s own client rather than only against this project's — see
[`scripts/interop`](../scripts/interop). A real reference client connects, handshakes, reaches
`is_time_synchronized()`, and receives 150 chunks / 576000 bytes of a three-second tone on both
cipher suites, paced over three seconds rather than dumped.

Synchronization is checked with *two* reference clients on one server, because a single client
cannot detect the failure that matters: it has no way to tell whether the audio it receives is
its own stream or a shared one. `two_clients.py` starts a second client a second late and
compares both by playback timestamp — 155 shared chunks, byte-identical, the late joiner
entering exactly 1s into the existing timeline.

**Not yet:** pairing, management, transcoding, resampling, playback control, and every role
but `player@v1`. Limits worth stating plainly rather than discovering:

- **One group, and nothing can ask to be regrouped.** Every client lands in the same group.
  Moving a client between groups is a `controller@v1` request, and that role is not served yet.
- **No playback control.** `client/command` is parsed and ignored; `server/command`,
  `server/state` and `stream/clear` are never sent. A stream starts when someone joins and
  ends when the source runs out — nothing can pause, seek or set a volume.
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
