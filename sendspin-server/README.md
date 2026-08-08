# sendspin-server

The server side of the [Sendspin Protocol](https://github.com/Sendspin/spec), in Rust.

A crate of its own rather than a feature of `sendspin`, because the two have genuinely
different dependency appetites. A server grows resamplers, encoders and signal analysis that an
embedded player has no use for, and a feature flag on one crate makes every one of those a
decision the player's build has to carry.

What it borrows from `sendspin` turns out to be most of the protocol, because most of the
protocol is direction-agnostic: the message vocabulary derives both `Serialize` and
`Deserialize`, so the whole wire surface works either way, and the framing, fragmentation and
Noise primitives do not care which end they are on. Nothing here reaches into the client
crate's internals — the split needed no new `pub`.

## Status

Early, and honest about it.

**Working:** the WebSocket upgrade; the encrypted `KKpsk2` handshake with this side as the
Noise *initiator* (the spec is explicit about that, and it is the thing most likely to be
assumed backwards); `server/hello` → `client/hello` → `server/activate`; and `client/time`
answered so a client's clock filter converges.

Validated against `aiosendspin`'s own client rather than only against this project's — see
[`scripts/interop`](../scripts/interop). A real reference client connects, handshakes and
reaches `is_time_synchronized()` on both cipher suites.

**Not yet:** roles, audio, groups, pairing, management. The server activates no roles at all,
which is a decision rather than an omission: a client granted `player@v1` and then never sent
audio looks broken, while one told it has no active roles is being told the truth.

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
