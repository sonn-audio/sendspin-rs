# Interop validation against the reference implementation

Loopback tests prove this crate's two halves agree with each other. They cannot prove the
spec is being read the same way `aiosendspin` reads it — the prologue byte-for-byte, the
`psk_id` derivation, the cleartext framing, the point at which the socket switches to
binary. Getting any of those subtly wrong produces code that passes its own tests and
cannot talk to a real server.

So the encrypted transport is validated against the reference implementation's own server.

## Running it

`aiosendspin` needs Python 3.12+ (it uses PEP 695 generics) and its server extras:

```bash
python3.13 -m venv .venv
.venv/bin/pip install aiohttp cpace cryptography mashumaro noiseprotocol orjson zeroconf \
                      pillow numpy av
git clone https://github.com/Sendspin/aiosendspin
```

Start the server. It bypasses `start_server()` so zeroconf stays out of the picture, and
leaves `allow_unencrypted` at its default of `False` — the point is to prove this client
speaks the encrypted transport, not to fall back to the legacy hello:

```bash
PYTHONPATH=./aiosendspin .venv/bin/python scripts/interop/reference_server.py 8927
```

Then drive a handshake against it:

```bash
cargo run --example noise_interop -- --server ws://127.0.0.1:8927/sendspin
cargo run --example noise_interop -- --server ws://127.0.0.1:8927/sendspin --suite aes
```

A pass ends with `INTEROP OK` and shows the decrypted `server/hello`. That last part is
what matters: decrypting an application message means both sides derived the same transport
keys from the same prologue and the same PSK, which is everything the handshake had to get
right.

## What it currently covers

Both cipher suites, the Sentinel-PSK path, and the transition from cleartext text frames to
encrypted binary frames.

`TRUST_UNPAIRED_CLIENT_ID=<client_id>` admits one unpaired client to playback, so a
Sentinel-keyed connection can be activated rather than merely tolerated — useful once
`server/activate` handling lands.
