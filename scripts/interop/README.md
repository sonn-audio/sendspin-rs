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

## Driving a real pairing

`PAIR_WITH=<client_id>:<pairing_psk>` makes the harness pair with that client as soon as it
connects, which is what an operator pasting a pairing token does. Both values are printed by
`--full --seed N`:

```bash
cargo run --example noise_interop -- --full --seed 9 --listen-secs 15 \
    --server ws://127.0.0.1:8931/sendspin
```

`TRUST_UNPAIRED_CLIENT_ID=<client_id>` instead admits one unpaired client to playback, so a
Sentinel-keyed connection gets roles activated rather than merely tolerated.

## What it covers, and what it found

Covered today: both cipher suites, the Sentinel-PSK path, the transition from cleartext text
frames to encrypted binary frames, `client/hello` and `server/activate` over Noise, clock
sync converging through the encrypted transport, and role activation.

Three defects came out of pointing it at the reference server, none of which a loopback test
would have surfaced:

1. **`client/hello` advertised no `supported_pair_methods`.** The server will not pair with a
   client that offered nothing, so pairing failed before it began. The advertisement is now
   derived from the pairing store rather than left to a caller, so it cannot drift from what
   the client can actually do.
2. **`client/state` still carries the legacy top-level `state` field**, and the server logs
   `non-compliant client` for it. Known and deliberate — see the conformance notes — but this
   is the first time it was observed rather than reasoned about.
3. **The hello sequence is not re-run after a re-handshake.** Still open. The server
   re-handshakes to the Pairing PSK before activating pairing, and the spec restarts the
   connection at `server/hello` → `client/hello` → `server/activate` once the new keys are in
   place. This client swaps the session correctly but then carries on mid-stream, and the
   clock-sync task keeps sending `client/time`, so the server reports
   `Expected client/hello, got ClientTimeMessage` and drops the connection. Pairing cannot
   complete until the restart is implemented, which also needs outbound traffic gated for the
   duration of the exchange.
