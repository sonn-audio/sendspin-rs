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

## Driving `source@v1`

`--source` runs the flow a real source runs, because the role is pairing-gated: a server
filters `source@v1` out of `active_roles` on a Sentinel-keyed connection, so the harness
connects once to pair, disconnects, and comes back on the long-term PSK. The server then
asks for capture and decodes what arrives.

```bash
# Start the server with PAIR_WITH; --source prints the client_id and pairing_psk to use.
cargo run --example noise_interop -- --source --seed 9 --listen-secs 20 \
    --server ws://127.0.0.1:8941/sendspin
```

A pass prints `SOURCE INTEROP OK` on the client and `SOURCE_INTEROP_OK` on the server, with
matching byte counts on both sides — the client's `chunks sent` against the server's
`SOURCE_DRAINED`. That equality is the point: the server only reaches a non-zero byte count
if the chunk header, binary type 12 and the server-clock timestamp were all packed the way
the reference unpacks them. The run also covers `server/command` in both directions, so
`client_stream/start`, the chunk stream and `client_stream/end` are each exercised.

`SOURCE_STOP_AFTER=<seconds>` (default 3) sets how much capture the server accepts before
asking the source to stop.

## What it covers, and what it found

Covered today: both cipher suites, the Sentinel-PSK path, the transition from cleartext text
frames to encrypted binary frames, `client/hello` and `server/activate` over Noise, clock
sync converging through the encrypted transport, and role activation.

Pairing completes end to end: the server reports `PAIRING_OK` and the client persists a
long-term record bound to the server's id.

`source@v1` streams end to end on both suites: the role activates on the long-term PSK, and
150 chunks (576000 bytes) sent arrive as 576000 bytes decoded on the server.

Six defects came out of pointing it at the reference server, none of which a loopback test
would have surfaced:

1. **`client/hello` advertised no `supported_pair_methods`.** The server will not pair with a
   client that offered nothing, so pairing failed before it began. The advertisement is now
   derived from the pairing store rather than left to a caller, so it cannot drift from what
   the client can actually do.
2. **`client/state` still carries the legacy top-level `state` field**, and the server logs
   `non-compliant client` for it. Known and deliberate — see the conformance notes — but this
   is the first time it was observed rather than reasoned about.
3. **The hello sequence was not re-run after a re-handshake.** The server re-handshakes to
   the Pairing PSK before activating pairing, and the spec restarts the connection at
   `server/hello` → `client/hello` → `server/activate` once the new keys are in place. This
   client swapped the session and carried on mid-stream while the clock-sync task kept
   sending `client/time`, so the server answered
   `Expected client/hello, got ClientTimeMessage` and dropped the connection. Fixed: the
   router re-runs the exchange, behind a gate that holds outbound traffic for its duration.
4. **The restart swallowed the activation it was run for.** With the restart in place the
   server then waited for a `client/pair-finalize` that never came:
   `malformed message awaiting ClientPairFinalizeMessage`. The helper consumed the pairing
   `server/activate` to log it and never handed it on. Fixed by returning it to the caller.
5. **`aiosendspin` sends `selected_pair_method`, the spec says `pairing.method`.** The spec
   replaced the bare field with a `pairing` object that can also carry `pin_length` and
   language hints; the reference still sends the older spelling. A client that reads only the
   newer one sees an activation naming no method and declines with `method_not_supported` —
   which is what happened. Both spellings are now accepted on receive, preferring the spec's.
   This is the mirror image of the visualizer `pitch` divergence: there the reference is ahead
   of the prose, here the prose is ahead of the reference, and a client that wants to work has
   to read both.
6. **The initial `client/state` reported state for roles the server had not activated.** The
   builder is told which roles a client *can* fill; `server/activate` decides which it
   actually got. Sending a `source` object regardless is flagged by the server as
   `client/state carried a source object for an inactive role` — and it happens on every
   unpaired connection, because `source@v1` is pairing-gated and filtered out there. Fixed
   by `ClientState::retain_active_roles`, which drops role objects the activation did not
   grant. `available` is kept either way: it is a property of the client, not of a role, and
   a server withholds binary data until it arrives.
