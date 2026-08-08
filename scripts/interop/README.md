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

## The other direction: a real client against the Rust server

Everything else here drives the reference implementation's *server* and asks whether this
crate's client can talk to it. `reference_client.py` inverts that: it drives the reference
implementation's *client* against the Rust server, which is the only way to find out whether
the server half reads the spec the same way.

```bash
cargo run --features server --example server -- --bind 127.0.0.1:8927 --seed 3
PYTHONPATH=./aiosendspin .venv/bin/python scripts/interop/reference_client.py \
    ws://127.0.0.1:8927/sendspin
SUITE=aes PYTHONPATH=./aiosendspin .venv/bin/python scripts/interop/reference_client.py \
    ws://127.0.0.1:8927/sendspin
```

A pass prints `CLIENT_INTEROP_OK`. The assertion behind it is `is_time_synchronized()`:
reaching it means both sides derived the same transport keys from the same prologue, framed
identically, agreed on the hello sequence, and exchanged enough clock samples for the filter
to settle. Both cipher suites pass.

The server activates no roles, deliberately — it has none to serve yet — so the client is
told the truth rather than granted `player@v1` and then left waiting for audio.

Two defects came out of the first run, neither of which a loopback test would have reached
because nothing in this crate had ever *parsed* these:

1. **`server/hello` went out with no envelope.** It is the one message whose payload shape
   depends on the transport rather than on its `type`, so it is not a `Message` variant and
   does not carry the tag for free. The client reported a missing discriminator.
2. **`client/hello` required `client_id` and `version`.** A spec-conformant client sends
   neither under encryption: the identity came from `client/init` and the Noise handshake
   authenticated it, which is a far stronger claim than a self-declared field. This crate
   still sends them — a known transition-mode divergence — but requiring them on receive
   turns away every client that reads the current spec. Both are optional now.

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

## Driving `player@v1`

`DRIVE_PLAYER=1` streams a tone to any client that has `player@v1` activated, and `--player`
takes it and decodes it. This is the mirror of `--source`, and the more load-bearing
direction: a player has to decode what *someone else's* encoder wrote. The reference encodes
through ffmpeg, so a decoder that only agrees with this crate's own encoder — which is all a
loopback test can show — fails right here.

```bash
DRIVE_PLAYER=1 TRUST_UNPAIRED_CLIENT_ID=<client_id> \
    PYTHONPATH=./aiosendspin .venv/bin/python scripts/interop/reference_server.py 9001
cargo run --example noise_interop -- --player --seed 9 --player-codec pcm \
    --listen-secs 12 --server ws://127.0.0.1:9001/sendspin
```

Nothing is played: there is no sound card in a harness, and the output device is not what is
under test. What is under test is that every chunk decodes, that the frame count matches what
the server says it pushed, and that the timestamps land in the *future* on the synchronized
clock — which is what playback scheduling runs on, and the one thing a decode-only test would
still miss.

`--player-codec` picks what the client advertises, because the server chooses from that list;
without it there is no way to make a run exercise a particular decoder. `PLAYER_SECONDS`
(default 3) sets how much is pushed.

| codec | pushed | chunks | encoded bytes | frames decoded |
| --- | --- | --- | --- | --- |
| `pcm` | 144000 frames | 120 | 576000 | 144000 |
| `opus` | 144000 frames | 150 | 44566 | 144000 |
| `flac` | 144000 frames | 31 | 39569 | 142848 |

PCM and Opus decode to the frame. FLAC is 1152 frames short, and that is the server's
choice rather than a decoding fault: 31 chunks of 4608 frames is 142848, so every byte that
arrived decoded completely, and `PushStream.stop()` states plainly that it "reset transformers
so any internal encoder state is discarded" — the partial block the encoder was still filling
is dropped rather than flushed. It is the mirror image of the trap on the source side, where
*this* client has to flush its encoder before `client_stream/end` or lose the same tail.

A pass prints `PLAYER INTEROP OK` on the client and `PLAYER_INTEROP_OK` on the server; compare
the client's `frames decoded` against the server's `PLAYER_PUSHED frames`. Lead times run
around 410-435 ms with no chunk already due on arrival.

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

`--codec pcm|flac|opus` picks what the source encodes. All three are validated against the
reference server's own decoders, which are ffmpeg's rather than this crate's — so a frame
that only `sendspin-rs` can read fails here:

| codec | sent | decoded on the server |
| --- | --- | --- |
| `pcm` | 576000 B | 576000 B |
| `flac` | 54062 B | 595200 B |
| `opus` | 24320 B | 583680 B |

The Opus figures are worth reading twice: 152 packets of 960 samples is 145920 sample frames,
and 583680 bytes at 4 bytes per frame is the same number. Nothing was dropped or padded.

A pass prints `SOURCE INTEROP OK` on the client and `SOURCE_INTEROP_OK` on the server, with
matching byte counts on both sides — the client's `chunks sent` against the server's
`SOURCE_DRAINED`. That equality is the point: the server only reaches a non-zero byte count
if the chunk header, binary type 12 and the server-clock timestamp were all packed the way
the reference unpacks them. The run also covers `server/command` in both directions, so
`client_stream/start`, the chunk stream and `client_stream/end` are each exercised.

`SOURCE_STOP_AFTER=<seconds>` (default 3) sets how much capture the server accepts before
asking the source to stop.

## Driving static-PIN pairing

`PAIR_PIN=<client_id>:<pin>` runs a static-PIN pairing instead of the Pairing PSK flow —
which means the whole CPace exchange over the wire, rather than handing a key over on a
channel the handshake already authenticated.

```bash
PAIR_PIN=<client_id>:12345678 \
    PYTHONPATH=./aiosendspin .venv/bin/python scripts/interop/reference_server.py 8980
cargo run --example noise_interop -- --source --seed 9 --static-pin 12345678 \
    --listen-secs 20 --server ws://127.0.0.1:8980/sendspin
```

The harness opens the pairing window itself, standing in for the operator gesture the flow
is gated on — that is the one thing here that is faked, because there is no button to press.

A pass prints `PIN_PAIRING_OK` on the server. Two things make that conclusive rather than
suggestive: `initiate_pairing` raises on any failure in the exchange, and the client comes
back on a long-term PSK afterwards — which only exists if the server unwrapped the sealed
PSK, and it can only do that with a CPace output that matches.

## Driving dynamic-PIN pairing

`PAIR_DYNAMIC_PIN=<client_id>:<pin_file>` runs the dynamic flow, where the PIN travels the
*other* way: the client derives it from the handshake hash and both nonces, shows it on the
device, and an operator types it into the server. So a harness run has to carry a value out
of the Rust process and into the Python one — `--pin-file` writes what the client emits,
and the server's `PinProvider` polls the same path until it appears.

```bash
PAIR_DYNAMIC_PIN=<client_id>:/tmp/dynpin.txt \
    PYTHONPATH=./aiosendspin .venv/bin/python scripts/interop/reference_server.py 8991
cargo run --example noise_interop -- --full --seed 9 --listen-secs 20 \
    --pin-file /tmp/dynpin.txt --server ws://127.0.0.1:8991/sendspin
```

The file stands in for the operator, and it is the only faked part: everything either side
computes is its own. The client clears a stale file before connecting, so a value left by a
previous run cannot be mistaken for this one's.

A pass prints `PIN_FROM_FILE=<pin>` and `DYNAMIC_PIN_PAIRING_OK` on the server, and the
client persists a long-term record and comes back with `player@v1` active after the
re-handshake. `PIN_FILE_TIMEOUT` (default 30s) bounds the wait.

Unlike the static flow this one is not gesture-gated at six digits, so no window is opened:
the gate applies only to an escalated method or a PIN below six digits. Both cipher suites
pass.

## Driving `management/*`

`DRIVE_MANAGEMENT=1` on the server opens a management session as soon as a client is on a
long-term PSK — so it fires on the reconnect, not on the connection that paired, which is
what the gating requires. Any paired client answers; `--source` already pairs and reconnects,
so it doubles as the management client:

```bash
DRIVE_MANAGEMENT=1 PAIR_WITH=<client_id>:<pairing_psk> \
    PYTHONPATH=./aiosendspin .venv/bin/python scripts/interop/reference_server.py 8950
cargo run --example noise_interop -- --source --seed 9 --listen-secs 25 \
    --server ws://127.0.0.1:8950/sendspin
```

The sequence walks the whole surface and ends with `MGMT_INTEROP_OK`. It deliberately checks
the negative outcomes too — a second `add-record` with the same key must answer
`already_exists`, and a `remove-record` naming nothing must answer `not_found` — because a
client that returns `ok` to everything passes a happy-path script and fails a real operator.
The config patch is read back rather than trusted (`MGMT_PATCH_APPLIED`), for the same reason.

## What it covers, and what it found

Covered today: both cipher suites, the Sentinel-PSK path, the transition from cleartext text
frames to encrypted binary frames, `client/hello` and `server/activate` over Noise, clock
sync converging through the encrypted transport, and role activation.

Pairing completes end to end: the server reports `PAIRING_OK` and the client persists a
long-term record bound to the server's id.

`source@v1` streams end to end on both suites: the role activates on the long-term PSK, and
150 chunks (576000 bytes) sent arrive as 576000 bytes decoded on the server.

`management/*` runs end to end against a real management session: records listed with their
binding and `used` flag, a record added and re-added, the pairing config read, patched and
read back, a record removed, and both negative outcomes (`already_exists`, `not_found`)
observed rather than assumed.

Static-PIN pairing completes end to end, so the CPace exchange, the confirmation ordering
and the PSK wrapping have all spoken rather than only passing their own tests.

`player@v1` runs end to end on all three codecs, which is the direction that matters most for
this crate: the decoders read what the reference's ffmpeg encoders write, not merely what its
own encoders write.

Dynamic-PIN pairing completes end to end on both suites, which covers the sequencing the
derivation tests could not: `server/pair-init` arriving where this client expects it, the
commitment surviving the round trip, and the server's three-step verification accepting what
the client sends.

Seven defects came out of pointing it at the reference server, none of which a loopback test
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
7. **The three capitalised pairing fields were serialized snake-cased.** The spec and
   `aiosendspin` both name `commit_B`, `nonce_A` and `nonce_B` after the CPace roles; this
   crate sent `commit_b` and read `nonce_a`. All three are optional or absent-tolerant on the
   wire, so nothing failed to parse — the server simply saw a `client/pair-init` with no
   commitment and stopped: `client/pair-init missing commit_B for dynamic PIN`. The static
   flow uses none of the three, which is why five interop runs passed without touching it.
   Fixed with `serde(rename)`, and pinned by a test that asserts the wire spelling rather
   than the round trip — a round trip through one implementation agrees with itself whatever
   it calls the field.

   The same run turned up a spec-versus-reference divergence underneath it: the spec carries
   the negotiated `pin_length` in the activation's `pairing` object and does not list it on
   `server/pair-init`, while `aiosendspin` sends it on `server/pair-init` and omits the
   `pairing` object entirely. Both are now read, preferring the activation's — so a server
   cannot shorten an already-agreed PIN late — and a length that arrives late is held to the
   same `min_pin_length` floor an early one would be. Reading only one of the two derives a
   PIN of the wrong length against half the servers that exist.
