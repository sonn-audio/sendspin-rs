# Handoff: what is left, and what it cost to learn

> Fork-internal. Written at the end of a long session so the next one does not re-derive any
> of this. Read the "Traps" section before writing code.

State as of `719bdd8` on `claude/sendspin-rust-python-parity-m6ktw9` (42 commits ahead of
`main`). **The client is done**: all 36 wire message types the two implementations name
between them are spoken and driven, and the load-bearing ones have been validated against
`aiosendspin` rather than only against their own tests. CI-equivalent green throughout: `cargo test --workspace --all-features`,
`cargo clippy --workspace --all-targets --all-features -- -D warnings`,
`RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --document-private-items --workspace`,
`cargo fmt --all --check`.

## Done, and validated against the reference server

| Area | Evidence |
| --- | --- |
| Noise `KKpsk2`, both cipher suites | handshake completes; `server/hello` decrypts |
| Whole client over the encrypted transport | `client/hello` out, `server/activate` in, clock sync converges |
| Role activation | `active_roles: ["player@v1"]` with unpaired access granted |
| In-band re-handshake + hello restart | session swap, then `server/hello` → `client/hello` → `server/activate` |
| Pairing PSK flow, end to end | server logs `PAIRING_OK`; client persists a bound record |
| `source@v1`, end to end | role activates on the long-term PSK; 576000 bytes sent = 576000 decoded, both suites |
| `management/*`, end to end | real management session: records, config patch read back, both negative outcomes |
| Source encoders | pcm/flac/opus decoded by the reference server's ffmpeg, byte counts exact |
| CPace | draft-21 vectors: generator, both shares, ISK, tags, low-order table both ways |
| PIN bindings | sid, PIN, commitment and wrapped PSK byte-exact against `aiosendspin` |
| Both PIN flows | driven from the router; static PIN completes against the reference server |
| Playback sync bounds | ±0.5 ms steady state, ±0.5% speed, asserted by tests |

## Left to do

### 1. Interop-run the dynamic PIN flow

The static flow has spoken to `aiosendspin` (`PAIR_PIN=<client_id>:<pin>`, see
`scripts/interop/README.md`). The dynamic one has not, and the reason is a plumbing problem
rather than a protocol one: in that flow the PIN travels the *other* way. The client derives
it and shows it; the operator types it into the server. So a harness run has to carry a value
out of the Rust process and into the Python one.

The cheapest honest route: give the example a `--pin-file <path>`, wire it to
`EncryptionSettings::emit_pin` so the derived PIN is written there, and give the server's
`PinProvider` a poll-until-present loop on the same path. Both ends already exist —
`emit_pin` is a callback on the settings, and `PairingAttempt(method=DYNAMIC_PIN,
pin_provider=...)` takes an awaitable.

Worth doing even though the derivation is already byte-exact against the reference: what is
untested is the *sequencing* — `server/pair-init` arriving where this client expects it, the
commitment surviving the round trip, and the server's three-step verification order accepting
what the client sends. Six defects this session lived in code that passed its own tests.

### 2. Open the PR

`main` and the fork's `main` are byte-identical, so the branch sits on current upstream.
Upstream PR #94 is a release-plz bot PR bumping 0.3.6 → 0.4.0; when someone merges it, this
branch will conflict on `Cargo.toml` and `CHANGELOG.md`. Trivial, but see it coming.

Note that `docs/tracking` is deliberately *not* on the code branch, so these notes cannot
ride along into an upstream PR by accident.

### 3. The server

Now in scope by decision. Measured against `aiosendspin` at `4c2d7c9`: the server is 14962
lines, and more is reusable than that number suggests.

**Already free.** Every message type derives both `Serialize` and `Deserialize`, so the whole
1329-line wire vocabulary works in both directions with no new model code. `session.rs`
already has `build_responder()` — the Noise responder is wired and tested, because a client is
the responder in a re-handshake. Framing, fragmentation and the transport are
direction-agnostic. `opus-rs` and `flac-codec` encode as well as decode, and now do.

**The six packages, by size and by kind:**

| Package | Python | Kind |
| --- | --- | --- |
| `push_stream.py` | 2613 | the motor: buffering, send-ahead, per-client pacing, resampling |
| `connection.py` | 2263 | per-connection state machine, Noise responder, role negotiation |
| visualizer DSP | ~1850 | FFT, mel, loudness, beat, f-peak, spectrum, pitch — real signal work |
| `server.py` + `client.py` | 2070 | lifecycle, zeroconf advertisement, the server's view of a client |
| roles (8) | ~2800 | player, visualizer, artwork, source, metadata, color, controller, draft_r1 |
| groups | ~1500 | `group/update`, the volume algorithm, membership |

Two of those are building rather than translating. `push_stream.py` leans on PyAV — ffmpeg
filter graphs for resampling — which Rust does not get for free; that becomes `rubato` plus
own pacing, and it is where synchronisation is won or lost. The visualizer DSP is numpy, so
686 lines of it is more than 686 lines of Rust.

**Start with a skeleton that brings a Python client up.** Noise responder, `server/hello` →
`client/hello` → `server/activate`, clock sync answered. No roles, no audio. The moment
`aiosendspin`'s `SendspinClient.connect(url)` reaches `is_time_synchronized()`, the interop
harness *inverts* — and everything after it is testable instead of hopeful. There are 35191
lines of Python tests pinning server behaviour to borrow from.

Then: role negotiation + player → PushStream → groups → the remaining roles → visualizer DSP
last, because it is the most decoupled and the least load-bearing.

**One architecture decision to take at commit one, not later.** This crate has had a single
entry point since #36, and `cpal`/`flac-codec`/`opus-rs` are unconditional dependencies. An
embedded player should not link the server. Put it behind a `server` feature from the start —
`discovery` is already precedent for the pattern.

## Traps

Every one of these cost real time in the last session.

**The interop harness is the only thing that finds protocol bugs.** Seven defects came out of
it or out of a fresh clone; every one lived in code that passed its own unit tests. See
`scripts/interop/README.md` for setup and the full list. `aiosendspin` needs **Python 3.12+**
(PEP 695 generics) and its server extras `pillow numpy av` even when no audio is involved —
the artwork role imports PIL at module load. On 3.11 you get a `SyntaxError` in `pairing.py`
that says nothing about the real cause.

**Re-clone `aiosendspin` and `Sendspin/spec` at the start of every session.** Both move
daily. The source role landing mid-session is what exposed that this crate's version of it
was largely invented.

**Neither the spec nor the reference is authoritative on its own.** They diverge in both
directions, and a client that wants to work reads both:

- Visualizer `pitch` on binary slot 21: the reference ships it, the spec reserves the slot.
  Decision taken: follow the reference, because features land there first and the prose is
  written up to match. Recorded in `spec-conformance.md`.
- Pairing method in `server/activate`: the spec says `pairing: {method, pin_length, languages}`,
  the reference still sends bare `selected_pair_method`. Both are accepted on receive,
  preferring the spec's. A client reading only the newer one declines every pairing.
- Where they *agree* and this crate differs, this crate is wrong. That was the source role.

**Ordering hazards in the encrypted transport**, all load-bearing:

- The prologue is the *exact transmitted bytes* of `client/init` ‖ `server/init`. Never
  re-serialize a parsed message to rebuild it.
- A re-handshake's Noise message 2 goes out under the **old** keys; only the next frame uses
  the new ones. Flush the reply (await the writer's ack) before swapping the session.
- After a re-handshake the connection restarts at `server/hello`, and nothing else may flow
  meanwhile — hence the `handshake_gate` on `WsSender`. Clock pings are dropped rather than
  queued while it is up: a delayed ping carries a stale `t1`, which is worse for the filter
  than a skipped sample.
- The pairing `server/activate` arrives *after* that restart. The helper that runs the restart
  must hand it back, not consume it.

**`source@v1` is pairing-gated, and that shapes how you test it.** A server filters the role
out of `active_roles` on a Sentinel-keyed or legacy connection, so it can only be exercised
after pairing has moved the client onto a long-term PSK — and not on the pairing connection
itself, which the spec keeps mutually exclusive with playback and which activates with empty
`active_roles`. Both the harness and `aiosendspin`'s own end-to-end test therefore pair,
disconnect, and reconnect. Two more preconditions the server enforces quietly: it ignores
chunks until the initial `client/state` has arrived, and it flags a `client_stream/start`
that no `server/command {command: start}` asked for.

**A role a client *can* fill is not a role it *has*.** `server/activate` decides, and
`client/state` reports only what it granted. This is what `ClientState::retain_active_roles`
is for; anything new that reports per-role state has to go through it.

**PIN pairing is gated on a gesture the crate cannot perform.** Static PIN gates every
attempt; dynamic PIN gates an escalated method or a PIN under six digits. The gesture is a
button, a reset pinhole, a power-cycle pattern — things only the host application observes —
so `PairingWindow` on `Connection` is a handle the crate holds and never raises by itself. The
interop harness opens it directly, which is the one thing there that is faked. Likewise
`EncryptionSettings::emit_pin`: the dynamic PIN has to reach the operator through *this
device*, and a crate that picked a channel would be guessing at hardware it cannot see.

**CPace's low-order point table is not "reject everything".** The draft is precise: `u0`-`u5`
and `u7` MUST abort, and the other five are unusual encodings that still multiply to a value
it publishes. The first attempt here asserted that all twelve were rejected and was wrong —
refusing them all would turn away peers the draft considers conformant. The test now pins each
expected output. Note also that the Python `cpace` package accepts those five too, so
"the reference passes the vectors" does not mean what it sounds like.

**Do not hand-roll crypto, and do not let a key generator degrade.** Two corrections in one
session: a hand-written X25519 montgomery ladder (replaced with `x25519-dalek`), and a
`random_psk` that fell back to hashing a pointer address when the CSPRNG was unreachable —
which would mint a guessable long-term PSK that looks like a working pairing. `random_psk`
returns `Result` for this reason, and `PairingConfig` has no `Default` because a `Default`
would have to invent a key.

## Known divergences to keep

Both deliberate, both stated in the README so they do not read as oversights:

- Visualizer `pitch` (slot 21), as above.
- `client_id` / `version` in `client/hello` and the legacy `state` in `client/state`. The spec
  moved or dropped these; current servers still read them. The reference server logs
  `non-compliant client` for the `state` field. They go away with transition mode, and should
  be removed by whatever change flips encryption on by default.

## Still open, non-blocking

- `reanchor_threshold_us` is 500 ms. Working off a 400 ms error at the ±0.5% cap takes ~80 s,
  all of it outside the ±1 ms floor; self-consistency with `target_seconds: 2.0` puts the
  crossover near 10 ms. Lowering it trades the accuracy floor against "one-shot
  resynchronization MUST be rare", and reanchor plans bypass `EngageGate` by design. This is a
  listening decision on hardware, not one the spec text settles.
- Encryption is opt-in. It is the compliant default and should flip — with the transition-mode
  fields above removed in the same change — once pairing is complete enough to rely on.
- A mid-connection `server/activate` that *adds* a role is not acted on. The router reads
  those activations only for pairing; it does not update `active_roles` or send the newly
  active role its full state, which the spec asks for ("When a role becomes active in
  `active_roles`, send its full state"). Not reachable on the source path — pairing ends the
  connection's playback activity, so a source arrives with its roles already settled — but it
  is a gap for any server that re-activates in place. Noticed while fixing the inactive-role
  state defect; deliberately left alone rather than widened into that change.
- The dynamic-PIN failure counter is persisted through `PairingConfig`, so a store that only
  keeps records in memory forgets it on restart — which is exactly the reset an attacker
  wants. A durable store is the fix, and the trait already allows one; nothing in-tree
  provides it.
- No benchmark exists, so the README's CPU and memory figures are labelled design targets.
  `aiosendspin` has `scripts/benchmark_clients.py` and a sync harness
  (`test_audible_sync_matrix`, `test_audible_sync_fuzz`) worth mirroring if the
  "hyper-efficient" claim is to be a measurement rather than an intention.
