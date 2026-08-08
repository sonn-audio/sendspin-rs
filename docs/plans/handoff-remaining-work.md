# Handoff: what is left, and what it cost to learn

> Fork-internal. Written at the end of a long session so the next one does not re-derive any
> of this. Read the "Traps" section before writing code.

State as of `684a998` on `claude/sendspin-rust-python-parity-m6ktw9` (40 commits ahead of
`main`). CI-equivalent green throughout: `cargo test --workspace --all-features`,
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
| Both PIN flows | driven end to end against a server side; both peers finish on one PSK |
| Playback sync bounds | ±0.5 ms steady state, ±0.5% speed, asserted by tests |

## Left to do

**Drive the PIN flows from the router.** This is the only thing standing between the client
and full wire parity, and it is wiring rather than research: `noise::pin_flow` is complete
and tested, `plan_pairing` already routes an offered method into it, and the router has an
arm that declines because it cannot yet finish the exchange.

Three things the router does not currently carry, and each is small on its own:

- **The Noise handshake hash.** The PAKE's `sid` binds to it. `snow` exposes it as the
  handshake hash once transport mode begins; it has to be captured there and kept in
  `SecurityContext` alongside `psk_id`, and it changes on a re-handshake like the rest.
- **A pairing-index counter.** The number of pairing `server/activate` messages since the
  last handshake. `client/pair-pending` and `client/pair-init` both carry it, and the server
  discards a lower value silently and treats a higher one as a protocol error.
- **An attempt held across several inbound messages.** Today `handle_pairing_activation`
  runs to completion inside one message; a PIN attempt spans four. It wants a
  `Option<PinPairing>` next to `pending_pairing`, fed from the router's match arms.

Two client-side obligations that go with it and have decision functions waiting in
`noise::pin`, but no persistence yet:

- **The failure counter.** `PinPairing::counts_as_failure` reports the one event that
  increments it — this side's own `server_kc` verification failing. It resets on success,
  persists across reboots, and is not partitioned by server or source address. It lives in
  `PairingConfig::dynamic_pin_failures`; nothing writes it yet.
- **The pairing window.** `dynamic_pin_needs_gesture` decides when an attempt is gated.
  Opening the window is an operator gesture the host application owns, so this needs an API
  on the builder rather than a policy in the crate — and `management/open-pairing-window`
  should stop answering `invalid` once one exists.

After that: advertise the methods in `client/hello`. The descriptor needs `min_pin_length`
on `dynamic_pin` and the `locations` hint on the others, derived from the store the way
`supported_pair_methods` already is.

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
- No benchmark exists, so the README's CPU and memory figures are labelled design targets.
  `aiosendspin` has `scripts/benchmark_clients.py` and a sync harness
  (`test_audible_sync_matrix`, `test_audible_sync_fuzz`) worth mirroring if the
  "hyper-efficient" claim is to be a measurement rather than an intention.
