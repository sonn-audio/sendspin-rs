# Handoff: what is left, and what it cost to learn

> Fork-internal. Written at the end of a long session so the next one does not re-derive any
> of this. Read the "Traps" section before writing code.

State as of `848e770` on `claude/sendspin-rust-python-parity-m6ktw9` (35 commits ahead of
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
| Playback sync bounds | ±0.5 ms steady state, ±0.5% speed, asserted by tests |

## Left to do

**1. `management/*` — seven messages.** `server/unpair`, `management/list-records`,
`management/add-record`, `management/remove-record`, `management/get-pairing-config`,
`management/set-pairing-config`, `management/result`. Mechanical on top of the `PairingStore`
that already exists. Reference: `aiosendspin/client/management.py` (six handlers) and
`tests/integration/test_management_flow.py`. Two rules worth reading in `management.md` first:
a shared-PSK record must **not** be removed by `server/unpair` (only by
`management/remove-record`), and `server/unpair` on a `trust_level: none` connection is ignored
rather than obeyed.

**2. CPace, and the two PIN pairing methods.** The real work.

- The suite is `CPACE-X25519-SHA512`, `draft-irtf-cfrg-cpace` **revision 21**, with the
  draft's optional explicit mutual key confirmation.
- No usable Rust crate: the only `cpace` on crates.io is a single 0.1.0 from May 2020, years
  before rev 21. Assume wire-incompatible.
- Two independent checks are available, and both should be used: the draft ships
  `testvectors.json` (the Python `cpace` package passes all of it including invalid-point
  rejection), **and** `aiosendspin` implements both PIN flows on both sides, so a real
  exchange is testable. Vectors prove the arithmetic; an exchange proves the binding — `sid`,
  the `ad` labels, the MCF tags, and the PSK wrapped under the CPace output.
- `plan_pairing` already declines both PIN methods with `pair/abort(method_not_supported)`,
  which leaves the connection open, so nothing breaks while they are unimplemented.

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
