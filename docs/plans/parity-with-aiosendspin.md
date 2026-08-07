# Parity with the Python implementation

> Fork-internal tracking. Not part of any upstream PR — kept here so the picture survives
> between work sessions.

A field-by-field comparison of this crate against `aiosendspin`, so the remaining
differences are a list someone can work through rather than something each contributor
rediscovers. Everything here is about the *client* side; `aiosendspin` also ships a full
server, which this crate does not aim at.

Read the columns as: does the Rust client understand what a current Python server sends,
and can it say what a current Python client says?

Checked against `aiosendspin` at `d6f4104` (2026-08-06) and `Sendspin/spec` at `d5f64a6`.

## The shape of the gap, in one count

Of the 37 wire message types the two implementations name between them, this crate speaks
17 and `aiosendspin` speaks 34. Every one of the 20 it is missing belongs to a single
subsystem — the encrypted transport and what hangs off it:

| Group | Missing here |
| --- | --- |
| Noise transport | `client/init`, `server/init`, `noise/handshake`, `server/activate` |
| Pairing | `client/pair-init`, `server/pair-init`, `client/pair-auth`, `server/pair-auth`, `client/pair-confirm`, `server/pair-confirm`, `client/pair-finalize`, `server/pair-finalize`, `pair/abort` |
| Management | `management/list-records`, `management/add-record`, `management/remove-record`, `management/get-pairing-config`, `management/set-pairing-config`, `management/result`, `server/unpair` |

Nothing outside that subsystem is missing. Spot-checked field by field, `ClientHello`,
`ClientState` and the legacy `ServerHello` match their Python counterparts exactly, and
`ClientState` is a superset — it carries `source` as well.

Three message types run the other way: `input_stream/start`, `input_stream/end` and
`input_stream/request-format`. `source@v1` is in the spec (`roles/source/v1.md`) but not yet
in `aiosendspin`'s `main` — it is pending there as PR #286. So on that role this crate is
the one that is ahead, and the Python side is the one with parity to reach. Which is worth
saying plainly: parity is not a subset relation in one direction.

Nor is `aiosendspin` simply the definition of the protocol — but it is not simply an
implementation of it either. New features land there first and the spec is written up to
match afterwards, so it leads the prose more often than it trails it. That makes it the
right reference to follow where it has moved ahead (see
[spec-conformance.md](spec-conformance.md) on visualizer slot 21), and the wrong one to
follow where this crate has moved ahead instead. Neither document is the authority on its
own; what the spec settles is the case where it states a rule and we break it.

## Closed

These were real differences and are addressed. None of them have landed on `main` yet:
each was developed on its own branch, `sonn` merges all ten, and they are consolidated for
upstream on the "on par with the spec and the reference" PR branch together with the sync
fix and the README.

| Area | What was missing |
| --- | --- |
| Group state | `paused` failed to deserialize, taking the whole `group/update` with it |
| Visualizer | Slot 21 (`pitch`) was rejected as reserved |
| Visualizer | `buffer_capacity` could not be changed in `stream/request-format` |
| Lifecycle | `pairing` / `management` connection reasons failed the handshake; four goodbye reasons were unsayable |
| Streams | `server_transmitted` was dropped, so a client could not check the lead it asked for |
| State | `available` was unsayable; only the older `state` enum was sent |
| Handshake | `trust_level`, `unpaired_access`, `supported_pair_methods`, `selected_pair_method` |
| Source | The `source@v1` role, and the `input_stream/*` lifecycle it needs |

Unknown enum values now land on an `Unknown` variant in the places a server can introduce
one. That is a deliberate asymmetry with the Python, which is strict: a strict client
throws away a whole message — sometimes a whole handshake — over a field it could have
ignored, and for the client end of a protocol that trade is the wrong way round.

## Open: the encrypted transport

The bulk of what remains is one subsystem. `aiosendspin/noise/` (~2400 lines) puts a Noise
handshake in front of the protocol, and everything below hangs off it:

- **`client/init` and the Noise handshake.** Under encryption the client's identity moves
  out of `client/hello` — `client_id` and `version` come from `client/init` instead, and
  `server/hello` shrinks to `{name}`.
- **`server/activate`.** With encryption, roles and purpose arrive after the handshake in
  `{activities, active_roles, selected_pair_method}` rather than in `server/hello`. This
  changes two things here: `Connection::server_hello` stops being the place role
  activation is read from, so the `Controller` handle cannot be built at `split()` time,
  and arbitration keys off `activities` instead of `connection_reason`. The rank ladder
  already added for connection reasons (management > playback > pairing > discovery) is
  the same one `aiosendspin` applies to activities, so that part transfers.
- **Pairing methods.** PSK, static PIN and dynamic PIN exchanges, with lockout after
  failed attempts and the abort reasons that go with them (`PairAbortReason`).
- **A trust store.** `aiosendspin/noise/trust_store.py` (~900 lines): pairing records
  keyed by PSK id, per-method configuration, storage accounting.
- **`management/*` and `server/unpair`.** Six messages that let a server administer the
  client's pairing records. They are only meaningful with the trust store — the payloads
  are PSK ids, PIN digits and record summaries — so they belong with it rather than ahead
  of it.

### This is the whole remaining delta, and it is on a clock

An earlier draft of this note called the encrypted transport "a feature to add, not a break
to repair", on the grounds that the unencrypted handshake still reaches a current server.
The first half of that is still true and the second half is worth stating more carefully,
because two things make the transition-mode path narrower than it looks:

- **The spec no longer has an unencrypted mode.** `connection.md` opens with "The WebSocket
  transport MUST be plain `ws://`. Confidentiality and integrity are provided end to end by
  the Noise layer inside the WebSocket payloads." There is no transition mode, no opt-out
  and no deprecation notice anywhere in the spec — the unencrypted handshake this crate
  speaks is not a supported variant of the current protocol, it is an artifact of servers
  that have not yet dropped it.
- **The Python client no longer speaks it either.** `Connection._bring_up` calls
  `_run_noise_handshake` unconditionally; there is no legacy branch. `aiosendspin` keeps
  `LegacyServerHelloMessage` deliberately outside its message union and says why in a
  comment: "The server only ever serializes and sends it; our own client always speaks the
  encrypted path and so never deserializes it."

So the two clients have disjoint transports. Everything in the tables above is real work
that is really done, but a client that cannot complete a Noise handshake is at 17 of 34
messages and reaching a current server only on a courtesy that the spec does not require
anyone to extend. That makes this subsystem the priority rather than the tail, and it still
wants to be its own sequence of changes rather than folded into anything above.

Suggested order, each independently useful:

1. Noise transport (`client/init`, handshake, encrypted frame wrapping) with pairing
   disabled — an encrypted session against a server that requires no pairing.
2. `server/activate`, role activation after the handshake, and arbitration by activity.
3. A trust-store trait plus an in-memory implementation, and the PSK pairing method.
4. PIN methods, lockout, and the abort reasons.
5. `management/*` and `server/unpair` on top of the trust store.

Steps 1–3 reach an encrypted, paired client and need no PAKE: `pairing_psk` authenticates
from a pre-shared secret with no PIN round. That matters for sequencing, because the PAKE
in step 4 is the one piece of this with no dependency to reach for.

### What the crates cover, and the one gap

- **Noise: covered.** The pattern is `Noise_KKpsk2_25519_{ChaChaPoly,AESGCM}_SHA256`. The
  `snow` crate implements every Noise pattern except the `fallback` modifier, and supports
  25519, both AEADs and SHA256 in its default resolver. Note that the suite is a negotiated
  choice, not a fixed one — `aiosendspin` gained AES-GCM alongside ChaChaPoly in #318 and
  carries `NoiseCipherSuite` as a client setting, so this should be a parameter here from
  the start rather than a constant to generalize later.
- **CPace: no usable dependency.** The two PIN methods wrap the delivered PSK under the
  output of a CPace PAKE. `aiosendspin` uses `cpace-py`, in the `CPACE-X25519-SHA512` suite
  of `draft-irtf-cfrg-cpace` **revision 21**, with the draft's optional explicit mutual key
  confirmation. The only `cpace` crate on crates.io is a single 0.1.0 published in May 2020
  — years before revision 21, and unmaintained since. Assume it is wire-incompatible and
  budget for implementing CPace against the draft directly. This is bounded rather than
  open-ended: the draft ships `testvectors.json`, `cpace-py` passes all of it including the
  invalid-point rejection set, and those same vectors validate a Rust implementation.

### Moved since this note was first written

`aiosendspin` is not a fixed target. Since 2026-07-31 it has taken AES-GCM and a
stalled-connection fix (#318), pairing-abort notifications for clients (#320), pairing
record replacement and PIN validation fixes (#317), and integer coercion on serialization
(#311, a mashumaro concern with no analogue in a typed Rust encoder). The spec is moving
too — the four most recent commits there are all pairing changes. Re-read both before
starting a step, not just this note.

## Open: smaller things, deliberately left

- **`visualizer@_draft_r1`.** The older visualizer wire, which uses `batch_max` where v1
  uses `rate_max` and moves `rate_max` inside the spectrum object. `aiosendspin` carries
  both wires; this crate speaks v1 only. Worth adding if a server on the old wire needs to
  be supported, and not before — it is a second shape for the same messages, and
  `stream/start.visualizer` would have to become a union to hold either.
- **Legacy support-key aliases.** `aiosendspin` accepts unversioned `player_support`
  spellings and records that it had to. That is a server-side courtesy to old clients;
  this crate emits the versioned keys and has nothing to be lenient about.
- **`unlisted_support_roles`, `legacy_support_keys_used`.** Diagnostics a server records
  about a client's hello. Not wire fields, and not a client's business.
