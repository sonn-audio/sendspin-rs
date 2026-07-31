# Parity with the Python implementation

A field-by-field comparison of this crate against `aiosendspin`, so the remaining
differences are a list someone can work through rather than something each contributor
rediscovers. Everything here is about the *client* side; `aiosendspin` also ships a full
server, which this crate does not aim at.

Read the columns as: does the Rust client understand what a current Python server sends,
and can it say what a current Python client says?

## Closed

These were real differences and are addressed, each on its own branch:

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

A client that speaks the unencrypted transition-mode handshake talks to a current server
today: the server keeps sending the legacy `server/hello`, with `server_id`, `version`,
`active_roles` and `connection_reason` in it. So this is a feature to add, not a break to
repair, and it is worth doing as its own sequence of changes rather than folded into
anything above.

Suggested order, each independently useful:

1. Noise transport (`client/init`, handshake, encrypted frame wrapping) with pairing
   disabled — an encrypted session against a server that requires no pairing.
2. `server/activate`, role activation after the handshake, and arbitration by activity.
3. A trust-store trait plus an in-memory implementation, and the PSK pairing method.
4. PIN methods, lockout, and the abort reasons.
5. `management/*` and `server/unpair` on top of the trust store.

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
