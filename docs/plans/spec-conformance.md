# Conformance with the Sendspin spec

> Fork-internal tracking. Not part of any upstream PR — kept here so the picture survives
> between work sessions.

Where this crate stands against [`Sendspin/spec`](https://github.com/Sendspin/spec) at
`d5f64a6` (2026-08-05), checked against the `sonn` branch — `main` plus the ten parity
branches — and against the sync fix that landed on top of it. See [parity-with-aiosendspin.md](parity-with-aiosendspin.md) for the comparison
against the Python client specifically.

The spec is the measure, with one qualification worth stating up front, because it decides
several entries below. New protocol features land in `aiosendspin` first and the spec is
written up to match afterwards, so "not in the spec yet" and "wrong" are different findings.
Where the spec has *moved past* us we are behind and should catch up; where `aiosendspin` has
moved past the *spec*, following it is how we stay current rather than a defect. What the
spec settles unambiguously is the third case: a rule it states and we break.

The short answer is no, not yet. One whole subsystem is missing, and a handful of smaller
divergences remain — some deliberate. Two audio-quality `MUST`s were being broken outright;
those are fixed.

## 1. The transport — not on spec at all

`connection.md` is unambiguous: "The WebSocket transport MUST be plain `ws://`.
Confidentiality and integrity are provided end to end by the Noise layer inside the
WebSocket payloads." There is no unencrypted mode in the spec, no transition mode, and no
opt-out. The handshake this crate speaks is not a supported variant of the current
protocol; it reaches current servers only because they still emit the legacy
`server/hello`.

That accounts for the 20 absent message types listed in the parity note. Two spec
requirements hang off the same subsystem and are easy to miss when scoping it:

- **Fragmentation.** Noise caps a transport message at 65535 bytes, so `messaging.md`
  defines fragment frames (types `2` and `3`) with a single in-flight message per
  direction. `BinaryFrame::from_bytes` currently returns `Unknown` for both. Malformed
  sequences — a fragment-end with nothing in flight, a non-fragment frame mid-message, an
  `orig_type` of `2` or `3` — are protocol errors where the receiver MUST close the
  connection. None of this can be exercised before Noise lands, because without it there
  is no 65535-byte limit to hit, but it belongs in the same work item.
- **Binary framing moves inside the AEAD.** Post-handshake, the type byte is the first
  byte of the decrypted plaintext rather than of the WebSocket frame. The binary ID
  assignments themselves are correct today (player `4`, artwork `8`–`11`, source `12`,
  visualizer `16`–`23`); it is the layer they sit in that changes.

## 2. Playback synchronization — two `MUST`s, now fixed

`roles/player/v1.md` sets two hard bounds on correction:

> **Maximum speed deviation:** The effective playback speed MUST stay within ±0.5% of
> normal speed, measured as a sliding average over 150 ms.

> **Accuracy floor:** In steady state, implementations MUST keep this error within ±1 ms.
> **Accuracy target:** Implementations SHOULD aim for ±0.5 ms.

`CorrectionPlanner::new` missed both. What it used, and what it uses now:

| Field | Was | Now | Spec |
| --- | --- | --- | --- |
| `max_speed_correction` | `0.04` (4%) | `0.005` | ±0.5% `MUST` |
| `engage_us` | `3_000` | `400` | under the ±0.5 ms target |
| `deadband_us` | `1_500` | `100` | ~100 µs suggested |

The thresholds were the more serious pair. Engaging at 3 ms and releasing at 1.5 ms put the
steady-state band at 1.5–3 ms — **entirely outside** the ±1 ms floor, so a player behaving
exactly as designed was out of spec. `error_us` at the call site is the filtered error
between `playback_instant` and `expected_instant`, which is the quantity the spec bounds,
so this was a direct comparison rather than an approximation. `max_speed_correction` bit
less often, since the rate only reaches its cap while a large error is being worked off,
but 4% is far past where a correction stays masked.

The planner's shape is unchanged and did not need changing: proportional rate, hysteresis,
reanchor above a threshold is a legitimate alternative to the spec's suggested
delete/insert strategy, which the spec explicitly invites ("Other strategies are allowed
and encouraged as long as they meet the rules in this section"). Only the constants were
wrong, and they now derive from named constants that cite the rule they encode.

The new defaults aim at the `SHOULD` target rather than stopping at the `MUST` floor,
which is the deliberate position: this implementation should have headroom the reference
implementations do not.

Tight thresholds are only safe because of what already sits in front of the planner, and
that is worth understanding before touching either number again. Presentation-latency noise
is one-sided — extra queued padding can make a reading later, never earlier — so
`SyncErrorFilter` takes a windowed **minimum** over 101 callbacks rather than an average,
and `EngageGate` requires ~50 consecutive correcting plans over a warm filter before a
single frame is actually dropped or repeated. The 3 ms threshold was a backend
accommodation (the comments record a 2 ms↔12 ms alternation on shared-mode WASAPI) for
noise the floor filter is specifically built to remove. `CorrectionPlanner::with_thresholds`
now exists for a backend that genuinely cannot settle at the defaults; it does not relax the
speed cap.

**Still open: `reanchor_threshold_us` is `500_000`.** Above the engage threshold and below
500 ms, the planner soft-corrects. At the ±0.5% cap, working off a 400 ms error takes ~80
seconds, all of it outside the ±1 ms floor. The spec's model is different: soft correction
handles drift, and anything "too large to correct smoothly" is a one-shot snap. Self-
consistency with `target_seconds: 2.0` puts the crossover near 10 ms — beyond that, the rate
saturates and the 2-second target is missed anyway.

This one was deliberately left alone, because it trades one `MUST` against another. Reanchor
plans bypass `EngageGate` by design, so lowering the threshold makes hard discontinuities
more frequent, and the spec says those `MUST` be rare. Picking the crossover is a listening
decision on real hardware, not one to make from the spec text alone.

## 3. `server/state` and `group/update` deltas are not merged

`messaging.md` requires the client to merge: "Only include fields that have changed. The
client will merge these updates into existing state. A leaf field set to `null` should be
cleared from the client's state; a whole role object set to `null` clears all of that
role's state." `group/update` carries the same delta rule.

Two things are missing:

- **No merge layer.** Each message is handed to the consumer raw, and the crate keeps no
  accumulated `metadata` / `controller` / `color` / group state. Every consumer has to
  rebuild the same accumulator, and none of them can do it correctly, because —
- **`null` and absent are indistinguishable.** `Option<T>` collapses `"title": null`
  (clear this field) and an omitted `title` (retain the last value) into `None`. The
  nullable leaves and the role objects both need `Option<Option<T>>` with
  `#[serde(default)]` before a correct merge is even expressible.

The merge is shallow by spec — nested objects like `metadata.progress` are replaced whole,
never deep-merged — so the accumulator itself is small. The type change is the part that
touches the public API.

## 4. `visualizer` slot 21 (`pitch`) — ahead of the spec on purpose

`roles/visualizer/v1.md` enumerates five types — `beat`, `loudness`, `f_peak`, `peak`,
`spectrum` — and reserves the rest: "Message types `21`, `22`, and `23` are reserved for
future visualizer types within the role's 16-23 allocation and must not be used by
implementations."

`aiosendspin` ships `VISUALIZATION_PITCH = 21` and a `"pitch"` type anyway, and there is no
spec PR in flight to legitimize it yet. This crate follows the Python here, deliberately:
the reference implementation is where this protocol's changes land first, and the spec has
consistently been written up to match it afterwards. Slot 21 is where `pitch` will be when
it is written down, and a client that waits for the prose is a client that cannot render
pitch against the servers already sending it.

So this is a known divergence and an accepted one, in both directions — accepting type 21
and advertising `"pitch"` in `visualizer@v1_support.types`. Recorded here so it reads as a
decision rather than an oversight, and so it can be revisited if the spec ever assigns 21
to something else. That is the actual risk being taken, and it is small: the reservation
means nothing else can claim the slot without a spec change that would break `aiosendspin`
too.

Note that this cuts the other way as well: it is the same reasoning that puts `source@v1` in
this crate ahead of the Python (see the parity note), just with the roles reversed.

## 5. Fields sent that the spec does not define

The same forward-compatibility rule bites twice more, in both cases deliberately:

- `client/hello` carries `client_id` and `version`. The spec moved both to `client/init`.
- `client/state` carries the legacy `state` enum alongside `available`. The spec has only
  `available`.

Both are transition-mode concessions that keep older servers working, and both stop being
needed the moment the Noise path lands. Leaving them is the right call for now; they are
listed here so they are removed as part of that work rather than surviving it by
accident.

## 6. Smaller divergences

- **`PlayerV1Support::buffer_capacity` is documented as "Buffer capacity in chunks."** The
  spec defines it as a byte count, and the value actually sent is bytes
  (`client_builder.rs` uses `50 * 1024 * 1024`), so this is a doc-comment bug rather than a
  wire bug — but a misleading one, since it invites a caller to pass a chunk count. Worth
  a second look at the 50 MB default too: the spec treats `buffer_capacity` as a hard
  per-player cap that servers fill toward on buffered streams.
- **Stringly-typed fields.** `PlayerV1Support::supported_commands` is `Vec<String>` where
  the spec enumerates `'volume' | 'mute'`, and `AudioFormatSpec::codec` is `String` where
  it enumerates `'opus' | 'flac' | 'pcm'`. `ControllerState::supported_commands` is the
  same. Nothing invalid goes out today, but nothing stops it either.
- **`PlaybackState::Paused`** is not in the spec, which defines `'playing' | 'stopped'`
  for `group/update`. Accepting it is correct leniency — `aiosendspin` sends it — and the
  crate never sends it. No change needed; noted so it is not mistaken for a spec value.

## What already conforms

Worth recording, so a future pass does not re-derive it: binary message IDs and their role
allocations; all eight `client/goodbye` reasons; the full 15-command controller surface
including `seek` / `seek_relative` with `seek_max_ms`; the `color` and `metadata` state
objects field for field; the `^1.5` perceptual volume curve with a 20 ms anti-click ramp;
`static_delay_ms` clamped to 0–5000 and subtracted from server timestamps before
scheduling; and the per-codec framing rules for PCM, FLAC and Opus.
