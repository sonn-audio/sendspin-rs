"""Two reference clients on one Rust server, to prove they are actually in sync.

Every other check in this directory can be satisfied by a server that is subtly broken in the
one way multi-room cares about. A single client cannot tell whether the audio it receives is
*its own* stream or a shared one — and before the group model this server pulled its audio
source once per connection, so two clients would each have been handed a different slice of the
track, on a different timeline, and both would have reported themselves perfectly healthy.

So this runs two clients against one server and compares what they received, chunk by chunk.
The assertion is not "both got audio" but "both got the *same* audio at the *same* playback
timestamps", which is the only thing that makes two speakers in two rooms sound like one
system.

The second client joins deliberately late. That covers the case a single-client check cannot
reach at all: a speaker added to a group mid-track has to be handed the format of the stream
already in flight and then fall into step on the existing timeline, rather than restarting the
track or being left unable to decode what arrives.

Prints SYNC_OK when the overlapping chunks match.
"""

from __future__ import annotations

import asyncio
import hashlib
import os
import sys
from dataclasses import replace

from aiosendspin.client.client import SendspinClient
from aiosendspin.models.player import ClientHelloPlayerSupport, SupportedAudioFormat
from aiosendspin.models.types import AudioCodec, PlayerCommand, Roles
from aiosendspin.noise import Identity
from aiosendspin.noise.trust_store import InMemoryClientPairingStore

URL = sys.argv[1] if len(sys.argv) > 1 else "ws://127.0.0.1:8927/sendspin"

SYNC_TIMEOUT = float(os.environ.get("SYNC_TIMEOUT", "20"))
PLAY_SECONDS = float(os.environ.get("PLAY_SECONDS", "4"))
# How long the second client waits before joining, so it lands mid-stream.
LATE_JOIN_DELAY = float(os.environ.get("LATE_JOIN_DELAY", "1.0"))


async def run_client(label: str, delay: float, chunks: list[tuple[int, str]]) -> int:
    """Connect one client and record a fingerprint of every chunk it is handed."""
    await asyncio.sleep(delay)

    store = InMemoryClientPairingStore()
    await store.store_pairing_config(
        replace(await store.get_pairing_config(), unpaired_access_enabled=True)
    )

    client = SendspinClient(
        Identity.generate(),
        f"aiosendspin {label}",
        [Roles.PLAYER],
        pairing_store=store,
        player_support=ClientHelloPlayerSupport(
            supported_formats=[
                SupportedAudioFormat(
                    codec=AudioCodec.PCM, channels=2, sample_rate=48000, bit_depth=16
                )
            ],
            buffer_capacity=50 * 1024 * 1024,
            supported_commands=[PlayerCommand.VOLUME, PlayerCommand.MUTE],
        ),
    )

    # The timestamp *and* a hash of the payload. Comparing only timestamps would pass for a
    # server that stamped two different tracks identically; comparing only payloads would pass
    # for one that sent the same audio to be played at different moments. Multi-room needs both
    # to match, so both are recorded.
    def on_chunk(timestamp_us: int, data: bytes, _fmt: object) -> None:
        chunks.append((timestamp_us, hashlib.md5(data).hexdigest()))

    client.add_audio_chunk_listener(on_chunk)

    try:
        await client.connect(URL)
    except Exception as exc:  # noqa: BLE001 - whatever it raised is the finding
        print(f"{label}_CONNECT_FAILED={type(exc).__name__}: {exc}", flush=True)
        return 1

    deadline = asyncio.get_running_loop().time() + SYNC_TIMEOUT
    while asyncio.get_running_loop().time() < deadline:
        if client.is_time_synchronized():
            break
        await asyncio.sleep(0.1)
    else:
        print(f"{label}_NOT_SYNCHRONIZED", flush=True)
        await client.disconnect()
        return 1

    await asyncio.sleep(PLAY_SECONDS - delay)
    print(f"{label} chunks={len(chunks)}", flush=True)
    await client.disconnect()
    return 0


async def main() -> int:
    """Run both clients, then compare what they were sent."""
    first: list[tuple[int, str]] = []
    second: list[tuple[int, str]] = []

    codes = await asyncio.gather(
        run_client("A", 0.0, first),
        run_client("B", LATE_JOIN_DELAY, second),
    )
    if any(codes):
        return 1

    if not first or not second:
        print("NO_AUDIO", flush=True)
        return 1

    # The late joiner started somewhere inside the first client's run. Line the two up by
    # timestamp rather than by index: they are the same timeline, so the shared region is
    # whatever both actually saw, and comparing by position would only ever compare A's start
    # against B's start.
    by_timestamp = dict(first)
    overlap = [(ts, digest) for ts, digest in second if ts in by_timestamp]
    if not overlap:
        print(
            f"NO_OVERLAP first={first[0][0]}..{first[-1][0]} "
            f"second={second[0][0]}..{second[-1][0]}",
            flush=True,
        )
        return 1

    mismatched = [ts for ts, digest in overlap if by_timestamp[ts] != digest]
    if mismatched:
        print(
            f"DESYNC {len(mismatched)}/{len(overlap)} shared timestamps carried "
            f"different audio; first at {mismatched[0]}",
            flush=True,
        )
        return 1

    # A late joiner that received the whole track from the beginning would mean the server
    # restarted the stream for it rather than seating it in the one already playing.
    if second[0][0] <= first[0][0]:
        print(
            f"RESTARTED the late joiner began at {second[0][0]}, at or before the "
            f"first client's {first[0][0]}",
            flush=True,
        )
        return 1

    print(f"OVERLAP={len(overlap)} chunks identical across both clients", flush=True)
    print(f"LATE_JOIN offset={second[0][0] - first[0][0]}us into the stream", flush=True)
    print("SYNC_OK", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
