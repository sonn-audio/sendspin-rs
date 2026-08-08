"""Run an aiosendspin client against the Rust server, for interop validation.

The mirror of `reference_server.py`, and the point at which the harness inverts: every other
check in this directory drives the reference implementation's *server* and asks whether this
crate's client can talk to it. This one drives the reference implementation's *client* and asks
the same question of the Rust server.

Prints CLIENT_INTEROP_OK once the connection is up and the clock has converged, which is the
milestone worth having on its own — a client that reaches `is_time_synchronized()` has agreed
with the server about the handshake, the prologue, the framing, the hello sequence and the
clock exchange, and every one of those is a place a fresh implementation gets it wrong.
"""

from __future__ import annotations

import asyncio
import logging
import os
import sys

from aiosendspin.client.client import SendspinClient
from aiosendspin.models.player import ClientHelloPlayerSupport, SupportedAudioFormat
from aiosendspin.models.types import AudioCodec, PlayerCommand, Roles
from aiosendspin.noise import Identity
from aiosendspin.noise.session import NoiseCipherSuite
from dataclasses import replace

from aiosendspin.noise.trust_store import InMemoryClientPairingStore

URL = sys.argv[1] if len(sys.argv) > 1 else "ws://127.0.0.1:8927/sendspin"

# How long to wait for the clock filter to converge before giving up. Generous: convergence
# needs several exchanges, and a loaded CI machine is slower than a desk.
SYNC_TIMEOUT = float(os.environ.get("SYNC_TIMEOUT", "20"))

# SUITE=aes runs the other defined cipher suite. Both have to work: a server that only ever
# saw one of them has tested half its handshake.
SUITE = (
    NoiseCipherSuite.AESGCM
    if os.environ.get("SUITE", "").lower() in {"aes", "aesgcm"}
    else NoiseCipherSuite.CHACHAPOLY
)


async def main() -> int:
    """Connect, wait for clock sync, and report what happened."""
    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
        stream=sys.stderr,
    )

    # The player role, so the run covers negotiation and the stream rather than only the
    # connection. PCM 16-bit is what the Rust server sends today; a client that advertised
    # something else would be testing the server's transcoding, which does not exist yet.
    # Unpaired access on, or the client refuses an activation from a Sentinel-keyed server with
    # `goodbye(pairing_required)` — correctly, since that key authenticates nobody. Turning it
    # on here is the operator decision a real device makes once, and it is what lets this run
    # reach the stream at all before the server can pair.
    store = InMemoryClientPairingStore()
    await store.store_pairing_config(
        replace(await store.get_pairing_config(), unpaired_access_enabled=True)
    )

    client = SendspinClient(
        Identity.generate(),
        "aiosendspin Interop",
        [Roles.PLAYER],
        pairing_store=store,
        cipher_suite=SUITE,
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

    # Counted rather than played: there is no sound card in a harness, and what is under test
    # is that the chunks arrive and parse at all.
    #
    # Lead time is deliberately *not* reported here. The reference client exposes no
    # server-clock reading on its public surface, and a number this script cannot measure is
    # worse than one it does not print — the Rust client's own `--player` harness measures it
    # from the other side, where the clock is reachable.
    stats = {"chunks": 0, "bytes": 0}

    def on_stream_start(message: object) -> None:
        print(f"STREAM_START={message.payload.player}", flush=True)

    def on_chunk(_timestamp_us: int, data: bytes, _fmt: object) -> None:
        stats["chunks"] += 1
        stats["bytes"] += len(data)

    client.add_stream_start_listener(on_stream_start)
    client.add_audio_chunk_listener(on_chunk)
    print(f"SUITE={SUITE.value}", flush=True)
    print(f"CONNECTING={URL}", flush=True)
    try:
        await client.connect(URL)
    except Exception as exc:  # noqa: BLE001 - whatever it raised is the finding
        print(f"CONNECT_FAILED={type(exc).__name__}: {exc}", flush=True)
        return 1

    info = getattr(client, "server_info", None)
    print(
        f"CONNECTED server_id={getattr(info, 'server_id', None)} "
        f"name={getattr(info, 'name', None)!r}",
        flush=True,
    )

    # The real assertion. Reaching this means both sides derived the same transport keys from
    # the same prologue, framed identically, agreed on the hello sequence, and exchanged enough
    # clock samples for the filter to settle.
    deadline = asyncio.get_running_loop().time() + SYNC_TIMEOUT
    while asyncio.get_running_loop().time() < deadline:
        if client.is_time_synchronized():
            print("TIME_SYNCHRONIZED", flush=True)
            break
        await asyncio.sleep(0.1)
    else:
        print(f"NOT_SYNCHRONIZED within {SYNC_TIMEOUT}s", flush=True)
        await client.disconnect()
        return 1

    # PLAY_SECONDS>0 keeps the connection open so a stream can be received and counted.
    play_seconds = float(os.environ.get("PLAY_SECONDS", "0"))
    if play_seconds > 0:
        await asyncio.sleep(play_seconds)
        print(f"AUDIO chunks={stats['chunks']} bytes={stats['bytes']}", flush=True)
        if stats["chunks"] == 0:
            print("NO_AUDIO", flush=True)
            await client.disconnect()
            return 1

    print("CLIENT_INTEROP_OK", flush=True)
    await client.disconnect()
    return 0



if __name__ == "__main__":
    try:
        sys.exit(asyncio.run(main()))
    except KeyboardInterrupt:
        sys.exit(130)
