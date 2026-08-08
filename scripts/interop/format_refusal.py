"""A client that cannot decode what the server sends must not be made a player.

This server sends one fixed format and does not transcode. Granting `player@v1` to a client that
cannot decode it produces the worst kind of fault: the client reports itself healthy, the server
reports itself healthy, and no sound comes out. Nothing in either log says why.

So this connects a real reference client advertising 44.1 kHz — the server sends 48 kHz — and
checks it was *not* activated as a player. The connection itself must survive: an unusable format
is a client this server has no work for, not a protocol error, and hanging up on it would break a
client that is perfectly able to do something else.

Prints FORMAT_REFUSAL_OK when both hold.
"""

from __future__ import annotations

import asyncio
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
# Long enough that audio would certainly have arrived if the server had decided to send any.
LISTEN = float(os.environ.get("LISTEN", "2.0"))


async def main() -> int:
    """Offer a format the server does not send, and check what came back."""
    store = InMemoryClientPairingStore()
    await store.store_pairing_config(
        replace(await store.get_pairing_config(), unpaired_access_enabled=True)
    )

    client = SendspinClient(
        Identity.generate(),
        "aiosendspin Wrong Format",
        [Roles.PLAYER],
        pairing_store=store,
        player_support=ClientHelloPlayerSupport(
            # 44.1 kHz against a server sending 48 kHz. Deliberately a *near* miss: a codec this
            # server has never heard of would be refused by any implementation, while a sample
            # rate one step away is what a real device actually gets wrong, and what would play
            # at the wrong pitch rather than failing outright.
            supported_formats=[
                SupportedAudioFormat(
                    codec=AudioCodec.PCM, channels=2, sample_rate=44100, bit_depth=16
                )
            ],
            buffer_capacity=50 * 1024 * 1024,
            supported_commands=[PlayerCommand.VOLUME, PlayerCommand.MUTE],
        ),
    )

    chunks = {"count": 0}
    client.add_audio_chunk_listener(lambda *_: chunks.__setitem__("count", chunks["count"] + 1))

    try:
        await client.connect(URL)
    except Exception as exc:  # noqa: BLE001 - whatever it raised is the finding
        print(f"CONNECT_FAILED={type(exc).__name__}: {exc}", flush=True)
        return 1

    deadline = asyncio.get_running_loop().time() + SYNC_TIMEOUT
    while asyncio.get_running_loop().time() < deadline:
        if client.is_time_synchronized():
            break
        await asyncio.sleep(0.1)
    else:
        print("NOT_SYNCHRONIZED the connection did not survive an unusable format", flush=True)
        await client.disconnect()
        return 1
    print("CONNECTED and synchronized", flush=True)

    active = list(getattr(client, "active_roles", []) or [])
    print(f"ACTIVE_ROLES={active}", flush=True)
    if any("player" in str(role) for role in active):
        print("ACTIVATED_ANYWAY the server promised playback it cannot deliver", flush=True)
        await client.disconnect()
        return 1

    # The stronger check, because it does not depend on how the client exposes its roles: no
    # audio may arrive at all.
    await asyncio.sleep(LISTEN)
    print(f"CHUNKS={chunks['count']}", flush=True)
    if chunks["count"] != 0:
        print("AUDIO_SENT_ANYWAY the client was fed a format it cannot decode", flush=True)
        await client.disconnect()
        return 1

    print("FORMAT_REFUSAL_OK", flush=True)
    await client.disconnect()
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
