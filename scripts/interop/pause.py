"""A controller pausing a player, over one Rust server.

The unit tests can prove the server *decided* to pause. Only a real client can prove the music
actually stopped, because a pause has to survive the send-ahead: at the moment the button is
pressed every player is already holding up to half a second of audio, stamped with times that
are about to arrive. A server that stops sending but never says `stream/clear` looks paused from
the inside and plays on from the outside.

So this runs two reference clients — one player, one controller — and counts chunks in windows.
Audio must be flowing, then stop within a window of the pause, then flow again after play.

Prints PAUSE_OK when all three hold.
"""

from __future__ import annotations

import asyncio
import os
import sys
from dataclasses import replace

from aiosendspin.client.client import SendspinClient
from aiosendspin.models.player import ClientHelloPlayerSupport, SupportedAudioFormat
from aiosendspin.models.types import AudioCodec, MediaCommand, PlayerCommand, Roles
from aiosendspin.noise import Identity
from aiosendspin.noise.trust_store import InMemoryClientPairingStore

URL = sys.argv[1] if len(sys.argv) > 1 else "ws://127.0.0.1:8927/sendspin"
SYNC_TIMEOUT = float(os.environ.get("SYNC_TIMEOUT", "20"))
# Long enough to cover the server's send-ahead, so a window that sees nothing really is silence
# rather than a gap between chunks.
WINDOW = float(os.environ.get("WINDOW", "1.5"))


async def connected(client: SendspinClient) -> bool:
    """Connect and wait for the clock filter to converge."""
    try:
        await client.connect(URL)
    except Exception as exc:  # noqa: BLE001 - whatever it raised is the finding
        print(f"CONNECT_FAILED={type(exc).__name__}: {exc}", flush=True)
        return False
    deadline = asyncio.get_running_loop().time() + SYNC_TIMEOUT
    while asyncio.get_running_loop().time() < deadline:
        if client.is_time_synchronized():
            return True
        await asyncio.sleep(0.1)
    print("NOT_SYNCHRONIZED", flush=True)
    return False


async def store() -> InMemoryClientPairingStore:
    """A pairing store that admits unpaired use, as a real device's operator would."""
    made = InMemoryClientPairingStore()
    await made.store_pairing_config(
        replace(await made.get_pairing_config(), unpaired_access_enabled=True)
    )
    return made


async def main() -> int:
    """Play, pause, resume, and check the audio followed."""
    counted = {"chunks": 0}

    player = SendspinClient(
        Identity.generate(),
        "aiosendspin Player",
        [Roles.PLAYER],
        pairing_store=await store(),
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
    player.add_audio_chunk_listener(lambda *_: counted.__setitem__("chunks", counted["chunks"] + 1))

    controller = SendspinClient(
        Identity.generate(),
        "aiosendspin Controller",
        [Roles.CONTROLLER],
        pairing_store=await store(),
    )

    if not await connected(player) or not await connected(controller):
        return 1

    def window() -> int:
        """Chunks received since the last call."""
        seen = counted["chunks"]
        counted["chunks"] = 0
        return seen

    await asyncio.sleep(WINDOW)
    playing = window()
    print(f"BEFORE_PAUSE={playing}", flush=True)
    if playing == 0:
        print("NO_AUDIO nothing was flowing, so a pause proves nothing", flush=True)
        return 1

    await controller.send_group_command(MediaCommand.PAUSE)
    # One window for the pause and the clear to land, then a second that must be silent. Split
    # in two so the chunks already in flight when the button was pressed are not counted
    # against the server.
    await asyncio.sleep(WINDOW)
    window()
    await asyncio.sleep(WINDOW)
    during = window()
    print(f"WHILE_PAUSED={during}", flush=True)
    if during != 0:
        print(f"STILL_PLAYING {during} chunks arrived while paused", flush=True)
        return 1

    await controller.send_group_command(MediaCommand.PLAY)
    await asyncio.sleep(WINDOW)
    after = window()
    print(f"AFTER_RESUME={after}", flush=True)
    if after == 0:
        print("NEVER_RESUMED the pause was permanent", flush=True)
        return 1

    print("PAUSE_OK", flush=True)
    await player.disconnect()
    await controller.disconnect()
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
