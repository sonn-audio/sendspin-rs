"""A reference controller client against the Rust server, for the command path.

The player checks in this directory only ever prove the server can *send*. This one proves it
can be told something: a real `aiosendspin` client activates `controller@v1`, sends a
`client/command`, and waits for the server's `server/state` to come back changed.

The refusal is checked as deliberately as the acceptance. `supported_commands` is a promise in
the same way an activated role is, and a server that quietly honours whatever it is sent leaves
a client no way to discover what it actually does. The example server advertises volume, mute,
play and pause and pointedly does *not* advertise `next` — it has one generated tone and nothing
to skip to — so sending `next` must change nothing at all.

Prints CONTROLLER_OK when both halves hold.
"""

from __future__ import annotations

import asyncio
import os
import sys
from dataclasses import replace

from aiosendspin.client.client import SendspinClient
from aiosendspin.models.types import MediaCommand, Roles
from aiosendspin.noise import Identity
from aiosendspin.noise.trust_store import InMemoryClientPairingStore

URL = sys.argv[1] if len(sys.argv) > 1 else "ws://127.0.0.1:8927/sendspin"
SYNC_TIMEOUT = float(os.environ.get("SYNC_TIMEOUT", "20"))
# How long to let a state update arrive before calling it absent. Generous: it is a round trip
# through the server, not a local call.
SETTLE = float(os.environ.get("SETTLE", "1.5"))


async def main() -> int:
    """Connect as a controller, send commands, and check what came back."""
    store = InMemoryClientPairingStore()
    await store.store_pairing_config(
        replace(await store.get_pairing_config(), unpaired_access_enabled=True)
    )

    client = SendspinClient(
        Identity.generate(),
        "aiosendspin Controller",
        [Roles.CONTROLLER],
        pairing_store=store,
    )

    # The listener is handed the whole `server/state` payload, so the controller half has to be
    # reached through it; a state that carries no controller object is not a controller update.
    states: list[object] = []

    def on_state(payload: object) -> None:
        controller = getattr(payload, "controller", None)
        if controller is not None and not isinstance(controller, type(None)):
            states.append(controller)

    client.add_controller_state_listener(on_state)

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
        print("NOT_SYNCHRONIZED", flush=True)
        await client.disconnect()
        return 1

    # The server states what it will honour before being asked anything, so a controller can
    # render only the buttons that do something.
    await asyncio.sleep(SETTLE)
    if not states:
        print("NO_CONTROLLER_STATE", flush=True)
        await client.disconnect()
        return 1
    # The commands arrive as enums, so compare on the wire value rather than the Python name.
    supported = [
        getattr(c, "value", c) for c in (getattr(states[-1], "supported_commands", []) or [])
    ]
    print(f"SUPPORTED={supported}", flush=True)
    if "next" in supported:
        print("UNEXPECTED the example advertised next; this check assumes it does not")
        await client.disconnect()
        return 1

    # --- the accepted command ---
    await client.send_group_command(MediaCommand.VOLUME, volume=42)
    await asyncio.sleep(SETTLE)
    volume = getattr(states[-1], "volume", None)
    print(f"VOLUME_AFTER_SET={volume}", flush=True)
    if volume != 42:
        print(f"VOLUME_NOT_APPLIED expected 42, state says {volume}", flush=True)
        await client.disconnect()
        return 1

    # --- the refused one ---
    # An unadvertised command must not move anything. Checked by count as well as by value: a
    # server that echoed a fresh state without changing the volume would still be answering a
    # command it never promised to accept.
    before = len(states)
    await client.send_group_command(MediaCommand.NEXT)
    await asyncio.sleep(SETTLE)
    if len(states) != before:
        print(
            f"UNADVERTISED_COMMAND_ANSWERED state changed {len(states) - before} time(s) "
            f"after a command the server never advertised",
            flush=True,
        )
        await client.disconnect()
        return 1

    # --- and the connection survived being told no ---
    # A refusal is not a protocol error: the client stays up and the next legal command works.
    await client.send_group_command(MediaCommand.MUTE, mute=True)
    await asyncio.sleep(SETTLE)
    muted = getattr(states[-1], "muted", None)
    print(f"MUTED_AFTER_REFUSAL={muted}", flush=True)
    if muted is not True:
        print("REFUSAL_BROKE_THE_CONNECTION a later legal command was not honoured", flush=True)
        await client.disconnect()
        return 1

    print("CONTROLLER_OK", flush=True)
    await client.disconnect()
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
