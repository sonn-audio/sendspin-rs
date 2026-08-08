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
from aiosendspin.models.types import Roles
from aiosendspin.noise import Identity
from aiosendspin.noise.session import NoiseCipherSuite
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

    # The metadata role on purpose: it needs no support object, so this checks the connection
    # rather than the negotiation of a role the server does not implement yet.
    client = SendspinClient(
        Identity.generate(),
        "aiosendspin Interop",
        [Roles.METADATA],
        pairing_store=InMemoryClientPairingStore(),
        cipher_suite=SUITE,
    )
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
            print("CLIENT_INTEROP_OK", flush=True)
            await client.disconnect()
            return 0
        await asyncio.sleep(0.1)

    print(f"NOT_SYNCHRONIZED within {SYNC_TIMEOUT}s", flush=True)
    await client.disconnect()
    return 1


if __name__ == "__main__":
    try:
        sys.exit(asyncio.run(main()))
    except KeyboardInterrupt:
        sys.exit(130)
