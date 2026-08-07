"""Run an encrypted aiosendspin server for Rust interop validation.

Starts the reference implementation's server on 127.0.0.1 with encryption mandatory
(allow_unencrypted stays False), bypassing start_server() so zeroconf never enters the
picture. Prints the server_id so the Rust side can address it, then reports every client
that completes a handshake.
"""

from __future__ import annotations

import asyncio
import logging
import os
import sys

from aiohttp import web

from aiosendspin.noise import Identity, InMemoryServerPairingStore
from aiosendspin.server.server import SendspinServer

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8927
# A fixed private key, so restarting the harness keeps the same server_id.
SERVER_PRIVATE = bytes(range(32))


async def main() -> None:
    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
        stream=sys.stderr,
    )
    identity = Identity.from_private_bytes(SERVER_PRIVATE)
    loop = asyncio.get_running_loop()
    server = SendspinServer(
        loop=loop,
        identity=identity,
        server_name="Interop Reference Server",
        pairing_store=InMemoryServerPairingStore(),
        # Left at its default on purpose: the point is to prove the Rust client speaks
        # the encrypted transport, not to fall back to the legacy hello.
        allow_unencrypted=False,
    )

    # Optionally admit one unpaired client to playback, so a Sentinel-keyed handshake
    # can be activated rather than merely tolerated.
    trust_client = os.environ.get("TRUST_UNPAIRED_CLIENT_ID")
    if trust_client:
        await server.trust_unpaired(trust_client)
        print(f"TRUSTED_UNPAIRED={trust_client}", flush=True)

    app = server._create_web_application()  # noqa: SLF001 - avoids zeroconf
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, host="127.0.0.1", port=PORT)
    await site.start()

    print(f"SERVER_ID={identity.peer_id}", flush=True)
    print(f"URL=ws://127.0.0.1:{PORT}/sendspin", flush=True)
    print("READY", flush=True)

    try:
        while True:
            await asyncio.sleep(1)
            clients = getattr(server, "clients", None)
            if clients:
                print(f"CLIENTS={list(clients)}", flush=True)
    except asyncio.CancelledError:
        pass
    finally:
        await runner.cleanup()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
