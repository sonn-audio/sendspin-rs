"""Run an encrypted aiosendspin server for Rust interop validation.

Starts the reference implementation's server on 127.0.0.1 with encryption mandatory
(allow_unencrypted stays False), bypassing start_server() so zeroconf never enters the
picture. Prints the server_id so the Rust side can address it, then reports every client
that completes a handshake.
"""

from __future__ import annotations

import asyncio
import base64
import logging
import os
import sys

from aiohttp import web

from aiosendspin.models.types import PairMethod
from aiosendspin.noise import Identity, InMemoryServerPairingStore
from aiosendspin.noise.pairing import PairingAttempt
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

    # PAIR_WITH=<client_id>:<pairing_psk_b64url> drives a real Pairing PSK pairing as soon
    # as that client connects, which is what an operator pasting a pairing token does.
    pair_spec = os.environ.get("PAIR_WITH")
    pair_client, pair_psk = (None, None)
    if pair_spec:
        cid, _, psk_b64 = pair_spec.partition(":")
        pair_client = cid
        pair_psk = base64.urlsafe_b64decode(psk_b64 + "=" * (-len(psk_b64) % 4))
        print(f"WILL_PAIR_WITH={pair_client}", flush=True)

    paired = False
    try:
        while True:
            await asyncio.sleep(1)
            clients = getattr(server, "clients", None)
            ids = [getattr(c, "client_id", None) for c in clients or []]
            if ids:
                print(f"CLIENTS={ids}", flush=True)
            if pair_client and not paired and pair_client in ids:
                paired = True
                print("PAIRING_START", flush=True)
                try:
                    await server.initiate_pairing(
                        pair_client,
                        PairingAttempt(method=PairMethod.PAIRING_PSK, pairing_psk=pair_psk),
                    )
                    print("PAIRING_OK", flush=True)
                except Exception as exc:  # noqa: BLE001 - report whatever the server raised
                    print(f"PAIRING_FAILED={type(exc).__name__}: {exc}", flush=True)
    except asyncio.CancelledError:
        pass
    finally:
        await runner.cleanup()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
