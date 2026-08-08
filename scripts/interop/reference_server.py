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
from aiosendspin.server.roles.source import (
    SourceSignalChangedEvent,
    SourceStreamEndedEvent,
    SourceStreamStartedEvent,
)
from aiosendspin.server.server import SendspinServer

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8927
# A fixed private key, so restarting the harness keeps the same server_id.
SERVER_PRIVATE = bytes(range(32))

# Seconds of capture to accept before asking the source to stop, so the run also
# exercises server/command(stop) -> client_stream/end rather than only the start path.
SOURCE_STOP_AFTER = float(os.environ.get("SOURCE_STOP_AFTER", "3"))


async def _drain_source(handle: object, stats: dict[str, int]) -> None:
    """Consume the decoded PCM the server hands back, and report what arrived.

    The byte count is the point: it can only be non-zero if the chunk header, the
    binary message type and the server-clock timestamp were all read the way the
    reference reads them.
    """
    async for pcm, timestamp_us in handle:  # type: ignore[attr-defined]
        stats["chunks"] += 1
        stats["bytes"] += len(pcm)
        stats["last_ts"] = timestamp_us
        if stats["chunks"] == 1:
            print(f"SOURCE_FIRST_CHUNK bytes={len(pcm)} ts={timestamp_us}", flush=True)
    print(f"SOURCE_DRAINED chunks={stats['chunks']} bytes={stats['bytes']}", flush=True)


def _drive_source(client: object, loop: asyncio.AbstractEventLoop) -> None:
    """Ask a source client to stream, and watch what the role decodes out of it.

    `source@v1` only activates on a long-term paired connection, so this fires after
    pairing has moved the client off the Sentinel PSK.
    """
    role = client.role("source@v1")  # type: ignore[attr-defined]
    if role is None:
        return
    stats = {"chunks": 0, "bytes": 0, "last_ts": 0}

    def _on_event(_client: object, event: object) -> None:
        if isinstance(event, SourceStreamStartedEvent):
            fmt = event.audio_format
            print(
                f"SOURCE_STREAM_STARTED codec_pcm {fmt.sample_rate}Hz "
                f"{fmt.bit_depth}bit {fmt.channels}ch",
                flush=True,
            )
            loop.create_task(_drain_source(event.handle, stats))
            loop.create_task(_stop_later(role, stats))
        elif isinstance(event, SourceStreamEndedEvent):
            print(
                f"SOURCE_STREAM_ENDED chunks={stats['chunks']} bytes={stats['bytes']}",
                flush=True,
            )
            if stats["chunks"] > 0:
                print("SOURCE_INTEROP_OK", flush=True)
        elif isinstance(event, SourceSignalChangedEvent):
            print(f"SOURCE_SIGNAL={event.signal.value}", flush=True)

    client.add_event_listener(_on_event)  # type: ignore[attr-defined]
    print(f"SOURCE_START_REQUESTED={client.client_id}", flush=True)  # type: ignore[attr-defined]
    role.request_start()


async def _stop_later(role: object, stats: dict[str, int]) -> None:
    """Exercise the stop path once enough capture has arrived to prove the start path."""
    await asyncio.sleep(SOURCE_STOP_AFTER)
    print(f"SOURCE_STOP_REQUESTED after={SOURCE_STOP_AFTER}s chunks={stats['chunks']}", flush=True)
    role.request_stop()  # type: ignore[attr-defined]


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
    sourced: set[str] = set()
    reported_roles: dict[str, list[str]] = {}
    try:
        while True:
            await asyncio.sleep(1)
            clients = getattr(server, "clients", None)
            ids = [getattr(c, "client_id", None) for c in clients or []]
            if ids:
                print(f"CLIENTS={ids}", flush=True)
            # A source client that reconnects on its long-term PSK gets the role
            # activated; drive capture as soon as that happens.
            for client in clients or []:
                cid = getattr(client, "client_id", None)
                if cid is None:
                    continue
                roles = list(getattr(client, "active_role_ids", []) or [])
                if reported_roles.get(cid) != roles:
                    reported_roles[cid] = roles
                    print(f"ROLES {cid}={roles}", flush=True)
                if cid not in sourced and "source@v1" in roles:
                    sourced.add(cid)
                    _drive_source(client, loop)
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
