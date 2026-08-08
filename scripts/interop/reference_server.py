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
import math
import os
import struct
import sys

from aiohttp import web

from aiosendspin.models.management import (
    ManagementSetPairingConfigPayload,
    SetUnpairedAccessConfig,
)
from aiosendspin.models.types import PairMethod
from aiosendspin.noise import Identity, InMemoryServerPairingStore
from aiosendspin.noise.pairing import PairingAttempt
from aiosendspin.noise.trust_store import PskCategory
from aiosendspin.server.audio import AudioFormat
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

# The tone pushed to a player client, and its shape. Seconds rather than chunks because the
# client reports what it decoded in frames, and both sides have to name the same number.
PLAYER_SECONDS = float(os.environ.get("PLAYER_SECONDS", "3"))
SAMPLE_RATE = 48_000
CHANNELS = 2


# How long to wait for the client to publish its derived dynamic PIN before giving up. The
# server's own attempt timeout is 180s, so this stays well inside it.
PIN_FILE_TIMEOUT = float(os.environ.get("PIN_FILE_TIMEOUT", "30"))


async def _read_pin_file(path: str) -> str:
    """Poll ``path`` until the client writes the dynamic PIN it derived, and return it.

    This stands in for the operator, and it is the whole reason the dynamic flow needs a
    harness at all: the PIN travels the other way. The client derives it from the handshake
    hash and both nonces and shows it on the device; a human reads it off and types it into
    the server. A file is the cheapest way to carry a value out of one process and into the
    other without pretending either side computed it.
    """
    deadline = asyncio.get_running_loop().time() + PIN_FILE_TIMEOUT
    while asyncio.get_running_loop().time() < deadline:
        try:
            with open(path, encoding="ascii") as handle:
                pin = handle.read().strip()
        except FileNotFoundError:
            pin = ""
        if pin:
            print(f"PIN_FROM_FILE={pin}", flush=True)
            return pin
        await asyncio.sleep(0.05)
    msg = f"no PIN appeared at {path} within {PIN_FILE_TIMEOUT}s"
    raise TimeoutError(msg)


def _is_paired(server: object, client_id: str) -> bool:
    """Whether this client's live connection is keyed by a long-term PSK."""
    try:
        connection = server._connection_for(client_id)  # noqa: SLF001
    except (KeyError, AttributeError):
        return False
    psk = getattr(connection, "_noise_psk", None)
    return psk is not None and psk.category is PskCategory.LONG_TERM


async def _drive_management(server: object, client_id: str) -> None:
    """Run a real management session against a paired client, and report every answer.

    Management is gated on a long-term PSK at both ends, so this only runs after pairing.
    The sequence walks the whole surface: read the records and the config, provision a
    record, patch the config, then remove what it added — so a client that answers `ok` to
    everything but never actually writes is caught by the read that follows.
    """
    try:
        connection = server.enable_management(client_id)  # type: ignore[attr-defined]
    except (RuntimeError, KeyError) as exc:
        print(f"MGMT_ENABLE_FAILED={type(exc).__name__}: {exc}", flush=True)
        return
    print(f"MGMT_ENABLED={client_id}", flush=True)

    result, records, storage = await connection.list_records()
    print(f"MGMT_LIST result={result.value} records={len(records)} storage={storage}", flush=True)
    for record in records:
        print(f"  record psk_id={record.psk_id} server_id={record.server_id} used={record.used}")

    # A key this server does not otherwise use, so the add is unambiguous.
    provisioned = bytes(range(32, 64))
    result = await connection.add_record(psk=provisioned, server_id=None)
    print(f"MGMT_ADD result={result.value}", flush=True)

    # Re-adding the same key must collide rather than silently replace.
    repeat = await connection.add_record(psk=provisioned, server_id=None)
    print(f"MGMT_ADD_AGAIN result={repeat.value} (expect already_exists)", flush=True)

    result, data, storage = await connection.get_pairing_config()
    print(
        f"MGMT_GET_CONFIG result={result.value} pairing_psk={data.pairing_psk} "
        f"static_pin={data.static_pin} dynamic_pin={data.dynamic_pin} "
        f"unpaired_access={data.unpaired_access} storage={storage}",
        flush=True,
    )

    result = await connection.set_pairing_config(
        ManagementSetPairingConfigPayload(
            unpaired_access=SetUnpairedAccessConfig(enabled=True)
        )
    )
    print(f"MGMT_SET_CONFIG result={result.value}", flush=True)

    _, data, _ = await connection.get_pairing_config()
    applied = data.unpaired_access is not None and data.unpaired_access.enabled
    print(f"MGMT_PATCH_APPLIED={applied}", flush=True)

    result, records, _ = await connection.list_records()
    added = [r for r in records if r.server_id is None]
    print(f"MGMT_LIST_AFTER_ADD records={len(records)} shared={len(added)}", flush=True)

    if added:
        result = await connection.remove_record(psk_id=added[0].psk_id)
        print(f"MGMT_REMOVE result={result.value}", flush=True)

    missing = await connection.remove_record(psk_id="not-a-real-psk-id")
    print(f"MGMT_REMOVE_MISSING result={missing.value} (expect not_found)", flush=True)

    print("MGMT_INTEROP_OK", flush=True)


async def _drive_player(client: object, loop: asyncio.AbstractEventLoop) -> None:
    """Stream a known tone to a player client, and report exactly what was pushed.

    The mirror of `_drive_source`: there the reference decodes what Rust encodes, here it
    encodes what Rust has to decode. Which is the half that matters for a player — the
    server picks the codec from the client's advertised formats and re-encodes with ffmpeg,
    so a decoder that only agrees with this crate's own encoder fails right here.

    The PCM pushed is generated rather than read from a file so both sides can state the
    same expected frame count without shipping a fixture.
    """
    group = client.group  # type: ignore[attr-defined]
    fmt = AudioFormat(sample_rate=SAMPLE_RATE, bit_depth=16, channels=CHANNELS)
    frames_per_chunk = SAMPLE_RATE // 50  # 20 ms
    chunks = int(PLAYER_SECONDS * 50)

    stream = group.start_stream()
    print(
        f"PLAYER_STREAM_START chunks={chunks} frames_per_chunk={frames_per_chunk} "
        f"{SAMPLE_RATE}Hz 16bit {CHANNELS}ch",
        flush=True,
    )
    phase = 0.0
    pushed_frames = 0
    try:
        for _ in range(chunks):
            pcm, phase = _tone(phase, frames_per_chunk)
            stream.prepare_audio(pcm, fmt)
            await stream.commit_audio()
            pushed_frames += frames_per_chunk
            await stream.sleep_to_limit_buffer(max_buffer_us=1_000_000)
    finally:
        stream.stop()

    print(
        f"PLAYER_PUSHED frames={pushed_frames} bytes={pushed_frames * CHANNELS * 2}",
        flush=True,
    )
    print("PLAYER_INTEROP_OK", flush=True)


def _tone(phase: float, frames: int) -> tuple[bytes, float]:
    """One chunk of a 440 Hz tone: interleaved little-endian 16-bit, and the new phase.

    The same waveform the Rust source harness sends, so a run in either direction is
    listening to the same thing.
    """
    step = 2.0 * math.pi * 440.0 / SAMPLE_RATE
    out = bytearray()
    for _ in range(frames):
        sample = int(math.sin(phase) * 0.2 * 32767)
        out += struct.pack("<h", sample) * CHANNELS
        phase += step
    return bytes(out), phase


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
        # the encrypted transport, not to fall back to the legacy hello. ALLOW_UNENCRYPTED=1
        # opens the transition-mode path, which is the only way to exercise a client that has
        # no persisted identity yet — everything about encryption stays covered by the runs
        # that leave this alone.
        allow_unencrypted=os.environ.get("ALLOW_UNENCRYPTED") == "1",
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

    # PAIR_PIN=<client_id>:<pin> drives a static-PIN pairing instead, which runs the whole
    # CPace exchange rather than handing a key over on an already-authenticated channel.
    pin_spec = os.environ.get("PAIR_PIN")
    pin_client, static_pin = (None, None)
    if pin_spec:
        pin_client, _, static_pin = pin_spec.partition(":")
        print(f"WILL_PIN_PAIR_WITH={pin_client} pin={static_pin}", flush=True)

    # PAIR_DYNAMIC_PIN=<client_id>:<pin_file> drives a dynamic-PIN pairing, where the PIN is
    # derived by the *client* and read back off the device — so the server waits for the file
    # the client's --pin-file writes rather than being told a PIN up front.
    dynamic_spec = os.environ.get("PAIR_DYNAMIC_PIN")
    dynamic_client, dynamic_pin_file = (None, None)
    if dynamic_spec:
        dynamic_client, _, dynamic_pin_file = dynamic_spec.partition(":")
        print(
            f"WILL_DYNAMIC_PIN_PAIR_WITH={dynamic_client} pin_file={dynamic_pin_file}",
            flush=True,
        )

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
    played: set[str] = set()
    # DRIVE_PLAYER=1 streams a tone to any client that has player@v1 activated.
    drive_player = os.environ.get("DRIVE_PLAYER") == "1"
    managed: set[str] = set()
    reported_roles: dict[str, list[str]] = {}
    # DRIVE_MANAGEMENT=1 runs a management session once a client is on a long-term PSK.
    drive_management = os.environ.get("DRIVE_MANAGEMENT") == "1"
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
                if drive_player and cid not in played and "player@v1" in roles:
                    played.add(cid)
                    loop.create_task(_drive_player(client, loop))
                # Management needs a long-term PSK, which only exists after pairing — so
                # this fires on the *reconnect*, not on the connection that paired.
                if drive_management and cid not in managed and _is_paired(server, cid):
                    managed.add(cid)
                    loop.create_task(_drive_management(server, cid))
            if pin_client and not paired and pin_client in ids:
                paired = True
                print("PIN_PAIRING_START", flush=True)

                async def _pin() -> str:
                    return static_pin

                try:
                    await server.initiate_pairing(
                        pin_client,
                        PairingAttempt(method=PairMethod.STATIC_PIN, pin_provider=_pin),
                    )
                    print("PIN_PAIRING_OK", flush=True)
                except Exception as exc:  # noqa: BLE001 - report whatever the server raised
                    print(f"PIN_PAIRING_FAILED={type(exc).__name__}: {exc}", flush=True)
            if dynamic_client and not paired and dynamic_client in ids:
                paired = True
                print("DYNAMIC_PIN_PAIRING_START", flush=True)

                async def _dynamic_pin() -> str:
                    return await _read_pin_file(dynamic_pin_file)

                try:
                    await server.initiate_pairing(
                        dynamic_client,
                        PairingAttempt(
                            method=PairMethod.DYNAMIC_PIN, pin_provider=_dynamic_pin
                        ),
                    )
                    print("DYNAMIC_PIN_PAIRING_OK", flush=True)
                except Exception as exc:  # noqa: BLE001 - report whatever the server raised
                    print(
                        f"DYNAMIC_PIN_PAIRING_FAILED={type(exc).__name__}: {exc}", flush=True
                    )
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
