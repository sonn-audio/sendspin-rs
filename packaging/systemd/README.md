# Running as a dedicated player

For the case this is really built for: a Raspberry Pi wired to speakers, no screen, nobody
watching it. Two decisions are already made in the unit file and both are worth understanding
before you change them.

## Installing

```bash
cargo build --release --features cli,hardware-volume
sudo install -m 755 target/release/sendspin /usr/local/bin/sendspin
sudo install -m 644 packaging/systemd/sendspin.service /etc/systemd/system/
sudoedit /etc/systemd/system/sendspin.service   # edit ExecStart
sudo systemctl daemon-reload
sudo systemctl enable --now sendspin
journalctl -u sendspin -f
```

The `hardware-volume` feature is worth having on a Pi: with an I2S DAC HAT the card has a real
gain stage, and using it means the volume the server sets is applied without throwing away
bits. Add `--hardware-volume` to `ExecStart` to turn it on.

## Pairing it

Nothing plays until the server is allowed to. On first start the log says so:

```
No pairing yet and unpaired access is off, so no server will activate a role.
Pair this client, or pass --allow-unpaired.
```

Two ways out. Pair it properly — the client id is in the log, and the server's own pairing
flow takes it from there — or add `--allow-unpaired` if the network is one you trust and you
would rather not. Pairing survives restarts, because the key and the records are in
`StateDirectory`.

If the server offers dynamic-PIN pairing, the PIN a headless box would normally *show* is
written to the log instead:

```
journalctl -u sendspin -f | grep 'Pairing PIN'
```

## Why `Restart=always` and not `on-failure`

`on-failure` is the more common choice and it is wrong here. The daemon exits 0 when its work
ends cleanly, and `on-failure` would leave the speaker silent after exactly the kind of event
this is meant to survive. The daemon already reconnects on its own (`--reconnect-secs`, five
seconds by default, backing off to a minute); the unit's restart is the backstop for what it
cannot handle from the inside — the audio device disappearing, or a panic.

## Why the sandboxing is shaped this way

`DynamicUser=yes` gives the service its own transient account, and `StateDirectory=sendspin`
gives it one writable directory, created 0700 and owned by that account. The identity key and
the pairing records live there, and the daemon finds it through `$STATE_DIRECTORY` without
being told.

That combination is why `PrivateDevices=no` and `DeviceAllow=char-alsa rw` are both present:
the default sandbox would hide `/dev/snd`, and a player with no sound card is not a player.
`SupplementaryGroups=audio` is what makes it readable.

The real-time scheduling is deliberately modest. The audio callback has a deadline and missing
it is an audible click, so it wants priority — but a runaway real-time thread on a single-core
Pi locks the whole machine, which is why the priority is 10 and `LimitRTPRIO` caps it at 20
rather than handing over the top of the range.

## Checking it

```bash
systemctl status sendspin
sudo -u '#0' /usr/local/bin/sendspin audio-devices list   # which card, and its index
journalctl -u sendspin -b | grep -E 'Client id|Settings|Hardware volume|Stream starting'
```

A working player logs its client id, the settings directory and how many pairing records it
holds, then `Stream starting` with the negotiated codec once a server sends audio.
