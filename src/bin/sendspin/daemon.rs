// ABOUTME: Turning the daemon's flags into a player configuration, and running the player the
// ABOUTME: library provides on it.

//! `sendspin daemon`.
//!
//! Two ways in, and the choice is the operator's: `--url` dials a server, and its absence
//! listens for one and advertises over mDNS. Neither the connection nor the playback is
//! implemented here — that is [`sendspin::player`], so that an application embedding the crate
//! gets the same player rather than a second copy of it. What is left is reading the flags,
//! resolving what they name, and reporting what could not be honoured.

use std::sync::Arc;
use std::time::Duration;

use sendspin::hooks::Hooks;
use sendspin::noise::file_store::{load_or_create_identity, FilePairingStore};
use sendspin::noise::trust_store::{PairingConfig, PairingStore};
use sendspin::player::{CodecOffer, Player, PlayerConfig};
use sendspin::protocol::client::EncryptionSettings;

use crate::cli::{default_product_name, hostname, DaemonArgs};

/// Run the daemon until the process is stopped.
pub async fn run(args: DaemonArgs) -> Result<(), Box<dyn std::error::Error>> {
    let static_delay = args.static_delay()?;
    let name = args.name.clone().unwrap_or_else(hostname);
    let product_name = args
        .product_name
        .clone()
        .unwrap_or_else(default_product_name);

    // Resolved before anything connects: a device that does not exist or a format it cannot
    // play is a startup error next to the flag that caused it, not silence once a server
    // starts sending.
    let device = args
        .audio_device
        .as_deref()
        .map(sendspin::audio::devices::find_device)
        .transpose()?;
    let format = args
        .audio_format
        .as_deref()
        .map(sendspin::audio::devices::parse_format)
        .transpose()?;
    if let (Some(device), Some(format)) = (device.as_ref(), format.as_ref()) {
        sendspin::audio::devices::verify_device_supports(device, format)?;
    }
    let hooks = Hooks::new(
        args.hook_start.clone(),
        args.hook_stop.clone(),
        args.hook_set_volume.as_deref(),
    )?;
    if hooks.volume_is_external() {
        log::info!("Volume is the --hook-set-volume script's; the audio path stays at unity");
    }
    // Underscore-prefixed because without the `hardware-volume` feature there is no field to
    // put it in; `open_mixer` still runs, to report the flag as unavailable rather than
    // ignoring it.
    let _mixer = open_mixer(&args, hooks.volume_is_external())?;
    if let Some(format) = format.as_ref() {
        log::info!(
            "Offering only {}:{}:{}:{}",
            format.codec,
            format.sample_rate,
            format.bit_depth,
            format.channels
        );
    }

    // The encrypted transport decides the `client_id` rather than taking one: it is the public
    // half of the stored keypair. Only transition mode leaves the name to the operator.
    let (client_id, encryption) = if args.no_encryption {
        if args.settings_dir.is_some() {
            log::warn!("--settings-dir is unused with --no-encryption: nothing is persisted");
        }
        let client_id = args
            .id
            .clone()
            .unwrap_or_else(|| format!("sendspin-rs-{}", hostname()));
        log::warn!(
            "Running in transition mode: no Noise layer, and no pairing. A server that \
             requires the encrypted transport will refuse this connection."
        );
        (client_id, None)
    } else {
        let dir = args.settings_dir()?;
        if args.id.is_some() {
            log::warn!(
                "--id is ignored under the encrypted transport: the client_id is the public \
                 half of the identity in {}",
                dir.display()
            );
        }
        let identity = load_or_create_identity(dir.join("identity.key"))?;
        let store = FilePairingStore::open(dir.join("pairing.json"))?;
        let records = store.records()?.len();
        log::info!("Settings: {} ({records} pairing record(s))", dir.display());

        // Written through rather than applied per run, so the choice is the operator's once
        // and not a flag they have to remember on every restart.
        let config = store.pairing_config()?;
        if args.allow_unpaired && !config.unpaired_access {
            store.set_pairing_config(PairingConfig {
                unpaired_access: true,
                ..config
            })?;
            log::info!("Unpaired access enabled and saved");
        } else if !store.pairing_config()?.unpaired_access && records == 0 {
            // Worth saying plainly: with no pairing and no unpaired access, a server activates
            // no roles at all, and a silent player looks like a broken one.
            log::warn!(
                "No pairing yet and unpaired access is off, so no server will activate a \
                 role. Pair this client, or pass --allow-unpaired."
            );
        }
        let mut settings = EncryptionSettings::with_store(identity.clone(), Arc::new(store));
        // The dynamic PIN has to reach the operator through this device, and only the host
        // application knows how. A daemon with no display or speaker has the log and nothing
        // else, so it says so rather than emitting a PIN nobody was told to look for.
        settings.emit_pin = Some(Arc::new(|pin: &str| {
            log::warn!("Pairing PIN (type this into the server): {pin}");
        }));
        (identity.client_id(), Some(settings))
    };

    log::info!("Client id: {client_id}");
    log::info!("Name: {name}");

    let rates = sendspin::audio::devices::output_rates(device.as_ref());
    if format.is_none() {
        log::info!(
            "Offering: {}",
            rates
                .iter()
                .map(|rate| format!("{rate}Hz"))
                .collect::<Vec<_>>()
                .join(", ")
        );
    }

    let config = PlayerConfig {
        name,
        client_id,
        product_name,
        manufacturer: args.manufacturer.clone(),
        encryption,
        static_delay,
        device,
        format,
        rates,
        hooks,
        #[cfg(all(feature = "hardware-volume", target_os = "linux"))]
        mixer: _mixer,
        // Spelled out rather than taken from `PlayerConfig::new`, whose defaults probe the
        // default output device — which this daemon has already done, for the device the
        // operator actually named. These five are settings an embedding application needs and
        // an operator has not asked for; giving them flags is a separate decision from making
        // them reachable.
        codecs: CodecOffer::all(),
        initial_volume: 100,
        initial_muted: false,
        buffer_ms: None,
        required_lead_time_ms: None,
    };
    let player = Player::new(config);

    match args.url.clone() {
        Some(url) => {
            // 0 opts out of reconnecting, for a foreground run where an exit is wanted.
            let reconnect = match args.reconnect_secs {
                0 => None,
                seconds => Some(Duration::from_secs(seconds)),
            };
            player.run_outbound(&url, reconnect).await
        }
        None => {
            if args.interface.is_some() {
                log::warn!(
                    "--interface restricts the listening socket only; the mDNS advertisement \
                     still goes out on every interface"
                );
            }
            player.run_inbound(&args.bind_address()).await
        }
    }
}

/// Open the card's mixer when `--hardware-volume` asked for one.
///
/// A card with no gain stage is common — plenty of DACs have none — so a mixer that will not
/// open is reported and stepped over rather than fatal: software attenuation still works, and
/// refusing to start would be the wrong trade for a device that can still play.
#[cfg(all(feature = "hardware-volume", target_os = "linux"))]
fn open_mixer(
    args: &DaemonArgs,
    volume_is_external: bool,
) -> Result<Option<Arc<sendspin::audio::mixer::Mixer>>, String> {
    let Some(card) = args.hardware_volume.as_deref() else {
        return Ok(None);
    };
    if volume_is_external {
        log::warn!("--hardware-volume is ignored: --hook-set-volume already owns the level");
        return Ok(None);
    }
    match sendspin::audio::mixer::Mixer::open(card) {
        Ok(mixer) => {
            log::info!("Hardware volume: {} on {}", mixer.element(), mixer.card());
            Ok(Some(Arc::new(mixer)))
        }
        Err(e) => {
            log::warn!("Falling back to software volume: {e}");
            Ok(None)
        }
    }
}

/// Without the feature, the flag is accepted and reported as unavailable rather than rejected:
/// a systemd unit shared across builds should not fail to start on the one built without it.
#[cfg(not(all(feature = "hardware-volume", target_os = "linux")))]
fn open_mixer(args: &DaemonArgs, _volume_is_external: bool) -> Result<Option<()>, String> {
    if args.hardware_volume.is_some() {
        log::warn!(
            "--hardware-volume needs the `hardware-volume` feature on Linux; using software \
             volume instead"
        );
    }
    Ok(None)
}
