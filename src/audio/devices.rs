// ABOUTME: Picking an output device and pinning a stream format, plus the parsing and the
// ABOUTME: up-front checks that turn a bad setting into a startup error rather than silence.

//! Audio device selection.
//!
//! Everything here fails early on purpose. An application that accepts a device it cannot open,
//! or a format the card cannot play, and then plays nothing has told its user nothing; the
//! failure belongs where the setting was made, with the list of what was available.

use cpal::traits::{DeviceTrait, HostTrait};

use crate::protocol::messages::AudioFormatSpec;

/// One output device, as a person choosing between them sees it.
pub struct DeviceInfo {
    /// Position in the enumeration, which is what makes a device selectable by number.
    pub index: usize,
    /// The platform's identifier for the device, stable enough to store in a setting.
    pub id: String,
    /// The human-readable description, where the platform offers one.
    pub description: Option<String>,
    /// The device itself, ready to open.
    pub device: cpal::Device,
}

/// Which way audio travels through a device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Playback: a player's output.
    Output,
    /// Capture: a source's input.
    Input,
}

/// Every device that can play audio, in a stable enumeration order.
///
/// Devices with no output configuration are skipped rather than listed and rejected later:
/// they are inputs, and offering one as a playback target is an invitation to a typo.
pub fn output_devices() -> Result<Vec<DeviceInfo>, String> {
    devices(Direction::Output)
}

/// Every device that can capture audio, on the same terms.
pub fn input_devices() -> Result<Vec<DeviceInfo>, String> {
    devices(Direction::Input)
}

/// Every device that can carry audio in `direction`.
pub fn devices(direction: Direction) -> Result<Vec<DeviceInfo>, String> {
    let mut found = Vec::new();
    for host_id in cpal::available_hosts() {
        let host = cpal::host_from_id(host_id)
            .map_err(|e| format!("could not open the {host_id:?} audio host: {e}"))?;
        let devices = host
            .devices()
            .map_err(|e| format!("could not enumerate audio devices: {e}"))?;
        for device in devices {
            let usable = match direction {
                Direction::Output => device
                    .supported_output_configs()
                    .map(|configs| configs.count() > 0)
                    .unwrap_or(false),
                Direction::Input => device
                    .supported_input_configs()
                    .map(|configs| configs.count() > 0)
                    .unwrap_or(false),
            };
            if !usable {
                continue;
            }
            found.push(DeviceInfo {
                index: found.len(),
                id: device
                    .id()
                    .map_or_else(|_| "<unknown>".to_string(), |id| id.to_string()),
                description: device.description().ok().map(|d| d.to_string()),
                device,
            });
        }
    }
    Ok(found)
}

/// Resolve `query` to a device, or say what was available instead.
///
/// Matched in decreasing specificity — index, exact id, exact description, then a
/// case-insensitive prefix — so a query of `1` cannot be stolen by a card whose name happens
/// to start with a digit, and a full id always beats a partial one.
pub fn find_device(query: &str) -> Result<cpal::Device, String> {
    find_device_in(query, Direction::Output)
}

/// Resolve `query` to a capture device.
pub fn find_input_device(query: &str) -> Result<cpal::Device, String> {
    find_device_in(query, Direction::Input)
}

/// Resolve `query` to a device carrying audio in `direction`.
pub fn find_device_in(query: &str, direction: Direction) -> Result<cpal::Device, String> {
    let devices = devices(direction)?;

    if let Ok(index) = query.parse::<usize>() {
        return devices
            .into_iter()
            .find(|d| d.index == index)
            .map(|d| d.device)
            .ok_or_else(|| format!("no audio device with index {index}"));
    }

    let lowered = query.to_lowercase();
    let matched = devices
        .iter()
        .position(|d| d.id == query)
        .or_else(|| {
            devices
                .iter()
                .position(|d| d.description.as_deref() == Some(query))
        })
        .or_else(|| {
            devices.iter().position(|d| {
                d.id.to_lowercase().starts_with(&lowered)
                    || d.description
                        .as_deref()
                        .is_some_and(|desc| desc.to_lowercase().starts_with(&lowered))
            })
        });

    match matched {
        Some(index) => Ok(devices
            .into_iter()
            .nth(index)
            .expect("index just found")
            .device),
        None => {
            let available: Vec<String> = devices.iter().map(|d| d.id.clone()).collect();
            Err(format!(
                "no audio device matching {query:?}. Available: {}",
                if available.is_empty() {
                    "none".to_string()
                } else {
                    available.join(", ")
                }
            ))
        }
    }
}

/// The sample rates worth offering a server, lowest first.
///
/// Every rate a Sendspin server is likely to hold a file at. Anything outside this set the
/// server resamples anyway, so naming it would offer a promise the card would have to keep
/// for no gain.
const CANDIDATE_RATES: [u32; 6] = [44_100, 48_000, 88_200, 96_000, 176_400, 192_000];

/// The rates `device` — or the platform default — can open for stereo playback.
///
/// A client that offers one fixed rate makes the server resample everything to it: a 44.1kHz
/// album then arrives altered even though the card would have played it untouched. Offering
/// what the hardware actually does is what leaves a bit-perfect server bit-perfect, and it
/// costs nothing, because the server still picks.
///
/// Falls back to 48kHz when the device cannot be asked. A client that cannot enumerate its own
/// card should claim the rate everything supports rather than claim nothing and go silent.
pub fn output_rates(device: Option<&cpal::Device>) -> Vec<u32> {
    let default_device;
    let device = match device {
        Some(device) => device,
        None => {
            default_device = cpal::default_host().default_output_device();
            match default_device.as_ref() {
                Some(device) => device,
                None => return vec![48_000],
            }
        }
    };

    let Ok(configs) = device.supported_output_configs() else {
        return vec![48_000];
    };
    // Stereo only: that is what `client/hello` offers.
    let ranges: Vec<_> = configs.filter(|range| range.channels() >= 2).collect();

    let rates: Vec<u32> = CANDIDATE_RATES
        .into_iter()
        .filter(|rate| {
            ranges
                .iter()
                .any(|range| (range.min_sample_rate()..=range.max_sample_rate()).contains(rate))
        })
        .collect();

    if rates.is_empty() {
        vec![48_000]
    } else {
        rates
    }
}

/// Parse `codec:sample_rate:bit_depth:channels`, e.g. `flac:48000:24:2`.
///
/// All four parts are required. A partial spelling would have to invent the rest, and a
/// silently invented sample rate is the kind of thing that plays at the wrong speed rather
/// than failing.
pub fn parse_format(spec: &str) -> Result<AudioFormatSpec, String> {
    let parts: Vec<&str> = spec.split(':').collect();
    let [codec, sample_rate, bit_depth, channels] = parts.as_slice() else {
        return Err(format!(
            "a format must be codec:sample_rate:bit_depth:channels, e.g. flac:48000:24:2 \
             (got {spec:?})"
        ));
    };

    if !matches!(*codec, "pcm" | "flac" | "opus") {
        return Err(format!(
            "codec {codec:?} is not one this client can decode (pcm, flac or opus)"
        ));
    }
    let sample_rate: u32 = sample_rate
        .parse()
        .map_err(|_| format!("sample rate {sample_rate:?} is not a number"))?;
    let bit_depth: u8 = bit_depth
        .parse()
        .map_err(|_| format!("bit depth {bit_depth:?} is not a number"))?;
    let channels: u8 = channels
        .parse()
        .map_err(|_| format!("channel count {channels:?} is not a number"))?;

    // Checked here rather than left to the decoder, so the message names the flag.
    if !matches!(bit_depth, 16 | 24) {
        return Err(format!("bit depth {bit_depth} is not 16 or 24"));
    }
    if channels == 0 {
        return Err("channel count must be at least 1".to_string());
    }
    if sample_rate == 0 {
        return Err("sample rate must be greater than zero".to_string());
    }
    // Opus is defined at 48 kHz, and a client that asks a server for anything else gets a
    // stream its own decoder will refuse.
    if *codec == "opus" && sample_rate != 48_000 {
        return Err(format!(
            "Opus is defined at 48000 Hz; {sample_rate} Hz cannot be decoded"
        ));
    }

    Ok(AudioFormatSpec {
        codec: (*codec).to_string(),
        channels,
        sample_rate,
        bit_depth,
    })
}

/// Check that a device can actually play this format, before a server is asked to send it.
///
/// The device is asked about the sample rate and the channel count only: the bit depth on the
/// wire is the codec's business, and the player converts to whatever sample type the device
/// wants. Verifying up front is the point — the alternative is a server encoding happily into
/// a stream that cannot be opened.
pub fn verify_device_supports(
    device: &cpal::Device,
    format: &AudioFormatSpec,
) -> Result<(), String> {
    let configs = device
        .supported_output_configs()
        .map_err(|e| format!("could not read the device's output configurations: {e}"))?;

    let mut seen = Vec::new();
    for config in configs {
        let min = config.min_sample_rate();
        let max = config.max_sample_rate();
        seen.push(format!("{}ch {min}-{max}Hz", config.channels()));
        if u32::from(config.channels()) == u32::from(format.channels)
            && (min..=max).contains(&format.sample_rate)
        {
            return Ok(());
        }
    }
    Err(format!(
        "the selected device cannot play {}ch at {}Hz. It supports: {}",
        format.channels,
        format.sample_rate,
        if seen.is_empty() {
            "nothing".to_string()
        } else {
            seen.join("; ")
        }
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_full_format_spec_parses_into_what_the_hello_advertises() {
        let format = parse_format("flac:48000:24:2").unwrap();
        assert_eq!(format.codec, "flac");
        assert_eq!(format.sample_rate, 48_000);
        assert_eq!(format.bit_depth, 24);
        assert_eq!(format.channels, 2);
    }

    /// Every part is required. Inventing a missing sample rate would play at the wrong speed
    /// rather than fail, which is the worse of the two outcomes.
    #[test]
    fn a_partial_format_spec_is_refused_rather_than_completed() {
        for bad in [
            "pcm",
            "pcm:48000",
            "pcm:48000:16",
            "pcm:48000:16:2:extra",
            "",
        ] {
            assert!(parse_format(bad).is_err(), "accepted {bad:?}");
        }
    }

    #[test]
    fn a_format_this_client_could_not_decode_is_refused_at_the_flag() {
        // A codec with no decoder here: the server would encode it and nothing would play.
        assert!(parse_format("mp3:48000:16:2").is_err());
        // Bit depths the decoders do not implement.
        assert!(parse_format("pcm:48000:32:2").is_err());
        assert!(parse_format("pcm:48000:8:2").is_err());
        // Degenerate values that would reach cpal as a zero-sized stream.
        assert!(parse_format("pcm:48000:16:0").is_err());
        assert!(parse_format("pcm:0:16:2").is_err());
        // Opus exists only at 48 kHz, so asking for anything else asks for an undecodable
        // stream — better refused at the flag than at the first chunk.
        assert!(parse_format("opus:44100:16:2").is_err());
        assert!(parse_format("opus:48000:16:2").is_ok());
    }

    /// Whatever this machine has — a full card, a null host, no device at all — the offer has
    /// to be a non-empty set of rates a server can actually pick from.
    #[test]
    fn the_advertised_rates_are_never_empty_and_never_invented() {
        let rates = output_rates(None);
        assert!(!rates.is_empty(), "a client must offer at least one rate");
        for rate in &rates {
            assert!(
                CANDIDATE_RATES.contains(rate),
                "offered {rate}Hz, which is not one of the candidates"
            );
        }
        // Ascending, so the list reads as a range rather than an arbitrary order.
        assert!(rates.windows(2).all(|pair| pair[0] < pair[1]), "{rates:?}");
    }

    #[test]
    fn non_numeric_parts_name_the_part_that_was_wrong() {
        let error = parse_format("pcm:forty-eight:16:2").unwrap_err();
        assert!(error.contains("sample rate"), "{error}");
        let error = parse_format("pcm:48000:sixteen:2").unwrap_err();
        assert!(error.contains("bit depth"), "{error}");
        let error = parse_format("pcm:48000:16:stereo").unwrap_err();
        assert!(error.contains("channel count"), "{error}");
    }
}
