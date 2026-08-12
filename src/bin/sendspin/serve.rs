// ABOUTME: The `serve` subcommand: run a Sendspin server that plays a file or a test tone to
// ABOUTME: whatever connects, and advertise it so clients can find it without being told an address.

//! `sendspin serve`.
//!
//! The other half of this binary. Where `daemon` is a player that a server drives, this is the
//! server that drives one — the same protocol read from the opposite end, which is the only way
//! to find out whether both halves agree.
//!
//! What it plays is deliberately narrow: a generated tone, or a WAV or FLAC file. Anything else
//! — MP3, AAC, a stream URL — needs a general-purpose decoder, and pulling ffmpeg in to gain one
//! would cost every player build a dependency it has no use for. The reference implementation
//! makes the opposite trade because Python can defer it to an optional package.

use std::path::Path;
use std::sync::Arc;

use parking_lot::Mutex;
use sendspin::noise::file_store::load_or_create_identity;
use sendspin::protocol::discovery::ServerAdvertisement;
use sendspin_proto::messages::{
    ControllerCommand, ControllerCommandType, MetadataState, StreamPlayerConfig,
};
use sendspin_server::{AudioSource, Controller, MetadataSource, SendspinServer, ServerConfig};

use crate::cli::ServeArgs;

/// A 440 Hz tone, for a server with nothing else to play.
struct Tone {
    sample_rate: u32,
    channels: u8,
    phase: Mutex<f32>,
}

impl AudioSource for Tone {
    fn format(&self) -> StreamPlayerConfig {
        StreamPlayerConfig {
            codec: "pcm".to_string(),
            sample_rate: self.sample_rate,
            channels: self.channels,
            bit_depth: 16,
            codec_header: None,
        }
    }

    fn next_chunk(&self, frames: usize) -> Option<Vec<u8>> {
        let mut phase = self.phase.lock();
        let step = std::f32::consts::TAU * 440.0 / self.sample_rate as f32;
        let mut pcm = Vec::with_capacity(frames * usize::from(self.channels) * 2);
        for _ in 0..frames {
            let sample = ((phase.sin() * 0.2) * f32::from(i16::MAX)) as i16;
            for _ in 0..self.channels {
                pcm.extend_from_slice(&sample.to_le_bytes());
            }
            *phase += step;
        }
        Some(pcm)
    }
}

/// PCM held in memory and handed out in order, looping when it runs out.
///
/// Decoded up front rather than streamed from disk: a source is pulled from the timeline's
/// thread, which must not block on a read, and a track is small next to the buffers a server
/// already holds. It loops because a server that falls silent at the end of one file looks
/// broken while it is being tested.
struct Track {
    format: StreamPlayerConfig,
    pcm: Vec<u8>,
    frame_bytes: usize,
    cursor: Mutex<usize>,
    title: String,
}

impl AudioSource for Track {
    fn format(&self) -> StreamPlayerConfig {
        self.format.clone()
    }

    fn next_chunk(&self, frames: usize) -> Option<Vec<u8>> {
        if self.pcm.is_empty() {
            return None;
        }
        let wanted = frames * self.frame_bytes;
        let mut cursor = self.cursor.lock();
        let mut chunk = Vec::with_capacity(wanted);
        while chunk.len() < wanted {
            let available = self.pcm.len() - *cursor;
            let take = available.min(wanted - chunk.len());
            chunk.extend_from_slice(&self.pcm[*cursor..*cursor + take]);
            *cursor += take;
            if *cursor >= self.pcm.len() {
                *cursor = 0;
            }
        }
        Some(chunk)
    }
}

impl MetadataSource for Track {
    // `repeat` and `shuffle` are deprecated in favour of the controller state but still part of
    // the struct, so they have to be named to construct it.
    #[allow(deprecated)]
    fn current(&self) -> Option<MetadataState> {
        Some(MetadataState {
            timestamp: 0,
            title: Some(self.title.clone()),
            artist: None,
            album_artist: None,
            album: None,
            artwork_url: None,
            year: None,
            track: None,
            progress: None,
            repeat: None,
            shuffle: None,
        })
    }
}

/// What this server will take from a controller.
///
/// Volume and mute are the group's and handled by the server crate. Play and pause act on the
/// timeline there too, so all this has to do is not lie about the rest: `next` and `previous`
/// are not advertised, because one looping source has nothing to skip to.
struct ServeController;

impl Controller for ServeController {
    fn supported_commands(&self) -> Vec<ControllerCommandType> {
        vec![
            ControllerCommandType::Volume,
            ControllerCommandType::Mute,
            ControllerCommandType::Play,
            ControllerCommandType::Pause,
        ]
    }

    fn handle(&self, command: &ControllerCommand) {
        log::info!("Controller asked for {:?}", command.command);
    }
}

/// Read a WAV or FLAC file into interleaved little-endian PCM.
fn load_track(path: &Path) -> Result<Track, String> {
    let bytes =
        std::fs::read(path).map_err(|e| format!("could not read {}: {e}", path.display()))?;
    let title = path.file_stem().map_or_else(
        || path.display().to_string(),
        |s| s.to_string_lossy().into(),
    );

    let (format, pcm) = if bytes.starts_with(b"fLaC") {
        decode_flac(&bytes)?
    } else if bytes.starts_with(b"RIFF") {
        decode_wav(&bytes)?
    } else {
        return Err(format!(
            "{} is neither WAV nor FLAC. This server decodes those two; anything else has to be \
             converted first.",
            path.display()
        ));
    };

    let frame_bytes = usize::from(format.channels) * usize::from(format.bit_depth) / 8;
    if frame_bytes == 0 || pcm.len() < frame_bytes {
        return Err(format!("{} holds no audio", path.display()));
    }
    Ok(Track {
        format,
        pcm,
        frame_bytes,
        cursor: Mutex::new(0),
        title,
    })
}

/// Split a FLAC file at the end of its metadata blocks and decode the frames.
fn decode_flac(bytes: &[u8]) -> Result<(StreamPlayerConfig, Vec<u8>), String> {
    use sendspin::audio::decode::{Decoder, FlacDecoder};

    // Each metadata block is a 1-byte last-flag-plus-type and a 24-bit big-endian length.
    // Audio frames begin after the block whose last-flag is set.
    let mut pos = 4;
    loop {
        let header = bytes
            .get(pos..pos + 4)
            .ok_or_else(|| "FLAC metadata ends mid-block".to_string())?;
        let last = header[0] & 0x80 != 0;
        let length = u32::from_be_bytes([0, header[1], header[2], header[3]]) as usize;
        pos += 4 + length;
        if last {
            break;
        }
    }
    let (header, frames) = bytes.split_at(pos);

    // STREAMINFO starts at byte 8; the rate, channel count and depth are a packed run of bits
    // 20, 3 and 5 wide starting at its byte 10.
    let info = bytes
        .get(8 + 10..8 + 14)
        .ok_or_else(|| "FLAC STREAMINFO is truncated".to_string())?;
    let packed = u32::from_be_bytes([info[0], info[1], info[2], info[3]]);
    let sample_rate = packed >> 12;
    let channels = ((packed >> 9) & 0x7) as u8 + 1;
    let bit_depth = ((packed >> 4) & 0x1f) as u8 + 1;
    if !matches!(bit_depth, 16 | 24) {
        return Err(format!(
            "FLAC at {bit_depth}-bit is not supported (16 or 24 only)"
        ));
    }

    let decoder =
        FlacDecoder::with_header(header).map_err(|e| format!("invalid FLAC header: {e}"))?;
    let samples = decoder
        .decode(frames)
        .map_err(|e| format!("could not decode the FLAC audio: {e}"))?;

    // The decoders hand back samples scaled to the full i32 range, so the shift undoes exactly
    // what the depth put in.
    let shift = 32 - u32::from(bit_depth);
    let bytes_per_sample = usize::from(bit_depth) / 8;
    let mut pcm = Vec::with_capacity(samples.len() * bytes_per_sample);
    for sample in samples.iter() {
        let scaled = sample >> shift;
        pcm.extend_from_slice(&scaled.to_le_bytes()[..bytes_per_sample]);
    }

    Ok((
        StreamPlayerConfig {
            codec: "pcm".to_string(),
            sample_rate,
            channels,
            bit_depth,
            codec_header: None,
        },
        pcm,
    ))
}

/// Read the `fmt ` and `data` chunks of a RIFF/WAVE file.
fn decode_wav(bytes: &[u8]) -> Result<(StreamPlayerConfig, Vec<u8>), String> {
    if bytes.get(8..12) != Some(b"WAVE") {
        return Err("not a RIFF/WAVE file".to_string());
    }
    let mut pos = 12;
    let mut format: Option<StreamPlayerConfig> = None;

    while pos + 8 <= bytes.len() {
        let id = &bytes[pos..pos + 4];
        let size = u32::from_le_bytes([
            bytes[pos + 4],
            bytes[pos + 5],
            bytes[pos + 6],
            bytes[pos + 7],
        ]) as usize;
        let body = bytes
            .get(pos + 8..pos + 8 + size)
            .ok_or_else(|| "WAV chunk runs past the end of the file".to_string())?;

        if id == b"fmt " {
            if body.len() < 16 {
                return Err("WAV fmt chunk is too short".to_string());
            }
            let tag = u16::from_le_bytes([body[0], body[1]]);
            // 1 is PCM; 0xFFFE is extensible, whose subformat this does not read, so it is
            // refused rather than assumed to be PCM.
            if tag != 1 {
                return Err(format!(
                    "WAV format {tag} is not plain PCM; convert the file first"
                ));
            }
            let channels = u16::from_le_bytes([body[2], body[3]]) as u8;
            let sample_rate = u32::from_le_bytes([body[4], body[5], body[6], body[7]]);
            let bit_depth = u16::from_le_bytes([body[14], body[15]]) as u8;
            if !matches!(bit_depth, 16 | 24) {
                return Err(format!(
                    "WAV at {bit_depth}-bit is not supported (16 or 24 only)"
                ));
            }
            format = Some(StreamPlayerConfig {
                codec: "pcm".to_string(),
                sample_rate,
                channels,
                bit_depth,
                codec_header: None,
            });
        } else if id == b"data" {
            let format = format.ok_or_else(|| "WAV data chunk precedes its fmt".to_string())?;
            return Ok((format, body.to_vec()));
        }

        // Chunks are word-aligned: an odd length is followed by a pad byte.
        pos += 8 + size + (size & 1);
    }
    Err("WAV file has no data chunk".to_string())
}

/// Run the server until the process is stopped.
pub async fn run(args: ServeArgs) -> Result<(), Box<dyn std::error::Error>> {
    // Persisted rather than generated per run: the `server_id` is the public half of this key,
    // and a server that gets a new identity on every restart is a new server to every client
    // that paired with it.
    let identity = load_or_create_identity(args.settings_dir()?.join("server.key"))?;
    let mut config = ServerConfig::new(identity, args.name.clone());

    let track = match args.source.as_deref() {
        Some(path) => Some(Arc::new(load_track(Path::new(path))?)),
        None => None,
    };
    match (&track, args.demo) {
        (Some(track), _) => {
            let format = track.format();
            log::info!(
                "Playing {} — {}Hz {}ch {}bit",
                track.title,
                format.sample_rate,
                format.channels,
                format.bit_depth
            );
            config = config
                .with_audio(Arc::clone(track) as Arc<dyn AudioSource>)
                .with_metadata(Arc::clone(track) as Arc<dyn MetadataSource>);
        }
        (None, true) => {
            log::info!("Playing a 440 Hz test tone");
            config = config.with_audio(Arc::new(Tone {
                sample_rate: 48_000,
                channels: 2,
                phase: Mutex::new(0.0),
            }));
        }
        // Worth saying rather than leaving an operator to wonder: a server with no source
        // handshakes and syncs clocks perfectly well, and plays nothing at all.
        (None, false) => log::warn!(
            "No --source and no --demo, so this server has nothing to play. Clients will \
             connect, sync and wait."
        ),
    }
    config = config.with_controller(Arc::new(ServeController));

    let bind = format!("0.0.0.0:{}", args.port);
    let server = SendspinServer::bind(&bind, config).await?;
    let server_id = server.server_id();
    log::info!("Server id: {server_id}");
    log::info!("Listening on ws://{}/sendspin", server.local_addr()?);

    // Held for the lifetime of the server: dropping it withdraws the record.
    let _advertisement = if args.no_discovery {
        None
    } else {
        match ServerAdvertisement::new(&server_id, &args.name, args.port) {
            Ok(advertisement) => Some(advertisement),
            // Not fatal: a server reachable at a known address is still a server, and refusing
            // to start because mDNS is unavailable would be the wrong trade on a locked-down
            // network.
            Err(e) => {
                log::warn!("Could not advertise over mDNS: {e}");
                None
            }
        }
    };

    server.serve_forever().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A 16-bit stereo WAV, built by hand so the parser is tested against bytes rather than
    /// against whatever a fixture happens to contain.
    fn wav_fixture() -> Vec<u8> {
        let mut wav = Vec::new();
        wav.extend_from_slice(b"RIFF");
        wav.extend_from_slice(&0u32.to_le_bytes()); // size, unread
        wav.extend_from_slice(b"WAVE");
        wav.extend_from_slice(b"fmt ");
        wav.extend_from_slice(&16u32.to_le_bytes());
        wav.extend_from_slice(&1u16.to_le_bytes()); // PCM
        wav.extend_from_slice(&2u16.to_le_bytes()); // stereo
        wav.extend_from_slice(&44_100u32.to_le_bytes());
        wav.extend_from_slice(&176_400u32.to_le_bytes()); // byte rate
        wav.extend_from_slice(&4u16.to_le_bytes()); // block align
        wav.extend_from_slice(&16u16.to_le_bytes()); // bits
        wav.extend_from_slice(b"data");
        wav.extend_from_slice(&8u32.to_le_bytes());
        wav.extend_from_slice(&[1, 0, 2, 0, 3, 0, 4, 0]);
        wav
    }

    #[test]
    fn a_wav_header_yields_its_format_and_samples() {
        let (format, pcm) = decode_wav(&wav_fixture()).unwrap();
        assert_eq!(format.sample_rate, 44_100);
        assert_eq!(format.channels, 2);
        assert_eq!(format.bit_depth, 16);
        assert_eq!(pcm, vec![1, 0, 2, 0, 3, 0, 4, 0]);
    }

    /// A source shorter than the requested chunk has to wrap rather than return a short chunk:
    /// a partial frame would desynchronise every player holding the timeline.
    #[test]
    fn a_track_loops_rather_than_running_out() {
        let (format, pcm) = decode_wav(&wav_fixture()).unwrap();
        let track = Track {
            format,
            pcm,
            frame_bytes: 4,
            cursor: Mutex::new(0),
            title: "fixture".to_string(),
        };
        // Two frames exist; asking for five must still give five frames' worth.
        let chunk = track.next_chunk(5).unwrap();
        assert_eq!(chunk.len(), 20);
        assert_eq!(&chunk[..8], &[1, 0, 2, 0, 3, 0, 4, 0]);
        assert_eq!(&chunk[8..16], &[1, 0, 2, 0, 3, 0, 4, 0]);
    }

    #[test]
    fn a_file_that_is_neither_wav_nor_flac_is_refused_by_name() {
        let Err(error) = load_track(Path::new("Cargo.toml")) else {
            panic!("Cargo.toml was accepted as audio");
        };
        assert!(error.contains("neither WAV nor FLAC"), "{error}");
    }

    /// The fixtures the FLAC conformance tests use, read the way `serve` would read a track.
    #[test]
    fn a_flac_file_decodes_to_pcm_of_the_right_size() {
        let bytes = std::fs::read("tests/data/48k_16bit_stereo.flac").unwrap();
        let (format, pcm) = decode_flac(&bytes).unwrap();
        assert_eq!(format.sample_rate, 48_000);
        assert_eq!(format.channels, 2);
        assert_eq!(format.bit_depth, 16);
        let expected = std::fs::read("tests/data/48k_16bit_stereo.expected.raw").unwrap();
        assert_eq!(
            pcm, expected,
            "decoded PCM differs from the reference output"
        );
    }
}
