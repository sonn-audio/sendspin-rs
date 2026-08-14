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

/// PCM arriving over the network, played as it comes.
///
/// A stream has no end to read to and no length to allocate, so this holds a window of what has
/// arrived and no more. Short of a chunk it pads with silence rather than ending: a radio
/// stream that stalls for a moment is still the same stream, and ending it would tell every
/// player in the group that the music stopped.
struct StreamedTrack {
    format: StreamPlayerConfig,
    frame_bytes: usize,
    pcm: Mutex<std::collections::VecDeque<u8>>,
    title: String,
}

impl StreamedTrack {
    /// Seconds of audio to hold. Enough to ride out a hiccup on the way in, short enough that
    /// what a listener hears is what the source is sending now.
    const WINDOW_SECONDS: usize = 4;

    fn window_bytes(&self) -> usize {
        Self::WINDOW_SECONDS * self.format.sample_rate as usize * self.frame_bytes
    }

    /// Take what has arrived, run a reader into it, and hand back the source.
    fn spawn(
        format: StreamPlayerConfig,
        title: String,
        mut body: impl std::io::Read + Send + 'static,
        leading: Vec<u8>,
    ) -> Arc<Self> {
        let frame_bytes = usize::from(format.channels) * usize::from(format.bit_depth) / 8;
        let track = Arc::new(Self {
            format,
            frame_bytes: frame_bytes.max(1),
            pcm: Mutex::new(leading.into()),
            title,
        });

        // A thread rather than a task: the read blocks, and the runtime this shares is the one
        // pacing every connected player.
        let writer = Arc::clone(&track);
        std::thread::spawn(move || {
            let mut buffer = vec![0u8; 16 * 1024];
            loop {
                match body.read(&mut buffer) {
                    Ok(0) => {
                        log::info!("Source stream ended");
                        return;
                    }
                    Ok(read) => {
                        let cap = writer.window_bytes();
                        let mut pcm = writer.pcm.lock();
                        pcm.extend(&buffer[..read]);
                        // Dropping the oldest rather than the newest: a listener wants what is
                        // being broadcast now, not the backlog of what was.
                        while pcm.len() > cap {
                            let excess = pcm.len() - cap;
                            pcm.drain(..excess);
                        }
                    }
                    Err(e) => {
                        log::error!("Source stream failed: {e}");
                        return;
                    }
                }
            }
        });
        track
    }
}

impl AudioSource for StreamedTrack {
    fn format(&self) -> StreamPlayerConfig {
        self.format.clone()
    }

    fn next_chunk(&self, frames: usize) -> Option<Vec<u8>> {
        let wanted = frames * self.frame_bytes;
        let mut pcm = self.pcm.lock();
        let take = wanted.min(pcm.len());
        // Whole frames only. Half a frame would put the channels the wrong way round for
        // everything after it.
        let take = take - take % self.frame_bytes;
        let mut chunk: Vec<u8> = pcm.drain(..take).collect();
        chunk.resize(wanted, 0);
        Some(chunk)
    }
}

impl MetadataSource for StreamedTrack {
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

/// What a source turned out to be: a whole track, or a stream still arriving.
enum Source {
    /// Read once and looped, which is what a file is.
    Track(Arc<Track>),
    /// Played as it arrives, which is what a stream is.
    Streamed(Arc<StreamedTrack>),
}

/// Fetch a URL and work out what is coming down it.
///
/// WAV is played as it arrives, because a broadcast has no end to read to. FLAC is not: this
/// crate's decoder is handed whole frames, so a FLAC URL is read to the end first and then
/// played like a file — which works for a track and not for a broadcast, and says so rather
/// than filling memory until something gives.
fn load_url(url: &str) -> Result<Source, String> {
    /// Enough of the head to hold a WAV header and then some, and to tell the two apart.
    const SNIFF_BYTES: usize = 64 * 1024;
    /// The most a source read whole may be. A broadcast would otherwise be read until the
    /// machine ran out of somewhere to put it.
    const MAX_BUFFERED: usize = 256 * 1024 * 1024;

    let (mut body, declared_length) = crate::fetch::get(url)?;
    let title = url
        .rsplit('/')
        .find(|part| !part.is_empty())
        .unwrap_or(url)
        .to_string();

    let mut head = Vec::new();
    let mut buffer = vec![0u8; 8 * 1024];
    while head.len() < SNIFF_BYTES {
        match std::io::Read::read(&mut body, &mut buffer) {
            Ok(0) => break,
            Ok(read) => head.extend_from_slice(&buffer[..read]),
            Err(e) => return Err(format!("could not read from {url}: {e}")),
        }
    }

    // A declared length means a file that happens to live behind a URL: it is played from its
    // beginning and looped, like a local one. A broadcast declares none, and is played from
    // wherever it is now — keeping only a window of it, because its beginning is gone and its
    // end never comes.
    let finite = declared_length.is_some_and(|length| length <= MAX_BUFFERED);

    if head.starts_with(b"RIFF") && !finite {
        let (format, leading) = wav_stream_header(&head)?;
        log::info!(
            "Streaming {} — {}Hz {}ch {}bit",
            title,
            format.sample_rate,
            format.channels,
            format.bit_depth
        );
        return Ok(Source::Streamed(StreamedTrack::spawn(
            format, title, body, leading,
        )));
    }

    if head.starts_with(b"fLaC") || head.starts_with(b"RIFF") {
        let mut all = head;
        loop {
            match std::io::Read::read(&mut body, &mut buffer) {
                Ok(0) => break,
                Ok(read) => {
                    all.extend_from_slice(&buffer[..read]);
                    if all.len() > MAX_BUFFERED {
                        return Err(format!(
                            "{url} has sent more than {} MB without ending. Only a finite \
                             source can be read whole; a FLAC broadcast cannot be played here \
                             at all, because the decoder is handed whole frames. Send WAV to \
                             stream.",
                            MAX_BUFFERED / 1024 / 1024
                        ));
                    }
                }
                Err(e) => return Err(format!("could not read from {url}: {e}")),
            }
        }
        let (format, pcm) = if all.starts_with(b"fLaC") {
            decode_flac(&all)?
        } else {
            decode_wav(&all)?
        };
        // Announced by the caller, which says the same thing for a local file.
        let frame_bytes = usize::from(format.channels) * usize::from(format.bit_depth) / 8;
        return Ok(Source::Track(Arc::new(Track {
            format,
            pcm,
            frame_bytes: frame_bytes.max(1),
            cursor: Mutex::new(0),
            title,
        })));
    }

    Err(format!(
        "{url} sends neither WAV nor FLAC. This server decodes those two; anything else needs a \
         general-purpose decoder it deliberately has not got."
    ))
}

/// Read a streamed WAV's header, and hand back whatever audio came with it.
fn wav_stream_header(head: &[u8]) -> Result<(StreamPlayerConfig, Vec<u8>), String> {
    // A broadcast's `data` chunk usually claims a length nobody means — often zero, often
    // 0xFFFFFFFF — so the header is read for its format and the rest is taken as audio.
    let (format, pcm) = decode_wav_head(head)?;
    Ok((format, pcm))
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
    let (format, data, declared) = wav_format(bytes)?;
    // A file means what its header says, so the declared length wins where it fits.
    let end = declared
        .map(|size| (data + size).min(bytes.len()))
        .unwrap_or(bytes.len());
    Ok((format, bytes[data..end].to_vec()))
}

/// The same, for audio still arriving.
///
/// A broadcast's `data` chunk claims a length nobody means — often zero, often the largest
/// number that fits — so the header is read for its format and everything after it is audio.
fn decode_wav_head(bytes: &[u8]) -> Result<(StreamPlayerConfig, Vec<u8>), String> {
    let (format, data, _) = wav_format(bytes)?;
    Ok((format, bytes[data..].to_vec()))
}

/// Walk the chunks to the format and the start of the audio.
///
/// Returns where the audio begins and how long the header claims it is, which a file can be
/// held to and a stream cannot.
fn wav_format(bytes: &[u8]) -> Result<(StreamPlayerConfig, usize, Option<usize>), String> {
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

        if id == b"data" {
            let format = format.ok_or_else(|| "WAV data chunk precedes its fmt".to_string())?;
            // A length that does not fit what is here is a stream's, not a file's.
            let declared = (pos + 8 + size <= bytes.len()).then_some(size);
            return Ok((format, pos + 8, declared));
        }

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

    let source = match args.source.as_deref() {
        Some(source) if crate::fetch::is_url(source) => Some(load_url(source)?),
        Some(path) => Some(Source::Track(Arc::new(load_track(Path::new(path))?))),
        None => None,
    };
    match (&source, args.demo) {
        (Some(Source::Track(track)), _) => {
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
        (Some(Source::Streamed(stream)), _) => {
            config = config
                .with_audio(Arc::clone(stream) as Arc<dyn AudioSource>)
                .with_metadata(Arc::clone(stream) as Arc<dyn MetadataSource>);
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
