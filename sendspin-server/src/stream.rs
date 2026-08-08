// ABOUTME: Handing PCM to a player: the chunk header, the timestamps that decide when it is
// ABOUTME: heard, and the send-ahead that keeps a client's buffer fed without flooding it.

//! Pushing audio to a player.
//!
//! Two numbers decide whether synchronized playback works, and neither is about the audio:
//!
//! **The timestamp.** Every chunk carries the server-clock time at which its first sample is
//! meant to be heard. A player schedules on it, so it has to be far enough in the future that
//! the chunk arrives, decodes and reaches the sound card before then. That distance is the
//! *lead*, and the spec has a client state its own requirement in `client/state`.
//!
//! **The pacing.** Chunks are stamped from a timeline that advances by sample count, not by
//! wall clock: a stream that timestamped by "now" would drift with every scheduling hiccup.
//! Wall clock decides only *when to send*, and the rule is to stay a fixed distance ahead of
//! the timeline rather than to send at a fixed rate — the difference shows up the moment the
//! machine is loaded.
//!
//! This is deliberately the simple version: PCM only, one client, no resampling and no
//! transcoding. The reference implementation's `PushStream` does all of that; what this pins
//! down first is the part everything else sits on.

use sendspin::protocol::messages::{StreamPlayerConfig, StreamStart};

/// Binary message type for player audio, per the spec.
pub const PLAYER_AUDIO: u8 = 0x04;

/// How far ahead of playback the stream tries to stay.
///
/// Large enough to cover a client's decode and buffer, small enough that a stop is not heard
/// half a second late. `aiosendspin` buffers to five seconds and this is a fraction of that on
/// purpose: this stream has no flow control yet, so it errs toward the client's floor rather
/// than filling it.
pub const DEFAULT_SEND_AHEAD_US: i64 = 500_000;

/// The audio a stream carries, and the timeline it is stamped on.
pub struct PlayerStream {
    format: StreamPlayerConfig,
    /// Server-clock time the stream's very first sample plays at.
    ///
    /// Held rather than derived: the position is `start + micros(frames_sent)`, and recovering
    /// `start` from the position needs the frame count it was computed with — which is exactly
    /// the value that just changed. Deriving it produced a timeline that never advanced.
    start_us: i64,
    /// Frames handed out so far, which is what advances the timeline.
    frames_sent: u64,
    bytes_per_frame: usize,
}

impl PlayerStream {
    /// Begin a stream whose first sample plays at `start_us` on the server clock.
    pub fn new(format: StreamPlayerConfig, start_us: i64) -> Self {
        let bytes_per_sample = usize::from(format.bit_depth) / 8;
        Self {
            bytes_per_frame: bytes_per_sample * usize::from(format.channels),
            format,
            start_us,
            frames_sent: 0,
        }
    }

    /// The `stream/start` that announces this stream.
    pub fn stream_start(&self, server_transmitted: i64) -> StreamStart {
        StreamStart {
            server_transmitted: Some(server_transmitted),
            player: Some(self.format.clone()),
            artwork: None,
            visualizer: None,
        }
    }

    /// The format being sent.
    pub fn format(&self) -> &StreamPlayerConfig {
        &self.format
    }

    /// When the next chunk is due to be heard.
    pub fn next_timestamp_us(&self) -> i64 {
        self.start_us + frames_to_micros(self.frames_sent, self.format.sample_rate)
    }

    /// Frames handed out so far.
    pub fn frames_sent(&self) -> u64 {
        self.frames_sent
    }

    /// Wrap one chunk of PCM into the binary frame a player expects, and advance the timeline.
    ///
    /// The header is one byte of message type and eight bytes of big-endian timestamp, then the
    /// payload — the same shape this project's client parses, and the same one the reference
    /// implementation writes.
    ///
    /// Returns `None` for a chunk that is not a whole number of frames: sending it would put
    /// the stream permanently half a sample out, which is audible and never recovers.
    pub fn chunk(&mut self, pcm: &[u8]) -> Option<Vec<u8>> {
        if self.bytes_per_frame == 0 || !pcm.len().is_multiple_of(self.bytes_per_frame) {
            return None;
        }
        let frames = pcm.len() / self.bytes_per_frame;

        let mut framed = Vec::with_capacity(9 + pcm.len());
        framed.push(PLAYER_AUDIO);
        framed.extend_from_slice(&self.next_timestamp_us().to_be_bytes());
        framed.extend_from_slice(pcm);

        // Advanced by the running frame count rather than by adding each chunk's duration:
        // accumulating per-chunk durations accumulates their rounding too, and at 50 chunks a
        // second that is a drift of its own making.
        self.frames_sent += frames as u64;
        Some(framed)
    }

    /// Whether the next chunk should go out yet, given the clock and how far ahead to stay.
    ///
    /// The stream sends while it is *behind* its send-ahead target and waits once it is
    /// comfortably ahead, which is what keeps a client's buffer level rather than sawtoothed.
    pub fn should_send(&self, now_us: i64, send_ahead_us: i64) -> bool {
        self.next_timestamp_us() - now_us < send_ahead_us
    }
}

/// Microseconds for a whole number of frames at `sample_rate`.
///
/// Done in `i128` because the intermediate product overflows `i64` after about six hours at
/// 48 kHz, and a server that has been playing all day is the normal case rather than the
/// exotic one.
pub fn frames_to_micros(frames: u64, sample_rate: u32) -> i64 {
    if sample_rate == 0 {
        return 0;
    }
    let micros = i128::from(frames) * 1_000_000 / i128::from(sample_rate);
    i64::try_from(micros).unwrap_or(i64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn format() -> StreamPlayerConfig {
        StreamPlayerConfig {
            codec: "pcm".to_string(),
            sample_rate: 48_000,
            channels: 2,
            bit_depth: 16,
            codec_header: None,
        }
    }

    /// The header is what a player reads before anything else, and getting it wrong is a
    /// stream that decodes to nothing.
    #[test]
    fn a_chunk_carries_the_type_and_a_big_endian_timestamp() {
        let mut stream = PlayerStream::new(format(), 1_000_000);
        // 4 frames of stereo 16-bit.
        let chunk = stream.chunk(&[0u8; 16]).unwrap();
        assert_eq!(chunk[0], PLAYER_AUDIO);
        assert_eq!(
            i64::from_be_bytes(chunk[1..9].try_into().unwrap()),
            1_000_000
        );
        assert_eq!(chunk.len(), 9 + 16);
    }

    /// A partial frame is refused rather than sent: half a sample of offset never recovers.
    #[test]
    fn a_chunk_that_is_not_whole_frames_is_refused() {
        let mut stream = PlayerStream::new(format(), 0);
        assert!(stream.chunk(&[0u8; 15]).is_none());
        assert!(stream.chunk(&[0u8; 1]).is_none());
        assert!(stream.chunk(&[]).is_some(), "an empty chunk is whole");
    }

    /// The timeline advances by sample count, and the accumulated position stays exact even
    /// where a single chunk's duration does not divide evenly.
    #[test]
    fn the_timeline_advances_by_samples_and_does_not_accumulate_rounding() {
        let mut stream = PlayerStream::new(format(), 0);
        // 441 frames at 48 kHz is 9187.5 µs — deliberately not a whole microsecond.
        let pcm = vec![0u8; 441 * 4];
        for index in 1..=1000u64 {
            stream.chunk(&pcm).unwrap();
            let expected = frames_to_micros(441 * index, 48_000);
            assert_eq!(
                stream.next_timestamp_us(),
                expected,
                "after {index} chunks the timeline had drifted"
            );
        }
        // A thousand chunks of 9187.5 µs is 9187500 µs. Adding per-chunk durations would have
        // lost half a microsecond a thousand times over.
        assert_eq!(stream.next_timestamp_us(), 9_187_500);
    }

    /// Send-ahead is a distance from the *playback* time, not a rate: a stream behind its
    /// target sends, one comfortably ahead waits.
    #[test]
    fn the_stream_sends_while_it_is_behind_its_lead() {
        let stream = PlayerStream::new(format(), 1_000_000);
        assert!(stream.should_send(900_000, DEFAULT_SEND_AHEAD_US));
        assert!(!stream.should_send(400_000, DEFAULT_SEND_AHEAD_US));
        // Exactly at the target counts as ahead, so the boundary does not oscillate.
        assert!(!stream.should_send(500_000, DEFAULT_SEND_AHEAD_US));
    }

    /// A day of playback must not wrap the timestamp arithmetic.
    #[test]
    fn a_long_stream_does_not_overflow() {
        // 24 hours at 48 kHz: the frame count times a million overflows i64 by a wide margin.
        let frames = 48_000u64 * 60 * 60 * 24;
        assert_eq!(frames_to_micros(frames, 48_000), 86_400_000_000);
        assert_eq!(frames_to_micros(0, 48_000), 0);
        // A degenerate rate is answered rather than dividing by zero.
        assert_eq!(frames_to_micros(100, 0), 0);
    }
}
