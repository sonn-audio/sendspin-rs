// ABOUTME: Turns captured PCM into stamped source chunks — the arithmetic every source has
// ABOUTME: to get right, in one place instead of in every host application.

//! Capture for the `source@v1` role.
//!
//! A source has to answer one question per chunk: *when was the first sample in this frame
//! captured, in the server's clock?* Getting it wrong produces audio that plays and never
//! lines up, which is far harder to diagnose than audio that does not play at all. Three
//! things go into the answer and each is easy to miss:
//!
//! - **The server's clock, not the local one.** The two differ by whatever the sync filter
//!   has measured, and a chunk stamped locally is wrong by that offset.
//! - **Sample position, not wall time.** Stamping each chunk with "now" folds every
//!   scheduling hiccup into the timeline. A capture anchored once and advanced by sample
//!   count does not drift when a thread is late.
//! - **Encoder lookahead.** A codec that buffers input before emitting it makes every chunk
//!   claim a later capture time than the truth, by a constant.
//!
//! [`SourceCapture`] owns all three. It deliberately does not own the connection: it returns
//! stamped frames and the caller sends them, which keeps this module free of protocol types
//! and lets the whole thing be tested without a socket.
//!
//! ```no_run
//! # use sendspin::audio::source_capture::SourceCapture;
//! # fn f(pcm: &[u8], server_now_us: i64) -> Result<(), sendspin::error::Error> {
//! let mut capture = SourceCapture::new("opus", 48_000, 16, 2)?;
//! for (timestamp_us, frame) in capture.feed(pcm, server_now_us)? {
//!     // sender.send_source_audio(timestamp_us, &frame).await?;
//!     let _ = (timestamp_us, frame);
//! }
//! # Ok(()) }
//! ```

use super::encode::{create_encoder, Encoder};
use crate::error::Error;

/// One stamped chunk, ready for `send_source_audio`.
pub type StampedFrame = (i64, Vec<u8>);

/// Encodes captured PCM and stamps each chunk in server time.
pub struct SourceCapture {
    encoder: Box<dyn Encoder>,
    codec: String,
    sample_rate: u32,
    bit_depth: u8,
    channels: u8,
    /// Server-clock time of the first sample of the stream, set on the first feed.
    anchor_us: Option<i64>,
    /// Sample frames handed to the wire so far, which is what advances the timeline.
    samples_sent: u64,
}

impl SourceCapture {
    /// A capture for one codec and input format.
    ///
    /// The format is the one the source will announce in `client_stream/start`; there is no
    /// resampling here, so `feed` expects PCM already in this shape.
    pub fn new(codec: &str, sample_rate: u32, bit_depth: u8, channels: u8) -> Result<Self, Error> {
        if sample_rate == 0 {
            return Err(Error::Protocol("sample rate must be non-zero".into()));
        }
        Ok(Self {
            encoder: create_encoder(codec, sample_rate, bit_depth, channels)?,
            codec: codec.to_string(),
            sample_rate,
            bit_depth,
            channels,
            anchor_us: None,
            samples_sent: 0,
        })
    }

    /// The codec header to announce, already base64-encoded, or `None` when the codec needs
    /// none.
    ///
    /// Standard base64 with padding, which is what the spec's `codec_header` field carries —
    /// not the base64url the PSK fields use.
    pub fn codec_header(&self) -> Option<String> {
        use base64::Engine;
        self.encoder
            .codec_header()
            .map(|header| base64::engine::general_purpose::STANDARD.encode(header))
    }

    /// The codec name to announce.
    pub fn codec(&self) -> &str {
        &self.codec
    }

    /// The sample rate to announce.
    pub fn sample_rate(&self) -> u32 {
        self.sample_rate
    }

    /// The bit depth to announce.
    pub fn bit_depth(&self) -> u8 {
        self.bit_depth
    }

    /// The channel count to announce.
    pub fn channels(&self) -> u8 {
        self.channels
    }

    /// Encode captured PCM, returning whatever chunks it completed.
    ///
    /// `server_now_us` is the capture time of this buffer's first sample, in the *server's*
    /// clock — convert with
    /// [`ClockSync::client_to_server_micros`](crate::sync::ClockSync::client_to_server_micros)
    /// and do not call this until the filter has converged, because before that there is no
    /// conversion to make.
    ///
    /// Only the first call's timestamp anchors the stream. Everything after is stamped from
    /// its own sample position, so a late caller shifts nothing.
    pub fn feed(&mut self, pcm: &[u8], server_now_us: i64) -> Result<Vec<StampedFrame>, Error> {
        let anchor = *self.anchor_us.get_or_insert(server_now_us);
        let frames = self.encoder.process(pcm)?;
        Ok(self.stamp(frames, anchor))
    }

    /// Flush the encoder's tail, so the last partial chunk is not lost.
    ///
    /// Called before `client_stream/end`. Returns nothing when the stream never started or
    /// the encoder holds no tail.
    pub fn finish(&mut self) -> Result<Vec<StampedFrame>, Error> {
        let Some(anchor) = self.anchor_us else {
            return Ok(Vec::new());
        };
        let frames = self.encoder.flush()?;
        Ok(self.stamp(frames, anchor))
    }

    /// Forget the timeline and the encoder's state, as a new stream would.
    ///
    /// The next `feed` re-anchors. Carrying the old anchor across a stream boundary would
    /// stamp the new stream with the previous one's timeline.
    pub fn reset(&mut self) {
        self.encoder.reset();
        self.anchor_us = None;
        self.samples_sent = 0;
    }

    /// Attach a timestamp to each frame, advancing the timeline by the frame's sample count.
    fn stamp(&mut self, frames: Vec<Vec<u8>>, anchor_us: i64) -> Vec<StampedFrame> {
        let lookahead_us = self.encoder.lookahead_us();
        let frame_samples = self.encoder.frame_samples() as u64;
        frames
            .into_iter()
            .map(|frame| {
                // Integer arithmetic on the sample count rather than an accumulated
                // duration: the rounding error stays bounded by one microsecond instead of
                // compounding once per chunk.
                let offset_us =
                    sendspin_proto::sync::frames_to_micros(self.samples_sent, self.sample_rate);
                self.samples_sent += frame_samples;
                (anchor_us + offset_us - lookahead_us, frame)
            })
            .collect()
    }
}
