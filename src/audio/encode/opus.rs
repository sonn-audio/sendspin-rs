// ABOUTME: Opus encoding for the source role: fixed 20 ms frames, and the encoder delay a
// ABOUTME: source has to subtract from its capture timestamps.

use super::{frame_stride, Encoder};
use crate::error::Error;

/// Opus runs at 48 kHz internally and the spec's source role sends it at that rate.
const OPUS_RATE: u32 = 48_000;

/// Frame length. 20 ms is Opus's default and the one every decoder handles.
const FRAME_US: u32 = 20_000;

/// The reference encoder's algorithmic delay, in samples at 48 kHz.
///
/// This is the `pre_skip` an `OpusHead` normally carries — 6.5 ms. The reference client reads
/// it back from libopus rather than assuming it; `opus-rs` does not expose the figure, so it
/// is stated here instead. Wrong by a millisecond it would shift every chunk's timestamp by
/// that much and no more, which is why it is a constant rather than a reason not to
/// compensate at all.
const PRE_SKIP_SAMPLES: u32 = 312;

/// A source captures music, not speech, so the encoder is told to optimise for it.
const ENCODER_APPLICATION: opus_rs::Application = opus_rs::Application::Audio;

/// Encodes captured PCM as Opus frames.
///
/// Opus takes only 16-bit input here, which is the spec's shape for the codec: it ignores the
/// announced `bit_depth` and decodes at 16 either way.
pub struct OpusEncoder {
    encoder: opus_rs::OpusEncoder,
    channels: u8,
    stride: usize,
    frame_samples: usize,
    buffer: Vec<u8>,
    scratch: Vec<f32>,
}

impl OpusEncoder {
    /// An encoder for one input format.
    pub fn new(sample_rate: u32, bit_depth: u8, channels: u8) -> Result<Self, Error> {
        if bit_depth != 16 {
            return Err(Error::Protocol(format!(
                "Opus capture requires 16-bit PCM, got {bit_depth}-bit"
            )));
        }
        if channels == 0 || channels > 2 {
            return Err(Error::Protocol(format!(
                "Opus capture requires mono or stereo, got {channels} channels"
            )));
        }
        let encoder =
            opus_rs::OpusEncoder::new(sample_rate as i32, channels as usize, ENCODER_APPLICATION)
                .map_err(|e| Error::Protocol(format!("could not create the Opus encoder: {e}")))?;
        let frame_samples =
            ((u64::from(sample_rate) * u64::from(FRAME_US)) / 1_000_000).max(1) as usize;
        Ok(Self {
            encoder,
            channels,
            stride: frame_stride(bit_depth, channels),
            frame_samples,
            buffer: Vec::new(),
            scratch: Vec::new(),
        })
    }

    /// Encode exactly one frame's worth of interleaved 16-bit PCM.
    fn encode_frame(&mut self, pcm: &[u8]) -> Result<Vec<u8>, Error> {
        // opus-rs takes float input; the wire carries s16, so scale rather than cast.
        self.scratch.clear();
        self.scratch.extend(
            pcm.chunks_exact(2)
                .map(|b| f32::from(i16::from_le_bytes([b[0], b[1]])) / f32::from(i16::MAX)),
        );
        // Comfortably above any 20 ms frame Opus will produce, so a frame is never truncated.
        let mut out = vec![0u8; 4000];
        let written = self
            .encoder
            .encode(&self.scratch, self.frame_samples, &mut out)
            .map_err(|e| Error::Protocol(format!("Opus encode failed: {e}")))?;
        out.truncate(written);
        Ok(out)
    }

    /// Bytes in one whole frame.
    fn frame_bytes(&self) -> usize {
        self.frame_samples * self.stride
    }
}

impl Encoder for OpusEncoder {
    /// None. Opus frames on this wire stand alone: the server is told the rate, channels and
    /// depth in `client_stream/start` and needs no `OpusHead`.
    fn codec_header(&self) -> Option<Vec<u8>> {
        None
    }

    fn frame_samples(&self) -> usize {
        self.frame_samples
    }

    /// The encoder consumes samples before it emits them, so a chunk stamped with the
    /// capture time of its first sample is late by exactly this much.
    fn lookahead_us(&self) -> i64 {
        i64::from(PRE_SKIP_SAMPLES) * 1_000_000 / i64::from(OPUS_RATE)
    }

    fn process(&mut self, pcm: &[u8]) -> Result<Vec<Vec<u8>>, Error> {
        if !pcm.len().is_multiple_of(self.stride) {
            return Err(Error::Protocol(format!(
                "pcm length {} is not a whole number of frames",
                pcm.len()
            )));
        }
        self.buffer.extend_from_slice(pcm);

        let frame = self.frame_bytes();
        let mut frames = Vec::new();
        while self.buffer.len() >= frame {
            let chunk: Vec<u8> = self.buffer.drain(..frame).collect();
            frames.push(self.encode_frame(&chunk)?);
        }
        Ok(frames)
    }

    fn flush(&mut self) -> Result<Vec<Vec<u8>>, Error> {
        if self.buffer.is_empty() {
            return Ok(Vec::new());
        }
        // Opus frames are a fixed length, so the tail is padded with silence rather than sent
        // short — a decoder has no way to be told the last one is different.
        let mut tail = std::mem::take(&mut self.buffer);
        tail.resize(self.frame_bytes(), 0);
        Ok(vec![self.encode_frame(&tail)?])
    }

    fn reset(&mut self) {
        self.buffer.clear();
        // A fresh encoder rather than a reset method: opus-rs offers none, and carrying
        // prediction state across a stream boundary would decode as a glitch on the first
        // frame of the next one.
        if let Ok(fresh) = opus_rs::OpusEncoder::new(
            OPUS_RATE as i32,
            self.channels as usize,
            ENCODER_APPLICATION,
        ) {
            self.encoder = fresh;
        }
    }
}
