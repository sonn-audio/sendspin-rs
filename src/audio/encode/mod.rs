// ABOUTME: Audio encoders for the source role: PCM, FLAC and Opus, each turning captured
// ABOUTME: PCM into the frames a source puts on the wire.

//! Encoders for the `source@v1` role.
//!
//! The mirror of [`decode`](crate::audio::decode). A source captures PCM locally and streams it up
//! to the server, which resamples and transcodes centrally — so there is no negotiation
//! here, only the format the source announces in `client_stream/start` and the frames that
//! follow it.
//!
//! Three things every encoder has to answer, and they are the whole trait:
//!
//! - **The codec header**, when the codec needs one out of band. FLAC does: its STREAMINFO
//!   cannot be inferred from a frame. PCM and Opus do not.
//! - **Frames**, produced whenever enough input has accumulated. A codec with a fixed frame
//!   size buffers until it has one; the caller feeds whatever size it captured in.
//! - **Lookahead**, the encoder's own delay ahead of the first input sample. A source stamps
//!   each chunk with the capture time of its first sample, so an encoder that consumes
//!   samples before emitting them would stamp every chunk late by exactly this much.

/// FLAC encoder.
pub mod flac;
/// Opus encoder.
pub mod opus;
/// PCM framing, which is encoding only in the sense that it cuts chunks.
pub mod pcm;

pub use flac::FlacEncoder;
pub use opus::OpusEncoder;
pub use pcm::PcmEncoder;

use crate::error::Error;

/// Turns captured PCM into the frames a source streams.
///
/// Input is interleaved, little-endian, at the bit depth the encoder was built with — the
/// same shape the source announced. Implementations buffer whatever does not fill a frame.
pub trait Encoder: Send {
    /// The out-of-band codec header, base64-encoded into `client_stream/start`.
    ///
    /// `None` for codecs whose frames stand alone.
    fn codec_header(&self) -> Option<Vec<u8>>;

    /// How many PCM frames — sample tuples, not bytes — each output frame carries.
    fn frame_samples(&self) -> usize;

    /// The encoder's delay ahead of its first input sample, in microseconds.
    ///
    /// Subtracted from a chunk's capture timestamp: without it every chunk claims to have
    /// been captured later than it was, and the server lines the audio up wrong by a
    /// constant.
    fn lookahead_us(&self) -> i64 {
        0
    }

    /// Encode what fills whole frames, buffering the rest.
    fn process(&mut self, pcm: &[u8]) -> Result<Vec<Vec<u8>>, Error>;

    /// Emit whatever is buffered, padding the last frame with silence.
    ///
    /// Padding rather than dropping: a partial frame is still audio the operator played, and
    /// a codec with a fixed frame size has no way to say "this one is shorter".
    fn flush(&mut self) -> Result<Vec<Vec<u8>>, Error>;

    /// Discard buffered input and start over, as a new stream would.
    fn reset(&mut self);
}

/// Build the encoder for a codec name as it appears on the wire.
///
/// The names are the spec's: `pcm`, `flac`, `opus`. Anything else is a codec this build
/// cannot produce, which is a configuration error rather than a protocol one.
pub fn create_encoder(
    codec: &str,
    sample_rate: u32,
    bit_depth: u8,
    channels: u8,
) -> Result<Box<dyn Encoder>, Error> {
    match codec {
        "pcm" => Ok(Box::new(PcmEncoder::new(sample_rate, bit_depth, channels))),
        "flac" => Ok(Box::new(FlacEncoder::new(
            sample_rate,
            bit_depth,
            channels,
        )?)),
        "opus" => Ok(Box::new(OpusEncoder::new(
            sample_rate,
            bit_depth,
            channels,
        )?)),
        other => Err(Error::Protocol(format!("cannot encode codec {other:?}"))),
    }
}

/// Bytes one interleaved PCM frame occupies.
pub(crate) fn frame_stride(bit_depth: u8, channels: u8) -> usize {
    (bit_depth as usize / 8) * channels as usize
}

/// Read interleaved little-endian PCM into signed samples.
///
/// 24-bit is sign-extended from three bytes; the wire carries it packed, and every encoder
/// here wants it widened.
pub(crate) fn samples_from_pcm(pcm: &[u8], bit_depth: u8) -> Result<Vec<i32>, Error> {
    let width = bit_depth as usize / 8;
    if width == 0 || !pcm.len().is_multiple_of(width) {
        return Err(Error::Protocol(format!(
            "pcm length {} is not a whole number of {bit_depth}-bit samples",
            pcm.len()
        )));
    }
    Ok(pcm
        .chunks_exact(width)
        .map(|bytes| match bytes {
            [a] => i32::from(*a as i8),
            [a, b] => i32::from(i16::from_le_bytes([*a, *b])),
            // Sign-extend the packed 24-bit sample into the top byte.
            [a, b, c] => i32::from_le_bytes([*a, *b, *c, if *c & 0x80 != 0 { 0xFF } else { 0 }]),
            [a, b, c, d] => i32::from_le_bytes([*a, *b, *c, *d]),
            _ => unreachable!("width is 1..=4"),
        })
        .collect())
}
