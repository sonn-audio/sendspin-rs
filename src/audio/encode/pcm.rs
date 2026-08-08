// ABOUTME: PCM "encoding" — cutting captured audio into fixed-size chunks, which is all a
// ABOUTME: raw stream needs before it goes on the wire.

use super::{frame_stride, Encoder};
use crate::error::Error;

/// The chunk length a source sends when nothing else decides it.
///
/// 25 ms is what the reference uses. Short enough that a chunk boundary costs little latency,
/// long enough that the per-chunk header and the Noise frame around it stay negligible.
const DEFAULT_CHUNK_US: u32 = 25_000;

/// Cuts interleaved PCM into fixed-size chunks.
///
/// There is no codec here — the bytes go out as they came in. What it does own is the chunk
/// boundary, which is the one thing a raw stream still has to decide.
pub struct PcmEncoder {
    stride: usize,
    chunk_samples: usize,
    buffer: Vec<u8>,
}

impl PcmEncoder {
    /// An encoder for one input format, chunking at the default 25 ms.
    pub fn new(sample_rate: u32, bit_depth: u8, channels: u8) -> Self {
        Self::with_chunk_duration(sample_rate, bit_depth, channels, DEFAULT_CHUNK_US)
    }

    /// An encoder chunking at an explicit duration.
    pub fn with_chunk_duration(
        sample_rate: u32,
        bit_depth: u8,
        channels: u8,
        chunk_us: u32,
    ) -> Self {
        // At least one sample per chunk, however short the caller asked for: a zero-sample
        // chunk would loop forever below.
        let chunk_samples =
            ((u64::from(sample_rate) * u64::from(chunk_us)) / 1_000_000).max(1) as usize;
        Self {
            stride: frame_stride(bit_depth, channels),
            chunk_samples,
            buffer: Vec::new(),
        }
    }

    /// Bytes in one whole output chunk.
    fn chunk_bytes(&self) -> usize {
        self.chunk_samples * self.stride
    }
}

impl Encoder for PcmEncoder {
    fn codec_header(&self) -> Option<Vec<u8>> {
        None
    }

    fn frame_samples(&self) -> usize {
        self.chunk_samples
    }

    fn process(&mut self, pcm: &[u8]) -> Result<Vec<Vec<u8>>, Error> {
        if self.stride == 0 {
            return Err(Error::Protocol(
                "pcm encoder has a zero frame stride".into(),
            ));
        }
        if !pcm.len().is_multiple_of(self.stride) {
            return Err(Error::Protocol(format!(
                "pcm length {} is not a whole number of frames",
                pcm.len()
            )));
        }
        self.buffer.extend_from_slice(pcm);

        let chunk = self.chunk_bytes();
        let whole = self.buffer.len() / chunk;
        let mut frames = Vec::with_capacity(whole);
        for _ in 0..whole {
            frames.push(self.buffer.drain(..chunk).collect());
        }
        Ok(frames)
    }

    fn flush(&mut self) -> Result<Vec<Vec<u8>>, Error> {
        if self.buffer.is_empty() {
            return Ok(Vec::new());
        }
        // Silence is zero at every bit depth this carries, so a resize does the padding.
        self.buffer.resize(self.chunk_bytes(), 0);
        Ok(vec![std::mem::take(&mut self.buffer)])
    }

    fn reset(&mut self) {
        self.buffer.clear();
    }
}
