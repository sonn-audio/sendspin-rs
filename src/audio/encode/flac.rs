// ABOUTME: FLAC encoding for the source role: one FLAC frame per chunk, with the STREAMINFO
// ABOUTME: header delivered out of band in client_stream/start.

use flac_codec::encode::{FlacStreamWriter, Options};

use super::{frame_stride, samples_from_pcm, Encoder};
use crate::error::Error;

/// Samples per FLAC frame.
///
/// 4096 is the format's usual block size and what a decoder expects to see; at 48 kHz it is
/// ~85 ms, which is long for a live chunk but is the granularity FLAC frames come in.
const BLOCK_SIZE: u16 = 4096;

/// Bytes in a STREAMINFO block, fixed by the format.
const STREAMINFO_LEN: usize = 34;

/// Encodes captured PCM as a sequence of standalone FLAC frames.
///
/// The split between header and frames is what the source wire needs and what a `.flac` file
/// does not: STREAMINFO travels once, in `client_stream/start`, and each chunk afterwards is
/// a complete frame the server can decode on its own.
pub struct FlacEncoder {
    sample_rate: u32,
    bit_depth: u8,
    channels: u8,
    stride: usize,
    buffer: Vec<u8>,
}

impl FlacEncoder {
    /// An encoder for one input format.
    ///
    /// FLAC carries 4 to 32 bits per sample and up to 8 channels; anything else is a format
    /// this codec cannot represent, so it is refused here rather than producing a stream no
    /// decoder will accept.
    pub fn new(sample_rate: u32, bit_depth: u8, channels: u8) -> Result<Self, Error> {
        if !(4..=32).contains(&bit_depth) {
            return Err(Error::Protocol(format!(
                "FLAC cannot carry {bit_depth}-bit samples"
            )));
        }
        if channels == 0 || channels > 8 {
            return Err(Error::Protocol(format!(
                "FLAC cannot carry {channels} channels"
            )));
        }
        if sample_rate == 0 || sample_rate > 0x000F_FFFF {
            return Err(Error::Protocol(format!(
                "FLAC cannot carry a {sample_rate} Hz stream"
            )));
        }
        Ok(Self {
            sample_rate,
            bit_depth,
            channels,
            stride: frame_stride(bit_depth, channels),
            buffer: Vec::new(),
        })
    }

    /// Encode one block of interleaved samples into a standalone FLAC frame.
    fn encode_block(&self, pcm: &[u8]) -> Result<Vec<u8>, Error> {
        let samples = samples_from_pcm(pcm, self.bit_depth)?;
        let mut out = Vec::new();
        let mut writer = FlacStreamWriter::new(&mut out, Options::default());
        writer
            .write(
                self.sample_rate,
                self.channels,
                u32::from(self.bit_depth),
                &samples,
            )
            .map_err(|e| Error::Protocol(format!("FLAC encode failed: {e}")))?;
        Ok(out)
    }

    /// Bytes in one whole block.
    fn block_bytes(&self) -> usize {
        BLOCK_SIZE as usize * self.stride
    }
}

impl Encoder for FlacEncoder {
    /// `fLaC` plus a final STREAMINFO metadata block: 42 bytes, which is the minimum a
    /// decoder needs before it can read a frame.
    ///
    /// The stream is live, so the fields that describe a finished file are left at their
    /// "unknown" encoding: frame sizes zero, total samples zero, and an all-zero MD5. A
    /// decoder reads those as "not stated" rather than as claims to check.
    fn codec_header(&self) -> Option<Vec<u8>> {
        let mut header = Vec::with_capacity(8 + STREAMINFO_LEN);
        header.extend_from_slice(b"fLaC");
        // Last-metadata-block flag (0x80) over block type 0, then the block's length.
        header.push(0x80);
        header.extend_from_slice(&(STREAMINFO_LEN as u32).to_be_bytes()[1..]);

        let mut info = [0u8; STREAMINFO_LEN];
        info[0..2].copy_from_slice(&BLOCK_SIZE.to_be_bytes());
        info[2..4].copy_from_slice(&BLOCK_SIZE.to_be_bytes());
        // Bytes 4..10 are min/max frame size, both "unknown" for a live stream.

        // Then a packed run: 20 bits sample rate, 3 bits channels-1, 5 bits depth-1, and the
        // top 4 bits of a 36-bit total-sample count that is likewise unknown here.
        let packed: u64 = (u64::from(self.sample_rate) << 44)
            | (u64::from(self.channels - 1) << 41)
            | (u64::from(self.bit_depth - 1) << 36);
        info[10..18].copy_from_slice(&packed.to_be_bytes());
        // Bytes 18..34 are the MD5 of the unencoded audio, zero when it is not being tracked.

        header.extend_from_slice(&info);
        Some(header)
    }

    fn frame_samples(&self) -> usize {
        BLOCK_SIZE as usize
    }

    fn process(&mut self, pcm: &[u8]) -> Result<Vec<Vec<u8>>, Error> {
        if !pcm.len().is_multiple_of(self.stride) {
            return Err(Error::Protocol(format!(
                "pcm length {} is not a whole number of frames",
                pcm.len()
            )));
        }
        self.buffer.extend_from_slice(pcm);

        let block = self.block_bytes();
        let mut frames = Vec::new();
        while self.buffer.len() >= block {
            let chunk: Vec<u8> = self.buffer.drain(..block).collect();
            frames.push(self.encode_block(&chunk)?);
        }
        Ok(frames)
    }

    fn flush(&mut self) -> Result<Vec<Vec<u8>>, Error> {
        if self.buffer.is_empty() {
            return Ok(Vec::new());
        }
        // A FLAC frame states its own block size, so a short final block is legal and no
        // padding is needed — unlike Opus, which has no way to say "this one is shorter".
        let tail = std::mem::take(&mut self.buffer);
        Ok(vec![self.encode_block(&tail)?])
    }

    fn reset(&mut self) {
        self.buffer.clear();
    }
}
