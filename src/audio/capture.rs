// ABOUTME: Opening a capture device and handing its PCM to an async caller in the layout the
// ABOUTME: protocol sends: interleaved, little-endian, at the requested depth.

//! Audio capture.
//!
//! The input side of [`SyncedPlayer`](crate::audio::SyncedPlayer)'s job, and much smaller,
//! because a source has no timeline to hold: the server owns that. All this has to do is open
//! the card at the format that was asked for, convert what the card hands back into the layout
//! the wire uses, and get it to the task that stamps and encodes it.

use cpal::traits::{DeviceTrait, HostTrait, StreamTrait};
use tokio::sync::mpsc;

/// A capture device, open and delivering.
///
/// The cpal stream is closed when this is dropped, which is what releases the input for
/// everything else on the machine — so a source holds one only while a server wants audio.
pub struct InputStream {
    // Kept for its `Drop`: dropping the stream is what stops the card.
    _stream: cpal::Stream,
    frames: mpsc::UnboundedReceiver<Vec<u8>>,
}

impl InputStream {
    /// Open `device` — or the platform default input — at this format.
    ///
    /// The card is asked for exactly the rate and channel count requested. A card that cannot
    /// do them is an error here rather than a resampler nobody asked for: a source announces
    /// its input format to the server, and the server is the one that resamples.
    pub fn open(
        device: Option<cpal::Device>,
        sample_rate: u32,
        channels: u8,
        bit_depth: u8,
    ) -> Result<Self, String> {
        if !matches!(bit_depth, 16 | 24) {
            return Err(format!("bit depth {bit_depth} is not 16 or 24"));
        }
        let device = match device {
            Some(device) => device,
            None => cpal::default_host()
                .default_input_device()
                .ok_or_else(|| "no default input device".to_string())?,
        };

        let supported = device
            .supported_input_configs()
            .map_err(|e| format!("could not read the device's input configurations: {e}"))?
            .find(|range| {
                u32::from(range.channels()) == u32::from(channels)
                    && (range.min_sample_rate()..=range.max_sample_rate()).contains(&sample_rate)
            })
            .ok_or_else(|| {
                format!("the capture device cannot record {channels}ch at {sample_rate}Hz")
            })?;
        let sample_format = supported.sample_format();
        let config = cpal::StreamConfig {
            channels: u16::from(channels),
            sample_rate,
            buffer_size: cpal::BufferSize::Default,
        };

        // Unbounded, and the one allocation this path makes per callback. A capture callback
        // that blocks on a full queue would drop samples on the floor with no way to say so;
        // a queue that grows is visible, and the consumer is a task that only has to stamp and
        // encode. The playback path makes the opposite trade, because there the deadline is
        // the card's.
        let (sender, frames) = mpsc::unbounded_channel();
        let on_error = |e| log::error!("Capture stream error: {e}");

        let stream = match sample_format {
            cpal::SampleFormat::F32 => device.build_input_stream(
                config,
                move |data: &[f32], _: &cpal::InputCallbackInfo| {
                    let _ = sender.send(from_f32(data, bit_depth));
                },
                on_error,
                None,
            ),
            cpal::SampleFormat::I16 => device.build_input_stream(
                config,
                move |data: &[i16], _: &cpal::InputCallbackInfo| {
                    let _ = sender.send(from_i16(data, bit_depth));
                },
                on_error,
                None,
            ),
            other => {
                return Err(format!(
                    "the capture device delivers {other:?}, which this crate does not convert"
                ))
            }
        }
        .map_err(|e| format!("could not open the capture device: {e}"))?;

        stream
            .play()
            .map_err(|e| format!("could not start capturing: {e}"))?;
        log::info!("Capture open: {channels}ch {sample_rate}Hz {bit_depth}-bit");

        Ok(Self {
            _stream: stream,
            frames,
        })
    }

    /// The next block of interleaved little-endian PCM, or `None` once the card stops.
    pub async fn recv(&mut self) -> Option<Vec<u8>> {
        self.frames.recv().await
    }
}

/// The loudest sample in a block, as a fraction of full scale.
///
/// A fact rather than a decision: what counts as signal is an installation's business — a
/// turntable's noise floor is not a capture card's — so this measures and says nothing about
/// what it means.
pub fn peak(pcm: &[u8], bit_depth: u8) -> f32 {
    match bit_depth {
        16 => pcm
            .chunks_exact(2)
            .map(|sample| {
                f32::from(i16::from_le_bytes([sample[0], sample[1]]).saturating_abs())
                    / f32::from(i16::MAX)
            })
            .fold(0.0, f32::max),
        24 => pcm
            .chunks_exact(3)
            .map(|sample| {
                // Sign-extend the 24-bit sample into an i32 before measuring it.
                let raw = i32::from_le_bytes([sample[0], sample[1], sample[2], 0]) << 8 >> 8;
                raw.abs() as f32 / 8_388_607.0
            })
            .fold(0.0, f32::max),
        _ => 0.0,
    }
}

/// Convert cpal's floats to the wire's integers, clamped so a hot input wraps to full scale
/// rather than to the opposite sign.
fn from_f32(data: &[f32], bit_depth: u8) -> Vec<u8> {
    let mut pcm = Vec::with_capacity(data.len() * usize::from(bit_depth) / 8);
    for sample in data {
        let clamped = sample.clamp(-1.0, 1.0);
        match bit_depth {
            16 => pcm.extend_from_slice(&((clamped * f32::from(i16::MAX)) as i16).to_le_bytes()),
            _ => {
                let scaled = (f64::from(clamped) * 8_388_607.0) as i32;
                pcm.extend_from_slice(&scaled.to_le_bytes()[..3]);
            }
        }
    }
    pcm
}

/// Convert cpal's 16-bit samples, widening when the wire carries more than the card gives.
fn from_i16(data: &[i16], bit_depth: u8) -> Vec<u8> {
    let mut pcm = Vec::with_capacity(data.len() * usize::from(bit_depth) / 8);
    for sample in data {
        match bit_depth {
            16 => pcm.extend_from_slice(&sample.to_le_bytes()),
            _ => pcm.extend_from_slice(&(i32::from(*sample) << 8).to_le_bytes()[..3]),
        }
    }
    pcm
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_scale_floats_reach_full_scale_integers() {
        assert_eq!(from_f32(&[1.0], 16), i16::MAX.to_le_bytes());
        assert_eq!(from_f32(&[-1.0], 16), (-i16::MAX).to_le_bytes());
    }

    /// A card that runs hot hands back values past ±1.0. Wrapping them would turn a loud
    /// passage into a burst of the opposite sign, which is heard as a click rather than as
    /// clipping.
    #[test]
    fn a_hot_input_clamps_rather_than_wrapping() {
        assert_eq!(from_f32(&[1.5], 16), i16::MAX.to_le_bytes());
        assert_eq!(from_f32(&[-1.5], 16), (-i16::MAX).to_le_bytes());
    }

    #[test]
    fn sixteen_bit_samples_widen_into_twenty_four() {
        // 0x0102 becomes 0x010200, little-endian over three bytes.
        assert_eq!(from_i16(&[0x0102], 24), vec![0x00, 0x02, 0x01]);
    }

    #[test]
    fn a_peak_is_measured_over_the_whole_block_at_either_depth() {
        // Full scale, one quiet sample beside it.
        let loud = from_i16(&[0, i16::MAX], 16);
        assert!((peak(&loud, 16) - 1.0).abs() < 1e-6);
        assert_eq!(peak(&from_i16(&[0, 0], 16), 16), 0.0);

        let loud_24 = from_i16(&[0, i16::MAX], 24);
        assert!((peak(&loud_24, 24) - 1.0).abs() < 1e-3);
    }

    /// A negative sample is as loud as a positive one; measuring the raw value would call the
    /// bottom half of a waveform silence.
    #[test]
    fn a_negative_sample_measures_as_loud_as_a_positive_one() {
        assert!((peak(&from_i16(&[-i16::MAX], 16), 16) - 1.0).abs() < 1e-6);
        assert!((peak(&from_i16(&[-i16::MAX], 24), 24) - 1.0).abs() < 1e-3);
    }

    /// Opens a real device, so it is skipped by default: a machine with no input, or one whose
    /// input is already claimed, would fail this for reasons that are not the code's.
    ///
    /// Run it with `cargo test --lib -- --ignored capture_delivers` when changing this module.
    #[tokio::test]
    #[ignore = "needs a capture device"]
    async fn capture_delivers_blocks_from_a_real_device() {
        let mut stream = InputStream::open(None, 48_000, 1, 16)
            .or_else(|_| InputStream::open(None, 44_100, 1, 16))
            .expect("no usable default input");
        let block = tokio::time::timeout(std::time::Duration::from_secs(2), stream.recv())
            .await
            .expect("the card delivered nothing within two seconds")
            .expect("the capture stream ended");
        assert!(!block.is_empty(), "a delivered block should hold samples");
        assert_eq!(block.len() % 2, 0, "16-bit samples come in pairs of bytes");
    }

    #[test]
    fn each_sample_takes_the_bytes_the_depth_asks_for() {
        assert_eq!(from_i16(&[1, 2, 3], 16).len(), 6);
        assert_eq!(from_i16(&[1, 2, 3], 24).len(), 9);
    }
}
