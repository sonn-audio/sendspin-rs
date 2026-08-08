// ABOUTME: The source-role encoders, checked by decoding what they produce — a frame that
// ABOUTME: only this crate can read would pass a shape test and fail a real server.

use sendspin::audio::decode::{Decoder, FlacDecoder, OpusDecoder, PcmDecoder};
use sendspin::audio::encode::{create_encoder, Encoder, FlacEncoder, OpusEncoder, PcmEncoder};

const RATE: u32 = 48_000;
const CHANNELS: u8 = 2;

/// Interleaved 16-bit little-endian sine, `frames` sample tuples long.
fn tone(frames: usize) -> Vec<u8> {
    let mut pcm = Vec::with_capacity(frames * CHANNELS as usize * 2);
    for n in 0..frames {
        let phase = std::f32::consts::TAU * 440.0 * n as f32 / RATE as f32;
        let sample = (phase.sin() * 0.3 * f32::from(i16::MAX)) as i16;
        for _ in 0..CHANNELS {
            pcm.extend_from_slice(&sample.to_le_bytes());
        }
    }
    pcm
}

// =============================================================================
// Framing
// =============================================================================

#[test]
fn pcm_cuts_whole_chunks_and_buffers_the_rest() {
    let mut encoder = PcmEncoder::with_chunk_duration(RATE, 16, CHANNELS, 20_000);
    let chunk_frames = RATE as usize / 50;
    assert_eq!(encoder.frame_samples(), chunk_frames);

    // One and a half chunks in: one chunk out, half a chunk held back.
    let frames = encoder
        .process(&tone(chunk_frames + chunk_frames / 2))
        .unwrap();
    assert_eq!(frames.len(), 1);
    assert_eq!(frames[0].len(), chunk_frames * CHANNELS as usize * 2);

    // Flush pads the remainder rather than dropping it: it is still audio that played.
    let tail = encoder.flush().unwrap();
    assert_eq!(tail.len(), 1);
    assert_eq!(tail[0].len(), chunk_frames * CHANNELS as usize * 2);
    assert!(encoder.flush().unwrap().is_empty(), "and then nothing");
}

#[test]
fn pcm_passes_its_input_through_unchanged() {
    let mut encoder = PcmEncoder::with_chunk_duration(RATE, 16, CHANNELS, 20_000);
    let pcm = tone(RATE as usize / 50);
    let frames = encoder.process(&pcm).unwrap();
    assert_eq!(frames[0], pcm, "raw PCM is not transformed, only cut");
}

#[test]
fn an_input_that_is_not_whole_frames_is_refused() {
    let mut encoder = PcmEncoder::new(RATE, 16, CHANNELS);
    // Three bytes cannot be a whole stereo 16-bit frame.
    assert!(encoder.process(&[0, 0, 0]).is_err());
}

// =============================================================================
// FLAC
// =============================================================================

/// The server checks this header byte for byte before it will build a decoder, so the shape
/// is worth pinning: `fLaC`, a last-metadata-block marker over type 0, and a length of 34.
#[test]
fn the_flac_header_carries_streaminfo_the_way_a_server_checks_for_it() {
    let encoder = FlacEncoder::new(RATE, 16, CHANNELS).unwrap();
    let header = encoder.codec_header().expect("FLAC needs a codec header");

    assert!(header.len() >= 42);
    assert_eq!(&header[..4], b"fLaC");
    assert_eq!(header[4] & 0x7F, 0, "block type 0 is STREAMINFO");
    assert_eq!(header[4] & 0x80, 0x80, "and it is the last block");
    assert_eq!(u32::from_be_bytes([0, header[5], header[6], header[7]]), 34);

    // The packed run: 20 bits of sample rate, then channels-1 and depth-1.
    let packed = u64::from_be_bytes(header[18..26].try_into().unwrap());
    assert_eq!((packed >> 44) & 0xF_FFFF, u64::from(RATE));
    assert_eq!((packed >> 41) & 0x7, u64::from(CHANNELS - 1));
    assert_eq!((packed >> 36) & 0x1F, 15, "16-bit is stored as 15");
}

#[test]
fn flac_frames_decode_back_to_the_samples_that_went_in() {
    let mut encoder = FlacEncoder::new(RATE, 16, CHANNELS).unwrap();
    let pcm = tone(4096);
    let frames = encoder.process(&pcm).unwrap();
    assert_eq!(frames.len(), 1, "4096 frames is exactly one FLAC block");

    // Built from this encoder's own header, so the decoder cross-checks every frame
    // against the STREAMINFO rather than trusting the frame alone.
    let header = encoder.codec_header().unwrap();
    let decoder = FlacDecoder::with_header(&header).unwrap();
    let decoded = decoder.decode(&frames[0]).unwrap();
    assert_eq!(decoded.len(), 4096 * CHANNELS as usize);

    // FLAC is lossless, so this is equality rather than a tolerance. The decoder widens
    // native-depth samples to full-scale i32 the way PcmDecoder does, so the comparison
    // shifts with it.
    let expected: Vec<i32> = pcm
        .chunks_exact(2)
        .map(|b| i32::from(i16::from_le_bytes([b[0], b[1]])) << 16)
        .collect();
    assert_eq!(decoded.as_ref(), expected.as_slice());
}

/// A FLAC frame states its own block size, so the tail goes out short rather than padded.
#[test]
fn a_short_final_flac_block_is_sent_as_it_is() {
    let mut encoder = FlacEncoder::new(RATE, 16, CHANNELS).unwrap();
    assert!(encoder.process(&tone(1000)).unwrap().is_empty());

    let tail = encoder.flush().unwrap();
    assert_eq!(tail.len(), 1);
    let decoder = FlacDecoder::with_header(&encoder.codec_header().unwrap()).unwrap();
    let decoded = decoder.decode(&tail[0]).unwrap();
    assert_eq!(
        decoded.len(),
        1000 * CHANNELS as usize,
        "1000 frames in, 1000 out — no silence added"
    );
}

// =============================================================================
// Opus
// =============================================================================

#[test]
fn opus_produces_twenty_millisecond_frames() {
    let mut encoder = OpusEncoder::new(RATE, 16, CHANNELS).unwrap();
    assert_eq!(encoder.frame_samples(), 960, "20 ms at 48 kHz");

    let frames = encoder.process(&tone(960 * 3)).unwrap();
    assert_eq!(frames.len(), 3);
    for frame in &frames {
        assert!(!frame.is_empty(), "an empty packet is not a frame");
    }
}

#[test]
fn opus_frames_decode_to_the_right_length() {
    let mut encoder = OpusEncoder::new(RATE, 16, CHANNELS).unwrap();
    let frames = encoder.process(&tone(960)).unwrap();

    let decoder = OpusDecoder::new(RATE, CHANNELS).unwrap();
    let decoded = decoder.decode(&frames[0]).unwrap();
    // Opus is lossy, so the samples differ; the frame length is what has to survive.
    assert_eq!(decoded.len(), 960 * CHANNELS as usize);
}

/// Without lookahead compensation every Opus chunk claims a capture time later than the
/// truth, by a constant — which is exactly the kind of error that plays but never lines up.
#[test]
fn opus_reports_its_encoder_delay_and_the_others_have_none() {
    let opus = OpusEncoder::new(RATE, 16, CHANNELS).unwrap();
    assert_eq!(opus.lookahead_us(), 6_500, "6.5 ms, the Opus pre-skip");

    assert_eq!(PcmEncoder::new(RATE, 16, CHANNELS).lookahead_us(), 0);
    assert_eq!(
        FlacEncoder::new(RATE, 16, CHANNELS).unwrap().lookahead_us(),
        0
    );
}

#[test]
fn opus_refuses_a_depth_it_cannot_carry() {
    // The spec decodes Opus at 16 bits whatever the announcement says, so accepting 24 here
    // would silently reinterpret the caller's samples.
    assert!(OpusEncoder::new(RATE, 24, CHANNELS).is_err());
    assert!(OpusEncoder::new(RATE, 16, 3).is_err());
}

// =============================================================================
// Selection
// =============================================================================

#[test]
fn the_factory_knows_the_codec_names_the_spec_uses() {
    for codec in ["pcm", "flac", "opus"] {
        assert!(
            create_encoder(codec, RATE, 16, CHANNELS).is_ok(),
            "{codec} should be encodable"
        );
    }
    assert!(create_encoder("mp3", RATE, 16, CHANNELS).is_err());
}

/// Only PCM needs to be told, because only PCM's bytes are read back verbatim.
#[test]
fn pcm_round_trips_through_the_decoder_that_reads_it() {
    let mut encoder = create_encoder("pcm", RATE, 16, CHANNELS).unwrap();
    let pcm = tone(480);
    let frames = encoder.process(&pcm).unwrap();
    let frames = if frames.is_empty() {
        encoder.flush().unwrap()
    } else {
        frames
    };

    let decoder = PcmDecoder::new(16);
    let decoded = decoder.decode(&frames[0]).unwrap();
    // Widened to full scale, as every decoder in this crate reports samples.
    assert_eq!(
        decoded[0],
        i32::from(i16::from_le_bytes([pcm[0], pcm[1]])) << 16
    );
}

// =============================================================================
// Capture timing
// =============================================================================

use sendspin::audio::SourceCapture;

/// Only the first feed anchors the stream; later ones are stamped from sample position.
///
/// This is the difference between a timeline that survives a late thread and one that folds
/// every scheduling hiccup into the audio.
#[test]
fn a_late_feed_does_not_shift_the_timeline() {
    let mut capture = SourceCapture::new("pcm", RATE, 16, CHANNELS).unwrap();
    // The PCM encoder chunks at 25 ms, so 50 ms is two whole chunks.
    let two_chunks = RATE as usize / 20;

    let first = capture.feed(&tone(two_chunks), 1_000_000).unwrap();
    assert_eq!(first.len(), 2);
    assert_eq!(first[0].0, 1_000_000);
    assert_eq!(first[1].0, 1_025_000);

    // The caller is 500 ms late, and says so. The stamps must ignore it.
    let second = capture.feed(&tone(two_chunks), 1_500_000).unwrap();
    assert_eq!(
        second[0].0, 1_050_000,
        "stamped from sample position, not from now"
    );
}

#[test]
fn the_first_chunk_carries_the_anchor_it_was_given() {
    let mut capture = SourceCapture::new("pcm", RATE, 16, CHANNELS).unwrap();
    let frames = capture.feed(&tone(RATE as usize / 40), 42_000_000).unwrap();
    assert_eq!(frames[0].0, 42_000_000);
}

/// Opus stamps earlier than its anchor by exactly its lookahead, because the encoder
/// consumed those samples before it emitted anything.
#[test]
fn opus_capture_subtracts_its_lookahead() {
    let mut capture = SourceCapture::new("opus", RATE, 16, CHANNELS).unwrap();
    let frames = capture.feed(&tone(960), 10_000_000).unwrap();
    assert_eq!(frames.len(), 1);
    assert_eq!(frames[0].0, 10_000_000 - 6_500);
}

#[test]
fn flac_capture_announces_a_header_and_pcm_does_not() {
    let flac = SourceCapture::new("flac", RATE, 16, CHANNELS).unwrap();
    let header = flac.codec_header().expect("FLAC announces STREAMINFO");
    // Standard base64, which is what the spec's codec_header carries — not the base64url
    // the PSK fields use, so the alphabets must not be confused.
    use base64::Engine;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(&header)
        .expect("codec_header must be standard base64");
    assert_eq!(&decoded[..4], b"fLaC");
    assert_eq!(decoded.len(), 42);

    assert!(SourceCapture::new("pcm", RATE, 16, CHANNELS)
        .unwrap()
        .codec_header()
        .is_none());
}

/// A reset re-anchors: carrying the old timeline into a new stream would stamp it with the
/// previous stream's clock.
#[test]
fn a_reset_starts_a_fresh_timeline() {
    let mut capture = SourceCapture::new("pcm", RATE, 16, CHANNELS).unwrap();
    capture.feed(&tone(RATE as usize / 10), 1_000_000).unwrap();
    capture.reset();

    let frames = capture.feed(&tone(RATE as usize / 40), 9_000_000).unwrap();
    assert_eq!(frames[0].0, 9_000_000, "the new anchor, not the old one");
}

#[test]
fn finishing_a_stream_that_never_started_yields_nothing() {
    let mut capture = SourceCapture::new("pcm", RATE, 16, CHANNELS).unwrap();
    assert!(capture.finish().unwrap().is_empty());
}

/// The stamps advance by exactly one chunk each, with no rounding drift over many chunks.
#[test]
fn stamps_advance_without_accumulating_rounding_error() {
    let mut capture = SourceCapture::new("opus", RATE, 16, CHANNELS).unwrap();
    let frames = capture.feed(&tone(960 * 50), 0).unwrap();
    assert_eq!(frames.len(), 50);
    for (index, (timestamp_us, _)) in frames.iter().enumerate() {
        // 960 samples at 48 kHz is exactly 20000 us, so every stamp is exact.
        assert_eq!(*timestamp_us, index as i64 * 20_000 - 6_500);
    }
}
