// ABOUTME: Clock synchronization for Sendspin protocol
// ABOUTME: NTP-style round-trip time calculation and server timestamp conversion

/// Clock synchronization implementation
pub mod clock;
/// Raw monotonic clock trait and platform implementations
pub mod raw_clock;

pub use clock::{ClockSync, SyncQuality};

/// Microseconds for a whole number of frames at `sample_rate`.
///
/// Here rather than in either end because both ends need it and both had their own: a server
/// stamping the chunks it sends and a client measuring the audio it has queued are asking the
/// same question, and an answer that disagrees between them is a drift neither can see.
///
/// Done in `i128` because the intermediate product overflows `i64` after about six hours at
/// 48 kHz, and a server that has been playing all day is the normal case rather than the exotic
/// one. A zero rate answers zero instead of dividing by it.
pub fn frames_to_micros(frames: u64, sample_rate: u32) -> i64 {
    if sample_rate == 0 {
        return 0;
    }
    let micros = i128::from(frames) * 1_000_000 / i128::from(sample_rate);
    i64::try_from(micros).unwrap_or(i64::MAX)
}

pub use raw_clock::{Clock, DefaultClock};

#[cfg(test)]
mod timeline_tests {
    use super::frames_to_micros;

    /// A day of playback must not wrap the arithmetic, which is what `i64` intermediates did.
    #[test]
    fn a_long_stream_does_not_overflow() {
        let frames = 48_000u64 * 60 * 60 * 24;
        assert_eq!(frames_to_micros(frames, 48_000), 86_400_000_000);
    }

    /// The degenerate rate is answered rather than panicking on a division by zero.
    #[test]
    fn a_zero_rate_is_answered() {
        assert_eq!(frames_to_micros(100, 0), 0);
        assert_eq!(frames_to_micros(0, 48_000), 0);
    }

    /// Truncation is toward zero and does not accumulate: the caller advances a running frame
    /// count and converts once, rather than summing per-chunk durations.
    #[test]
    fn conversion_truncates_rather_than_accumulating() {
        assert_eq!(frames_to_micros(441, 48_000), 9_187);
        assert_eq!(frames_to_micros(441 * 1000, 48_000), 9_187_500);
    }
}
