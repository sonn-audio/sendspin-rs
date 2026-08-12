// ABOUTME: Turning a percentage into a level a hardware mixer understands, on the two kinds of
// ABOUTME: mixer that exist, and back again.

//! Mixer scaling.
//!
//! A percentage is a promise about loudness, and a mixer's raw range is not. Which arithmetic
//! turns one into the other depends on what the card is:
//!
//! - **A mixer that reports a dB range.** Its steps mean something known, so a percentage can
//!   be turned into an attenuation. Loudness is perceived roughly logarithmically, so the
//!   mapping is logarithmic too — which is what makes 50% sound like half rather than measure
//!   like half.
//! - **A mixer that reports no dB information at all.** Its steps mean nothing this crate can
//!   discover, so the only honest mapping is straight onto the register range. Any curve
//!   applied here would be a guess dressed up as a calibration.
//!
//! The arithmetic matches the mapped scale that `amixer -M` uses, which is the same scale the
//! reference command-line client drives its mixer through — so a card set to 40% by either
//! lands in the same place.
//!
//! Everything here is free functions over integers, testable without a sound card. The ALSA
//! binding that feeds them lives in [`crate::audio::mixer`] and is Linux-only; this is not,
//! because arithmetic has no platform.

/// A dB span at or below which the scale is treated as linear in dB.
///
/// Below roughly this much range, a logarithmic mapping crowds every useful level into the top
/// of the control and leaves most of the travel doing nothing audible. The threshold is the
/// reference mapping's own.
const MAX_LINEAR_DB_SPAN_MB: i64 = 24 * 100;

/// The value ALSA reports as the minimum when the bottom of the range is silence rather than a
/// finite attenuation.
///
/// A range that bottoms out in true silence has no lowest dB value to normalise against, so the
/// mapping skips the correction that a finite floor needs.
const DB_GAIN_MUTE: i64 = -9_999_999;

/// How a percentage is mapped onto a mixer's own scale.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum VolumeScale {
    /// Decide from what the card reports: its dB range where it has one, its raw range where it
    /// does not.
    ///
    /// Right for every card that describes itself honestly, which is most of them.
    #[default]
    Automatic,
    /// Always map through the card's dB range, ignoring what it reports about having one.
    ///
    /// For a card whose dB information is wrong in the other direction — present but unusable.
    Decibel,
    /// Always map linearly onto the raw register range.
    ///
    /// For a card that reports a dB range it does not honour. Cards do this, and an application
    /// that has measured one is in a better position to say so than this crate is.
    Raw,
}

/// The scale actually in use, once the card has been asked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChosenScale {
    /// Map through dB, logarithmically over this span in millibels.
    Decibel {
        /// The card's quietest setting, in hundredths of a dB.
        min: i64,
        /// The card's loudest setting, in hundredths of a dB.
        max: i64,
    },
    /// Map straight onto the raw range, because the card said nothing about dB.
    Raw,
}

impl ChosenScale {
    /// Pick a scale for a card whose dB range reads `db_range`.
    ///
    /// `db_range` is what the card reports; a card with no dB information reports a range that
    /// is empty or inverted, which is the same thing said two ways.
    ///
    /// Deliberately not derived from the level the card currently sits at: at maximum every
    /// mixer reads zero dB below maximum, so a card that happens to be turned up would be
    /// misread as having no range at all.
    pub fn choose(requested: VolumeScale, db_range: (i64, i64)) -> Self {
        let (min, max) = db_range;
        let usable = max > min;
        match requested {
            VolumeScale::Raw => Self::Raw,
            VolumeScale::Decibel | VolumeScale::Automatic if usable => Self::Decibel { min, max },
            // Asked for dB on a card that has none: there is nothing to map through, and
            // refusing to set a volume at all would be the worse answer.
            VolumeScale::Decibel => Self::Raw,
            VolumeScale::Automatic => Self::Raw,
        }
    }

    /// A phrase for the log line that records the decision.
    pub fn describe(&self) -> String {
        match self {
            Self::Decibel { min, max } => format!(
                "dB scale over {:.1}..{:.1} dB",
                *min as f64 / 100.0,
                *max as f64 / 100.0
            ),
            Self::Raw => "raw register steps (the card reports no dB range)".to_string(),
        }
    }
}

/// Map 0-100 onto a card's dB range, in hundredths of a dB.
///
/// Logarithmic over a wide range and linear over a narrow one, matching the reference mapping.
/// The floor correction keeps 0% at the card's quietest setting rather than a little above it,
/// which on a card whose range bottoms out at a finite attenuation is the difference between
/// "off" and "quiet".
pub fn percent_to_millibel(percent: u8, min: i64, max: i64) -> i64 {
    if max <= min {
        return min;
    }
    let fraction = f64::from(percent.min(100)) / 100.0;

    if max - min <= MAX_LINEAR_DB_SPAN_MB {
        return min + (fraction * (max - min) as f64).round() as i64;
    }

    let mut fraction = fraction;
    if min != DB_GAIN_MUTE {
        let floor = normalized_floor(min, max);
        fraction = fraction * (1.0 - floor) + floor;
    }
    if fraction <= 0.0 {
        return min;
    }
    let value = max + (6000.0 * fraction.log10()).round() as i64;
    value.clamp(min, max)
}

/// The inverse of [`percent_to_millibel`], so a level reads back as the percentage that set it.
///
/// The two have to agree. A client that writes 40 and reads 27 reports a level nobody chose,
/// and every controller watching it shows the wrong number.
pub fn millibel_to_percent(millibel: i64, min: i64, max: i64) -> u8 {
    if max <= min {
        return 0;
    }
    let millibel = millibel.clamp(min, max);

    let normalized = if max - min <= MAX_LINEAR_DB_SPAN_MB {
        (millibel - min) as f64 / (max - min) as f64
    } else {
        let raw = 10f64.powf((millibel - max) as f64 / 6000.0);
        if min == DB_GAIN_MUTE {
            raw
        } else {
            let floor = normalized_floor(min, max);
            (raw - floor) / (1.0 - floor)
        }
    };
    (normalized * 100.0).round().clamp(0.0, 100.0) as u8
}

/// Where the card's quietest setting sits on the logarithmic scale, as a fraction.
fn normalized_floor(min: i64, max: i64) -> f64 {
    10f64.powf((min - max) as f64 / 6000.0)
}

/// Map 0-100 onto the card's own raw range.
pub fn percent_to_raw(percent: u8, min: i64, max: i64) -> i64 {
    let percent = i64::from(percent.min(100));
    if max <= min {
        return min;
    }
    // Rounded, not truncated. A card with only 87 steps — and coarse ranges are common on
    // hardware mixers — would otherwise send 1% to step 0, which is silence, and then report
    // 1% back to the server. The level a client states has to be the level the card is at.
    min + ((max - min) * percent + 50) / 100
}

/// The inverse of [`percent_to_raw`], rounded to the nearest percent.
pub fn raw_to_percent(value: i64, min: i64, max: i64) -> u8 {
    if max <= min {
        return 0;
    }
    let clamped = value.clamp(min, max);
    // Rounded rather than truncated: a card whose range is 0-87 would otherwise report 99%
    // for the value this code writes for 100%.
    let percent = ((clamped - min) * 100 + (max - min) / 2) / (max - min);
    u8::try_from(percent.clamp(0, 100)).unwrap_or(100)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A card calibrated in dB, one step per dB, reporting a 90 dB span.
    const WIDE_DB: (i64, i64) = (-9000, 0);
    /// The raw range that goes with it.
    const WIDE_RAW: (i64, i64) = (0, 90);

    /// The case this whole module exists for.
    ///
    /// Mapping a percentage straight onto the register puts 30% at 27 of 90 steps, which on a
    /// card where a step is a dB is 63 dB of attenuation — inaudible where the user asked for
    /// "a bit quiet". Through the dB scale it lands near 30 dB down, which is what a listener
    /// means by 30%.
    #[test]
    fn thirty_percent_is_thirty_decibels_down_not_sixty_three() {
        let millibel = percent_to_millibel(30, WIDE_DB.0, WIDE_DB.1);
        let db = millibel as f64 / 100.0;
        assert!(
            (-32.0..=-28.0).contains(&db),
            "30% should land near -30 dB, got {db:.1} dB"
        );

        // What the raw mapping would have done on the same card, for contrast.
        let raw = percent_to_raw(30, WIDE_RAW.0, WIDE_RAW.1);
        assert_eq!(raw - 90, -63, "the raw mapping puts 30% at -63 dB");
    }

    /// Writing a percentage and reading it back has to return it. A controller that shows a
    /// number nobody set is worse than one that shows nothing.
    #[test]
    fn every_percentage_survives_the_round_trip_through_the_db_scale() {
        for percent in 0..=100u8 {
            let millibel = percent_to_millibel(percent, WIDE_DB.0, WIDE_DB.1);
            let back = millibel_to_percent(millibel, WIDE_DB.0, WIDE_DB.1);
            assert!(
                back.abs_diff(percent) <= 1,
                "{percent}% came back as {back}% (at {millibel} mB)"
            );
        }
    }

    /// A card that reports no dB information keeps the raw mapping, and that round-trips too.
    #[test]
    fn a_card_with_no_decibel_information_round_trips_on_its_raw_range() {
        let (min, max) = (0i64, 87i64);
        assert_eq!(
            ChosenScale::choose(VolumeScale::Automatic, (0, 0)),
            ChosenScale::Raw
        );
        for percent in 0..=100u8 {
            let raw = percent_to_raw(percent, min, max);
            let back = raw_to_percent(raw, min, max);
            // 87 steps cannot represent 101 percentages; one step is the most that can be asked.
            assert!(
                back.abs_diff(percent) <= 2,
                "{percent}% came back as {back}% on an {min}..{max} card"
            );
        }
    }

    /// The ends are exact on both scales. A player that cannot reach silence or full scale is
    /// broken in a way no tolerance excuses.
    #[test]
    fn the_ends_are_exact_on_both_scales() {
        assert_eq!(percent_to_millibel(0, WIDE_DB.0, WIDE_DB.1), WIDE_DB.0);
        assert_eq!(percent_to_millibel(100, WIDE_DB.0, WIDE_DB.1), WIDE_DB.1);
        assert_eq!(millibel_to_percent(WIDE_DB.0, WIDE_DB.0, WIDE_DB.1), 0);
        assert_eq!(millibel_to_percent(WIDE_DB.1, WIDE_DB.0, WIDE_DB.1), 100);

        assert_eq!(percent_to_raw(0, 0, 87), 0);
        assert_eq!(percent_to_raw(100, 0, 87), 87);
        assert_eq!(raw_to_percent(0, 0, 87), 0);
        assert_eq!(raw_to_percent(87, 0, 87), 100);
    }

    /// Turning the volume up must never turn the card down.
    #[test]
    fn neither_mapping_ever_goes_backwards() {
        let mut previous = i64::MIN;
        for percent in 0..=100u8 {
            let millibel = percent_to_millibel(percent, WIDE_DB.0, WIDE_DB.1);
            assert!(
                millibel >= previous,
                "{percent}% went down to {millibel} mB"
            );
            previous = millibel;
        }
        let mut previous = i64::MIN;
        for percent in 0..=100u8 {
            let raw = percent_to_raw(percent, 0, 87);
            assert!(raw >= previous, "{percent}% went down to {raw}");
            previous = raw;
        }
    }

    /// A narrow dB range — a few dB of trim rather than a volume control — maps linearly,
    /// because a logarithmic curve over three dB leaves most of the travel doing nothing.
    #[test]
    fn a_narrow_decibel_range_maps_linearly() {
        let (min, max) = (-300i64, 0i64);
        assert_eq!(percent_to_millibel(50, min, max), -150);
        assert_eq!(millibel_to_percent(-150, min, max), 50);
    }

    /// A range whose floor is silence rather than a finite attenuation skips the floor
    /// correction, and still reaches both ends.
    #[test]
    fn a_range_that_bottoms_out_in_silence_still_reaches_both_ends() {
        let (min, max) = (DB_GAIN_MUTE, 0i64);
        assert_eq!(percent_to_millibel(0, min, max), min);
        assert_eq!(percent_to_millibel(100, min, max), max);
        assert_eq!(millibel_to_percent(max, min, max), 100);
    }

    /// An application that has measured its card can overrule what the card says about itself.
    #[test]
    fn an_application_can_overrule_what_the_card_reports() {
        // A card reporting a perfectly good dB range, forced onto its raw steps.
        assert_eq!(
            ChosenScale::choose(VolumeScale::Raw, WIDE_DB),
            ChosenScale::Raw
        );
        // And the other way: asking for dB on a card that has none cannot invent one.
        assert_eq!(
            ChosenScale::choose(VolumeScale::Decibel, (0, 0)),
            ChosenScale::Raw
        );
        assert_eq!(
            ChosenScale::choose(VolumeScale::Automatic, WIDE_DB),
            ChosenScale::Decibel {
                min: WIDE_DB.0,
                max: WIDE_DB.1
            }
        );
    }

    /// A degenerate range must not divide by zero or report nonsense.
    #[test]
    fn a_card_with_no_usable_range_is_handled_rather_than_dividing_by_zero() {
        assert_eq!(percent_to_millibel(50, 5, 5), 5);
        assert_eq!(millibel_to_percent(5, 5, 5), 0);
        assert_eq!(percent_to_raw(50, 10, 0), 10);
        assert_eq!(raw_to_percent(3, 10, 0), 0);
    }
}
