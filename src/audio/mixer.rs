// ABOUTME: Driving the system mixer instead of attenuating in software, so a hardware volume
// ABOUTME: control and this client agree on one level rather than fighting over two.

//! Hardware volume, via ALSA.
//!
//! Software attenuation throws away bits: a 16-bit stream played at 30% has lost its bottom
//! two bits before it reaches the DAC. A card with a real analogue or digital gain stage does
//! it without that loss, and it is also the level a knob on the front panel moves — so a
//! client that ignores the mixer shows a number that is not what anyone hears.
//!
//! Which element to drive is the whole problem, and the priority list here is borrowed from
//! `sendspin-cli` because it encodes hardware knowledge rather than taste: `Digital` is what
//! the HiFiBerry DAC+ and most I2S DAC HATs expose, `Master` what generic cards and USB
//! interfaces use, `PCM` what the Raspberry Pi's own headphone output calls it.
//!
//! Not compiled in unless the `hardware-volume` feature is on, and Linux-only: this is an
//! ALSA binding, and a daemon on a card with no mixer should not carry it.

/// Mixer elements to prefer, in order, when a card exposes more than one with playback volume.
const PREFERRED_ELEMENTS: &[&str] = &["Digital", "Master", "PCM"];

/// A playback volume control on one card.
pub struct Mixer {
    card: String,
    element: String,
}

impl Mixer {
    /// Open the best playback volume control on `card`, or say why there is none.
    ///
    /// `card` is an ALSA card name such as `default`, `hw:0`, or the `plughw:1` form a device
    /// id carries. A card with no playback element is not an error worth failing a daemon
    /// over — plenty of DACs have no gain stage at all — so the caller decides what to do.
    pub fn open(card: &str) -> Result<Self, String> {
        let mixer = alsa::mixer::Mixer::new(card, false)
            .map_err(|e| format!("could not open the mixer on {card}: {e}"))?;

        let mut candidates = Vec::new();
        for element in mixer.iter() {
            let Some(selem) = alsa::mixer::Selem::new(element) else {
                continue;
            };
            if !selem.has_playback_volume() {
                continue;
            }
            let name = selem.get_id().get_name().unwrap_or_default().to_string();
            if !name.is_empty() {
                candidates.push(name);
            }
        }
        if candidates.is_empty() {
            return Err(format!("{card} has no playback volume control"));
        }

        // A named preference wins wherever the card offers one; otherwise the first element
        // with playback volume, which is what a single-control card has anyway.
        let element = PREFERRED_ELEMENTS
            .iter()
            .find(|preferred| candidates.iter().any(|name| name == *preferred))
            .map(|preferred| (*preferred).to_string())
            .unwrap_or_else(|| candidates[0].clone());

        Ok(Self {
            card: card.to_string(),
            element,
        })
    }

    /// The card this drives.
    pub fn card(&self) -> &str {
        &self.card
    }

    /// The element being driven, so an operator can see which knob moved.
    pub fn element(&self) -> &str {
        &self.element
    }

    /// Set the playback volume to `percent` (0-100), and the mute switch if the card has one.
    ///
    /// The mixer handle is opened per call rather than held: a card that disappears and comes
    /// back — a USB DAC being re-plugged — leaves a stale handle behind, and volume changes are
    /// rare enough that reopening costs nothing worth saving.
    pub fn set(&self, percent: u8, muted: bool) -> Result<(), String> {
        let mixer = alsa::mixer::Mixer::new(&self.card, false)
            .map_err(|e| format!("could not open the mixer on {}: {e}", self.card))?;
        let selem_id = alsa::mixer::SelemId::new(&self.element, 0);
        let selem = mixer
            .find_selem(&selem_id)
            .ok_or_else(|| format!("{} is gone from {}", self.element, self.card))?;

        let (min, max) = selem.get_playback_volume_range();
        let value = scale_to_range(percent, min, max);
        selem
            .set_playback_volume_all(value)
            .map_err(|e| format!("could not set the volume on {}: {e}", self.element))?;

        // Not every card has a mute switch. Where there is none, zero volume is the mute, and
        // the caller has already passed the muted level in.
        if selem.has_playback_switch() {
            selem
                .set_playback_switch_all(i32::from(!muted))
                .map_err(|e| format!("could not set the mute switch on {}: {e}", self.element))?;
        }
        Ok(())
    }

    /// Read back the current volume as a percentage, and whether the card is muted.
    ///
    /// Used at startup so a client reports the level that is actually set rather than assuming
    /// its own default — the knob may have been moved while this was not running.
    pub fn read(&self) -> Result<(u8, bool), String> {
        let mixer = alsa::mixer::Mixer::new(&self.card, false)
            .map_err(|e| format!("could not open the mixer on {}: {e}", self.card))?;
        let selem_id = alsa::mixer::SelemId::new(&self.element, 0);
        let selem = mixer
            .find_selem(&selem_id)
            .ok_or_else(|| format!("{} is gone from {}", self.element, self.card))?;

        let (min, max) = selem.get_playback_volume_range();
        let raw = selem
            .get_playback_volume(alsa::mixer::SelemChannelId::mono())
            .map_err(|e| format!("could not read the volume on {}: {e}", self.element))?;
        let muted = if selem.has_playback_switch() {
            selem
                .get_playback_switch(alsa::mixer::SelemChannelId::mono())
                .map(|on| on == 0)
                .unwrap_or(false)
        } else {
            false
        };
        Ok((scale_from_range(raw, min, max), muted))
    }
}

/// Map 0-100 onto the card's own range.
///
/// Kept as a free function so the arithmetic is testable without a sound card, which is the
/// only part of this that can be tested without one.
fn scale_to_range(percent: u8, min: i64, max: i64) -> i64 {
    let percent = i64::from(percent.min(100));
    if max <= min {
        return min;
    }
    // Rounded, not truncated. A card with only 87 steps — and coarse ranges are common on
    // hardware mixers — would otherwise send 1% to step 0, which is silence, and then report
    // 1% back to the server. The level a client states has to be the level the card is at.
    min + ((max - min) * percent + 50) / 100
}

/// The inverse of [`scale_to_range`], rounded to the nearest percent.
fn scale_from_range(value: i64, min: i64, max: i64) -> u8 {
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

    /// The endpoints have to be exact: 100 must reach the card's maximum, not one below it.
    #[test]
    fn the_ends_of_the_range_map_exactly() {
        assert_eq!(scale_to_range(0, 0, 65536), 0);
        assert_eq!(scale_to_range(100, 0, 65536), 65536);
        // A range that does not start at zero, which is what a card with dB scaling reports.
        assert_eq!(scale_to_range(0, -10239, 400), -10239);
        assert_eq!(scale_to_range(100, -10239, 400), 400);
    }

    /// A round trip lands within one of the card's own steps, which is the most that can be
    /// asked of it.
    ///
    /// Exactness is not available and claiming it would be a lie: a card with 87 steps cannot
    /// represent 101 distinct percentages, so two percentages share a step and the step maps
    /// back to one of them. What matters is that the error is bounded by the hardware's own
    /// resolution rather than by a rounding mistake — a client reporting 51 when the knob is
    /// one step off 50 is honest; reporting 1 when the card is silent is not.
    #[test]
    fn a_percentage_survives_the_round_trip_to_within_one_step() {
        for (min, max) in [(0i64, 65536i64), (0, 87), (-10239, 400), (0, 100), (0, 20)] {
            let steps = max - min;
            // One step, in percent, rounded up.
            let tolerance = (100 + steps - 1) / steps;
            for percent in 0..=100u8 {
                let raw = scale_to_range(percent, min, max);
                let back = scale_from_range(raw, min, max);
                let drift = (i64::from(back) - i64::from(percent)).abs();
                assert!(
                    drift <= tolerance,
                    "{percent}% on a {min}..{max} card came back as {back}%                      (drift {drift} > one step of {tolerance}%)"
                );
            }
        }
    }

    /// The ends are exact on every card, whatever its resolution: 0 is the card's minimum and
    /// 100 its maximum, and both read back as themselves. A player that cannot reach silence
    /// or full scale is broken in a way no tolerance excuses.
    #[test]
    fn the_ends_of_the_range_round_trip_exactly() {
        for (min, max) in [(0i64, 65536i64), (0, 87), (-10239, 400), (0, 100), (0, 20)] {
            assert_eq!(scale_to_range(0, min, max), min);
            assert_eq!(scale_to_range(100, min, max), max);
            assert_eq!(scale_from_range(min, min, max), 0);
            assert_eq!(scale_from_range(max, min, max), 100);
        }
    }

    /// Turning the volume up must never turn the card down.
    #[test]
    fn the_mapping_never_goes_backwards() {
        for (min, max) in [(0i64, 65536i64), (0, 87), (-10239, 400), (0, 20)] {
            let mut previous = i64::MIN;
            for percent in 0..=100u8 {
                let raw = scale_to_range(percent, min, max);
                assert!(
                    raw >= previous,
                    "{percent}% on a {min}..{max} card went down to {raw}"
                );
                previous = raw;
            }
        }
    }

    /// A card with a degenerate range must not divide by zero or report nonsense.
    #[test]
    fn a_card_with_no_usable_range_is_handled_rather_than_dividing_by_zero() {
        assert_eq!(scale_to_range(50, 5, 5), 5);
        assert_eq!(scale_from_range(5, 5, 5), 0);
        assert_eq!(scale_to_range(50, 10, 0), 10);
        assert_eq!(scale_from_range(3, 10, 0), 0);
    }

    /// Values outside the range are clamped rather than wrapped into something loud.
    #[test]
    fn values_beyond_the_range_are_clamped() {
        assert_eq!(scale_to_range(200, 0, 100), 100, "percent is capped at 100");
        assert_eq!(scale_from_range(-5000, 0, 100), 0);
        assert_eq!(scale_from_range(5000, 0, 100), 100);
    }
}
