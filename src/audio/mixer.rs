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
//! How a percentage becomes a level is [`crate::audio::volume_scale`], which is separate and
//! not Linux-gated: the arithmetic is the part that can be tested without a sound card, and it
//! is where the difference between the two kinds of mixer lives.
//!
//! Not compiled in unless the `hardware-volume` feature is on, and Linux-only: this is an
//! ALSA binding, and a daemon on a card with no mixer should not carry it.

use crate::audio::volume_scale::{
    millibel_to_percent, percent_to_millibel, percent_to_raw, raw_to_percent, ChosenScale,
    VolumeScale,
};

/// Mixer elements to prefer, in order, when a card exposes more than one with playback volume.
const PREFERRED_ELEMENTS: &[&str] = &["Digital", "Master", "PCM"];

/// A playback volume control on one card.
pub struct Mixer {
    card: String,
    element: String,
    scale: ChosenScale,
}

impl Mixer {
    /// Open the best playback volume control on `card`, or say why there is none.
    ///
    /// `card` is an ALSA card name such as `default`, `hw:0`, or the `plughw:1` form a device
    /// id carries. A card with no playback element is not an error worth failing a daemon
    /// over — plenty of DACs have no gain stage at all — so the caller decides what to do.
    /// `scale` decides how a percentage is mapped. [`VolumeScale::Automatic`] reads the answer
    /// off the card and is right for hardware that describes itself honestly; the other two are
    /// for hardware that does not, which an application is better placed to know than this
    /// crate is.
    pub fn open(card: &str, scale: VolumeScale) -> Result<Self, String> {
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

        // Asked once, at open, and from the card's own description rather than from the level
        // it happens to sit at: at maximum every mixer reads zero dB below maximum, so a card
        // that is merely turned up would be misread as having no range at all.
        let db_range = mixer
            .find_selem(&alsa::mixer::SelemId::new(&element, 0))
            .map(|selem| {
                let (min, max) = selem.get_playback_db_range();
                (min.0, max.0)
            })
            .unwrap_or((0, 0));
        let scale = ChosenScale::choose(scale, db_range);
        // Logged once, with the numbers behind it, so a card that behaves oddly can be
        // diagnosed from a log rather than by ear.
        log::info!(
            "Volume on {card}/{element}: {} (card reports {}..{} mB)",
            scale.describe(),
            db_range.0,
            db_range.1
        );

        Ok(Self {
            card: card.to_string(),
            element,
            scale,
        })
    }

    /// The scale this mixer maps percentages through.
    pub fn scale(&self) -> ChosenScale {
        self.scale
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

        match self.scale {
            ChosenScale::Decibel { min, max } => {
                let target = percent_to_millibel(percent, min, max);
                // Rounded down where the card cannot hit the value exactly: erring quiet is the
                // safe direction when the alternative is a step louder than was asked for.
                selem
                    .set_playback_db_all(alsa::mixer::MilliBel(target), alsa::Round::Floor)
                    .map_err(|e| format!("could not set the volume on {}: {e}", self.element))?;
            }
            ChosenScale::Raw => {
                let (min, max) = selem.get_playback_volume_range();
                let value = percent_to_raw(percent, min, max);
                selem
                    .set_playback_volume_all(value)
                    .map_err(|e| format!("could not set the volume on {}: {e}", self.element))?;
            }
        }

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

        // Read back on the same scale it was written on. A client that writes 40 and reads 27
        // reports a level nobody set, and every controller watching it shows the wrong number.
        let percent = match self.scale {
            ChosenScale::Decibel { min, max } => {
                let millibel = selem
                    .get_playback_vol_db(alsa::mixer::SelemChannelId::mono())
                    .map_err(|e| format!("could not read the volume on {}: {e}", self.element))?;
                millibel_to_percent(millibel.0, min, max)
            }
            ChosenScale::Raw => {
                let (min, max) = selem.get_playback_volume_range();
                let raw = selem
                    .get_playback_volume(alsa::mixer::SelemChannelId::mono())
                    .map_err(|e| format!("could not read the volume on {}: {e}", self.element))?;
                raw_to_percent(raw, min, max)
            }
        };
        let muted = if selem.has_playback_switch() {
            selem
                .get_playback_switch(alsa::mixer::SelemChannelId::mono())
                .map(|on| on == 0)
                .unwrap_or(false)
        } else {
            false
        };
        Ok((percent, muted))
    }
}
