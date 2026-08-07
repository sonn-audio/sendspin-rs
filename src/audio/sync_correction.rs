// ABOUTME: Sync correction planner for drop/insert cadence, plus the
// ABOUTME: measurement filter and engage gate that keep it off phantom errors

/// Correction schedule for drop/insert cadence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CorrectionSchedule {
    /// Insert one frame every N frames (0 disables).
    pub insert_every_n_frames: u32,
    /// Drop one frame every N frames (0 disables).
    pub drop_every_n_frames: u32,
    /// True when re-anchoring is required.
    pub reanchor: bool,
}

impl CorrectionSchedule {
    /// True when any correction (insert, drop, or reanchor) is active.
    pub fn is_correcting(&self) -> bool {
        self.insert_every_n_frames > 0 || self.drop_every_n_frames > 0 || self.reanchor
    }
}

/// Spec dead band for the suggested correction strategy: below this, a chunk
/// goes out unchanged. Used as the disengage threshold.
const SPEC_DEADBAND_US: i64 = 100;

/// Spec accuracy *target* (`SHOULD` aim for ±0.5 ms), under the `MUST` floor of
/// ±1 ms. Engaging below the target is what keeps steady state inside it rather
/// than merely inside the floor.
const SPEC_ACCURACY_TARGET_US: i64 = 500;

/// Spec cap on effective playback speed: `MUST` stay within ±0.5% of normal,
/// measured as a sliding average over 150 ms.
const SPEC_MAX_SPEED_DEVIATION: f64 = 0.005;

/// Planner that converts sync error into a correction schedule.
///
/// Uses hysteresis to prevent oscillation at the deadband boundary:
/// correction engages at `engage_us` and disengages at `deadband_us`.
///
/// The thresholds are bounded by the spec's playback-synchronization rules, not
/// chosen for comfort: steady-state error `MUST` stay within ±1 ms and `SHOULD`
/// be within ±0.5 ms, and the effective playback speed `MUST` stay within ±0.5%
/// of normal over a 150 ms sliding average. [`CorrectionPlanner::new`] targets
/// the `SHOULD`, on the principle that this implementation should have headroom
/// the reference implementations do not.
///
/// Tight thresholds are only safe because the measurement in front of the
/// planner is filtered: presentation-latency noise is one-sided, so
/// `SyncErrorFilter` takes a windowed *minimum* rather than an average, and
/// `EngageGate` additionally requires a sustained run of correcting plans over
/// a warm filter before any frame is actually dropped or repeated. A backend
/// whose presentation timestamps are coarser than the defaults assume can relax
/// them with [`CorrectionPlanner::with_thresholds`], at the cost of a wider
/// steady-state band.
#[derive(Debug, Clone, Copy)]
pub struct CorrectionPlanner {
    deadband_us: i64,
    engage_us: i64,
    reanchor_threshold_us: i64,
    target_seconds: f64,
    max_speed_correction: f64,
}

impl CorrectionPlanner {
    /// Create a planner with spec-aligned thresholds.
    ///
    /// Engages below the ±0.5 ms accuracy target and releases at the suggested
    /// strategy's ~100 µs dead band, so a settled stream sits inside the target
    /// rather than inside the ±1 ms floor.
    pub fn new() -> Self {
        Self {
            deadband_us: SPEC_DEADBAND_US,
            engage_us: SPEC_ACCURACY_TARGET_US - SPEC_DEADBAND_US,
            reanchor_threshold_us: 500_000,
            target_seconds: 2.0,
            max_speed_correction: SPEC_MAX_SPEED_DEVIATION,
        }
    }

    /// Create a planner with explicit engage/disengage thresholds in µs.
    ///
    /// For backends whose presentation timestamps are too coarse for the
    /// spec-aligned defaults to settle — a raw reading can sit a whole engine
    /// period above true alignment, and while `SyncErrorFilter` is built to
    /// recover the floor from exactly that noise, it can only do so when the
    /// floor mode is sampled within its window. Widening the band trades
    /// steady-state accuracy for fewer engagements; it does not relax the speed
    /// cap, which stays at the spec's ±0.5% either way.
    ///
    /// `engage_us` is clamped to at least `deadband_us` so hysteresis cannot
    /// invert.
    pub fn with_thresholds(deadband_us: i64, engage_us: i64) -> Self {
        Self {
            deadband_us,
            engage_us: engage_us.max(deadband_us),
            ..Self::new()
        }
    }

    /// Plan a correction schedule from sync error and sample rate.
    ///
    /// `error_us` is the sync error in microseconds (positive = ahead, negative = behind).
    /// `currently_correcting` controls hysteresis: when already correcting, the lower
    /// deadband threshold is used instead of the engage threshold.
    pub fn plan(
        &self,
        error_us: i64,
        sample_rate: u32,
        currently_correcting: bool,
    ) -> CorrectionSchedule {
        let abs_error = error_us.saturating_abs();

        // Hysteresis: use lower threshold to keep correcting, higher to start.
        let threshold = if currently_correcting {
            self.deadband_us
        } else {
            self.engage_us
        };

        if abs_error <= threshold {
            return CorrectionSchedule {
                insert_every_n_frames: 0,
                drop_every_n_frames: 0,
                reanchor: false,
            };
        }

        if abs_error >= self.reanchor_threshold_us {
            return CorrectionSchedule {
                insert_every_n_frames: 0,
                drop_every_n_frames: 0,
                reanchor: true,
            };
        }

        let sample_rate_f = sample_rate as f64;
        let frames_error = (error_us as f64 * sample_rate_f) / 1_000_000.0;
        let desired_corrections_per_sec = frames_error.abs() / self.target_seconds;
        let max_corrections_per_sec = sample_rate_f * self.max_speed_correction;
        let corrections_per_sec = desired_corrections_per_sec.min(max_corrections_per_sec);

        if corrections_per_sec <= 0.0 {
            return CorrectionSchedule {
                insert_every_n_frames: 0,
                drop_every_n_frames: 0,
                reanchor: false,
            };
        }

        let interval_frames = (sample_rate_f / corrections_per_sec).round() as u32;

        if error_us > 0 {
            CorrectionSchedule {
                insert_every_n_frames: 0,
                drop_every_n_frames: interval_frames.max(1),
                reanchor: false,
            }
        } else {
            CorrectionSchedule {
                insert_every_n_frames: interval_frames.max(1),
                drop_every_n_frames: 0,
                reanchor: false,
            }
        }
    }
}

impl Default for CorrectionPlanner {
    fn default() -> Self {
        Self::new()
    }
}

/// Measurements kept by [`SyncErrorFilter`]. 101 callbacks is ~1s at the
/// common 10ms WASAPI period (2-4s on 20-40ms periods): long enough that the
/// floor mode gets sampled even through dense flapping, short enough that a
/// real displacement reaches the output within about a second.
pub(crate) const SYNC_ERROR_WINDOW: usize = 101;

/// Windowed minimum (floor tracker) over recent sync-error measurements.
///
/// Audio presentation timestamps are quantized to the engine period: under
/// scheduler jitter the wake-time padding snapshot jumps *up* by whole
/// periods (observed as a 2ms <-> 12ms alternation on shared-mode WASAPI)
/// while the endpoint FIFO plays gaplessly. The noise is one-sided — extra
/// queued padding can only make a reading later, never earlier — so the
/// window floor is the honest alignment estimate: it holds regardless of
/// which mode has the majority, so long as the floor mode is sampled at
/// least once per window. A real displacement (engine starvation inserting
/// silence, a cursor jump) shifts every reading *including the floor*, so it
/// still reaches the planner within one window.
///
/// The response is deliberately asymmetric: a drop in error propagates
/// immediately (a new low sample becomes the floor at once, so a running
/// correction converges without overshoot), while a rise propagates only
/// once the old floor ages out of the window — exactly the conservatism an
/// engage decision wants. A spuriously *low* outlier would bias toward
/// under-correction, the safe direction. The padding term never produces
/// one (padding cannot go below empty); the clock filter normally moves by
/// microseconds once settled, though an outlier time sample can still step
/// the estimate by low single-digit milliseconds in either direction — a
/// negative step costs at most one window of under-correction.
///
/// Allocation-free, O(window) scan per update; sized for the audio callback.
#[derive(Debug, Clone)]
pub(crate) struct SyncErrorFilter {
    samples: [i64; SYNC_ERROR_WINDOW],
    len: usize,
    next: usize,
}

impl SyncErrorFilter {
    /// Create an empty (cold) filter.
    pub fn new() -> Self {
        Self {
            samples: [0; SYNC_ERROR_WINDOW],
            len: 0,
            next: 0,
        }
    }

    /// Discard all samples, e.g. after a reanchor or generation change made
    /// prior measurements meaningless.
    pub fn reset(&mut self) {
        self.len = 0;
        self.next = 0;
    }

    /// True once the window is fully populated. A floor over a partial
    /// window is still returned by [`SyncErrorFilter::update`], but engage
    /// decisions should wait for warmth (see [`EngageGate`]).
    pub fn is_warm(&self) -> bool {
        self.len == SYNC_ERROR_WINDOW
    }

    /// Record a raw error measurement (µs) and return the windowed minimum.
    pub fn update(&mut self, raw_error_us: i64) -> i64 {
        self.samples[self.next] = raw_error_us;
        self.next = (self.next + 1) % SYNC_ERROR_WINDOW;
        if self.len < SYNC_ERROR_WINDOW {
            self.len += 1;
        }
        // While filling, the live samples are the contiguous prefix
        // (next == len until the first wrap); afterwards the whole array.
        // Stale slots past `len` are never read. `len >= 1` here, so the
        // fold always sees at least one real sample.
        self.samples[..self.len]
            .iter()
            .copied()
            .fold(i64::MAX, i64::min)
    }
}

impl Default for SyncErrorFilter {
    fn default() -> Self {
        Self::new()
    }
}

/// Consecutive correcting plans required before a correction may engage from
/// idle: ~0.5s at a 10ms callback period. Filtered errors already move at
/// window timescale, so a genuine displacement holds the streak trivially;
/// the gate keeps engagement evidence-backed across filter resets and
/// warm-up, when the estimate is least trustworthy.
pub(crate) const ENGAGE_STREAK_PLANS: u32 = 50;

/// Gate between the planner and the applied schedule: an idle stream only
/// starts correcting after a sustained run of correcting plans over a warm
/// filter. Every engaged correction mutates real audio (dropped or repeated
/// frames are audible as ticks), so engagement must be evidence-backed;
/// disengagement and replanning of a running correction stay immediate
/// because stopping or retuning is never audible.
#[derive(Debug, Clone)]
pub(crate) struct EngageGate {
    streak: u32,
}

impl EngageGate {
    /// Create a gate with no accumulated streak.
    pub fn new() -> Self {
        Self { streak: 0 }
    }

    /// Clear the accumulated streak.
    pub fn reset(&mut self) {
        self.streak = 0;
    }

    /// Admit or suppress a planned schedule.
    ///
    /// `currently_correcting` is whether a correction episode is already
    /// running; `filter_warm` is whether the error filter window is fully
    /// populated. Reanchor plans always pass: they indicate gross real
    /// displacement where a delayed reaction is worse than a rare false
    /// positive.
    pub fn admit(
        &mut self,
        planned: CorrectionSchedule,
        currently_correcting: bool,
        filter_warm: bool,
    ) -> CorrectionSchedule {
        if planned.reanchor || currently_correcting || !planned.is_correcting() {
            self.streak = 0;
            return planned;
        }
        self.streak = self.streak.saturating_add(1);
        if filter_warm && self.streak >= ENGAGE_STREAK_PLANS {
            planned
        } else {
            CorrectionSchedule::default()
        }
    }
}

impl Default for EngageGate {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_no_correction_within_engage_threshold() {
        let planner = CorrectionPlanner::new();
        let schedule = planner.plan(300, 48_000, false);
        assert!(!schedule.is_correcting(), "should not engage below 400µs");
    }

    #[test]
    fn test_correction_engages_above_threshold() {
        let planner = CorrectionPlanner::new();
        let schedule = planner.plan(600, 48_000, false);
        assert!(schedule.is_correcting(), "should engage above 400µs");
        assert!(schedule.drop_every_n_frames > 0, "positive error = drop");
    }

    #[test]
    fn test_hysteresis_keeps_correcting_above_deadband() {
        let planner = CorrectionPlanner::new();
        // 250µs error: below engage (400µs) but above the dead band (100µs).
        // Should keep correcting if already active.
        let schedule = planner.plan(250, 48_000, true);
        assert!(
            schedule.is_correcting(),
            "should keep correcting above the 100µs dead band"
        );
    }

    #[test]
    fn test_hysteresis_stops_below_deadband() {
        let planner = CorrectionPlanner::new();
        let schedule = planner.plan(50, 48_000, true);
        assert!(
            !schedule.is_correcting(),
            "should stop below the 100µs dead band"
        );
    }

    #[test]
    fn test_negative_error_inserts() {
        let planner = CorrectionPlanner::new();
        let schedule = planner.plan(-5_000, 48_000, false);
        assert!(
            schedule.insert_every_n_frames > 0,
            "negative error = insert"
        );
        assert_eq!(schedule.drop_every_n_frames, 0);
    }

    #[test]
    fn test_reanchor_at_large_error() {
        let planner = CorrectionPlanner::new();
        let schedule = planner.plan(500_000, 48_000, false);
        assert!(schedule.reanchor);
    }

    #[test]
    fn test_exact_engage_threshold_does_not_engage() {
        let planner = CorrectionPlanner::new();
        let schedule = planner.plan(400, 48_000, false);
        assert!(
            !schedule.is_correcting(),
            "exactly at engage threshold should not engage (<=)"
        );
    }

    #[test]
    fn test_exact_deadband_threshold_disengages() {
        let planner = CorrectionPlanner::new();
        let schedule = planner.plan(100, 48_000, true);
        assert!(
            !schedule.is_correcting(),
            "exactly at deadband threshold should disengage (<=)"
        );
    }

    /// The spec caps effective playback speed at ±0.5% of normal over a 150 ms
    /// sliding average. One correction moves the output by one frame, so the
    /// deviation is the correction rate over the sample rate — assert it across
    /// error magnitudes and rates, including errors far past the reanchor
    /// threshold and rates where rounding is coarsest.
    #[test]
    fn test_speed_deviation_never_exceeds_spec_cap() {
        let planner = CorrectionPlanner::new();
        for sample_rate in [44_100u32, 48_000, 96_000, 192_000] {
            for error_us in [
                101i64, 250, 401, 1_000, 5_000, 10_000, 50_000, 250_000, 499_999,
            ] {
                for error_us in [error_us, -error_us] {
                    let schedule = planner.plan(error_us, sample_rate, true);
                    let interval = schedule
                        .insert_every_n_frames
                        .max(schedule.drop_every_n_frames);
                    if interval == 0 {
                        continue;
                    }
                    let deviation =
                        f64::from(sample_rate) / f64::from(interval) / f64::from(sample_rate);
                    assert!(
                        deviation <= SPEC_MAX_SPEED_DEVIATION,
                        "{deviation} exceeds the ±0.5% cap at {error_us}µs / {sample_rate}Hz"
                    );
                }
            }
        }
    }

    /// The spec puts a hard floor of ±1 ms on steady-state error. Correction has
    /// to begin below it, or a stream behaving exactly as designed sits outside
    /// the floor indefinitely.
    #[test]
    fn test_steady_state_band_is_inside_the_spec_floor() {
        const SPEC_ACCURACY_FLOOR_US: i64 = 1_000;
        let planner = CorrectionPlanner::new();
        let schedule = planner.plan(SPEC_ACCURACY_FLOOR_US, 48_000, false);
        assert!(
            schedule.is_correcting(),
            "an error at the ±1ms floor must already be correcting"
        );
        assert!(
            planner.engage_us < SPEC_ACCURACY_FLOOR_US,
            "engage threshold {}µs must sit below the ±1ms floor",
            planner.engage_us
        );
        assert!(
            planner.deadband_us < SPEC_ACCURACY_TARGET_US,
            "dead band {}µs must sit below the ±0.5ms target",
            planner.deadband_us
        );
    }

    #[test]
    fn test_with_thresholds_cannot_invert_hysteresis() {
        let planner = CorrectionPlanner::with_thresholds(2_000, 500);
        assert!(!planner.plan(1_500, 48_000, false).is_correcting());
        assert!(!planner.plan(1_500, 48_000, true).is_correcting());
    }

    #[test]
    fn test_negative_hysteresis_keeps_inserting_above_deadband() {
        let planner = CorrectionPlanner::new();
        let schedule = planner.plan(-2_000, 48_000, true);
        assert!(
            schedule.is_correcting(),
            "should keep correcting negative error above deadband"
        );
        assert!(
            schedule.insert_every_n_frames > 0,
            "negative error = insert"
        );
        assert_eq!(schedule.drop_every_n_frames, 0);
    }

    // -- Exact interval values --
    //
    // The tests above only check *which* field is set (drop vs insert).
    // These pin down the actual interval arithmetic: `frames_error`, the
    // `desired` / `max` corrections_per_sec cap, and the `interval_frames`
    // rounding. Checking a single "correction engaged" bit lets the
    // arithmetic drift silently; checking the computed cadence doesn't.

    #[test]
    fn test_drop_interval_below_speed_cap_matches_spec() {
        // 5ms error at 48 kHz, already correcting (deadband threshold):
        //   frames_error                = 5000 * 48000 / 1_000_000 = 240 frames
        //   desired_corrections_per_sec = 240 / 2.0                = 120
        //   max_corrections_per_sec     = 48000 * 0.04             = 1920 (not binding)
        //   interval_frames             = round(48000 / 120)       = 400
        let planner = CorrectionPlanner::new();
        let s = planner.plan(5_000, 48_000, true);
        assert_eq!(
            s.drop_every_n_frames, 400,
            "5ms drift should produce drop every 400 frames"
        );
        assert_eq!(s.insert_every_n_frames, 0);
    }

    #[test]
    fn test_insert_interval_below_speed_cap_matches_spec() {
        // Mirror of the drop test with a negative error.
        let planner = CorrectionPlanner::new();
        let s = planner.plan(-5_000, 48_000, true);
        assert_eq!(
            s.insert_every_n_frames, 400,
            "-5ms drift should produce insert every 400 frames"
        );
        assert_eq!(s.drop_every_n_frames, 0);
    }

    #[test]
    fn test_drop_interval_hits_max_speed_cap() {
        // 200ms error — large enough that the desired rate exceeds the cap:
        //   frames_error                = 200000 * 48000 / 1_000_000 = 9600
        //   desired_corrections_per_sec = 9600 / 2.0                 = 4800
        //   max_corrections_per_sec     = 48000 * 0.005              = 240 (binding)
        //   interval_frames             = round(48000 / 240)         = 200
        // One frame every 200 is a 0.5% speed deviation: the spec's cap exactly.
        let planner = CorrectionPlanner::new();
        let s = planner.plan(200_000, 48_000, true);
        assert_eq!(
            s.drop_every_n_frames, 200,
            "large drift should be capped at the spec's ±0.5% speed deviation"
        );
    }

    #[test]
    fn test_filter_constant_input_passes_through() {
        let mut filter = SyncErrorFilter::new();
        for _ in 0..SYNC_ERROR_WINDOW {
            assert_eq!(filter.update(4_000), 4_000);
        }
        assert!(filter.is_warm());
    }

    #[test]
    fn test_filter_warms_only_after_full_window() {
        let mut filter = SyncErrorFilter::new();
        for _ in 0..SYNC_ERROR_WINDOW - 1 {
            filter.update(0);
            assert!(!filter.is_warm());
        }
        filter.update(0);
        assert!(filter.is_warm());
    }

    #[test]
    fn test_filter_floor_ignores_flap_at_any_duty() {
        // Period-quantized flapping is one-sided (+one period). Even a 90%
        // majority in the high mode — enough to drag any central-tendency
        // estimate — must not lift the floor while the quiet mode is sampled
        // at least once per window.
        let mut filter = SyncErrorFilter::new();
        for i in 0..SYNC_ERROR_WINDOW * 3 {
            let raw = if i % 10 == 0 { 0 } else { 10_000 };
            let floor = filter.update(raw);
            if i >= 1 {
                assert_eq!(floor, 0, "flap majority must not lift the floor");
            }
        }
    }

    #[test]
    fn test_filter_floor_follows_persistent_rise_after_full_window() {
        // A real displacement shifts every reading including the floor; the
        // output must follow once the old floor ages out of the window.
        let mut filter = SyncErrorFilter::new();
        for _ in 0..SYNC_ERROR_WINDOW {
            filter.update(0);
        }
        let mut floor = 0;
        for i in 0..SYNC_ERROR_WINDOW {
            floor = filter.update(10_000);
            if i < SYNC_ERROR_WINDOW - 1 {
                assert_eq!(floor, 0, "rise must wait for the window to age out");
            }
        }
        assert_eq!(floor, 10_000, "persistent rise must reach the output");
    }

    #[test]
    fn test_filter_floor_follows_drop_immediately() {
        // A running correction shrinks the error; the floor must track the
        // new low on the very next sample so the correction converges
        // without overshoot.
        let mut filter = SyncErrorFilter::new();
        for _ in 0..SYNC_ERROR_WINDOW {
            filter.update(10_000);
        }
        assert_eq!(filter.update(2_000), 2_000, "new low becomes the floor");
    }

    #[test]
    fn test_filter_handles_negative_errors() {
        // Negative true error (audio early, insert side) with one-sided
        // positive excursions on top.
        let mut filter = SyncErrorFilter::new();
        for i in 0..SYNC_ERROR_WINDOW {
            let raw = if i % 3 == 0 { 10_000 } else { -5_000 };
            filter.update(raw);
        }
        assert_eq!(filter.update(-5_000), -5_000);
    }

    #[test]
    fn test_filter_single_low_evicted_exactly_after_window() {
        // One low among highs must stop being the floor exactly WINDOW
        // updates after it was recorded.
        let mut filter = SyncErrorFilter::new();
        filter.update(1_000);
        for i in 0..SYNC_ERROR_WINDOW - 1 {
            assert_eq!(filter.update(10_000), 1_000, "low still in window at {i}");
        }
        assert_eq!(
            filter.update(10_000),
            10_000,
            "low must age out exactly one window after it was recorded"
        );
    }

    #[test]
    fn test_filter_tracks_min_across_multiple_wraps() {
        // Distinct values across several ring cycles: the floor must always
        // equal the true minimum of the last WINDOW samples.
        let mut filter = SyncErrorFilter::new();
        let mut recent: Vec<i64> = Vec::new();
        for i in 0..(SYNC_ERROR_WINDOW as i64 * 5) {
            let value = (i * 37) % 1_000 + if i % 13 == 0 { -500 } else { 0 };
            recent.push(value);
            if recent.len() > SYNC_ERROR_WINDOW {
                recent.remove(0);
            }
            let expected = *recent.iter().min().unwrap();
            assert_eq!(filter.update(value), expected, "mismatch at update {i}");
        }
    }

    #[test]
    fn test_filter_reset_clears_window() {
        // Fill with a LOW value so stale slots would drag the floor down if
        // reset failed to fence them off.
        let mut filter = SyncErrorFilter::new();
        for _ in 0..SYNC_ERROR_WINDOW {
            filter.update(-10_000);
        }
        filter.reset();
        assert!(!filter.is_warm());
        assert_eq!(
            filter.update(5_000),
            5_000,
            "floor after reset must reflect only new samples"
        );
    }

    fn correcting_plan() -> CorrectionSchedule {
        CorrectionSchedule {
            insert_every_n_frames: 0,
            drop_every_n_frames: 200,
            reanchor: false,
        }
    }

    #[test]
    fn test_gate_requires_sustained_streak() {
        let mut gate = EngageGate::new();
        for _ in 0..ENGAGE_STREAK_PLANS - 1 {
            let admitted = gate.admit(correcting_plan(), false, true);
            assert!(!admitted.is_correcting(), "streak not yet sustained");
        }
        let admitted = gate.admit(correcting_plan(), false, true);
        assert!(admitted.is_correcting(), "sustained streak must engage");
    }

    #[test]
    fn test_gate_streak_resets_on_idle_plan() {
        let mut gate = EngageGate::new();
        for _ in 0..ENGAGE_STREAK_PLANS - 1 {
            gate.admit(correcting_plan(), false, true);
        }
        gate.admit(CorrectionSchedule::default(), false, true);
        let admitted = gate.admit(correcting_plan(), false, true);
        assert!(
            !admitted.is_correcting(),
            "an idle plan must reset the streak"
        );
    }

    #[test]
    fn test_gate_cold_filter_never_engages() {
        let mut gate = EngageGate::new();
        for _ in 0..ENGAGE_STREAK_PLANS * 2 {
            let admitted = gate.admit(correcting_plan(), false, false);
            assert!(!admitted.is_correcting(), "cold filter must not engage");
        }
    }

    #[test]
    fn test_gate_reanchor_bypasses() {
        let mut gate = EngageGate::new();
        let reanchor = CorrectionSchedule {
            insert_every_n_frames: 0,
            drop_every_n_frames: 0,
            reanchor: true,
        };
        let admitted = gate.admit(reanchor, false, false);
        assert!(admitted.reanchor, "reanchor must bypass the gate");
    }

    #[test]
    fn test_gate_running_correction_replans_freely() {
        let mut gate = EngageGate::new();
        let admitted = gate.admit(correcting_plan(), true, true);
        assert!(
            admitted.is_correcting(),
            "a running correction must replan without gating"
        );
        let disengage = gate.admit(CorrectionSchedule::default(), true, true);
        assert!(
            !disengage.is_correcting(),
            "disengage must pass immediately"
        );
    }
}
