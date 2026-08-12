// ABOUTME: Audio types and processing for sendspin-rs
// ABOUTME: Contains Sample type, AudioFormat, Buffer, and codec definitions

/// Opening a capture device for the source role.
#[cfg(feature = "source")]
pub mod capture;
/// Audio decoder implementations (PCM, Opus, FLAC)
pub mod decode;

/// Choosing an output device and checking what it can play.
pub mod devices;
/// Audio encoders for the source role.
pub mod encode;
/// Lock-free volume/mute control
pub mod gain;

/// Driving a card's own volume control instead of attenuating in software.
#[cfg(all(feature = "hardware-volume", target_os = "linux"))]
pub mod mixer;

/// Buffer pool for reusing audio sample buffers
pub mod pool;
/// Capture helper for the source role: encode and stamp in server time.
pub mod source_capture;
/// Sync correction planner for drop/insert cadence
pub mod sync_correction;
/// Synced playback helper using output timestamps
pub mod synced_player;
/// Core audio type definitions (Sample, Codec, AudioFormat, AudioBuffer)
pub mod types;
/// Turning a percentage into a level a hardware mixer understands.
///
/// Not Linux-gated, unlike the binding that uses it: the arithmetic has no platform, and
/// keeping it here is what lets it be tested on a machine with no ALSA at all.
#[cfg(feature = "hardware-volume")]
pub mod volume_scale;

pub use gain::GainControl;
pub use pool::BufferPool;
pub use source_capture::SourceCapture;
pub use sync_correction::{CorrectionPlanner, CorrectionSchedule};
pub use synced_player::{ProcessCallback, SyncedPlayer, SyncedPlayerConfig};
pub use types::{AudioBuffer, AudioFormat, Codec};
