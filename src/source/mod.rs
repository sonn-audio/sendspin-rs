// ABOUTME: The source session: capturing a local input and streaming it to a server on demand,
// ABOUTME: from the first hello to the last frame.

//! Being a source.
//!
//! A source is a player in reverse. It captures a local input — a line-in, a turntable preamp,
//! a capture card — and sends it upstream, where the server resamples, mixes and distributes.
//! The device stays simple, and the server decides when it plays.
//!
//! [`SourceCapture`](crate::audio::SourceCapture) covers the arithmetic: server-clock stamps,
//! sample-position anchoring, encoder lookahead. This is the session around it — connecting,
//! advertising the role, answering `server/command`, announcing the format in
//! `client_stream/start`, streaming, and ending. The shape mirrors
//! [`Player`](crate::player::Player) deliberately: an application that has embedded one should
//! recognise the other.
//!
//! ```no_run
//! # async fn run() -> Result<(), Box<dyn std::error::Error>> {
//! use sendspin::source::{Source, SourceConfig};
//!
//! let source = Source::new(SourceConfig::new("linein".to_string(), "Line In".to_string()));
//! source.run_outbound("ws://server:8927/sendspin", None).await?;
//! # Ok(())
//! # }
//! ```
//!
//! ## Signal presence
//!
//! `line_sense` is the one thing only this end can know: whether anything is actually playing
//! into the input. This crate does not decide it. The reference implementation's source client
//! does not either — it reports what its application tells it, and the server surfaces that —
//! so a threshold chosen here would be an invention with the protocol's name on it. Call
//! [`Source::set_signal`] from whatever is watching the input, and see `examples/embedded_source.rs`
//! for one policy.

use std::sync::Arc;
use std::time::Duration;

/// How often a start the clock was not ready for is retried.
const START_RETRY_INTERVAL: Duration = Duration::from_millis(200);

use tokio::sync::watch;

use crate::audio::SourceCapture;
use crate::protocol::client::{Encryption, EncryptionSettings, WsSender};
#[cfg(feature = "discovery")]
use crate::protocol::manager::ConnectionManager;
use crate::protocol::messages::{
    ClientStreamSource, Message, SourceCommandType, SourceFeatures, SourceSignal, SourceState,
    SourceV1Support,
};
use crate::ProtocolClientBuilder;

/// Where a source is in its connection to a server.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ConnectionState {
    /// Not connected, and not currently trying.
    #[default]
    Disconnected,
    /// Dialling a server, or waiting for one to dial in.
    Connecting,
    /// Connected, with the role activated. The server has not asked for audio.
    Connected,
    /// The server asked for audio and it is going out.
    Streaming,
}

/// What the source is doing, for an application that has to show it.
#[derive(Debug, Clone, Default)]
pub struct SourceStatus {
    /// Where the connection stands.
    pub connection: ConnectionState,
    /// The connected server's identity, once there is one.
    pub server_id: Option<String>,
    /// The connected server's friendly name.
    pub server_name: Option<String>,
    /// The format announced for the stream currently going out.
    pub format: Option<ClientStreamSource>,
    /// The signal presence last reported, for a source that senses its input.
    pub signal: Option<SourceSignal>,
    /// The last thing that went wrong, kept until something else does.
    pub last_error: Option<String>,
}

/// Everything a server learns about this source, and everything the session needs to capture.
pub struct SourceConfig {
    /// Friendly name, shown wherever a server lists its clients.
    pub name: String,
    /// Stable identity. Under the encrypted transport this must be the public half of
    /// [`encryption`](Self::encryption)'s identity.
    pub client_id: String,
    /// Product name reported in `client/hello`.
    pub product_name: String,
    /// Manufacturer reported in `client/hello`.
    pub manufacturer: Option<String>,
    /// The encrypted transport's identity and trust store, or `None` to speak cleartext.
    pub encryption: Option<EncryptionSettings>,
    /// The capture device, or `None` for the platform default input.
    pub device: Option<cpal::Device>,
    /// The codec to send: `pcm`, `flac` or `opus`.
    ///
    /// There is no negotiation. The spec has a source announce its input format in
    /// `client_stream/start` and the server, which resamples and transcodes centrally, take
    /// whatever it announces.
    pub codec: String,
    /// Sample rate to capture and send at.
    pub sample_rate: u32,
    /// Channel count to capture and send.
    pub channels: u8,
    /// Bits per sample to send.
    pub bit_depth: u8,
    /// Whether to advertise `line_sense` — that this source reports signal presence.
    ///
    /// Advertise it only if something is going to call [`Source::set_signal`]. A source that
    /// claims the feature and never reports leaves the server waiting on a promise.
    pub line_sense: bool,
}

impl SourceConfig {
    /// A configuration for 48kHz 16-bit stereo PCM from the default input, with no signal
    /// sensing and a cleartext transport.
    pub fn new(client_id: String, name: String) -> Self {
        Self {
            name,
            client_id,
            product_name: format!(
                "sendspin-rs on {} {}",
                std::env::consts::OS,
                std::env::consts::ARCH
            ),
            manufacturer: None,
            encryption: None,
            device: None,
            codec: "pcm".to_string(),
            sample_rate: 48_000,
            channels: 2,
            bit_depth: 16,
            line_sense: false,
        }
    }

    /// The format this source will announce in `client_stream/start`.
    fn stream_format(&self, codec_header: Option<String>) -> ClientStreamSource {
        ClientStreamSource {
            codec: self.codec.clone(),
            channels: self.channels,
            sample_rate: self.sample_rate,
            bit_depth: self.bit_depth,
            codec_header,
        }
    }
}

/// A source: a configuration, and the session that runs on it.
pub struct Source {
    config: SourceConfig,
    status: watch::Sender<SourceStatus>,
    signal: Arc<watch::Sender<Option<SourceSignal>>>,
    level: watch::Sender<f32>,
    /// Audio from somewhere other than a capture device, taken by the first session that starts.
    ///
    /// One session's worth: a caller that feeds a source this way owns the thing producing the
    /// audio, and when that ends there is nothing to reconnect to. Behind a lock only so that
    /// running a source stays `&self`, as every other way of driving one is.
    frames: std::sync::Mutex<Option<tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>>>,
}

/// A handle for reporting signal presence from wherever the input is being watched.
///
/// Separate from [`Source`] because the two usually live in different places: the session runs
/// in one task, and whatever decides that audio is present — a level watcher, a GPIO pin on a
/// detector, a person pressing a button — runs in another.
#[derive(Clone)]
pub struct SignalReporter(Arc<watch::Sender<Option<SourceSignal>>>);

impl SignalReporter {
    /// Report whether audio is present on the input.
    pub fn report(&self, signal: SourceSignal) {
        let _ = self.0.send(Some(signal));
    }
}

impl Source {
    /// The externally-fed audio, for the one session that gets it.
    fn take_frames(&self) -> Option<tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>> {
        self.frames.lock().expect("the frames lock").take()
    }

    /// A source whose audio arrives from somewhere other than a capture device.
    ///
    /// Same protocol, same announcement, same encoder: only where the samples come from differs.
    /// Bluetooth is the case this exists for -- a phone's audio, decoded outside this crate,
    /// already interleaved little-endian at the format the config names.
    pub fn with_frames(
        config: SourceConfig,
        frames: tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>,
    ) -> Self {
        let source = Self::new(config);
        *source.frames.lock().expect("a fresh source's frames") = Some(frames);
        source
    }

    /// Build a source. Nothing is captured and nothing is sent until it is run.
    pub fn new(config: SourceConfig) -> Self {
        Self {
            frames: std::sync::Mutex::new(None),
            config,
            status: watch::Sender::new(SourceStatus::default()),
            signal: Arc::new(watch::Sender::new(None)),
            level: watch::Sender::new(0.0),
        }
    }

    /// Watch the input's level: the loudest sample of each captured block, 0.0 to 1.0.
    ///
    /// On its own channel rather than in [`status`](Self::status), because it changes with
    /// every block and the rest of the status does not — an application watching for a format
    /// change should not be woken fifty times a second by a level it is not reading.
    ///
    /// This is what makes a signal policy possible without the crate having one: measure here,
    /// decide there, and report the decision with [`set_signal`](Self::set_signal).
    pub fn levels(&self) -> watch::Receiver<f32> {
        self.level.subscribe()
    }

    /// Watch what this source is doing.
    pub fn status(&self) -> watch::Receiver<SourceStatus> {
        self.status.subscribe()
    }

    /// The configuration this source was built with.
    pub fn config(&self) -> &SourceConfig {
        &self.config
    }

    /// Report whether audio is present on the input.
    ///
    /// Only meaningful when [`SourceConfig::line_sense`] is set, and only the application can
    /// decide it — see the module documentation. Reported to the server when it changes.
    pub fn set_signal(&self, signal: SourceSignal) {
        let _ = self.signal.send(Some(signal));
    }

    /// A handle that reports signal presence, usable from another task.
    pub fn signal_reporter(&self) -> SignalReporter {
        SignalReporter(Arc::clone(&self.signal))
    }

    /// Dial `url` and stream when asked to.
    ///
    /// With `reconnect`, dials again whenever the server goes away and never returns. A source fed
    /// from outside gets one attempt at most: its audio is gone once the session that took it ends.
    ///
    pub async fn run_outbound(
        &self,
        url: &str,
        reconnect: Option<Duration>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let Some(base) = reconnect else {
            return run_outbound(
                &self.config,
                &self.status,
                &self.signal,
                &self.level,
                url,
                self.take_frames(),
            )
            .await;
        };

        let ceiling = Duration::from_secs(60);
        let mut wait = base;
        loop {
            match run_outbound(
                &self.config,
                &self.status,
                &self.signal,
                &self.level,
                url,
                self.take_frames(),
            )
            .await
            {
                Ok(()) => wait = base,
                Err(e) => {
                    log::warn!("Connection to {url} failed: {e}");
                    self.status
                        .send_modify(|status| status.last_error = Some(e.to_string()));
                    wait = (wait * 2).min(ceiling);
                }
            }
            log::info!("Reconnecting to {url} in {}s", wait.as_secs());
            tokio::time::sleep(wait).await;
        }
    }

    /// Listen on `bind` for servers that dial in, advertise over mDNS, and serve whichever
    /// connection wins arbitration.
    #[cfg(feature = "discovery")]
    pub async fn run_inbound(&mut self, bind: &str) -> Result<(), Box<dyn std::error::Error>> {
        run_inbound(
            &self.config,
            &self.status,
            &self.signal,
            &self.level,
            bind,
            self.take_frames(),
        )
        .await
    }
}

/// The client template both directions are built from, so the two cannot drift.
fn template(config: &SourceConfig) -> ProtocolClientBuilder {
    ProtocolClientBuilder::builder()
        .client_id(config.client_id.clone())
        .name(config.name.clone())
        .source_v1_support(SourceV1Support {
            features: config.line_sense.then_some(SourceFeatures {
                line_sense: Some(true),
            }),
        })
        // No source object in the first `client/state`. There is nothing to put in one until
        // something has sensed the input, and an empty object is a message the reference client
        // does not send — the availability the handshake already reports is what a server reads
        // to know a client has stated itself.
        .product_name(Some(config.product_name.clone()))
        .manufacturer(config.manufacturer.clone())
        .encryption(match &config.encryption {
            Some(settings) => Encryption::Enabled(settings.clone()),
            None => Encryption::Disabled,
        })
        .build()
}

async fn run_outbound(
    config: &SourceConfig,
    status: &watch::Sender<SourceStatus>,
    signal: &watch::Sender<Option<SourceSignal>>,
    level: &watch::Sender<f32>,
    url: &str,
    frames: Option<tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>>,
) -> Result<(), Box<dyn std::error::Error>> {
    log::info!("Connecting to {url}");
    status.send_modify(|status| status.connection = ConnectionState::Connecting);
    let client = template(config).connect(url).await?;
    let hello = client.server_hello().clone();
    log::info!(
        "Connected to {} ({}), roles {:?}",
        hello.name,
        hello.server_id,
        hello.active_roles
    );

    let conn = client.split();
    capture(
        conn.messages,
        conn.clock_sync,
        conn.sender,
        config,
        status,
        signal.subscribe(),
        level,
        (hello.server_id, hello.name),
        frames,
    )
    .await;
    log::info!("Server closed the connection");
    Ok(())
}

#[cfg(feature = "discovery")]
async fn run_inbound(
    config: &SourceConfig,
    status: &watch::Sender<SourceStatus>,
    signal: &watch::Sender<Option<SourceSignal>>,
    level: &watch::Sender<f32>,
    bind: &str,
    frames: Option<tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>>,
) -> Result<(), Box<dyn std::error::Error>> {
    let listener = template(config).listen(bind).await?;
    let port = listener.local_addr()?.port();
    let mut manager = ConnectionManager::new(listener);
    status.send_modify(|status| status.connection = ConnectionState::Connecting);

    let _advertisement =
        crate::protocol::discovery::ClientAdvertisement::new(&config.client_id, &config.name, port)
            .inspect_err(|e| log::error!("Could not advertise over mDNS: {e}"))
            .ok();
    log::info!(
        "Listening on {bind}, advertising _sendspin._tcp.local. as {:?}",
        config.name
    );

    // One receiver, so it goes to the first server that gets this far and to no other: an
    // external feed cannot be split, and handing half of it to a second connection would be
    // worse than handing it none.
    let mut frames = frames;
    while let Some(conn) = manager.next_connection().await {
        let server_id = conn.server_hello.server_id.clone();
        log::info!("Serving {server_id} from {}", conn.peer);
        capture(
            conn.messages,
            conn.clock_sync,
            conn.sender,
            config,
            status,
            signal.subscribe(),
            level,
            (server_id.clone(), conn.server_hello.name.clone()),
            frames.take(),
        )
        .await;
        log::info!("{server_id} disconnected — waiting for the next server");
    }
    Ok(())
}

/// Capture and stream for one connection, until it ends.
#[allow(clippy::too_many_arguments)]
async fn capture(
    mut messages: tokio::sync::mpsc::UnboundedReceiver<Message>,
    clock_sync: Arc<parking_lot::Mutex<crate::sync::ClockSync>>,
    sender: WsSender,
    config: &SourceConfig,
    status: &watch::Sender<SourceStatus>,
    mut signal: watch::Receiver<Option<SourceSignal>>,
    level: &watch::Sender<f32>,
    server: (String, String),
    // Audio from outside this crate, for a source that is not a sound card. Taken by the first
    // stream that starts; a second start finds it gone, which is what the end of that audio means.
    mut external: Option<tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>>,
) {
    status.send_modify(|status| {
        status.connection = ConnectionState::Connected;
        status.server_id = Some(server.0);
        status.server_name = Some(server.1);
    });

    // The capture stream is opened on demand rather than at connect: an input held open is an
    // input nothing else on the machine can use, and a server may never ask for audio at all.
    let mut input: Option<crate::audio::capture::InputStream> = None;
    let mut encoder: Option<SourceCapture> = None;
    // A start the server has asked for and this client has not been able to honour yet.
    let mut start_requested = false;
    let mut start_tick = tokio::time::interval(START_RETRY_INTERVAL);

    loop {
        tokio::select! {
            msg = messages.recv() => {
                let Some(msg) = msg else { break };
                let Message::ServerCommand(command) = msg else { continue };
                let Some(source) = command.source else { continue };
                match source.command {
                    // Both commands are idempotent by spec: a start while the stream is open
                    // must not restart it, and a stop while stopped is ignored.
                    SourceCommandType::Start if input.is_none() => {
                        // Held rather than acted on, because the clock may not be ready. The
                        // start is attempted on the next tick and every tick after it.
                        start_requested = true;
                    }
                    SourceCommandType::Stop if start_requested || input.is_some() => {
                        let announced = input.is_some();
                        start_requested = false;
                        // Dropped first, so nothing new arrives while the tail is flushed.
                        input = None;
                        if !announced {
                            // Asked to stop a stream that was never announced, because the
                            // clock was not ready to stamp it. There is nothing to end.
                            continue;
                        }
                        if let Some(mut capture) = encoder.take() {
                            flush(&mut capture, &sender).await;
                        }
                        if let Err(e) = sender.send_client_stream_end().await {
                            log::warn!("Could not end the input stream: {e}");
                        }
                        log::info!("Stream ended");
                        status.send_modify(|status| {
                            status.connection = ConnectionState::Connected;
                            status.format = None;
                        });
                    }
                    _ => {}
                }
            }
            // A stream is announced only once its frames can be stamped in the server's clock.
            // Announcing earlier hands the server a stream it cannot place in time, and then
            // silence until the filter settles; the reference client refuses to start for the
            // same reason.
            _ = start_tick.tick(), if start_requested && input.is_none() => {
                let ready = {
                    let clock = clock_sync.lock();
                    let now = clock.clock().now_micros();
                    clock.client_to_server_micros(now).is_some()
                };
                if ready {
                    match start(config, &sender, status, &mut external).await {
                        Ok((stream, capture)) => {
                            input = Some(stream);
                            encoder = Some(capture);
                        }
                        Err(e) => {
                            log::error!("Could not start capturing: {e}");
                            status.send_modify(|status| status.last_error = Some(e));
                            start_requested = false;
                        }
                    }
                }
            }
            Ok(()) = signal.changed() => {
                let reported = *signal.borrow_and_update();
                let Some(reported) = reported else { continue };
                status.send_modify(|status| status.signal = Some(reported));
                if !config.line_sense {
                    // Reporting a feature that was never advertised is a message the server has
                    // no reason to read, and a promise this client did not make.
                    continue;
                }
                if let Err(e) = sender.send_source_state(SourceState { signal: Some(reported) }).await {
                    log::warn!("Could not report signal presence: {e}");
                }
            }
            pcm = async { input.as_mut().expect("guarded below").recv().await }, if input.is_some() => {
                let Some(pcm) = pcm else {
                    // The card stopped handing over audio: the stream is over whatever the
                    // server asked for, and saying so beats sending silence it did not know was
                    // silence.
                    log::error!("The capture device stopped");
                    status.send_modify(|status| {
                        status.last_error = Some("the capture device stopped".to_string())
                    });
                    input = None;
                    encoder = None;
                    continue;
                };
                // Stamps go out in the *server's* clock. While the filter is still settling
                // there is no conversion yet, and a frame stamped with local time would never
                // line up — so there is nothing worth sending.
                let now = clock_sync.lock().clock().now_micros();
                let Some(server_now) = clock_sync.lock().client_to_server_micros(now) else {
                    continue;
                };
                // Published before encoding, so an application sees the input as the card gave
                // it rather than as a codec left it.
                let _ = level.send(crate::audio::capture::peak(&pcm, config.bit_depth));
                let Some(capture) = encoder.as_mut() else { continue };
                match capture.feed(&pcm, server_now) {
                    Ok(frames) => {
                        for frame in frames {
                            if let Err(e) = sender.send_source_audio(frame.0, &frame.1).await
                            {
                                log::warn!("Could not send captured audio: {e}");
                                break;
                            }
                        }
                    }
                    Err(e) => log::warn!("Could not encode captured audio: {e}"),
                }
            }
            else => break,
        }
    }

    status.send_modify(|status| {
        status.connection = ConnectionState::Disconnected;
        status.server_id = None;
        status.server_name = None;
        status.format = None;
    });
}

/// Open the input, announce the format, and start streaming.
async fn start(
    config: &SourceConfig,
    sender: &WsSender,
    status: &watch::Sender<SourceStatus>,
    external: &mut Option<tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>>,
) -> Result<(crate::audio::capture::InputStream, SourceCapture), String> {
    let stream = match external.take() {
        Some(frames) => crate::audio::capture::InputStream::from_frames(frames),
        None => crate::audio::capture::InputStream::open(
            config.device.clone(),
            config.sample_rate,
            config.channels,
            config.bit_depth,
        )?,
    };
    let capture = SourceCapture::new(
        &config.codec,
        config.sample_rate,
        config.bit_depth,
        config.channels,
    )
    .map_err(|e| format!("could not build the encoder: {e}"))?;

    // Announced before the first frame, so a format change is a stream boundary rather than
    // something the server has to infer.
    let format = config.stream_format(capture.codec_header());
    sender
        .send_client_stream_start(format.clone())
        .await
        .map_err(|e| format!("could not announce the input stream: {e}"))?;
    log::info!(
        "Stream starting: {} {}Hz {}ch {}bit",
        format.codec,
        format.sample_rate,
        format.channels,
        format.bit_depth
    );
    status.send_modify(|status| {
        status.connection = ConnectionState::Streaming;
        status.format = Some(format);
    });
    Ok((stream, capture))
}

/// Send whatever the encoder was still holding.
///
/// An encoder with lookahead keeps frames back; ending the stream without them truncates the
/// audio by exactly that much, which is the kind of loss nobody hears and everybody argues about.
async fn flush(capture: &mut SourceCapture, sender: &WsSender) {
    match capture.finish() {
        Ok(frames) => {
            for frame in frames {
                if let Err(e) = sender.send_source_audio(frame.0, &frame.1).await {
                    log::warn!("Could not send the last captured audio: {e}");
                    break;
                }
            }
        }
        Err(e) => log::warn!("Could not flush the encoder: {e}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audio_handed_in_from_outside_goes_to_one_session() {
        // Whoever runs the source first gets the audio; a reconnect must not wait on a receiver
        // that is already drained, so the second attempt captures instead.
        let config = SourceConfig::new("id".to_string(), "name".to_string());
        let (_tx, rx) = tokio::sync::mpsc::unbounded_channel();
        let source = Source::with_frames(config, rx);
        assert!(source.take_frames().is_some());
        assert!(source.take_frames().is_none());
    }

    #[test]
    fn a_source_that_does_not_sense_its_input_does_not_advertise_the_feature() {
        let config = SourceConfig::new("id".to_string(), "name".to_string());
        assert!(!config.line_sense);
        let support = SourceV1Support {
            features: config.line_sense.then_some(SourceFeatures {
                line_sense: Some(true),
            }),
        };
        assert!(support.features.is_none());
    }

    #[test]
    fn the_announced_format_is_the_configured_one() {
        let mut config = SourceConfig::new("id".to_string(), "name".to_string());
        config.codec = "flac".to_string();
        config.sample_rate = 44_100;
        config.bit_depth = 24;
        let format = config.stream_format(Some("aGVhZGVy".to_string()));
        assert_eq!(format.codec, "flac");
        assert_eq!(format.sample_rate, 44_100);
        assert_eq!(format.bit_depth, 24);
        assert_eq!(format.channels, 2);
        assert_eq!(format.codec_header.as_deref(), Some("aGVhZGVy"));
    }
}
