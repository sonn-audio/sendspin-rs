// ABOUTME: A group is one timeline shared by every player in it: audio is pulled once, stamped
// ABOUTME: once, and handed to all members identically, which is what makes multi-room work.

//! Synchronized playback across more than one client.
//!
//! The reason this exists is a bug you cannot see with one speaker in the room. Before it, the
//! [`AudioSource`](crate::AudioSource) was pulled *per connection*: two clients each got their
//! own timeline, their own start time, and — because a pull consumes samples — their own
//! *different* samples. Two speakers playing different halves of a track is the exact opposite
//! of what multi-room means, and a single client can never reveal it.
//!
//! A group fixes it by inverting the ownership. The group owns the timeline and pulls the
//! source once; each chunk is framed once and the *same bytes* go to every member. Sharing the
//! framed chunk behind an [`Arc`] is not only cheaper than framing per member, it is what makes
//! identical delivery structural rather than something the code has to remember to do.
//!
//! # Joining late
//!
//! A client that connects mid-track cannot make sense of a binary chunk it has no format for,
//! so the group keeps the `stream/start` describing the stream in flight and hands it to
//! whoever joins. The joiner then picks up the *current* timeline — it does not get its own,
//! and it does not restart the track — which is what lets a speaker be added to a playing group
//! and fall into step.
//!
//! # What a member missing a beat costs
//!
//! Delivery is a broadcast channel with a bounded queue. A member that stops draining it — a
//! wedged socket, a client that stopped reading — falls behind and is told it lagged rather
//! than being allowed to hold the group back. Audio is realtime: a chunk delivered late is
//! worth less than no chunk at all, and one slow member must never become every member's
//! problem.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use tokio::sync::{broadcast, Notify};

use sendspin_proto::messages::{
    ControllerCommand, ControllerCommandType, ControllerState, GroupUpdate, Message, PlaybackState,
    PlayerCommand, PlayerCommandType, ServerCommand, ServerState, StreamEnd, StreamStart,
};

use crate::stream::{PlayerStream, DEFAULT_SEND_AHEAD_US};
use crate::ServerConfig;

/// How many frames a member may fall behind before it is dropped from the stream.
///
/// Two seconds of audio at 20 ms a chunk, so a member has to be badly stuck rather than merely
/// unlucky to hit it. Bounded rather than unbounded on purpose: an unbounded queue in front of
/// a stalled socket does not preserve the audio, it just moves where the memory grows.
const MEMBER_QUEUE: usize = 100;

/// 20 ms of audio per chunk, matching the reference implementation.
///
/// Small enough that a stop is not heard long after it was asked for, large enough that the
/// per-chunk overhead stays negligible.
const CHUNK_MS: u32 = 20;

/// One frame destined for a member's socket.
///
/// Pre-framed rather than pre-serialized-per-member: the binary chunk is the hot path, and it
/// must be byte-identical everywhere for the group to be synchronized at all.
#[derive(Debug)]
pub enum Outgoing {
    /// A JSON control message.
    Json(Box<Message>),
    /// A binary audio frame, already carrying its type byte and timestamp.
    Binary(Vec<u8>),
}

/// The mutable half of a group, behind one lock.
struct GroupInner {
    playback: PlaybackState,
    /// Everyone in the group, whatever their role.
    ///
    /// A controller or a display belongs to a group as much as a speaker does — it is how it
    /// learns what is playing and what it may ask for.
    members: usize,
    /// The members that actually play audio.
    ///
    /// Counted apart from `members` because only these keep the stream running. A group holding
    /// nothing but a controller has nobody to play *to*, and pulling the source for it would
    /// consume a track that no one hears.
    listeners: usize,
    /// The `stream/start` for the stream currently in flight, kept so a late joiner can be
    /// told what it is about to receive. `None` when nothing is playing.
    current_start: Option<StreamStart>,
    /// Group volume, 0-100.
    volume: u8,
    muted: bool,
}

/// A set of clients sharing one playback timeline.
pub struct Group {
    id: String,
    name: Option<String>,
    config: Arc<ServerConfig>,
    tx: broadcast::Sender<Arc<Outgoing>>,
    inner: Mutex<GroupInner>,
    /// Raised when membership changes, so an idle group starts promptly instead of polling.
    wake: Notify,
    chunks_sent: AtomicU64,
}

impl Group {
    /// Create a group and start the task that drives its timeline.
    pub fn spawn(config: Arc<ServerConfig>, id: String, name: Option<String>) -> Arc<Self> {
        let (tx, _) = broadcast::channel(MEMBER_QUEUE);
        let group = Arc::new(Self {
            id,
            name,
            config,
            tx,
            inner: Mutex::new(GroupInner {
                playback: PlaybackState::Stopped,
                members: 0,
                listeners: 0,
                current_start: None,
                volume: 100,
                muted: false,
            }),
            wake: Notify::new(),
            chunks_sent: AtomicU64::new(0),
        });
        tokio::spawn(run(Arc::clone(&group)));
        group
    }

    /// This group's identifier, as clients see it.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// How many chunks this group has broadcast over its life.
    pub fn chunks_sent(&self) -> u64 {
        self.chunks_sent.load(Ordering::Relaxed)
    }

    /// How many members are currently in the group, of any role.
    pub fn members(&self) -> usize {
        self.inner.lock().expect("group lock").members
    }

    /// How many members actually play audio.
    pub fn listeners(&self) -> usize {
        self.inner.lock().expect("group lock").listeners
    }

    /// The group's current playback state.
    pub fn playback_state(&self) -> PlaybackState {
        self.inner.lock().expect("group lock").playback
    }

    /// Add a member, returning its feed and everything it needs to catch up.
    ///
    /// The `stream/start` comes back with the membership rather than being broadcast, because
    /// it is only new information to the joiner: broadcasting it would tell every existing
    /// member to restart a stream they are already playing.
    pub fn join(self: &Arc<Self>, plays: bool) -> Membership {
        let rx = self.tx.subscribe();
        // Pulled at join rather than replayed from a cached broadcast: a joiner needs what is
        // playing *now*, and the source is the only thing that knows.
        let metadata = self
            .config
            .metadata
            .as_ref()
            .and_then(|source| source.current());
        let (catch_up, update) = {
            let mut inner = self.inner.lock().expect("group lock");
            inner.members += 1;
            if plays {
                inner.listeners += 1;
            }
            (
                inner.current_start.clone(),
                GroupUpdate {
                    playback_state: Some(inner.playback),
                    group_id: Some(self.id.clone()),
                    group_name: self.name.clone(),
                },
            )
        };
        self.wake.notify_waiters();
        Membership {
            group: Arc::clone(self),
            rx,
            catch_up,
            update,
            metadata,
            plays,
        }
    }

    /// The controller state to advertise, if this server has a controller behind it.
    pub fn controller_state(&self) -> Option<ControllerState> {
        let controller = self.config.controller.as_ref()?;
        let inner = self.inner.lock().expect("group lock");
        Some(ControllerState {
            supported_commands: controller
                .supported_commands()
                .iter()
                .map(command_name)
                .collect(),
            volume: inner.volume,
            muted: inner.muted,
            repeat: None,
            shuffle: None,
            seek_max_ms: controller.seek_max_ms(),
        })
    }

    /// Act on a `client/command` from a controller.
    ///
    /// Commands split in two. Volume and mute are the group's own business — it holds the
    /// levels and the players take them from here — so they are applied and echoed as a
    /// `server/command` to every player. Everything else is playback the server does not own:
    /// what "next track" means belongs to whatever is producing the audio, so it is handed to
    /// the application rather than guessed at.
    ///
    /// A command outside `supported_commands` is refused rather than attempted. The list is a
    /// promise in the same way an activated role is, and honouring something never advertised
    /// would leave a client unable to discover what this server actually does.
    pub fn handle_controller_command(&self, cmd: &ControllerCommand) {
        let Some(controller) = self.config.controller.as_ref() else {
            return;
        };
        let supported = controller.supported_commands();
        if !supported.contains(&cmd.command) {
            log::warn!(
                "refusing {:?}: not in this server's supported_commands {:?}",
                cmd.command,
                supported
            );
            return;
        }

        match cmd.command {
            ControllerCommandType::Volume => {
                let Some(level) = cmd.volume else { return };
                // Clamped rather than refused: a controller with a slightly different idea of
                // the range should still move the volume, not silently do nothing.
                let level = level.min(100);
                self.inner.lock().expect("group lock").volume = level;
                self.broadcast_player_command(PlayerCommand {
                    command: PlayerCommandType::Volume,
                    volume: Some(level),
                    mute: None,
                    static_delay_ms: None,
                });
                self.broadcast_state();
            }
            ControllerCommandType::Mute => {
                let Some(muted) = cmd.mute else { return };
                self.inner.lock().expect("group lock").muted = muted;
                self.broadcast_player_command(PlayerCommand {
                    command: PlayerCommandType::Mute,
                    volume: None,
                    mute: Some(muted),
                    static_delay_ms: None,
                });
                self.broadcast_state();
            }
            ControllerCommandType::Seek => {
                // A seek past the end is dropped rather than clamped: unlike a volume, landing
                // somewhere other than where the user asked is not a smaller version of the
                // request, it is a different one.
                match (cmd.position_ms, controller.seek_max_ms()) {
                    (Some(position), Some(max)) if position <= max => controller.handle(cmd),
                    (Some(position), Some(max)) => {
                        log::warn!("refusing seek to {position}ms, past this server's {max}ms");
                    }
                    _ => log::warn!("refusing seek with no position or no seekable range"),
                }
            }
            _ => controller.handle(cmd),
        }
    }

    /// Tell every player to apply a command.
    fn broadcast_player_command(&self, player: PlayerCommand) {
        self.broadcast(Outgoing::Json(Box::new(Message::ServerCommand(
            ServerCommand {
                player: Some(player),
                source: None,
            },
        ))));
    }

    /// Tell every member the controller state changed.
    fn broadcast_state(&self) {
        let Some(controller) = self.controller_state() else {
            return;
        };
        self.broadcast(Outgoing::Json(Box::new(Message::ServerState(
            ServerState {
                metadata: None,
                controller: Some(controller),
                color: None,
            },
        ))));
    }

    /// Tell every member what is playing, if this server knows.
    ///
    /// Sent on each stream start rather than on a timer: metadata that changes is a new track,
    /// and a new track is a new stream.
    fn broadcast_metadata(&self) {
        let Some(source) = self.config.metadata.as_ref() else {
            return;
        };
        let Some(metadata) = source.current() else {
            return;
        };
        self.broadcast(Outgoing::Json(Box::new(Message::ServerState(
            ServerState {
                metadata: Some(metadata),
                controller: None,
                color: None,
            },
        ))));
    }

    /// Put one frame on every member's feed.
    ///
    /// A send with no members is not an error: a group whose last client just left is a normal
    /// state, not a failure to report.
    fn broadcast(&self, out: Outgoing) {
        let _ = self.tx.send(Arc::new(out));
    }

    /// Tell every member the group's state changed.
    fn broadcast_group_update(&self) {
        let update = {
            let inner = self.inner.lock().expect("group lock");
            GroupUpdate {
                playback_state: Some(inner.playback),
                group_id: Some(self.id.clone()),
                group_name: self.name.clone(),
            }
        };
        self.broadcast(Outgoing::Json(Box::new(Message::GroupUpdate(update))));
    }

    fn set_playback(&self, state: PlaybackState) {
        self.inner.lock().expect("group lock").playback = state;
    }

    fn set_current_start(&self, start: Option<StreamStart>) {
        self.inner.lock().expect("group lock").current_start = start;
    }
}

/// One client's place in a group, and its feed of what to send.
///
/// Leaving is [`Drop`] rather than an explicit call so that every way a connection can end —
/// a clean goodbye, a decode error, a dropped socket, a panic — takes the member out of the
/// group. A membership that outlived its connection would keep an empty group streaming.
pub struct Membership {
    group: Arc<Group>,
    rx: broadcast::Receiver<Arc<Outgoing>>,
    catch_up: Option<StreamStart>,
    update: GroupUpdate,
    metadata: Option<sendspin_proto::messages::MetadataState>,
    plays: bool,
}

impl Membership {
    /// The `stream/start` for a stream already in flight, if this member joined mid-track.
    pub fn catch_up(&mut self) -> Option<StreamStart> {
        self.catch_up.take()
    }

    /// The `group/update` describing the group this member just joined.
    pub fn group_update(&self) -> GroupUpdate {
        self.update.clone()
    }

    /// What is playing, for a member that activated `metadata@v1`.
    ///
    /// Handed to the joiner alone, like the `stream/start`: broadcasting it would re-send every
    /// existing member metadata they already have.
    pub fn metadata(&mut self) -> Option<sendspin_proto::messages::MetadataState> {
        self.metadata.take()
    }

    /// The group this member belongs to.
    pub fn group(&self) -> &Arc<Group> {
        &self.group
    }

    /// Whether this member should be sent audio.
    ///
    /// The control messages go to everyone in the group; the binary frames do not. A controller
    /// or a display is a member so it hears about state, not so it receives samples it has no
    /// way to play.
    pub fn plays(&self) -> bool {
        self.plays
    }

    /// Wait for the next frame to send.
    ///
    /// A member that fell too far behind is told how much it missed rather than being handed
    /// stale audio; the caller decides whether to carry on. Returns `None` only when the group
    /// itself is gone.
    pub async fn next(&mut self) -> Option<Result<Arc<Outgoing>, u64>> {
        match self.rx.recv().await {
            Ok(out) => Some(Ok(out)),
            Err(broadcast::error::RecvError::Lagged(missed)) => Some(Err(missed)),
            Err(broadcast::error::RecvError::Closed) => None,
        }
    }
}

impl Drop for Membership {
    fn drop(&mut self) {
        let mut inner = self.group.inner.lock().expect("group lock");
        inner.members = inner.members.saturating_sub(1);
        if self.plays {
            inner.listeners = inner.listeners.saturating_sub(1);
        }
        drop(inner);
        self.group.wake.notify_waiters();
    }
}

/// The wire name of a controller command.
///
/// Taken from the serde representation rather than written out again, so the names this server
/// advertises in `supported_commands` cannot drift from the ones it parses.
fn command_name(command: &ControllerCommandType) -> String {
    serde_json::to_value(command)
        .ok()
        .and_then(|value| value.as_str().map(str::to_string))
        .unwrap_or_default()
}

/// Drive one group's timeline for as long as the server lives.
async fn run(group: Arc<Group>) {
    loop {
        // An empty group pulls nothing. A source consumed with nobody listening is audio
        // silently thrown away, and on a finite source it is a track that plays to an empty
        // room and is gone by the time someone connects.
        while group.listeners() == 0 {
            group.wake.notified().await;
        }

        let Some(source) = group.config.audio.clone() else {
            // Nothing to play. Wait for the membership to change rather than spinning.
            group.wake.notified().await;
            continue;
        };

        stream_once(&group, source.as_ref()).await;

        // A finished source must not immediately restart: that would loop the track forever
        // for whoever is still connected. Wait for the room to change first.
        group.wake.notified().await;
    }
}

/// Play the source through once, to whoever is in the group.
async fn stream_once(group: &Arc<Group>, source: &dyn crate::AudioSource) {
    let clock = &group.config.clock;

    // The first sample plays one send-ahead from now, so every member has the full lead to
    // receive, decode and schedule it rather than being handed audio that is already due.
    let start_us = clock.now_micros() + DEFAULT_SEND_AHEAD_US;
    let mut stream = PlayerStream::new(source.format(), start_us);

    let announce = stream.stream_start(clock.now_micros());
    group.set_current_start(Some(announce.clone()));
    group.set_playback(PlaybackState::Playing);
    group.broadcast(Outgoing::Json(Box::new(Message::StreamStart(announce))));
    group.broadcast_group_update();
    group.broadcast_metadata();
    log::info!(
        "group {} streaming: {} {}Hz {}ch {}bit to {} member(s)",
        group.id,
        stream.format().codec,
        stream.format().sample_rate,
        stream.format().channels,
        stream.format().bit_depth,
        group.listeners()
    );

    let frames_per_chunk = (stream.format().sample_rate * CHUNK_MS / 1000) as usize;

    loop {
        if group.listeners() == 0 {
            log::info!("group {} lost its last player; stopping", group.id);
            break;
        }

        // Sending is driven by the timeline rather than by a timer: the stream says when it is
        // behind its lead, and the wait is only ever long enough to get back to that point.
        let now = clock.now_micros();
        if !stream.should_send(now, DEFAULT_SEND_AHEAD_US) {
            let wait = (stream.next_timestamp_us() - now - DEFAULT_SEND_AHEAD_US).max(0) as u64;
            tokio::time::sleep(std::time::Duration::from_micros(wait)).await;
            continue;
        }

        let Some(pcm) = source.next_chunk(frames_per_chunk) else {
            log::info!("group {} source finished", group.id);
            break;
        };
        let Some(framed) = stream.chunk(&pcm) else {
            log::warn!(
                "group {} source returned {} bytes, which is not whole frames; stopping",
                group.id,
                pcm.len()
            );
            break;
        };

        group.broadcast(Outgoing::Binary(framed));
        group.chunks_sent.fetch_add(1, Ordering::Relaxed);
    }

    group.broadcast(Outgoing::Json(Box::new(Message::StreamEnd(StreamEnd {
        server_transmitted: Some(clock.now_micros()),
        roles: None,
    }))));
    group.set_current_start(None);
    group.set_playback(PlaybackState::Stopped);
    group.broadcast_group_update();
}

#[cfg(test)]
mod tests {
    use super::*;
    use sendspin_proto::messages::StreamPlayerConfig;
    use sendspin_proto::noise::keys::Identity;

    /// A source that hands out a counter, so a caller can tell *which* samples it received
    /// rather than only how many.
    struct CountingSource {
        next: Mutex<u8>,
        chunks: Mutex<usize>,
        limit: usize,
    }

    impl CountingSource {
        fn new(limit: usize) -> Self {
            Self {
                next: Mutex::new(0),
                chunks: Mutex::new(0),
                limit,
            }
        }
    }

    impl crate::AudioSource for CountingSource {
        fn format(&self) -> StreamPlayerConfig {
            StreamPlayerConfig {
                codec: "pcm".to_string(),
                sample_rate: 48_000,
                channels: 2,
                bit_depth: 16,
                codec_header: None,
            }
        }

        fn next_chunk(&self, frames: usize) -> Option<Vec<u8>> {
            let mut chunks = self.chunks.lock().unwrap();
            if *chunks >= self.limit {
                return None;
            }
            *chunks += 1;
            let mut next = self.next.lock().unwrap();
            let value = *next;
            *next = next.wrapping_add(1);
            Some(vec![value; frames * 4])
        }
    }

    struct FixedTrack;

    impl crate::MetadataSource for FixedTrack {
        #[allow(deprecated)]
        fn current(&self) -> Option<sendspin_proto::messages::MetadataState> {
            Some(sendspin_proto::messages::MetadataState {
                timestamp: 0,
                title: Some("Test Tone".to_string()),
                artist: None,
                album_artist: None,
                album: None,
                artwork_url: None,
                year: None,
                track: None,
                progress: None,
                repeat: None,
                shuffle: None,
            })
        }
    }

    fn config(limit: usize) -> Arc<ServerConfig> {
        let identity = Identity::generate().expect("identity");
        Arc::new(
            ServerConfig::new(identity, "Test".to_string())
                .with_audio(Arc::new(CountingSource::new(limit))),
        )
    }

    /// The property the whole group model exists for: two members receive byte-identical
    /// audio, which means the same samples carrying the same timestamps. Before groups, each
    /// connection pulled the source itself and two members got *different* samples.
    #[tokio::test]
    async fn two_members_receive_identical_audio() {
        let group = Group::spawn(config(5), "g1".to_string(), Some("Kitchen".to_string()));
        let mut a = group.join(true);
        let mut b = group.join(true);

        let mut a_binary = Vec::new();
        let mut b_binary = Vec::new();
        while a_binary.len() < 5 {
            if let Some(Ok(out)) = a.next().await {
                if let Outgoing::Binary(bytes) = out.as_ref() {
                    a_binary.push(bytes.clone());
                }
            }
        }
        while b_binary.len() < 5 {
            if let Some(Ok(out)) = b.next().await {
                if let Outgoing::Binary(bytes) = out.as_ref() {
                    b_binary.push(bytes.clone());
                }
            }
        }

        assert_eq!(
            a_binary, b_binary,
            "members received different audio, so they would not be in sync"
        );
        // And the samples really did differ chunk to chunk, so the comparison above was not
        // trivially true because every chunk happened to be identical anyway.
        assert_ne!(a_binary[0], a_binary[1]);
    }

    /// A member joining mid-stream needs the format before the binary frames mean anything.
    #[tokio::test]
    async fn a_late_joiner_is_handed_the_stream_in_flight() {
        let group = Group::spawn(config(100), "g1".to_string(), None);
        let mut first = group.join(true);
        // Let the stream actually start before the second member arrives.
        loop {
            match first.next().await {
                Some(Ok(out)) => {
                    if matches!(out.as_ref(), Outgoing::Binary(_)) {
                        break;
                    }
                }
                _ => panic!("the stream never started"),
            }
        }

        let mut late = group.join(true);
        assert!(
            late.catch_up().is_some(),
            "a late joiner was given no stream/start, so it cannot decode what follows"
        );
        assert_eq!(
            late.group_update().playback_state,
            Some(PlaybackState::Playing)
        );
    }

    /// Nothing is pulled from the source while the room is empty: a track that played to
    /// nobody would be gone by the time someone connected.
    #[tokio::test]
    async fn an_empty_group_consumes_nothing() {
        let group = Group::spawn(config(5), "g1".to_string(), None);
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert_eq!(group.chunks_sent(), 0);
        assert_eq!(group.playback_state(), PlaybackState::Stopped);

        let _member = group.join(true);
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert!(
            group.chunks_sent() > 0,
            "a joined member was never sent audio"
        );
    }

    /// A joiner is told what is playing at the moment it arrives, not at the moment the track
    /// started: a display connected mid-song still has to show the song.
    #[tokio::test]
    async fn a_joiner_is_told_what_is_playing() {
        let identity = Identity::generate().expect("identity");
        let config = Arc::new(
            ServerConfig::new(identity, "Test".to_string())
                .with_audio(Arc::new(CountingSource::new(100)))
                .with_metadata(Arc::new(FixedTrack)),
        );
        let group = Group::spawn(config, "g1".to_string(), None);
        let mut member = group.join(true);
        assert_eq!(
            member.metadata().and_then(|m| m.title),
            Some("Test Tone".to_string())
        );
    }

    /// A server with no metadata source hands out none, rather than an empty track that a
    /// client would render as a blank now-playing screen.
    #[tokio::test]
    async fn a_server_without_metadata_offers_none() {
        let group = Group::spawn(config(5), "g1".to_string(), None);
        let mut member = group.join(true);
        assert!(member.metadata().is_none());
    }

    /// A controller that records what it was asked to do, so a test can tell the difference
    /// between a command that was refused and one that was quietly swallowed.
    struct RecordingController {
        supported: Vec<ControllerCommandType>,
        seek_max: Option<u64>,
        handled: Mutex<Vec<ControllerCommandType>>,
    }

    impl crate::Controller for RecordingController {
        fn supported_commands(&self) -> Vec<ControllerCommandType> {
            self.supported.clone()
        }
        fn seek_max_ms(&self) -> Option<u64> {
            self.seek_max
        }
        fn handle(&self, command: &ControllerCommand) {
            self.handled.lock().unwrap().push(command.command.clone());
        }
    }

    fn command(command: ControllerCommandType) -> ControllerCommand {
        ControllerCommand {
            command,
            volume: None,
            mute: None,
            position_ms: None,
            offset_ms: None,
        }
    }

    fn with_controller(controller: Arc<RecordingController>) -> Arc<ServerConfig> {
        let identity = Identity::generate().expect("identity");
        Arc::new(
            ServerConfig::new(identity, "Test".to_string())
                .with_audio(Arc::new(CountingSource::new(1000)))
                .with_controller(controller),
        )
    }

    /// `supported_commands` is a promise in the same way an activated role is. Honouring
    /// something never advertised leaves a client with no way to discover what this server
    /// actually does, so an unadvertised command is refused rather than attempted.
    #[tokio::test]
    async fn a_command_that_was_never_advertised_is_refused() {
        let controller = Arc::new(RecordingController {
            supported: vec![ControllerCommandType::Play],
            seek_max: None,
            handled: Mutex::new(Vec::new()),
        });
        let group = Group::spawn(
            with_controller(Arc::clone(&controller)),
            "g1".to_string(),
            None,
        );

        group.handle_controller_command(&command(ControllerCommandType::Next));
        assert!(
            controller.handled.lock().unwrap().is_empty(),
            "an unadvertised command reached the application"
        );

        group.handle_controller_command(&command(ControllerCommandType::Play));
        assert_eq!(
            *controller.handled.lock().unwrap(),
            vec![ControllerCommandType::Play]
        );
    }

    /// Volume is the group's own state, so it is applied here and every player is told, rather
    /// than being handed to the application to deal with.
    #[tokio::test]
    async fn volume_is_applied_by_the_group_and_pushed_to_players() {
        let controller = Arc::new(RecordingController {
            supported: vec![ControllerCommandType::Volume],
            seek_max: None,
            handled: Mutex::new(Vec::new()),
        });
        let group = Group::spawn(
            with_controller(Arc::clone(&controller)),
            "g1".to_string(),
            None,
        );
        let mut player = group.join(true);

        let mut cmd = command(ControllerCommandType::Volume);
        cmd.volume = Some(42);
        group.handle_controller_command(&cmd);

        assert!(
            controller.handled.lock().unwrap().is_empty(),
            "volume was delegated when the group owns it"
        );
        assert_eq!(group.controller_state().unwrap().volume, 42);

        // The player is told, so it can apply the level locally.
        let mut saw_command = false;
        for _ in 0..20 {
            match player.next().await {
                Some(Ok(out)) => {
                    if let Outgoing::Json(msg) = out.as_ref() {
                        if let Message::ServerCommand(server_command) = msg.as_ref() {
                            assert_eq!(
                                server_command.player.as_ref().and_then(|p| p.volume),
                                Some(42)
                            );
                            saw_command = true;
                            break;
                        }
                    }
                }
                _ => break,
            }
        }
        assert!(saw_command, "no player was told about the volume change");
    }

    /// A volume outside the range is clamped, because a controller with a slightly different
    /// idea of the scale should still move the volume rather than silently do nothing.
    #[tokio::test]
    async fn an_out_of_range_volume_is_clamped_not_dropped() {
        let controller = Arc::new(RecordingController {
            supported: vec![ControllerCommandType::Volume],
            seek_max: None,
            handled: Mutex::new(Vec::new()),
        });
        let group = Group::spawn(with_controller(controller), "g1".to_string(), None);

        let mut cmd = command(ControllerCommandType::Volume);
        cmd.volume = Some(200);
        group.handle_controller_command(&cmd);
        assert_eq!(group.controller_state().unwrap().volume, 100);
    }

    /// A seek is not clamped. Landing somewhere other than where the user asked is not a
    /// smaller version of the request, it is a different one — so an out-of-range seek is
    /// dropped instead.
    #[tokio::test]
    async fn a_seek_past_the_end_is_refused_rather_than_clamped() {
        let controller = Arc::new(RecordingController {
            supported: vec![ControllerCommandType::Seek],
            seek_max: Some(60_000),
            handled: Mutex::new(Vec::new()),
        });
        let group = Group::spawn(
            with_controller(Arc::clone(&controller)),
            "g1".to_string(),
            None,
        );

        let mut past = command(ControllerCommandType::Seek);
        past.position_ms = Some(90_000);
        group.handle_controller_command(&past);
        assert!(controller.handled.lock().unwrap().is_empty());

        let mut inside = command(ControllerCommandType::Seek);
        inside.position_ms = Some(30_000);
        group.handle_controller_command(&inside);
        assert_eq!(controller.handled.lock().unwrap().len(), 1);
    }

    /// A group holding nothing but a controller has nobody to play to, so the source is not
    /// consumed on its behalf: the track would be gone by the time a speaker arrived.
    #[tokio::test]
    async fn a_controller_alone_does_not_start_the_stream() {
        let group = Group::spawn(config(5), "g1".to_string(), None);
        let _watcher = group.join(false);
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert_eq!(group.members(), 1);
        assert_eq!(group.listeners(), 0);
        assert_eq!(group.chunks_sent(), 0, "audio was pulled for a non-player");

        let _player = group.join(true);
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert!(group.chunks_sent() > 0);
    }

    /// Leaving is by drop, so every way a connection can end takes its member with it.
    #[tokio::test]
    async fn a_dropped_membership_leaves_the_group() {
        let group = Group::spawn(config(100), "g1".to_string(), None);
        let member = group.join(true);
        assert_eq!(group.members(), 1);
        drop(member);
        assert_eq!(group.members(), 0);
    }
}
