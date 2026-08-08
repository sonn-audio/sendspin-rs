use sendspin::protocol::messages::{
    ArtworkChannel, ArtworkFormatRequest, ArtworkSource, ArtworkV1Support, AudioFormatSpec,
    ClientCommand, ClientGoodbye, ClientHello, ClientState, ClientSyncState, ClientTime,
    ColorState, ConnectionReason, ControllerCommand, ControllerCommandType, DeviceInfo,
    GoodbyeReason, ImageFormat, Message, PairMethod, PairMethodDescriptor, PlaybackState,
    PlayerCommandType, PlayerFormatRequest, PlayerState, PlayerStateCommand, PlayerV1Support,
    RepeatMode, ServerTime, SpectrumConfig, SpectrumScale, StreamArtworkChannelConfig,
    StreamRequestFormat, StreamVisualizerConfig, TrustLevel, UnpairedAccess, VisualizerDataType,
    VisualizerFormatRequest, VisualizerV1Support,
};

// =============================================================================
// Handshake Tests
// =============================================================================

#[test]
fn test_client_hello_serialization() {
    let hello = ClientHello {
        client_id: Some("test-client-123".to_string()),
        name: "Test Player".to_string(),
        version: Some(1),
        supported_roles: vec!["player@v1".to_string()],
        trust_level: TrustLevel::default(),
        supported_pair_methods: None,
        unpaired_access: UnpairedAccess::default(),
        device_info: Some(DeviceInfo {
            product_name: Some("Sendspin-RS Player".to_string()),
            manufacturer: Some("Sendspin".to_string()),
            software_version: Some("0.1.0".to_string()),
            mac_address: None,
        }),
        player_v1_support: Some(PlayerV1Support {
            supported_formats: vec![AudioFormatSpec {
                codec: "pcm".to_string(),
                channels: 2,
                sample_rate: 48000,
                bit_depth: 24,
            }],
            buffer_capacity: 50 * 1024 * 1024, // 50 MB
            supported_commands: vec!["volume".to_string(), "mute".to_string()],
        }),
        source_v1_support: None,
        artwork_v1_support: None,
        visualizer_v1_support: None,
    };

    let message = Message::ClientHello(hello);
    let json = serde_json::to_string(&message).unwrap();

    assert!(json.contains("\"type\":\"client/hello\""));
    assert!(json.contains("\"client_id\":\"test-client-123\""));
    assert!(json.contains("\"player@v1_support\""));
    assert!(json.contains("\"player@v1\""));
}

#[test]
fn test_server_hello_deserialization() {
    let json = r#"{
        "type": "server/hello",
        "payload": {
            "server_id": "server-456",
            "name": "Test Server",
            "version": 1,
            "active_roles": ["player@v1"],
            "connection_reason": "playback"
        }
    }"#;

    let message: Message = serde_json::from_str(json).unwrap();

    match message {
        Message::ServerHello(hello) => {
            assert_eq!(hello.server_id, "server-456");
            assert_eq!(hello.name, "Test Server");
            assert_eq!(hello.version, 1);
            assert_eq!(hello.active_roles, vec!["player@v1"]);
            assert_eq!(hello.connection_reason, ConnectionReason::Playback);
        }
        _ => panic!("Expected ServerHello"),
    }
}

// =============================================================================
// State Tests
// =============================================================================

#[test]
fn test_client_state_serialization() {
    let state = ClientState {
        available: Some(true),
        state: Some(ClientSyncState::Synchronized),
        player: Some(PlayerState {
            volume: Some(100),
            muted: Some(false),
            static_delay_ms: Some(0),
            required_lead_time_ms: Some(500),
            min_buffer_ms: Some(500),
            supported_commands: None,
        }),
        source: None,
    };

    let message = Message::ClientState(state);
    let json = serde_json::to_string(&message).unwrap();

    assert!(json.contains("\"type\":\"client/state\""));
    assert!(json.contains("\"state\":\"synchronized\""));
    assert!(json.contains("\"volume\":100"));
    assert!(json.contains("\"static_delay_ms\":0"));
}

#[test]
fn test_client_sync_state_external_source() {
    let state = ClientState {
        available: Some(false),
        state: Some(ClientSyncState::ExternalSource),
        player: None,
        source: None,
    };

    let message = Message::ClientState(state);
    let json = serde_json::to_string(&message).unwrap();

    assert!(json.contains("\"state\":\"external_source\""));
}

#[test]
#[allow(deprecated)]
fn test_server_state_metadata_deserialization() {
    let json = r#"{
        "type": "server/state",
        "payload": {
            "metadata": {
                "timestamp": 1234567890,
                "title": "Test Song",
                "artist": "Test Artist",
                "album": "Test Album",
                "year": 2024,
                "track": 3,
                "progress": {
                    "track_progress": 60000,
                    "track_duration": 180000,
                    "playback_speed": 1000
                },
                "repeat": "off",
                "shuffle": false
            }
        }
    }"#;

    let message: Message = serde_json::from_str(json).unwrap();

    match message {
        Message::ServerState(state) => {
            let metadata = state.metadata.expect("Expected metadata");
            assert_eq!(metadata.timestamp, 1234567890);
            assert_eq!(metadata.title, Some("Test Song".to_string()));
            assert_eq!(metadata.artist, Some("Test Artist".to_string()));
            assert_eq!(metadata.album, Some("Test Album".to_string()));
            assert_eq!(metadata.year, Some(2024));
            assert_eq!(metadata.track, Some(3));

            let progress = metadata.progress.expect("Expected progress");
            assert_eq!(progress.track_progress, 60000);
            assert_eq!(progress.track_duration, 180000);
            assert_eq!(progress.playback_speed, 1000);

            assert_eq!(metadata.repeat, Some(RepeatMode::Off));
            assert_eq!(metadata.shuffle, Some(false));
        }
        _ => panic!("Expected ServerState"),
    }
}

#[test]
fn test_server_state_controller_deserialization() {
    let json = r#"{
        "type": "server/state",
        "payload": {
            "controller": {
                "supported_commands": ["play", "next", "previous", "volume", "mute"],
                "volume": 75,
                "muted": false,
                "repeat": "all",
                "shuffle": true
            }
        }
    }"#;

    let message: Message = serde_json::from_str(json).unwrap();

    match message {
        Message::ServerState(state) => {
            let controller = state.controller.expect("Expected controller");
            assert_eq!(controller.volume, 75);
            assert!(!controller.muted);
            assert_eq!(controller.repeat, Some(RepeatMode::All));
            assert_eq!(controller.shuffle, Some(true));
            assert!(controller.supported_commands.contains(&"play".to_string()));
            assert!(controller
                .supported_commands
                .contains(&"volume".to_string()));
        }
        _ => panic!("Expected ServerState"),
    }
}

// =============================================================================
// Command Tests
// =============================================================================

#[test]
fn test_client_command_serialization() {
    let command = ClientCommand {
        controller: Some(ControllerCommand {
            command: ControllerCommandType::Play,
            volume: None,
            mute: None,
            position_ms: None,
            offset_ms: None,
        }),
    };

    let message = Message::ClientCommand(command);
    let json = serde_json::to_string(&message).unwrap();

    assert!(json.contains("\"type\":\"client/command\""));
    assert!(json.contains("\"command\":\"play\""));
}

#[test]
fn test_server_command_deserialization() {
    let json = r#"{
        "type": "server/command",
        "payload": {
            "player": {
                "command": "volume",
                "volume": 80
            }
        }
    }"#;

    let message: Message = serde_json::from_str(json).unwrap();

    match message {
        Message::ServerCommand(cmd) => {
            let player = cmd.player.expect("Expected player command");
            assert_eq!(player.command, PlayerCommandType::Volume);
            assert_eq!(player.volume, Some(80));
            assert!(player.mute.is_none());
            assert!(player.static_delay_ms.is_none());
        }
        _ => panic!("Expected ServerCommand"),
    }
}

#[test]
fn test_server_command_set_static_delay() {
    let json = r#"{
        "type": "server/command",
        "payload": {
            "player": {
                "command": "set_static_delay",
                "static_delay_ms": 250
            }
        }
    }"#;

    let message: Message = serde_json::from_str(json).unwrap();

    match message {
        Message::ServerCommand(cmd) => {
            let player = cmd.player.expect("Expected player command");
            assert_eq!(player.command, PlayerCommandType::SetStaticDelay);
            assert_eq!(player.static_delay_ms, Some(250));
            assert!(player.volume.is_none());
        }
        _ => panic!("Expected ServerCommand"),
    }
}

#[test]
fn test_client_command_volume() {
    let command = ClientCommand {
        controller: Some(ControllerCommand {
            command: ControllerCommandType::Volume,
            volume: Some(50),
            mute: None,
            position_ms: None,
            offset_ms: None,
        }),
    };

    let message = Message::ClientCommand(command);
    let json = serde_json::to_string(&message).unwrap();

    assert!(json.contains("\"volume\":50"));
}

#[test]
fn test_client_command_seek() {
    let command = ClientCommand {
        controller: Some(ControllerCommand {
            command: ControllerCommandType::Seek,
            volume: None,
            mute: None,
            position_ms: Some(90_500),
            offset_ms: None,
        }),
    };

    let message = Message::ClientCommand(command);
    let json = serde_json::to_string(&message).unwrap();

    assert!(json.contains("\"command\":\"seek\""));
    assert!(json.contains("\"position_ms\":90500"));
    assert!(!json.contains("offset_ms"));

    // Round-trip: the serialized form must deserialize back identically.
    let parsed: Message = serde_json::from_str(&json).unwrap();
    match parsed {
        Message::ClientCommand(cmd) => {
            let ctrl = cmd.controller.expect("Expected controller command");
            assert_eq!(ctrl.command, ControllerCommandType::Seek);
            assert_eq!(ctrl.position_ms, Some(90_500));
            assert!(ctrl.offset_ms.is_none());
        }
        _ => panic!("Expected ClientCommand"),
    }
}

#[test]
fn test_client_command_seek_relative() {
    let command = ClientCommand {
        controller: Some(ControllerCommand {
            command: ControllerCommandType::SeekRelative,
            volume: None,
            mute: None,
            position_ms: None,
            offset_ms: Some(-10_000),
        }),
    };

    let message = Message::ClientCommand(command);
    let json = serde_json::to_string(&message).unwrap();

    assert!(json.contains("\"command\":\"seek_relative\""));
    assert!(json.contains("\"offset_ms\":-10000"));
    assert!(!json.contains("position_ms"));

    // Round-trip: the serialized form must deserialize back identically,
    // preserving the negative offset.
    let parsed: Message = serde_json::from_str(&json).unwrap();
    match parsed {
        Message::ClientCommand(cmd) => {
            let ctrl = cmd.controller.expect("Expected controller command");
            assert_eq!(ctrl.command, ControllerCommandType::SeekRelative);
            assert_eq!(ctrl.offset_ms, Some(-10_000));
            assert!(ctrl.position_ms.is_none());
        }
        _ => panic!("Expected ClientCommand"),
    }
}

#[test]
fn test_server_state_controller_seek_max_ms() {
    let json = r#"{
        "type": "server/state",
        "payload": {
            "controller": {
                "supported_commands": ["play", "seek", "seek_relative"],
                "volume": 75,
                "muted": false,
                "seek_max_ms": 245000
            }
        }
    }"#;

    let message: Message = serde_json::from_str(json).unwrap();

    match message {
        Message::ServerState(state) => {
            let controller = state.controller.expect("Expected controller");
            assert_eq!(controller.seek_max_ms, Some(245_000));
            assert!(controller.supported_commands.contains(&"seek".to_string()));
            assert!(controller
                .supported_commands
                .contains(&"seek_relative".to_string()));
        }
        _ => panic!("Expected ServerState"),
    }
}

#[test]
fn test_server_state_controller_seek_max_ms_absent_is_none() {
    // Servers omit seek_max_ms when the seekable range is unknown; older
    // servers never send it. Both must deserialize to None.
    let json = r#"{
        "type": "server/state",
        "payload": {
            "controller": {
                "supported_commands": ["play", "seek_relative"],
                "volume": 75,
                "muted": false
            }
        }
    }"#;

    let message: Message = serde_json::from_str(json).unwrap();

    match message {
        Message::ServerState(state) => {
            let controller = state.controller.expect("Expected controller");
            assert_eq!(controller.seek_max_ms, None);
        }
        _ => panic!("Expected ServerState"),
    }
}

#[test]
fn test_server_state_color_deserialization() {
    let json = r#"{
        "type": "server/state",
        "payload": {
            "color": {
                "timestamp": 1234567890,
                "background_dark": [18, 24, 32],
                "background_light": [240, 244, 248],
                "primary": [200, 60, 40],
                "accent": [40, 120, 200],
                "on_dark": [235, 235, 235],
                "on_light": [30, 30, 30]
            }
        }
    }"#;

    let message: Message = serde_json::from_str(json).unwrap();

    match message {
        Message::ServerState(state) => {
            let color = state.color.expect("Expected color state");
            assert_eq!(color.timestamp, 1_234_567_890);
            assert_eq!(color.background_dark, Some([18, 24, 32]));
            assert_eq!(color.background_light, Some([240, 244, 248]));
            assert_eq!(color.primary, Some([200, 60, 40]));
            assert_eq!(color.accent, Some([40, 120, 200]));
            assert_eq!(color.on_dark, Some([235, 235, 235]));
            assert_eq!(color.on_light, Some([30, 30, 30]));
        }
        _ => panic!("Expected ServerState"),
    }
}

#[test]
fn test_server_state_color_sparse_fields_are_none() {
    // The server sends only the palette entries it has; all color fields
    // besides timestamp are optional.
    let json = r#"{
        "type": "server/state",
        "payload": {
            "color": {
                "timestamp": 1234567890,
                "primary": [200, 60, 40]
            }
        }
    }"#;

    let message: Message = serde_json::from_str(json).unwrap();

    match message {
        Message::ServerState(state) => {
            let color = state.color.expect("Expected color state");
            assert_eq!(color.primary, Some([200, 60, 40]));
            assert_eq!(color.background_dark, None);
            assert_eq!(color.background_light, None);
            assert_eq!(color.accent, None);
            assert_eq!(color.on_dark, None);
            assert_eq!(color.on_light, None);
        }
        _ => panic!("Expected ServerState"),
    }
}

#[test]
fn test_server_state_color_null_clears_role_state() {
    // A whole role object set to null clears all of that role's state; it
    // must at minimum deserialize without error.
    let json = r#"{
        "type": "server/state",
        "payload": {
            "color": null
        }
    }"#;

    let message: Message = serde_json::from_str(json).unwrap();

    match message {
        Message::ServerState(state) => {
            assert!(state.color.is_none());
        }
        _ => panic!("Expected ServerState"),
    }
}

#[test]
fn test_color_state_serialization_skips_absent_fields() {
    let color = ColorState {
        timestamp: 42,
        background_dark: Some([0, 0, 0]),
        background_light: None,
        primary: None,
        accent: None,
        on_dark: None,
        on_light: None,
    };

    let json = serde_json::to_string(&color).unwrap();

    assert!(json.contains("\"timestamp\":42"));
    assert!(json.contains("\"background_dark\":[0,0,0]"));
    assert!(!json.contains("background_light"));
    assert!(!json.contains("primary"));
    assert!(!json.contains("accent"));
    assert!(!json.contains("on_dark"));
    assert!(!json.contains("on_light"));
}

#[test]
fn test_color_component_out_of_range_rejected() {
    // RGB components are 0-255; 256 does not fit in a u8.
    let json = r#"{
        "timestamp": 42,
        "primary": [256, 0, 0]
    }"#;

    assert!(serde_json::from_str::<ColorState>(json).is_err());
}

#[test]
fn test_color_wrong_component_count_rejected() {
    // Colors are exactly [R, G, B].
    let json = r#"{
        "timestamp": 42,
        "primary": [10, 20]
    }"#;

    assert!(serde_json::from_str::<ColorState>(json).is_err());
}

// =============================================================================
// Stream Control Tests
// =============================================================================

#[test]
fn test_stream_start_deserialization() {
    let json = r#"{
        "type": "stream/start",
        "payload": {
            "player": {
                "codec": "pcm",
                "sample_rate": 48000,
                "channels": 2,
                "bit_depth": 24
            }
        }
    }"#;

    let message: Message = serde_json::from_str(json).unwrap();

    match message {
        Message::StreamStart(start) => {
            let player = start.player.expect("Expected player config");
            assert_eq!(player.codec, "pcm");
            assert_eq!(player.sample_rate, 48000);
            assert_eq!(player.channels, 2);
            assert_eq!(player.bit_depth, 24);
            assert!(start.artwork.is_none());
            assert!(start.visualizer.is_none());
        }
        _ => panic!("Expected StreamStart"),
    }
}

#[test]
fn test_visualizer_negotiation_serialization() {
    let hello = ClientHello {
        client_id: Some("visualizer-client".to_string()),
        name: "Visualizer".to_string(),
        version: Some(1),
        supported_roles: vec!["visualizer@v1".to_string()],
        trust_level: TrustLevel::default(),
        supported_pair_methods: None,
        unpaired_access: UnpairedAccess::default(),
        device_info: None,
        player_v1_support: None,
        source_v1_support: None,
        artwork_v1_support: None,
        visualizer_v1_support: Some(VisualizerV1Support {
            types: vec![VisualizerDataType::Loudness, VisualizerDataType::Spectrum],
            buffer_capacity: 4096,
            rate_max: 60,
            spectrum: Some(SpectrumConfig {
                n_disp_bins: 32,
                scale: SpectrumScale::Mel,
                f_min: 40,
                f_max: 16_000,
            }),
        }),
    };
    let json = serde_json::to_string(&Message::ClientHello(hello)).unwrap();
    assert!(json.contains("\"visualizer@v1_support\""));
    assert!(json.contains("\"types\":[\"loudness\",\"spectrum\"]"));
    assert!(json.contains("\"scale\":\"mel\""));

    let start: Message = serde_json::from_str(
        r#"{
            "type": "stream/start",
            "payload": {
                "visualizer": {
                    "types": ["beat", "peak"],
                    "rate_max": 30,
                    "tracks_downbeats": true
                }
            }
        }"#,
    )
    .unwrap();
    match start {
        Message::StreamStart(start) => {
            assert_eq!(
                start.visualizer,
                Some(StreamVisualizerConfig {
                    types: vec![VisualizerDataType::Beat, VisualizerDataType::Peak],
                    rate_max: 30,
                    tracks_downbeats: Some(true),
                    spectrum: None,
                })
            );
        }
        other => panic!("expected stream/start, got {other:?}"),
    }

    let request = StreamRequestFormat {
        player: None,
        artwork: None,
        visualizer: Some(VisualizerFormatRequest {
            types: Some(vec![VisualizerDataType::FPeak]),
            rate_max: Some(24),
            buffer_capacity: None,
            spectrum: None,
        }),
    };
    let json = serde_json::to_string(&Message::StreamRequestFormat(request)).unwrap();
    assert!(json.contains("\"visualizer\""));
    assert!(json.contains("\"f_peak\""));

    let partial = VisualizerFormatRequest {
        types: Some(vec![VisualizerDataType::Spectrum]),
        rate_max: None,
        buffer_capacity: None,
        spectrum: None,
    };
    assert!(partial.validate().is_ok());
    let empty = VisualizerFormatRequest {
        types: None,
        rate_max: None,
        buffer_capacity: None,
        spectrum: None,
    };
    assert!(empty.validate().is_err());
}

#[test]
fn test_stream_end_deserialization() {
    let json = r#"{
        "type": "stream/end",
        "payload": {
            "roles": ["player@v1"]
        }
    }"#;

    let message: Message = serde_json::from_str(json).unwrap();

    match message {
        Message::StreamEnd(end) => {
            assert_eq!(end.roles, Some(vec!["player@v1".to_string()]));
        }
        _ => panic!("Expected StreamEnd"),
    }
}

#[test]
fn test_stream_clear_deserialization() {
    let json = r#"{
        "type": "stream/clear",
        "payload": {}
    }"#;

    let message: Message = serde_json::from_str(json).unwrap();

    match message {
        Message::StreamClear(clear) => {
            assert!(clear.roles.is_none());
        }
        _ => panic!("Expected StreamClear"),
    }
}

#[test]
fn test_stream_request_format_serialization() {
    let request = StreamRequestFormat {
        player: Some(PlayerFormatRequest {
            codec: Some("pcm".to_string()),
            channels: Some(2),
            sample_rate: Some(48000),
            bit_depth: Some(16),
        }),
        artwork: Some(ArtworkFormatRequest {
            channel: 0,
            source: Some(ArtworkSource::Album),
            format: Some(ImageFormat::Jpeg),
            media_width: Some(600),
            media_height: Some(600),
        }),
        visualizer: None,
    };

    let message = Message::StreamRequestFormat(request);
    let json = serde_json::to_string(&message).unwrap();

    assert!(json.contains("\"type\":\"stream/request-format\""));
    assert!(json.contains("\"codec\":\"pcm\""));
    assert!(json.contains("\"channels\":2"));
    assert!(json.contains("\"sample_rate\":48000"));
    assert!(json.contains("\"bit_depth\":16"));
    assert!(json.contains("\"source\":\"album\""));
    assert!(json.contains("\"format\":\"jpeg\""));
}

#[test]
fn test_stream_request_format_omits_unspecified_fields() {
    let request = StreamRequestFormat {
        player: Some(PlayerFormatRequest {
            codec: Some("pcm".to_string()),
            channels: None,
            sample_rate: None,
            bit_depth: None,
        }),
        artwork: None,
        visualizer: None,
    };

    let json = serde_json::to_string(&Message::StreamRequestFormat(request)).unwrap();

    assert!(json.contains("\"type\":\"stream/request-format\""));
    assert!(json.contains("\"player\""));
    assert!(json.contains("\"codec\":\"pcm\""));
    assert!(!json.contains("\"artwork\""));
    assert!(!json.contains("\"channels\""));
    assert!(!json.contains("\"sample_rate\""));
    assert!(!json.contains("\"bit_depth\""));
}

// =============================================================================
// Group Tests
// =============================================================================

#[test]
fn test_group_update_deserialization() {
    let json = r#"{
        "type": "group/update",
        "payload": {
            "playback_state": "playing",
            "group_id": "living-room",
            "group_name": "Living Room"
        }
    }"#;

    let message: Message = serde_json::from_str(json).unwrap();

    match message {
        Message::GroupUpdate(update) => {
            assert_eq!(update.playback_state, Some(PlaybackState::Playing));
            assert_eq!(update.group_id, Some("living-room".to_string()));
            assert_eq!(update.group_name, Some("Living Room".to_string()));
        }
        _ => panic!("Expected GroupUpdate"),
    }
}

// Test all playback state variants
#[test]
fn test_playback_state_variants() {
    let states = [
        (r#""playing""#, PlaybackState::Playing),
        (r#""paused""#, PlaybackState::Paused),
        (r#""stopped""#, PlaybackState::Stopped),
    ];

    for (json_val, expected) in states {
        let parsed: PlaybackState = serde_json::from_str(json_val).unwrap();
        assert_eq!(parsed, expected);
    }
}

// =============================================================================
// Goodbye Tests
// =============================================================================

#[test]
fn test_client_goodbye_serialization() {
    let goodbye = ClientGoodbye {
        reason: GoodbyeReason::AnotherServer,
    };

    let message = Message::ClientGoodbye(goodbye);
    let json = serde_json::to_string(&message).unwrap();

    assert!(json.contains("\"type\":\"client/goodbye\""));
    assert!(json.contains("\"reason\":\"another_server\""));
}

#[test]
fn test_goodbye_reason_variants() {
    let reasons = [
        (r#""another_server""#, GoodbyeReason::AnotherServer),
        (r#""shutdown""#, GoodbyeReason::Shutdown),
        (r#""restart""#, GoodbyeReason::Restart),
        (r#""user_request""#, GoodbyeReason::UserRequest),
    ];

    for (json_val, expected) in reasons {
        let parsed: GoodbyeReason = serde_json::from_str(json_val).unwrap();
        assert_eq!(parsed, expected);
    }
}

// =============================================================================
// Repeat Mode Tests
// =============================================================================

#[test]
fn test_repeat_mode_variants() {
    let modes = [
        (r#""off""#, RepeatMode::Off),
        (r#""one""#, RepeatMode::One),
        (r#""all""#, RepeatMode::All),
    ];

    for (json_val, expected) in modes {
        let parsed: RepeatMode = serde_json::from_str(json_val).unwrap();
        assert_eq!(parsed, expected);
    }
}

// =============================================================================
// Artwork Tests
// =============================================================================

#[test]
fn test_artwork_v1_support_serialization() {
    let support = ArtworkV1Support {
        channels: vec![
            ArtworkChannel {
                source: ArtworkSource::Album,
                format: ImageFormat::Jpeg,
                media_width: 800,
                media_height: 800,
            },
            ArtworkChannel {
                source: ArtworkSource::Artist,
                format: ImageFormat::Png,
                media_width: 400,
                media_height: 400,
            },
        ],
    };

    let json = serde_json::to_string(&support).unwrap();

    assert!(json.contains("\"source\":\"album\""));
    assert!(json.contains("\"format\":\"jpeg\""));
    assert!(json.contains("\"media_width\":800"));
    assert!(json.contains("\"source\":\"artist\""));
    assert!(json.contains("\"format\":\"png\""));
}

#[test]
fn test_artwork_source_variants() {
    let sources = [
        (r#""album""#, ArtworkSource::Album),
        (r#""artist""#, ArtworkSource::Artist),
        (r#""none""#, ArtworkSource::None),
    ];

    for (json_val, expected) in sources {
        let parsed: ArtworkSource = serde_json::from_str(json_val).unwrap();
        assert_eq!(parsed, expected);
    }
}

#[test]
fn test_image_format_variants() {
    let formats = [
        (r#""jpeg""#, ImageFormat::Jpeg),
        (r#""png""#, ImageFormat::Png),
        (r#""bmp""#, ImageFormat::Bmp),
    ];

    for (json_val, expected) in formats {
        let parsed: ImageFormat = serde_json::from_str(json_val).unwrap();
        assert_eq!(parsed, expected);
    }
}

// =============================================================================
// Time Sync Tests
// =============================================================================

#[test]
fn test_client_time_serialization() {
    let msg = Message::ClientTime(ClientTime {
        client_transmitted: 1_700_000_000_000_000,
    });
    let json = serde_json::to_string(&msg).unwrap();

    assert!(json.contains("\"type\":\"client/time\""));
    assert!(json.contains("\"client_transmitted\":1700000000000000"));

    // Round-trip
    let parsed: Message = serde_json::from_str(&json).unwrap();
    match parsed {
        Message::ClientTime(ct) => {
            assert_eq!(ct.client_transmitted, 1_700_000_000_000_000);
        }
        _ => panic!("Expected ClientTime"),
    }
}

#[test]
fn test_server_time_deserialization() {
    let json = r#"{
        "type": "server/time",
        "payload": {
            "client_transmitted": 1000000,
            "server_received": 1005100,
            "server_transmitted": 1005110
        }
    }"#;

    let msg: Message = serde_json::from_str(json).unwrap();
    match msg {
        Message::ServerTime(st) => {
            assert_eq!(st.client_transmitted, 1_000_000);
            assert_eq!(st.server_received, 1_005_100);
            assert_eq!(st.server_transmitted, 1_005_110);
        }
        _ => panic!("Expected ServerTime"),
    }
}

#[test]
fn test_server_time_fields_feed_clock_sync() {
    use sendspin::sync::{ClockSync, DefaultClock};
    use std::sync::Arc;

    // Simulate two sync rounds using the same field mapping
    // that message_router uses: st.client_transmitted = t1,
    // st.server_received = t2, st.server_transmitted = t3.
    let mut sync = ClockSync::new(Arc::new(DefaultClock::new()));
    assert!(!sync.is_synchronized());

    let st1 = ServerTime {
        client_transmitted: 1_000_000,
        server_received: 1_005_100,
        server_transmitted: 1_005_100,
    };
    let t4_1: i64 = 1_000_200;
    sync.update(
        st1.client_transmitted,
        st1.server_received,
        st1.server_transmitted,
        t4_1,
    );

    let st2 = ServerTime {
        client_transmitted: 2_000_000,
        server_received: 2_005_100,
        server_transmitted: 2_005_100,
    };
    let t4_2: i64 = 2_000_200;
    sync.update(
        st2.client_transmitted,
        st2.server_received,
        st2.server_transmitted,
        t4_2,
    );

    // After two rounds, the filter should be synchronized
    assert!(sync.is_synchronized());

    // Verify the offset is reasonable: server time ≈ client time + 5000µs
    let client = sync.server_to_client_micros(3_005_100);
    assert!(client.is_some());
    let diff = (client.unwrap() - 3_000_100).abs();
    assert!(diff < 50, "offset drift too large: {}", diff);
}

// =============================================================================
// Stream Artwork Config Tests
// =============================================================================

#[test]
fn test_stream_start_artwork_deserialization() {
    let json = r#"{
        "type": "stream/start",
        "payload": {
            "artwork": {
                "channels": [
                    {
                        "source": "album",
                        "format": "jpeg",
                        "width": 800,
                        "height": 800
                    }
                ]
            }
        }
    }"#;

    let message: Message = serde_json::from_str(json).unwrap();

    match message {
        Message::StreamStart(start) => {
            assert!(start.player.is_none());
            let artwork = start.artwork.expect("Expected artwork config");
            assert_eq!(artwork.channels.len(), 1);
            let ch = &artwork.channels[0];
            assert_eq!(ch.source, ArtworkSource::Album);
            assert_eq!(ch.format, ImageFormat::Jpeg);
            assert_eq!(ch.width, 800);
            assert_eq!(ch.height, 800);
        }
        _ => panic!("Expected StreamStart"),
    }
}

#[test]
fn test_stream_start_artwork_multi_channel() {
    let json = r#"{
        "type": "stream/start",
        "payload": {
            "artwork": {
                "channels": [
                    { "source": "album", "format": "jpeg", "width": 800, "height": 800 },
                    { "source": "artist", "format": "png", "width": 400, "height": 400 }
                ]
            }
        }
    }"#;

    let message: Message = serde_json::from_str(json).unwrap();

    match message {
        Message::StreamStart(start) => {
            let artwork = start.artwork.expect("Expected artwork config");
            assert_eq!(artwork.channels.len(), 2);
            assert_eq!(artwork.channels[0].source, ArtworkSource::Album);
            assert_eq!(artwork.channels[1].source, ArtworkSource::Artist);
            assert_eq!(artwork.channels[1].format, ImageFormat::Png);
        }
        _ => panic!("Expected StreamStart"),
    }
}

#[test]
fn test_stream_artwork_channel_config_roundtrip() {
    let config = StreamArtworkChannelConfig {
        source: ArtworkSource::Album,
        format: ImageFormat::Jpeg,
        width: 256,
        height: 256,
    };

    let json = serde_json::to_string(&config).unwrap();
    assert!(json.contains("\"source\":\"album\""));
    assert!(json.contains("\"format\":\"jpeg\""));
    assert!(json.contains("\"width\":256"));

    let parsed: StreamArtworkChannelConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.source, ArtworkSource::Album);
    assert_eq!(parsed.width, 256);
}

// =============================================================================
// Deserialization Error Path Tests
// =============================================================================

#[test]
fn test_malformed_json_rejected() {
    let result = serde_json::from_str::<Message>("not valid json at all");
    assert!(result.is_err());
}

#[test]
fn test_empty_json_object_rejected() {
    let result = serde_json::from_str::<Message>("{}");
    assert!(result.is_err());
}

#[test]
fn test_unknown_message_type_rejected() {
    let json = r#"{"type": "invalid/type", "payload": {}}"#;
    let result = serde_json::from_str::<Message>(json);
    assert!(result.is_err());
}

#[test]
fn test_missing_payload_rejected() {
    let json = r#"{"type": "client/hello"}"#;
    let result = serde_json::from_str::<Message>(json);
    assert!(result.is_err());
}

#[test]
fn test_client_hello_missing_required_fields() {
    // Missing client_id, name, version, supported_roles
    let json = r#"{"type": "client/hello", "payload": {}}"#;
    let result = serde_json::from_str::<Message>(json);
    assert!(result.is_err());
}

#[test]
fn test_server_hello_missing_required_fields() {
    let json = r#"{"type": "server/hello", "payload": {"server_id": "s1"}}"#;
    let result = serde_json::from_str::<Message>(json);
    assert!(result.is_err());
}

#[test]
fn test_unknown_connection_reason_is_accepted_as_unknown() {
    // See `an_unknown_connection_reason_does_not_fail_the_handshake`: the reason lives
    // inside server/hello, so refusing the value refuses the server.
    let json = r#"{
        "type": "server/hello",
        "payload": {
            "server_id": "s1",
            "name": "Test",
            "version": 1,
            "active_roles": [],
            "connection_reason": "invalid_reason"
        }
    }"#;
    let parsed: Message = serde_json::from_str(json).unwrap();
    let Message::ServerHello(hello) = parsed else {
        panic!("expected server/hello");
    };
    assert_eq!(hello.connection_reason, ConnectionReason::Unknown);
}

#[test]
fn test_unknown_playback_state_is_not_rejected() {
    // `paused` was removed from the spec and is back; a client that treats an
    // unrecognised state as a parse error loses the whole message over a field it
    // could have ignored, so unknown states land on `Unknown` instead.
    let parsed: PlaybackState = serde_json::from_str(r#""buffering""#).unwrap();
    assert_eq!(parsed, PlaybackState::Unknown);
}

#[test]
fn test_invalid_repeat_mode_rejected() {
    let result = serde_json::from_str::<RepeatMode>(r#""shuffle""#);
    assert!(result.is_err());
}

#[test]
fn test_invalid_goodbye_reason_rejected() {
    let result = serde_json::from_str::<GoodbyeReason>(r#""timeout""#);
    assert!(result.is_err());
}

#[test]
fn test_wrong_type_in_payload_field_rejected() {
    // version should be u32, not string
    let json = r#"{
        "type": "client/hello",
        "payload": {
            "client_id": "c1",
            "name": "Test",
            "version": "not_a_number",
            "supported_roles": []
        }
    }"#;
    let result = serde_json::from_str::<Message>(json);
    assert!(result.is_err());
}

#[test]
fn test_null_payload_rejected() {
    let json = r#"{"type": "client/hello", "payload": null}"#;
    let result = serde_json::from_str::<Message>(json);
    assert!(result.is_err());
}

#[test]
fn test_client_state_empty_payload_accepted() {
    // ClientState with player: None should be valid
    let json = r#"{"type": "client/state", "payload": {}}"#;
    let result = serde_json::from_str::<Message>(json);
    assert!(result.is_ok());
    match result.unwrap() {
        Message::ClientState(state) => assert!(state.player.is_none()),
        _ => panic!("Expected ClientState"),
    }
}

#[test]
fn test_server_state_empty_payload_accepted() {
    // ServerState with no metadata or controller should be valid
    let json = r#"{"type": "server/state", "payload": {}}"#;
    let result = serde_json::from_str::<Message>(json);
    assert!(result.is_ok());
    match result.unwrap() {
        Message::ServerState(state) => {
            assert!(state.metadata.is_none());
            assert!(state.controller.is_none());
        }
        _ => panic!("Expected ServerState"),
    }
}

#[test]
fn test_stream_end_empty_roles_accepted() {
    let json = r#"{"type": "stream/end", "payload": {}}"#;
    let result = serde_json::from_str::<Message>(json);
    assert!(result.is_ok());
    match result.unwrap() {
        Message::StreamEnd(end) => assert!(end.roles.is_none()),
        _ => panic!("Expected StreamEnd"),
    }
}

// =============================================================================
// Deprecation & Wire Format Tests
// =============================================================================

/// Old JSON that includes `state` inside the player object (from pre-0.2.0
/// clients/servers) should still deserialize without error. The unknown field
/// is ignored since PlayerState no longer has a `state` field.
#[test]
fn test_player_state_ignores_legacy_state_field() {
    let json = r#"{
        "type": "client/state",
        "payload": {
            "player": {
                "state": "error",
                "volume": 50,
                "muted": true
            }
        }
    }"#;

    let message: Message = serde_json::from_str(json).unwrap();

    match message {
        Message::ClientState(cs) => {
            assert!(cs.state.is_none());

            let player = cs.player.expect("Expected player");
            assert_eq!(player.volume, Some(50));
            assert_eq!(player.muted, Some(true));
            assert!(player.static_delay_ms.is_none());
            assert!(player.supported_commands.is_none());
        }
        _ => panic!("Expected ClientState"),
    }
}

/// supported_commands roundtrip: serialize with commands, deserialize, verify.
#[test]
fn test_player_state_supported_commands_roundtrip() {
    let state = ClientState {
        available: Some(true),
        state: Some(ClientSyncState::Synchronized),
        player: Some(PlayerState {
            volume: Some(100),
            muted: Some(false),
            static_delay_ms: Some(0),
            required_lead_time_ms: Some(500),
            min_buffer_ms: Some(500),
            supported_commands: Some(vec![PlayerStateCommand::SetStaticDelay]),
        }),
        source: None,
    };

    let message = Message::ClientState(state);
    let json = serde_json::to_string(&message).unwrap();

    assert!(json.contains("\"supported_commands\":[\"set_static_delay\"]"));

    // Roundtrip
    let parsed: Message = serde_json::from_str(&json).unwrap();
    match parsed {
        Message::ClientState(cs) => {
            let player = cs.player.expect("Expected player");
            let cmds = player
                .supported_commands
                .expect("Expected supported_commands");
            assert_eq!(cmds, vec![PlayerStateCommand::SetStaticDelay]);
        }
        _ => panic!("Expected ClientState"),
    }
}

/// ArtworkFormatRequest uses typed enums for source and format,
/// verify they serialize to the correct wire strings.
#[test]
fn test_artwork_format_request_typed_enums() {
    let request = ArtworkFormatRequest {
        channel: 0,
        source: Some(ArtworkSource::Album),
        format: Some(ImageFormat::Jpeg),
        media_width: Some(800),
        media_height: Some(800),
    };

    let json = serde_json::to_string(&request).unwrap();

    // Enums should serialize as lowercase strings, not struct representations
    assert!(
        json.contains("\"source\":\"album\""),
        "source not serialized as string: {}",
        json
    );
    assert!(
        json.contains("\"format\":\"jpeg\""),
        "format not serialized as string: {}",
        json
    );

    // Roundtrip
    let parsed: ArtworkFormatRequest = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.source, Some(ArtworkSource::Album));
    assert_eq!(parsed.format, Some(ImageFormat::Jpeg));
    assert_eq!(parsed.channel, 0);
}

/// ArtworkFormatRequest should deserialize from wire JSON with string values
/// (this is what a real server would send).
#[test]
fn test_artwork_format_request_from_wire_json() {
    let json = r#"{
        "channel": 1,
        "source": "artist",
        "format": "png",
        "media_width": 400,
        "media_height": 400
    }"#;

    let parsed: ArtworkFormatRequest = serde_json::from_str(json).unwrap();
    assert_eq!(parsed.channel, 1);
    assert_eq!(parsed.source, Some(ArtworkSource::Artist));
    assert_eq!(parsed.format, Some(ImageFormat::Png));
    assert_eq!(parsed.media_width, Some(400));
    assert_eq!(parsed.media_height, Some(400));
}

#[test]
fn group_update_accepts_every_playback_state() {
    // A `paused` group used to fail to deserialize, and because the state sits inside
    // the message envelope, the failure took the whole group/update with it: a client
    // learned nothing about the group it had just been put in.
    for (wire, expected) in [
        ("playing", PlaybackState::Playing),
        ("paused", PlaybackState::Paused),
        ("stopped", PlaybackState::Stopped),
    ] {
        let raw = format!(
            r#"{{"type":"group/update","payload":{{"playback_state":"{}","group_id":"g1"}}}}"#,
            wire
        );
        let parsed: Message = serde_json::from_str(&raw).expect(wire);
        let Message::GroupUpdate(update) = parsed else {
            panic!("expected group/update");
        };
        assert_eq!(update.playback_state, Some(expected));
    }
}

#[test]
fn every_connection_reason_the_spec_defines_parses() {
    for (wire, expected) in [
        ("discovery", ConnectionReason::Discovery),
        ("pairing", ConnectionReason::Pairing),
        ("playback", ConnectionReason::Playback),
        ("management", ConnectionReason::Management),
    ] {
        let parsed: ConnectionReason = serde_json::from_str(&format!("\"{}\"", wire)).expect(wire);
        assert_eq!(parsed, expected);
    }
}

#[test]
fn an_unknown_playback_state_does_not_lose_the_group_update() {
    let raw = r#"{"type":"group/update","payload":{"playback_state":"buffering","group_id":"g1","group_name":"Kitchen"}}"#;
    let parsed: Message = serde_json::from_str(raw).unwrap();
    let Message::GroupUpdate(update) = parsed else {
        panic!("expected group/update");
    };
    assert_eq!(update.playback_state, Some(PlaybackState::Unknown));
    assert_eq!(update.group_name.as_deref(), Some("Kitchen"));
}

#[test]
fn an_unknown_connection_reason_does_not_fail_the_handshake() {
    // The reason arrives inside server/hello, so rejecting the value rejects the
    // handshake: the client would refuse to talk to a server whose purpose it simply
    // did not recognise.
    let json = r#"{
        "type": "server/hello",
        "payload": {
            "server_id": "s1",
            "name": "Test",
            "version": 1,
            "active_roles": [],
            "connection_reason": "teleconference"
        }
    }"#;
    let parsed: Message = serde_json::from_str(json).unwrap();
    let Message::ServerHello(hello) = parsed else {
        panic!("expected server/hello");
    };
    assert_eq!(hello.connection_reason, ConnectionReason::Unknown);
}

#[test]
fn the_goodbye_reasons_for_trust_and_admission_round_trip() {
    for (reason, wire) in [
        (GoodbyeReason::Unauthorized, "unauthorized"),
        (GoodbyeReason::PairingRequired, "pairing_required"),
        (GoodbyeReason::ConcurrentAttempt, "concurrent_attempt"),
        (GoodbyeReason::Unpaired, "unpaired"),
    ] {
        let json = serde_json::to_string(&reason).unwrap();
        assert_eq!(json, format!("\"{}\"", wire));
        assert_eq!(
            serde_json::from_str::<GoodbyeReason>(&json).unwrap(),
            reason
        );
    }
}

#[test]
fn stream_messages_carry_the_moment_the_server_sent_them() {
    // The start of the window `required_lead_time_ms` is measured over. A client that
    // asks for 500 ms of lead can only tell whether it got it by comparing this against
    // the timestamp of the first chunk.
    let json = r#"{
        "type": "stream/start",
        "payload": {
            "server_transmitted": 1717171717000000,
            "player": {"codec": "pcm", "sample_rate": 48000, "channels": 2, "bit_depth": 16}
        }
    }"#;
    let parsed: Message = serde_json::from_str(json).unwrap();
    let Message::StreamStart(start) = parsed else {
        panic!("expected stream/start");
    };
    assert_eq!(start.server_transmitted, Some(1_717_171_717_000_000));

    for json in [
        r#"{"type":"stream/end","payload":{"server_transmitted":42}}"#,
        r#"{"type":"stream/clear","payload":{"server_transmitted":42}}"#,
    ] {
        let parsed: Message = serde_json::from_str(json).unwrap();
        let stamped = match parsed {
            Message::StreamEnd(end) => end.server_transmitted,
            Message::StreamClear(clear) => clear.server_transmitted,
            other => panic!("unexpected {:?}", other),
        };
        assert_eq!(stamped, Some(42));
    }
}

#[test]
fn a_stream_without_a_transmit_stamp_still_parses() {
    // Servers that predate the field omit it, and a stream is playable without knowing
    // when its trigger was sent.
    let parsed: Message =
        serde_json::from_str(r#"{"type":"stream/end","payload":{"roles":["player"]}}"#).unwrap();
    let Message::StreamEnd(end) = parsed else {
        panic!("expected stream/end");
    };
    assert_eq!(end.server_transmitted, None);
    assert_eq!(end.roles.as_deref(), Some(&["player".to_string()][..]));
}

#[test]
fn a_visualizer_request_may_change_only_its_buffer_ceiling() {
    // Lowering the ceiling is the one visualizer change a client makes for reasons that
    // have nothing to do with what it wants to see -- so it has to count as a change on
    // its own, or the request is rejected before it reaches the wire.
    let request = VisualizerFormatRequest {
        types: None,
        rate_max: None,
        buffer_capacity: Some(32 * 1024),
        spectrum: None,
    };
    assert!(request.validate().is_ok());
    let json = serde_json::to_string(&request).unwrap();
    assert_eq!(json, r#"{"buffer_capacity":32768}"#);
}

#[test]
fn availability_is_sent_in_both_spellings() {
    // `available` is what a current server reads; `state` is what one that predates it
    // reads. Sending only the new field would make a client look permanently free to a
    // server that never learned about it -- so it sends both, from one call.
    let json = serde_json::to_string(&Message::ClientState(ClientState::availability(
        ClientSyncState::ExternalSource,
    )))
    .unwrap();
    assert!(json.contains("\"available\":false"));
    assert!(json.contains("\"state\":\"external_source\""));

    let json = serde_json::to_string(&Message::ClientState(ClientState::availability(
        ClientSyncState::Synchronized,
    )))
    .unwrap();
    assert!(json.contains("\"available\":true"));
    assert!(json.contains("\"state\":\"synchronized\""));
}

#[test]
fn availability_reads_the_new_field_first_and_falls_back_to_the_old_one() {
    let modern: ClientState = serde_json::from_str(r#"{"available":false}"#).unwrap();
    assert_eq!(modern.is_available(), Some(false));

    let legacy: ClientState = serde_json::from_str(r#"{"state":"external_source"}"#).unwrap();
    assert_eq!(legacy.is_available(), Some(false));
    let legacy: ClientState = serde_json::from_str(r#"{"state":"synchronized"}"#).unwrap();
    assert_eq!(legacy.is_available(), Some(true));

    // A partial update that only carries volume says nothing about availability, and
    // reading silence as "unavailable" would stop the music.
    let partial: ClientState = serde_json::from_str(r#"{"player":{"volume":40}}"#).unwrap();
    assert_eq!(partial.is_available(), None);
}

#[test]
fn hello_declares_trust_and_unpaired_access_by_default() {
    // A client with no trust store extends no trust and does admit unpaired servers.
    // Both statements are true of this library, and a server that reads neither field
    // sees the same hello it always did.
    let hello = ClientHello {
        client_id: Some("c1".to_string()),
        name: "Test".to_string(),
        version: Some(1),
        supported_roles: vec!["player@v1".to_string()],
        trust_level: TrustLevel::default(),
        supported_pair_methods: None,
        unpaired_access: UnpairedAccess::default(),
        device_info: None,
        player_v1_support: None,
        source_v1_support: None,
        artwork_v1_support: None,
        visualizer_v1_support: None,
    };
    let json = serde_json::to_string(&Message::ClientHello(hello)).unwrap();
    assert!(json.contains(r#""trust_level":"none""#));
    assert!(json.contains(r#""unpaired_access":{"enabled":true}"#));
    assert!(!json.contains("supported_pair_methods"));
}

#[test]
fn a_pin_offer_carries_only_the_fields_that_method_uses() {
    let descriptor = PairMethodDescriptor {
        method: PairMethod::DynamicPin,
        out_channels: Some(vec!["display".to_string()]),
        locked_out: Some(false),
        min_pin_length: Some(6),
    };
    let json = serde_json::to_string(&descriptor).unwrap();
    assert_eq!(
        json,
        r#"{"method":"dynamic_pin","out_channels":["display"],"locked_out":false,"min_pin_length":6}"#
    );

    let psk = PairMethodDescriptor {
        method: PairMethod::PairingPsk,
        out_channels: None,
        locked_out: None,
        min_pin_length: None,
    };
    assert_eq!(
        serde_json::to_string(&psk).unwrap(),
        r#"{"method":"pairing_psk"}"#
    );
}

#[test]
fn a_hello_without_the_pairing_fields_still_parses() {
    // Every server sending the older hello, and every recorded fixture, omits them.
    let hello: ClientHello = serde_json::from_str(
        r#"{"client_id":"c1","name":"Test","version":1,"supported_roles":[]}"#,
    )
    .unwrap();
    assert_eq!(hello.trust_level, TrustLevel::None);
    assert!(hello.unpaired_access.enabled);
    assert!(hello.supported_pair_methods.is_none());
}

#[test]
fn a_pairing_server_hello_carries_the_method_it_picked() {
    let json = r#"{
        "type": "server/hello",
        "payload": {
            "server_id": "s1",
            "name": "Test",
            "version": 1,
            "active_roles": ["player@v1"],
            "connection_reason": "playback",
            "selected_pair_method": "static_pin"
        }
    }"#;
    let parsed: Message = serde_json::from_str(json).unwrap();
    let Message::ServerHello(hello) = parsed else {
        panic!("expected server/hello");
    };
    assert_eq!(hello.selected_pair_method, Some(PairMethod::StaticPin));

    // And is absent on every other kind of connection.
    let json = r#"{
        "type": "server/hello",
        "payload": {
            "server_id": "s1",
            "name": "Test",
            "version": 1,
            "active_roles": [],
            "connection_reason": "discovery"
        }
    }"#;
    let parsed: Message = serde_json::from_str(json).unwrap();
    let Message::ServerHello(hello) = parsed else {
        panic!("expected server/hello");
    };
    assert_eq!(hello.selected_pair_method, None);
}
