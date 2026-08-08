// ABOUTME: Wire tests for the source@v1 role, pinned to the shapes the spec defines and
// ABOUTME: aiosendspin implements — deliberately small, because the role is.

use sendspin::protocol::client::pack_source_audio;
use sendspin::protocol::messages::{
    ClientHello, ClientState, ClientStreamEnd, ClientStreamSource, ClientStreamStart, Message,
    ServerCommand, SourceCommand, SourceCommandType, SourceFeatures, SourceSignal, SourceState,
    SourceV1Support, TrustLevel, UnpairedAccess,
};

/// The support object is one optional flag, and that is the whole capability advertisement.
///
/// There is no format pre-negotiation in this role: the source announces its format in
/// `client_stream/start`, and the server — which resamples and transcodes centrally — takes
/// what it is given.
#[test]
fn the_support_object_advertises_only_line_sense() {
    let support = SourceV1Support {
        features: Some(SourceFeatures {
            line_sense: Some(true),
        }),
    };
    assert_eq!(
        serde_json::to_string(&support).unwrap(),
        r#"{"features":{"line_sense":true}}"#
    );
    // No features at all is valid: a source that senses nothing says nothing.
    assert_eq!(
        serde_json::to_string(&SourceV1Support::default()).unwrap(),
        "{}"
    );
}

#[test]
fn the_support_object_rides_under_its_versioned_key() {
    let hello = ClientHello {
        client_id: Some("c1".to_string()),
        name: "Line In".to_string(),
        version: Some(1),
        supported_roles: vec!["source@v1".to_string()],
        trust_level: TrustLevel::None,
        supported_pair_methods: None,
        unpaired_access: UnpairedAccess::default(),
        device_info: None,
        player_v1_support: None,
        source_v1_support: Some(SourceV1Support::default()),
        artwork_v1_support: None,
        visualizer_v1_support: None,
    };
    let json = serde_json::to_string(&Message::ClientHello(hello)).unwrap();
    assert!(json.contains(r#""source@v1_support":{}"#), "{json}");
}

/// `client/state.source` carries signal presence and nothing else. Whether the source is
/// streaming is not reported: the server asked for it, and the stream messages mark the
/// transitions.
#[test]
fn source_state_carries_only_signal() {
    let state = ClientState {
        available: Some(true),
        state: None,
        player: None,
        source: Some(SourceState {
            signal: Some(SourceSignal::Present),
        }),
    };
    let json = serde_json::to_string(&Message::ClientState(state)).unwrap();
    assert!(json.contains(r#""source":{"signal":"present"}"#), "{json}");
    assert_eq!(
        serde_json::to_string(&SourceState::default()).unwrap(),
        "{}"
    );
}

#[test]
fn signal_values_use_the_spec_spellings() {
    for (value, wire) in [
        (SourceSignal::Present, "\"present\""),
        (SourceSignal::Absent, "\"absent\""),
    ] {
        assert_eq!(serde_json::to_string(&value).unwrap(), wire);
        assert_eq!(serde_json::from_str::<SourceSignal>(wire).unwrap(), value);
    }
    // A value this build does not know must not fail the client/state it arrives in.
    assert_eq!(
        serde_json::from_str::<SourceSignal>("\"clipping\"").unwrap(),
        SourceSignal::Unknown
    );
}

/// `server/command.source` is one field with two values. The role is server-driven.
#[test]
fn server_command_carries_start_or_stop() {
    for (wire, expected) in [
        ("start", SourceCommandType::Start),
        ("stop", SourceCommandType::Stop),
    ] {
        let raw =
            format!(r#"{{"type":"server/command","payload":{{"source":{{"command":"{wire}"}}}}}}"#);
        let parsed: Message = serde_json::from_str(&raw).unwrap();
        let Message::ServerCommand(command) = parsed else {
            panic!("expected server/command");
        };
        assert_eq!(command.source.unwrap().command, expected);
    }
}

#[test]
fn an_unknown_source_command_does_not_lose_the_message() {
    let raw = r#"{"type":"server/command","payload":{"source":{"command":"pause"}}}"#;
    let parsed: Message = serde_json::from_str(raw).unwrap();
    let Message::ServerCommand(command) = parsed else {
        panic!("expected server/command");
    };
    assert_eq!(command.source.unwrap().command, SourceCommandType::Unknown);
}

#[test]
fn a_server_command_round_trips() {
    let command = ServerCommand {
        player: None,
        source: Some(SourceCommand {
            command: SourceCommandType::Start,
        }),
    };
    assert_eq!(
        serde_json::to_string(&Message::ServerCommand(command)).unwrap(),
        r#"{"type":"server/command","payload":{"source":{"command":"start"}}}"#
    );
}

/// The format announcement, which is where a source's format is settled for good.
#[test]
fn client_stream_start_announces_the_format() {
    let start = ClientStreamStart {
        source: ClientStreamSource {
            codec: "pcm".to_string(),
            channels: 2,
            sample_rate: 48_000,
            bit_depth: 16,
            codec_header: None,
        },
    };
    assert_eq!(
        serde_json::to_string(&Message::ClientStreamStart(start)).unwrap(),
        r#"{"type":"client_stream/start","payload":{"source":{"codec":"pcm","channels":2,"sample_rate":48000,"bit_depth":16}}}"#
    );
}

#[test]
fn a_flac_stream_carries_its_codec_header() {
    // FLAC needs the fLaC marker and STREAMINFO out of band, standard Base64 with padding.
    let start = ClientStreamStart {
        source: ClientStreamSource {
            codec: "flac".to_string(),
            channels: 2,
            sample_rate: 44_100,
            bit_depth: 16,
            codec_header: Some("ZkxhQwAAACI=".to_string()),
        },
    };
    let json = serde_json::to_string(&start).unwrap();
    assert!(json.contains(r#""codec_header":"ZkxhQwAAACI=""#), "{json}");
}

#[test]
fn client_stream_end_is_an_empty_payload_object() {
    // An empty object, not null: the envelope parses either way, but `{}` is what the spec
    // and the reference both put on the wire.
    assert_eq!(
        serde_json::to_string(&Message::ClientStreamEnd(ClientStreamEnd {})).unwrap(),
        r#"{"type":"client_stream/end","payload":{}}"#
    );
}

#[test]
fn the_stream_messages_use_the_names_the_spec_defines() {
    // Regression: these were `input_stream/*`, which appears nowhere in the spec or in
    // aiosendspin, so a source built on them could not reach any server.
    let json = serde_json::to_string(&Message::ClientStreamStart(ClientStreamStart {
        source: ClientStreamSource {
            codec: "opus".to_string(),
            channels: 2,
            sample_rate: 48_000,
            bit_depth: 16,
            codec_header: None,
        },
    }))
    .unwrap();
    assert!(json.contains(r#""type":"client_stream/start""#), "{json}");
    assert!(!json.contains("input_stream"), "{json}");
}

#[test]
fn a_source_audio_chunk_is_type_12_with_a_big_endian_timestamp() {
    let frame = pack_source_audio(0x0102_0304_0506_0708, &[0xAA, 0xBB]);
    assert_eq!(frame[0], 12, "source audio is binary type 12");
    assert_eq!(&frame[1..9], &[1, 2, 3, 4, 5, 6, 7, 8]);
    assert_eq!(&frame[9..], &[0xAA, 0xBB]);
}

/// A role object in `client/state` is only meaningful for a role the server activated.
///
/// `source@v1` is pairing-gated, so an unpaired connection never has it in `active_roles` —
/// and the reference server flags a `source` object arriving there as a non-compliant
/// client. Found by pointing the interop harness at that server.
#[test]
fn client_state_drops_role_objects_the_server_did_not_activate() {
    let mut state = ClientState {
        available: Some(true),
        state: None,
        player: Some(sendspin::protocol::messages::PlayerState::default()),
        source: Some(SourceState {
            signal: Some(SourceSignal::Absent),
        }),
    };
    state.retain_active_roles(&["player@v1".to_string()]);

    assert!(state.player.is_some(), "an activated role keeps its state");
    assert!(
        state.source.is_none(),
        "an inactive role must not report state"
    );
    // Availability is a property of the client, not of a role: a server withholds binary
    // data until it arrives, so dropping it would stall the connection.
    assert_eq!(state.available, Some(true));
}

#[test]
fn client_state_keeps_source_once_the_role_is_active() {
    let mut state = ClientState {
        available: Some(true),
        state: None,
        player: None,
        source: Some(SourceState {
            signal: Some(SourceSignal::Present),
        }),
    };
    state.retain_active_roles(&["source@v1".to_string(), "metadata@v1".to_string()]);
    assert!(state.source.is_some());
}
