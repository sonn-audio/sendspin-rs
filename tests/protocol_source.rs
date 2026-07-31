// ABOUTME: Wire-format tests for the source@v1 role
// ABOUTME: Covers hello support, state, server commands, input_stream lifecycle and binary framing

use sendspin::protocol::client::pack_source_audio;
use sendspin::protocol::messages::{
    ClientCommand, ClientHello, ClientState, InputStreamEnd, InputStreamFormatRequest,
    InputStreamSource, InputStreamStart, Message, ServerCommand, SourceClientCommand,
    SourceClientCommandType, SourceCommandType, SourceControl, SourceFeatures, SourceFormat,
    SourceSignal, SourceState, SourceStateType, SourceV1Support,
};

fn support() -> SourceV1Support {
    SourceV1Support {
        supported_formats: vec![SourceFormat {
            codec: "pcm".to_string(),
            channels: 2,
            sample_rate: 48_000,
            bit_depth: 16,
        }],
        controls: Some(vec![SourceControl::Play, SourceControl::Activate]),
        features: Some(SourceFeatures {
            level: Some(true),
            line_sense: Some(true),
        }),
    }
}

#[test]
fn hello_carries_the_versioned_support_key() {
    let hello = ClientHello {
        client_id: "kitchen-linein".to_string(),
        name: "Kitchen Line-In".to_string(),
        version: 1,
        supported_roles: vec!["source@v1".to_string()],
        device_info: None,
        player_v1_support: None,
        source_v1_support: Some(support()),
        artwork_v1_support: None,
        visualizer_v1_support: None,
    };

    let json = serde_json::to_string(&Message::ClientHello(hello)).unwrap();
    // The versioned key is what the server looks for; a plain `source_support`
    // silently deactivates the role.
    assert!(json.contains("\"source@v1_support\""));
    assert!(json.contains("\"supported_formats\""));
    assert!(json.contains("\"line_sense\":true"));
}

#[test]
fn source_state_omits_what_it_does_not_know() {
    let json = serde_json::to_string(&Message::ClientState(ClientState {
        state: None,
        player: None,
        source: Some(SourceState {
            state: SourceStateType::Streaming,
            level: Some(0.42),
            signal: Some(SourceSignal::Present),
        }),
    }))
    .unwrap();
    assert!(json.contains("\"source\":{\"state\":\"streaming\""));
    assert!(json.contains("\"signal\":\"present\""));
    // No player object on a source-only client, and no top-level state either.
    assert!(!json.contains("\"player\""));
}

#[test]
fn unknown_signal_is_a_value_not_a_fallback() {
    let json = serde_json::to_string(&SourceSignal::Unknown).unwrap();
    assert_eq!(json, "\"unknown\"");
}

#[test]
fn server_command_carries_start_and_vad_settings() {
    let raw = r#"{"type":"server/command","payload":{"source":{"command":"start","vad":{"threshold_db":-45.0,"hold_ms":2000}}}}"#;
    let parsed: Message = serde_json::from_str(raw).unwrap();
    let Message::ServerCommand(ServerCommand { source, .. }) = parsed else {
        panic!("expected server/command");
    };
    let source = source.expect("source command");
    assert_eq!(source.command, Some(SourceCommandType::Start));
    let vad = source.vad.expect("vad settings");
    assert_eq!(vad.threshold_db, Some(-45.0));
    assert_eq!(vad.hold_ms, Some(2000));
}

#[test]
fn server_command_control_reaches_the_attached_device() {
    let raw = r#"{"type":"server/command","payload":{"source":{"control":"next"}}}"#;
    let parsed: Message = serde_json::from_str(raw).unwrap();
    let Message::ServerCommand(ServerCommand { source, .. }) = parsed else {
        panic!("expected server/command");
    };
    let source = source.expect("source command");
    assert_eq!(source.control, Some(SourceControl::Next));
    assert_eq!(source.command, None);
}

#[test]
fn an_unknown_control_parses_instead_of_failing() {
    // Forward compatibility: a server that learns a new control must not take the
    // connection down with it.
    let raw = r#"{"type":"server/command","payload":{"source":{"control":"teleport"}}}"#;
    let parsed: Message = serde_json::from_str(raw).unwrap();
    let Message::ServerCommand(ServerCommand { source, .. }) = parsed else {
        panic!("expected server/command");
    };
    assert_eq!(source.unwrap().control, Some(SourceControl::Unknown));
}

#[test]
fn source_events_ride_in_client_command() {
    let json = serde_json::to_string(&Message::ClientCommand(ClientCommand {
        controller: None,
        source: Some(SourceClientCommand {
            command: SourceClientCommandType::Started,
        }),
    }))
    .unwrap();
    assert_eq!(
        json,
        r#"{"type":"client/command","payload":{"source":{"command":"started"}}}"#
    );
}

#[test]
fn input_stream_lifecycle_round_trips() {
    let start = serde_json::to_string(&Message::InputStreamStart(InputStreamStart {
        source: InputStreamSource {
            codec: "pcm".to_string(),
            channels: 2,
            sample_rate: 48_000,
            bit_depth: 16,
            codec_header: None,
        },
    }))
    .unwrap();
    assert!(start.starts_with(r#"{"type":"input_stream/start""#));
    assert!(!start.contains("codec_header"));

    // An empty payload object, not null: the server parses the envelope either way
    // but a null payload is not what the spec describes.
    let end = serde_json::to_string(&Message::InputStreamEnd(InputStreamEnd {})).unwrap();
    assert_eq!(end, r#"{"type":"input_stream/end","payload":{}}"#);

    let raw = r#"{"type":"input_stream/request-format","payload":{"source":{"codec":"flac","sample_rate":44100}}}"#;
    let parsed: Message = serde_json::from_str(raw).unwrap();
    let Message::InputStreamRequestFormat(request) = parsed else {
        panic!("expected input_stream/request-format");
    };
    assert_eq!(request.source.codec.as_deref(), Some("flac"));
    assert_eq!(request.source.sample_rate, Some(44_100));
    assert_eq!(request.source.bit_depth, None);
}

#[test]
fn a_format_request_may_be_empty() {
    let json = serde_json::to_string(&InputStreamFormatRequest::default()).unwrap();
    assert_eq!(json, "{}");
}

#[test]
fn source_audio_frames_are_type_12_with_a_big_endian_timestamp() {
    let framed = pack_source_audio(0x0102_0304_0506_0708, &[0xAA, 0xBB]);
    assert_eq!(framed[0], 12);
    assert_eq!(
        &framed[1..9],
        &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]
    );
    assert_eq!(&framed[9..], &[0xAA, 0xBB]);
}

#[test]
fn a_capture_timestamp_before_the_epoch_survives_the_round_trip() {
    // i64, not u64: a monotonic-to-server conversion can legitimately land
    // negative while the filter is still settling.
    let framed = pack_source_audio(-1, &[]);
    assert_eq!(&framed[1..9], &[0xFF; 8]);
}
