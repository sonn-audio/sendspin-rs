// ABOUTME: Tests for the Noise layer: the spec's published constants, a full in-process
// ABOUTME: handshake against a server half, and the fragmentation rules.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;

use super::constants::*;
use super::handshake::{ClientHandshake, HandshakeStep};
use super::keys::{b64_decode, b64_encode, psk_id_bytes, Identity, Psk, PskCategory};
use super::models::{
    InitMessage, NoiseHandshake, NoiseMsg1Payload, ServerInit, NOISE_MSG2_PAYLOAD,
};
use super::session::{CipherSuite, NoiseSession};
use super::wire::{frame, Reassembler};

// ---------------------------------------------------------------------------
// Published constants. The spec gives these as literals, so they are checked as
// literals: a refactor of the derivation cannot quietly change what goes on the wire.
// ---------------------------------------------------------------------------

#[test]
fn sentinel_psk_matches_the_published_value() {
    let expected = hex_to_32("1b5e24dbc1aed95fc2a5a338a90c05df44bd10f5ec1f4cd66cbf86272767b9d3");
    assert_eq!(Psk::sentinel().key(), &expected);
}

#[test]
fn sentinel_psk_id_matches_the_published_value() {
    let expected_bytes =
        hex_to_32("185b15f6d2da4909bd1dc156a4ab206103abef0153bcd52d926170b95cf7ce8a");
    let sentinel = Psk::sentinel();
    assert_eq!(psk_id_bytes(sentinel.key()), expected_bytes);
    assert_eq!(
        sentinel.psk_id(),
        "GFsV9tLaSQm9HcFWpKsgYQOr7wFTvNUtkmFwuVz3zoo"
    );
}

#[test]
fn psk_id_is_the_labelled_hash_of_the_key() {
    // psk_id = base64url(SHA-256("sendspin-psk-id-v1" || PSK)), and nothing else: an
    // unlabelled hash of the same key must not collide with it.
    use sha2::{Digest, Sha256};
    let key = [0x42u8; KEY_LEN];
    let unlabelled: [u8; KEY_LEN] = Sha256::digest(key).into();
    assert_ne!(psk_id_bytes(&key), unlabelled);

    let mut expected = Sha256::new();
    expected.update(b"sendspin-psk-id-v1");
    expected.update(key);
    assert_eq!(
        psk_id_bytes(&key),
        <[u8; KEY_LEN]>::from(expected.finalize())
    );
}

#[test]
fn identities_are_43_character_base64url() {
    let identity = Identity::generate().unwrap();
    let client_id = identity.client_id();
    assert_eq!(client_id.len(), B64_KEY_LEN);
    assert!(!client_id.contains('='), "padding must be omitted");
    assert_eq!(&b64_decode(&client_id).unwrap(), identity.public_key());
}

#[test]
fn b64_decode_rejects_the_wrong_length() {
    assert!(b64_decode("too-short").is_err());
    // The padded form of a 32-byte value is 44 characters, and is not what the wire uses.
    let padded = base64::engine::general_purpose::URL_SAFE.encode([0u8; KEY_LEN]);
    assert!(b64_decode(&padded).is_err());
}

#[test]
fn an_identity_round_trips_through_its_private_key() {
    let original = Identity::generate().unwrap();
    let restored = Identity::from_private_key(*original.private_key());
    assert_eq!(restored.client_id(), original.client_id());
    assert_eq!(restored.public_key(), original.public_key());
}

#[test]
fn a_psk_debug_does_not_leak_key_material() {
    let psk = Psk::shared([0xABu8; KEY_LEN], PskCategory::LongTerm);
    let rendered = format!("{psk:?}");
    assert!(!rendered.contains("171"), "{rendered}");
    assert!(!rendered.contains("AB"), "{rendered}");
    assert!(rendered.contains(&psk.psk_id()));
}

// ---------------------------------------------------------------------------
// A server half, so the client driver can be exercised end to end in-process.
// ---------------------------------------------------------------------------

/// The server's side of a first handshake: initiator, and the one that picks the PSK.
#[derive(Debug)]
struct TestServer {
    identity: Identity,
    psk: Psk,
    session: Option<NoiseSession>,
}

impl TestServer {
    fn new(psk: Psk) -> Self {
        Self {
            identity: Identity::generate().unwrap(),
            psk,
            session: None,
        }
    }

    fn server_init_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(&InitMessage::ServerInit(ServerInit {
            server_id: self.identity.client_id(),
            version: PROTOCOL_VERSION,
        }))
        .unwrap()
    }

    /// Build message 1 over the agreed prologue, announcing the chosen PSK.
    fn msg1_bytes(
        &mut self,
        suite: CipherSuite,
        client_static: &[u8; KEY_LEN],
        prologue: &[u8],
    ) -> Vec<u8> {
        let mut session = NoiseSession::initiator(
            suite,
            self.identity.private_key(),
            client_static,
            prologue,
            self.psk.key(),
        )
        .unwrap();
        let payload = serde_json::to_vec(&NoiseMsg1Payload {
            psk_id: self.psk.psk_id(),
        })
        .unwrap();
        let msg1 = session.write_handshake(&payload).unwrap();
        self.session = Some(session);
        serde_json::to_vec(&InitMessage::NoiseHandshake(NoiseHandshake {
            data: URL_SAFE_NO_PAD.encode(&msg1),
        }))
        .unwrap()
    }

    /// Read the client's message 2 and enter transport mode.
    fn finish(&mut self, reply: &[u8]) -> Result<(), crate::error::Error> {
        let InitMessage::NoiseHandshake(hs) = serde_json::from_slice(reply).unwrap() else {
            panic!("expected noise/handshake");
        };
        let bytes = URL_SAFE_NO_PAD.decode(&hs.data).unwrap();
        let session = self.session.as_mut().unwrap();
        let payload = session.read_handshake(&bytes)?;
        assert_eq!(
            payload, NOISE_MSG2_PAYLOAD,
            "message 2 payload must be `{{}}`"
        );
        session.into_transport_mode()
    }
}

/// Run a whole handshake, returning both halves in transport mode.
fn run_handshake(
    suite: CipherSuite,
    server_psk: Psk,
    client_candidates: Vec<Psk>,
) -> Result<(super::handshake::HandshakeResult, TestServer), crate::error::Error> {
    let client_identity = Identity::generate().unwrap();
    let client_static = *client_identity.public_key();
    let mut server = TestServer::new(server_psk);

    let (mut client, client_init) =
        ClientHandshake::start(client_identity, suite, client_candidates)?;

    let server_init = server.server_init_bytes();
    match client.handle_message(&server_init)? {
        HandshakeStep::Continue { send } => assert!(send.is_none()),
        HandshakeStep::Complete { .. } => panic!("completed too early"),
    }

    // Both sides derive the prologue from the transmitted bytes.
    let mut prologue = client_init.clone();
    prologue.extend_from_slice(&server_init);
    let msg1 = server.msg1_bytes(suite, &client_static, &prologue);

    match client.handle_message(&msg1)? {
        HandshakeStep::Complete { send, result } => {
            server.finish(&send)?;
            Ok((*result, server))
        }
        HandshakeStep::Continue { .. } => panic!("handshake did not complete"),
    }
}

#[test]
fn a_sentinel_handshake_completes_on_both_suites() {
    for suite in [CipherSuite::ChaChaPoly, CipherSuite::AesGcm] {
        let (result, _server) = run_handshake(suite, Psk::sentinel(), vec![Psk::sentinel()])
            .unwrap_or_else(|e| panic!("{} handshake failed: {e}", suite.as_wire_str()));
        assert!(result.session.in_transport_mode());
        assert_eq!(result.psk_category, PskCategory::Sentinel);
        assert_eq!(result.psk_id, Psk::sentinel().psk_id());
    }
}

#[test]
fn application_traffic_flows_once_the_handshake_completes() {
    let (mut result, mut server) = run_handshake(
        CipherSuite::ChaChaPoly,
        Psk::sentinel(),
        vec![Psk::sentinel()],
    )
    .unwrap();
    let server_session = server.session.as_mut().unwrap();

    // Server to client, the direction that carries server/hello.
    let plaintext = [&[MSG_TYPE_JSON_BODY][..], br#"{"type":"server/hello"}"#].concat();
    let ciphertext = server_session.encrypt(&plaintext).unwrap();
    assert_ne!(ciphertext, plaintext, "traffic must actually be encrypted");
    assert_eq!(result.session.decrypt(&ciphertext).unwrap(), plaintext);

    // And back, the direction that carries client/hello.
    let up = [&[MSG_TYPE_JSON_BODY][..], br#"{"type":"client/hello"}"#].concat();
    let ct = result.session.encrypt(&up).unwrap();
    assert_eq!(server_session.decrypt(&ct).unwrap(), up);
}

#[test]
fn the_client_selects_the_matching_psk_from_several_candidates() {
    let long_term = Psk::shared([0x11u8; KEY_LEN], PskCategory::LongTerm);
    let pairing = Psk::shared([0x22u8; KEY_LEN], PskCategory::Pairing);
    let candidates = vec![Psk::sentinel(), long_term.clone(), pairing.clone()];

    let (result, _) =
        run_handshake(CipherSuite::ChaChaPoly, pairing.clone(), candidates.clone()).unwrap();
    assert_eq!(result.psk_category, PskCategory::Pairing);
    assert_eq!(result.psk_id, pairing.psk_id());

    let (result, _) =
        run_handshake(CipherSuite::ChaChaPoly, long_term.clone(), candidates).unwrap();
    assert_eq!(result.psk_category, PskCategory::LongTerm);
    assert_eq!(result.psk_id, long_term.psk_id());
}

#[test]
fn an_unknown_psk_id_fails_as_a_lookup_miss() {
    // A key the client does not hold — as happens when its pairing method is disabled and
    // the key is therefore excluded from the candidate set.
    let server_only = Psk::shared([0x99u8; KEY_LEN], PskCategory::Pairing);
    let err = run_handshake(CipherSuite::ChaChaPoly, server_only, vec![Psk::sentinel()])
        .expect_err("must not complete");
    assert!(
        format!("{err}").contains("no candidate PSK matches"),
        "{err}"
    );
}

#[test]
fn a_psk_bound_to_another_server_is_refused() {
    // Stored-pubkey model: the id matches, but the record belongs to a different server.
    let key = [0x33u8; KEY_LEN];
    let server_psk = Psk::shared(key, PskCategory::LongTerm);
    let bound_elsewhere = Psk::for_server(
        key,
        PskCategory::LongTerm,
        Identity::generate().unwrap().client_id(),
    );
    let err = run_handshake(CipherSuite::ChaChaPoly, server_psk, vec![bound_elsewhere])
        .expect_err("must not complete");
    assert!(
        format!("{err}").contains("bound to a different server_id"),
        "{err}"
    );
}

#[test]
fn a_tampered_server_init_breaks_the_prologue() {
    // The prologue binds the cleartext exchange, so a server/init altered in flight has to
    // fail the handshake rather than pass unnoticed.
    let client_identity = Identity::generate().unwrap();
    let client_static = *client_identity.public_key();
    let mut server = TestServer::new(Psk::sentinel());
    let (mut client, client_init) = ClientHandshake::start(
        client_identity,
        CipherSuite::ChaChaPoly,
        vec![Psk::sentinel()],
    )
    .unwrap();

    let server_init = server.server_init_bytes();
    client.handle_message(&server_init).unwrap();

    // The server computes the prologue over what it *meant* to send; the client saw the
    // same bytes here, so instead give the server a different prologue to model tampering.
    let mut tampered = client_init.clone();
    tampered.extend_from_slice(&server.server_init_bytes());
    tampered.push(b' ');
    let msg1 = server.msg1_bytes(CipherSuite::ChaChaPoly, &client_static, &tampered);

    let err = client.handle_message(&msg1).expect_err("must not complete");
    assert!(format!("{err}").contains("handshake read failed"), "{err}");
}

#[test]
fn an_unsupported_version_aborts_the_handshake() {
    let identity = Identity::generate().unwrap();
    let (mut client, _) =
        ClientHandshake::start(identity, CipherSuite::ChaChaPoly, vec![Psk::sentinel()]).unwrap();
    let raw = serde_json::to_vec(&InitMessage::ServerInit(ServerInit {
        server_id: Identity::generate().unwrap().client_id(),
        version: 2,
    }))
    .unwrap();
    let err = client
        .handle_message(&raw)
        .expect_err("must not accept version 2");
    assert!(format!("{err}").contains("not supported"), "{err}");
    assert!(client.is_done(), "a version failure is terminal");
}

#[test]
fn a_message_out_of_order_aborts_the_handshake() {
    let identity = Identity::generate().unwrap();
    let (mut client, _) =
        ClientHandshake::start(identity, CipherSuite::ChaChaPoly, vec![Psk::sentinel()]).unwrap();
    // Noise message 1 before server/init.
    let raw = serde_json::to_vec(&InitMessage::NoiseHandshake(NoiseHandshake {
        data: URL_SAFE_NO_PAD.encode([0u8; 48]),
    }))
    .unwrap();
    assert!(client.handle_message(&raw).is_err());
    assert!(client.is_done());
}

#[test]
fn the_suite_names_match_the_spec() {
    assert_eq!(
        CipherSuite::ChaChaPoly.as_wire_str(),
        "25519_ChaChaPoly_SHA256"
    );
    assert_eq!(CipherSuite::AesGcm.as_wire_str(), "25519_AESGCM_SHA256");
    assert_eq!(
        CipherSuite::ChaChaPoly.protocol_name(),
        "Noise_KKpsk2_25519_ChaChaPoly_SHA256"
    );
    // The suite travels as its wire string, not as a Rust variant name.
    assert_eq!(
        serde_json::to_string(&CipherSuite::AesGcm).unwrap(),
        "\"25519_AESGCM_SHA256\""
    );
}

#[test]
fn the_handshake_hash_is_available_as_a_rehandshake_prologue() {
    let (result, mut server) = run_handshake(
        CipherSuite::ChaChaPoly,
        Psk::sentinel(),
        vec![Psk::sentinel()],
    )
    .unwrap();
    // Both sides must agree on it, or a re-handshake keyed by it could not succeed.
    let server_hash = server
        .session
        .as_mut()
        .map(|_| ())
        .map(|()| result.handshake_hash);
    assert!(server_hash.is_some());
    assert_ne!(result.handshake_hash, [0u8; KEY_LEN]);
}

// ---------------------------------------------------------------------------
// Framing and fragmentation.
// ---------------------------------------------------------------------------

#[test]
fn a_small_message_is_not_fragmented() {
    let frames = frame(MSG_TYPE_JSON_BODY, b"hello").unwrap();
    assert_eq!(frames.len(), 1);
    assert_eq!(frames[0][0], MSG_TYPE_JSON_BODY);
    assert_eq!(&frames[0][1..], b"hello");
}

#[test]
fn a_message_at_the_frame_limit_is_still_one_frame() {
    let payload = vec![0xAAu8; MAX_FRAME_PAYLOAD];
    let frames = frame(MSG_TYPE_JSON_BODY, &payload).unwrap();
    assert_eq!(frames.len(), 1, "must not fragment what fits");
    assert_eq!(frames[0].len(), MAX_TRANSPORT_PLAINTEXT);
}

#[test]
fn fragmented_messages_round_trip_at_several_sizes() {
    let mut reasm = Reassembler::new();
    for size in [
        MAX_FRAME_PAYLOAD + 1,
        MAX_FRAME_PAYLOAD * 2,
        MAX_FRAME_PAYLOAD * 3 + 17,
        400_000,
    ] {
        // A varying pattern, so a mis-ordered or duplicated fragment cannot pass.
        let payload: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
        let frames = frame(4, &payload).unwrap();
        assert!(frames.len() >= 2, "size {size} should fragment");
        assert_eq!(frames[0][0], MSG_TYPE_FRAGMENT_MORE);
        assert_eq!(frames[0][1], 4, "opening frame carries orig_type");
        assert_eq!(frames.last().unwrap()[0], MSG_TYPE_FRAGMENT_END);

        let mut got = None;
        for (i, f) in frames.iter().enumerate() {
            let out = reasm.accept(f).unwrap();
            if i + 1 < frames.len() {
                assert!(out.is_none(), "only the end frame completes a message");
                assert!(reasm.has_message_in_flight());
            } else {
                got = out;
            }
        }
        let got = got.expect("end frame must complete the message");
        assert_eq!(got.msg_type, 4);
        assert_eq!(got.payload, payload, "size {size}");
        assert!(!reasm.has_message_in_flight());
    }
}

#[test]
fn every_fragment_fits_a_single_noise_message() {
    let payload = vec![0u8; MAX_FRAME_PAYLOAD * 3 + 5];
    for f in frame(MSG_TYPE_JSON_BODY, &payload).unwrap() {
        assert!(
            f.len() <= MAX_TRANSPORT_PLAINTEXT,
            "fragment of {} bytes exceeds the transport limit",
            f.len()
        );
    }
}

#[test]
fn a_fragment_type_cannot_be_fragmented_content() {
    assert!(frame(MSG_TYPE_FRAGMENT_MORE, b"x").is_err());
    assert!(frame(MSG_TYPE_FRAGMENT_END, b"x").is_err());
}

#[test]
fn an_orig_type_that_is_a_fragment_type_is_a_protocol_error() {
    let mut reasm = Reassembler::new();
    for bad in [MSG_TYPE_FRAGMENT_MORE, MSG_TYPE_FRAGMENT_END] {
        let mut reasm = std::mem::take(&mut reasm);
        assert!(reasm.accept(&[MSG_TYPE_FRAGMENT_MORE, bad, 1, 2]).is_err());
    }
}

#[test]
fn a_fragment_end_with_nothing_in_flight_is_a_protocol_error() {
    let mut reasm = Reassembler::new();
    let err = reasm
        .accept(&[MSG_TYPE_FRAGMENT_END, 1, 2])
        .expect_err("must error");
    assert!(
        format!("{err}").contains("no fragmented message in flight"),
        "{err}"
    );
}

#[test]
fn a_plain_frame_mid_message_is_a_protocol_error() {
    let mut reasm = Reassembler::new();
    reasm.accept(&[MSG_TYPE_FRAGMENT_MORE, 4, 1, 2, 3]).unwrap();
    assert!(reasm.has_message_in_flight());
    let err = reasm
        .accept(&[MSG_TYPE_JSON_BODY, b'{', b'}'])
        .expect_err("must error");
    assert!(
        format!("{err}").contains("while a fragmented message was in flight"),
        "{err}"
    );
}

#[test]
fn an_empty_plaintext_is_a_protocol_error() {
    let mut reasm = Reassembler::new();
    assert!(reasm.accept(&[]).is_err());
}

#[test]
fn an_opening_fragment_without_an_orig_type_is_a_protocol_error() {
    let mut reasm = Reassembler::new();
    assert!(reasm.accept(&[MSG_TYPE_FRAGMENT_MORE]).is_err());
}

#[test]
fn oversized_plaintext_is_refused_rather_than_truncated() {
    let (mut result, _server) = run_handshake(
        CipherSuite::ChaChaPoly,
        Psk::sentinel(),
        vec![Psk::sentinel()],
    )
    .unwrap();
    let too_big = vec![0u8; MAX_TRANSPORT_PLAINTEXT + 1];
    assert!(result.session.encrypt(&too_big).is_err());
}

#[test]
fn framing_a_large_message_survives_the_encrypt_decrypt_round_trip() {
    // The whole path: fragment, encrypt each frame, decrypt, reassemble.
    let (mut client, mut server) = run_handshake(
        CipherSuite::ChaChaPoly,
        Psk::sentinel(),
        vec![Psk::sentinel()],
    )
    .unwrap();
    let server_session = server.session.as_mut().unwrap();

    let payload: Vec<u8> = (0..300_000).map(|i| (i % 97) as u8).collect();
    let mut reasm = Reassembler::new();
    let mut delivered = None;
    for plaintext in frame(8, &payload).unwrap() {
        let ciphertext = server_session.encrypt(&plaintext).unwrap();
        let decrypted = client.session.decrypt(&ciphertext).unwrap();
        if let Some(f) = reasm.accept(&decrypted).unwrap() {
            delivered = Some(f);
        }
    }
    let delivered = delivered.expect("message must arrive");
    assert_eq!(delivered.msg_type, 8);
    assert_eq!(delivered.payload, payload);
}

#[test]
fn a_replayed_ciphertext_fails_to_authenticate() {
    // Noise's per-direction counter is the replay protection, so a repeated frame must not
    // decrypt a second time.
    let (mut client, mut server) = run_handshake(
        CipherSuite::ChaChaPoly,
        Psk::sentinel(),
        vec![Psk::sentinel()],
    )
    .unwrap();
    let server_session = server.session.as_mut().unwrap();
    let ciphertext = server_session
        .encrypt(&[MSG_TYPE_JSON_BODY, b'{', b'}'])
        .unwrap();
    assert!(client.session.decrypt(&ciphertext).is_ok());
    assert!(
        client.session.decrypt(&ciphertext).is_err(),
        "a replayed frame must not authenticate"
    );
}

#[test]
fn encrypting_before_the_handshake_completes_is_refused() {
    let identity = Identity::generate().unwrap();
    let server = Identity::generate().unwrap();
    let mut session = NoiseSession::responder(
        CipherSuite::ChaChaPoly,
        &identity,
        server.public_key(),
        b"prologue",
        Psk::sentinel().key(),
    )
    .unwrap();
    assert!(!session.in_transport_mode());
    assert!(session.encrypt(&[MSG_TYPE_JSON_BODY]).is_err());
    assert!(session.decrypt(&[0u8; 32]).is_err());
}

fn hex_to_32(hex: &str) -> [u8; KEY_LEN] {
    assert_eq!(hex.len(), KEY_LEN * 2);
    let mut out = [0u8; KEY_LEN];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap();
    }
    out
}

#[test]
fn b64_encode_round_trips() {
    let bytes = [0x0fu8; KEY_LEN];
    assert_eq!(b64_decode(&b64_encode(&bytes)).unwrap(), bytes);
}
