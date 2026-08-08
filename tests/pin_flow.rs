// ABOUTME: The two PIN pairing flows driven end to end against a minimal server side, plus
// ABOUTME: the failure paths that decide whether a wrong PIN is a retry or a hang-up.

//! The state machine is client-side, so exercising it needs a server. The one here is
//! deliberately thin — it does the CPace half and nothing else — because the point is to
//! check the client's sequencing and its decisions, not to write a second implementation.
//!
//! What the flows have to get right, and what each test pins:
//!
//! - The client verifies `server_kc` **before** revealing `client_kc`, so a server that
//!   does not know the PIN never gets a tag to attack offline.
//! - A wrong PIN is `pair/abort(pin_mismatch)` and the connection lives; a malformed field
//!   is a protocol error and it does not.
//! - Both sides end up with the same PSK, or the pairing was pointless.

use sendspin::noise::cpace::{CPace, Role};
use sendspin::noise::keys::{b64_decode_bytes, b64_encode_bytes, b64_encode_slice};
use sendspin::noise::pairing::PairAbortReason;
use sendspin::noise::pin::{self, AD_CLIENT, AD_SERVER};
use sendspin::noise::pin_flow::{
    open_wrapped_psk, PinLength, PinPairing, PinStep, ServerPairAuth, ServerPairConfirm,
    ServerPairInit,
};
use sendspin::noise::{CipherSuite, InMemoryPairingStore, PairingStore};
use sendspin::protocol::messages::{Message, PairMethod};

const HASH: [u8; 32] = [0x5A; 32];
const INDEX: u32 = 3;

fn store() -> InMemoryPairingStore {
    InMemoryPairingStore::new().unwrap()
}

/// The server half of one attempt: enough CPace to answer, and nothing more.
struct Server {
    sid: Vec<u8>,
    run: Option<CPace>,
    output: Option<sendspin::noise::cpace::CPaceOutput>,
}

impl Server {
    fn new(pin_value: &str, index: u32) -> Self {
        let sid = pin::session_id(&HASH, index);
        let run =
            CPace::start(Role::Initiator, pin_value.as_bytes(), &sid, b"", AD_SERVER).unwrap();
        Self {
            sid,
            run: Some(run),
            output: None,
        }
    }

    fn pair_auth(&self) -> ServerPairAuth {
        ServerPairAuth {
            pake_msg_1: b64_encode_bytes(self.run.as_ref().unwrap().public_share()),
        }
    }

    /// Ingest `Yb` and produce the server's confirmation tag.
    fn pair_confirm(&mut self, client_auth: &str) -> ServerPairConfirm {
        let yb = b64_decode_bytes::<32>(client_auth).unwrap();
        let output = self.run.take().unwrap().derive(&yb, AD_CLIENT).unwrap();
        let tag = b64_encode_bytes(&output.own_tag);
        self.output = Some(output);
        ServerPairConfirm { server_kc: tag }
    }
}

/// Drive a static-PIN attempt to its end, returning the client's last step and the server.
fn run_static(client_pin: &str, server_pin: &str) -> (PinStep, Server, InMemoryPairingStore) {
    let store = store();
    let (mut attempt, init) = PinPairing::start(
        PairMethod::StaticPin,
        CipherSuite::ChaChaPoly,
        HASH,
        INDEX,
        PinLength {
            negotiated: Some(8),
            minimum: 8,
        },
        "server-1",
        Some(client_pin),
    )
    .unwrap();
    assert_eq!(init.pairing_index, INDEX);
    assert!(init.commit_b.is_none(), "static PIN carries no commitment");

    let mut server = Server::new(server_pin, INDEX);
    let step = attempt.on_server_pair_auth(&server.pair_auth());
    let PinStep::Send(message) = step else {
        panic!("expected client/pair-auth, got {step:?}");
    };
    let Message::ClientPairAuth(auth) = *message else {
        panic!("expected client/pair-auth")
    };

    let confirm = server.pair_confirm(&auth.pake_msg_2);
    let step = attempt.on_server_pair_confirm(&confirm, &store);
    (step, server, store)
}

// =============================================================================
// Static PIN
// =============================================================================

/// The whole static flow, and the property that makes it worth running: both sides end up
/// holding the same 32 bytes.
#[test]
fn a_matching_static_pin_pairs_both_sides_onto_one_psk() {
    let (step, server, _store) = run_static("12345678", "12345678");
    let PinStep::Finalize {
        confirm,
        finalize,
        record,
    } = step
    else {
        panic!("expected to finalize, got {step:?}");
    };

    // The server accepts the client's tag, which is the mirror of the check the client just
    // made — neither side reveals to a peer that failed.
    let client_kc = b64_decode_bytes::<64>(&confirm.client_kc).unwrap();
    let output = server.output.as_ref().unwrap();
    assert!(output.verify(&client_kc), "server accepts client_kc");
    assert!(confirm.nonce_b.is_none(), "static PIN reveals no nonce");

    // And the PSK the server unwraps is the one the client filed.
    let wrapped = finalize.wrapped_psk.expect("PIN flows wrap the PSK");
    assert!(finalize.long_term_psk.is_none(), "and never send it bare");
    let unwrapped =
        open_wrapped_psk(CipherSuite::ChaChaPoly, &server.sid, &output.isk, &wrapped).unwrap();
    assert_eq!(record.as_psk().key(), &unwrapped);
    assert_eq!(record.server_id(), Some("server-1"));
}

/// A wrong PIN aborts with `pin_mismatch` and leaves the connection open.
///
/// The distinction matters operationally: a mistyped PIN should let the operator try again
/// on the same connection, not drop them back to discovery.
#[test]
fn a_wrong_static_pin_aborts_without_revealing_a_tag() {
    let (step, _server, _store) = run_static("12345678", "87654321");
    assert!(
        matches!(step, PinStep::Abort(PairAbortReason::PinMismatch)),
        "got {step:?}"
    );
    assert!(
        !PairAbortReason::PinMismatch.closes_connection(),
        "a mistyped PIN is not a hang-up"
    );
}

#[test]
fn a_static_attempt_needs_a_configured_pin_of_the_right_shape() {
    for bad in [None, Some("1234"), Some("abcdefgh")] {
        assert!(
            PinPairing::start(
                PairMethod::StaticPin,
                CipherSuite::ChaChaPoly,
                HASH,
                INDEX,
                PinLength {
                    negotiated: Some(8),
                    minimum: 8,
                },
                "server-1",
                bad,
            )
            .is_err(),
            "accepted {bad:?}"
        );
    }
}

// =============================================================================
// Dynamic PIN
// =============================================================================

/// The whole dynamic flow: commitment out first, nonce in, PIN derived, and the commitment
/// opened only at the end.
#[test]
fn the_dynamic_flow_commits_first_and_opens_last() {
    let store = store();
    let (mut attempt, init) = PinPairing::start(
        PairMethod::DynamicPin,
        CipherSuite::ChaChaPoly,
        HASH,
        INDEX,
        PinLength {
            negotiated: Some(6),
            minimum: 6,
        },
        "server-1",
        None,
    )
    .unwrap();
    let commit_b = init.commit_b.expect("dynamic PIN commits up front");

    // The server's nonce arrives, and both sides can now derive the same PIN.
    let nonce_a = [0x11u8; 32];
    let step = attempt.on_server_pair_init(&ServerPairInit {
        nonce_a: b64_encode_bytes(&nonce_a),
        pin_length: None,
    });
    let PinStep::EmitPin(pin_value) = step else {
        panic!("expected a PIN to emit, got {step:?}");
    };
    assert_eq!(pin_value.len(), 6);

    let mut server = Server::new(&pin_value, INDEX);
    let step = attempt.on_server_pair_auth(&server.pair_auth());
    let PinStep::Send(message) = step else {
        panic!("expected client/pair-auth, got {step:?}")
    };
    let Message::ClientPairAuth(auth) = *message else {
        panic!("expected client/pair-auth")
    };

    let confirm = server.pair_confirm(&auth.pake_msg_2);
    let step = attempt.on_server_pair_confirm(&confirm, &store);
    let PinStep::Finalize { confirm, .. } = step else {
        panic!("expected to finalize, got {step:?}");
    };

    // The revealed nonce opens the commitment sent before nonce_A was known — which is what
    // stops the client from having chosen it to steer the PIN.
    let nonce_b_b64 = confirm.nonce_b.expect("dynamic PIN reveals its nonce");
    let nonce_b = b64_decode_bytes::<32>(&nonce_b_b64).unwrap();
    let commitment = b64_decode_bytes::<32>(&commit_b).unwrap();
    assert!(pin::commit_opens(&commitment, &nonce_b));

    // And the PIN really was the one both sides derived from those two nonces.
    assert_eq!(
        pin::derive_pin(&HASH, &nonce_a, &nonce_b, 6).unwrap(),
        pin_value
    );
}

/// Only this side's own failed verification counts toward the escalation counter.
#[test]
fn a_failed_verification_is_what_counts_as_a_failure() {
    let store = store();
    let (mut attempt, _) = PinPairing::start(
        PairMethod::DynamicPin,
        CipherSuite::ChaChaPoly,
        HASH,
        INDEX,
        PinLength {
            negotiated: Some(6),
            minimum: 6,
        },
        "server-1",
        None,
    )
    .unwrap();
    let step = attempt.on_server_pair_init(&ServerPairInit {
        nonce_a: b64_encode_bytes(&[0x11u8; 32]),
        pin_length: None,
    });
    let PinStep::EmitPin(_) = step else {
        panic!("expected a PIN")
    };

    // A server that guessed wrong: its tag will not verify.
    let mut server = Server::new("999999", INDEX);
    let step = attempt.on_server_pair_auth(&server.pair_auth());
    let PinStep::Send(message) = step else {
        panic!("expected client/pair-auth")
    };
    let Message::ClientPairAuth(auth) = *message else {
        panic!("expected client/pair-auth")
    };
    let step = attempt.on_server_pair_confirm(&server.pair_confirm(&auth.pake_msg_2), &store);

    assert!(matches!(step, PinStep::Abort(PairAbortReason::PinMismatch)));
    assert!(attempt.counts_as_failure(&step), "this increments it");
}

// =============================================================================
// Sequencing and malformed input
// =============================================================================

/// A message that arrives out of sequence is a protocol error, not a retry.
#[test]
fn out_of_sequence_messages_are_protocol_errors() {
    let store = store();
    let (mut attempt, _) = PinPairing::start(
        PairMethod::StaticPin,
        CipherSuite::ChaChaPoly,
        HASH,
        INDEX,
        PinLength {
            negotiated: Some(8),
            minimum: 8,
        },
        "server-1",
        Some("12345678"),
    )
    .unwrap();

    // The static flow has no server/pair-init at all.
    let step = attempt.on_server_pair_init(&ServerPairInit {
        nonce_a: b64_encode_bytes(&[0u8; 32]),
        pin_length: None,
    });
    assert!(matches!(step, PinStep::ProtocolError(_)), "got {step:?}");

    // And a confirmation before the auth exchange has nothing to confirm against.
    let (mut attempt, _) = PinPairing::start(
        PairMethod::StaticPin,
        CipherSuite::ChaChaPoly,
        HASH,
        INDEX,
        PinLength {
            negotiated: Some(8),
            minimum: 8,
        },
        "server-1",
        Some("12345678"),
    )
    .unwrap();
    let step = attempt.on_server_pair_confirm(
        &ServerPairConfirm {
            server_kc: b64_encode_slice(&[0u8; 64]),
        },
        &store,
    );
    assert!(matches!(step, PinStep::ProtocolError(_)), "got {step:?}");
}

/// A field of the wrong width is malformed, and no conformant peer sends one.
#[test]
fn malformed_fields_are_protocol_errors() {
    let (mut attempt, _) = PinPairing::start(
        PairMethod::DynamicPin,
        CipherSuite::ChaChaPoly,
        HASH,
        INDEX,
        PinLength {
            negotiated: Some(6),
            minimum: 6,
        },
        "server-1",
        None,
    )
    .unwrap();
    for bad in ["", "not-base64url!", &b64_encode_slice(&[0u8; 31])] {
        let (mut fresh, _) = PinPairing::start(
            PairMethod::DynamicPin,
            CipherSuite::ChaChaPoly,
            HASH,
            INDEX,
            PinLength {
                negotiated: Some(6),
                minimum: 6,
            },
            "server-1",
            None,
        )
        .unwrap();
        let step = fresh.on_server_pair_init(&ServerPairInit {
            nonce_a: bad.to_string(),
            pin_length: None,
        });
        assert!(
            matches!(step, PinStep::ProtocolError(_)),
            "accepted {bad:?}"
        );
    }

    // A share of the wrong length is refused before it reaches the curve.
    let step = attempt.on_server_pair_init(&ServerPairInit {
        nonce_a: b64_encode_bytes(&[1u8; 32]),
        pin_length: None,
    });
    assert!(matches!(step, PinStep::EmitPin(_)));
    let step = attempt.on_server_pair_auth(&ServerPairAuth {
        pake_msg_1: b64_encode_slice(&[0u8; 31]),
    });
    assert!(matches!(step, PinStep::ProtocolError(_)), "got {step:?}");
}

/// The Pairing PSK method is not a PIN flow and must not be driven through this machine.
#[test]
fn the_psk_method_is_not_a_pin_flow() {
    assert!(PinPairing::start(
        PairMethod::PairingPsk,
        CipherSuite::ChaChaPoly,
        HASH,
        INDEX,
        PinLength {
            negotiated: Some(8),
            minimum: 8,
        },
        "server-1",
        None,
    )
    .is_err());
}

// =============================================================================
// Wire shapes
// =============================================================================

#[test]
fn the_pairing_messages_use_the_names_the_spec_defines() {
    let cases = [
        (
            Message::ClientPairPending(sendspin::noise::pin_flow::ClientPairPending {
                pairing_index: 1,
            }),
            "client/pair-pending",
        ),
        (
            Message::ServerPairInit(ServerPairInit {
                nonce_a: "x".into(),
                pin_length: None,
            }),
            "server/pair-init",
        ),
        (
            Message::ServerPairAuth(ServerPairAuth {
                pake_msg_1: "x".into(),
            }),
            "server/pair-auth",
        ),
        (
            Message::ServerPairConfirm(ServerPairConfirm {
                server_kc: "x".into(),
            }),
            "server/pair-confirm",
        ),
    ];
    for (message, name) in cases {
        let json = serde_json::to_string(&message).unwrap();
        assert!(json.contains(&format!(r#""type":"{name}""#)), "{json}");
    }
}

/// The three pairing fields the spec capitalises, spelled the way it spells them.
///
/// Worth a test of its own because getting one wrong is invisible to this crate: the field is
/// optional on the wire, so a snake-cased `commit_b` does not fail to parse anywhere — it
/// simply is not the field the peer is looking for, and the server reports a client that
/// offered no commitment. Both the spec and `aiosendspin` name these after the CPace roles.
#[test]
fn the_capitalised_pairing_fields_keep_their_wire_spelling() {
    let init = serde_json::to_value(Message::ClientPairInit(
        sendspin::noise::pin_flow::ClientPairInit {
            pairing_index: 1,
            commit_b: Some("commitment".into()),
        },
    ))
    .unwrap();
    assert_eq!(init["payload"]["commit_B"], "commitment");

    let confirm = serde_json::to_value(Message::ClientPairConfirm(
        sendspin::noise::pin_flow::ClientPairConfirm {
            client_kc: "tag".into(),
            nonce_b: Some("nonce".into()),
        },
    ))
    .unwrap();
    assert_eq!(confirm["payload"]["nonce_B"], "nonce");

    // And the one that arrives: a server sends `nonce_A`, so that is what has to parse.
    let incoming = r#"{"nonce_A":"nonce","pin_length":6}"#;
    let parsed: ServerPairInit = serde_json::from_str(incoming).unwrap();
    assert_eq!(parsed.nonce_a, "nonce");
    assert_eq!(parsed.pin_length, Some(6));
}

/// Where the two sources disagree about which message carries `pin_length`, read both.
///
/// The spec puts it in the activation's `pairing` object and does not list it on
/// `server/pair-init`; `aiosendspin` sends it on `server/pair-init` and leaves the activation
/// without a `pairing` object. A client that reads only one derives a PIN of the wrong length
/// against half the servers in existence.
#[test]
fn a_pin_length_stated_only_in_server_pair_init_still_decides_the_length() {
    let (mut attempt, _) = PinPairing::start(
        PairMethod::DynamicPin,
        CipherSuite::ChaChaPoly,
        HASH,
        INDEX,
        // The activation named none, which is what the reference server does.
        PinLength {
            negotiated: None,
            minimum: 6,
        },
        "server-1",
        None,
    )
    .unwrap();
    let step = attempt.on_server_pair_init(&ServerPairInit {
        nonce_a: b64_encode_bytes(&[0x11u8; 32]),
        pin_length: Some(8),
    });
    let PinStep::EmitPin(pin_value) = step else {
        panic!("expected a PIN, got {step:?}");
    };
    assert_eq!(pin_value.len(), 8, "the late length is the one used");
}

/// The activation's value wins, so a late message cannot shorten an agreed PIN.
#[test]
fn a_pin_length_agreed_in_the_activation_is_not_reopened() {
    let (mut attempt, _) = PinPairing::start(
        PairMethod::DynamicPin,
        CipherSuite::ChaChaPoly,
        HASH,
        INDEX,
        PinLength {
            negotiated: Some(10),
            minimum: 6,
        },
        "server-1",
        None,
    )
    .unwrap();
    let step = attempt.on_server_pair_init(&ServerPairInit {
        nonce_a: b64_encode_bytes(&[0x11u8; 32]),
        pin_length: Some(6),
    });
    let PinStep::EmitPin(pin_value) = step else {
        panic!("expected a PIN, got {step:?}");
    };
    assert_eq!(pin_value.len(), 10, "the activation decided this");
}

/// A late length below this client's floor is refused, exactly as an early one would be.
///
/// Otherwise the deferral would be a way around the check: name nothing in the activation,
/// then ask for four digits once the client has already committed to its nonce.
#[test]
fn a_late_pin_length_is_held_to_the_same_floor() {
    let (mut attempt, _) = PinPairing::start(
        PairMethod::DynamicPin,
        CipherSuite::ChaChaPoly,
        HASH,
        INDEX,
        PinLength {
            negotiated: None,
            minimum: 6,
        },
        "server-1",
        None,
    )
    .unwrap();
    let step = attempt.on_server_pair_init(&ServerPairInit {
        nonce_a: b64_encode_bytes(&[0x11u8; 32]),
        pin_length: Some(4),
    });
    assert!(
        matches!(step, PinStep::Abort(PairAbortReason::PinLengthUnacceptable)),
        "got {step:?}"
    );
    assert!(
        !PairAbortReason::PinLengthUnacceptable.closes_connection(),
        "the server may still offer another method"
    );
}

/// The optional fields are omitted rather than sent as null, because the static flow's
/// absence of a commitment is what tells the server which flow it is in.
#[test]
fn the_static_flow_omits_the_dynamic_fields() {
    let (_, init) = PinPairing::start(
        PairMethod::StaticPin,
        CipherSuite::ChaChaPoly,
        HASH,
        INDEX,
        PinLength {
            negotiated: Some(8),
            minimum: 8,
        },
        "server-1",
        Some("12345678"),
    )
    .unwrap();
    let json = serde_json::to_string(&Message::ClientPairInit(init)).unwrap();
    assert_eq!(
        json,
        r#"{"type":"client/pair-init","payload":{"pairing_index":3}}"#
    );
}

// =============================================================================
// The operator gesture
// =============================================================================

/// The window admits one attempt and is never raised by the crate itself.
///
/// Opening it is a deliberate local action — a button, a pinhole, a power-cycle pattern —
/// and it is what stops a stranger on the network from pairing with a device nobody is
/// standing next to. Only the host application can observe such a thing.
#[test]
fn the_pairing_window_starts_closed_and_is_opened_by_the_caller() {
    use sendspin::protocol::client::PairingWindow;

    // A fresh connection has no window open: the default has to be the safe one, because a
    // client that boots into "will pair with anyone" is a client that pairs with anyone.
    let window = PairingWindow::default();
    assert!(!window.is_open());

    window.open();
    assert!(window.is_open());

    // And a caller enforcing the spec's five-minute lifetime can withdraw it again.
    window.close();
    assert!(!window.is_open());
}

/// The failure counter escalates the dynamic method and survives in the config.
#[test]
fn ten_failures_escalate_the_dynamic_method() {
    use sendspin::noise::pin::{dynamic_pin_needs_gesture, ESCALATION_THRESHOLD};
    use sendspin::noise::PairingConfig;

    // A comfortable PIN length, so escalation is the only thing that can gate it.
    assert!(!dynamic_pin_needs_gesture(ESCALATION_THRESHOLD - 1, 8));
    assert!(dynamic_pin_needs_gesture(ESCALATION_THRESHOLD, 8));

    let store = InMemoryPairingStore::new().unwrap();
    let config = store.pairing_config().unwrap();
    assert_eq!(config.dynamic_pin_failures, 0, "a fresh client has none");

    store
        .set_pairing_config(PairingConfig {
            dynamic_pin_failures: ESCALATION_THRESHOLD,
            ..config
        })
        .unwrap();
    assert_eq!(
        store.pairing_config().unwrap().dynamic_pin_failures,
        ESCALATION_THRESHOLD
    );
}
