// ABOUTME: CPACE-X25519-SHA512 against the published test vectors of
// ABOUTME: draft-irtf-cfrg-cpace-21 — the only thing that proves the arithmetic.

//! The draft ships `testvectors.json` with every intermediate value: the generator, both
//! public shares, the raw DH output and the ISK. Checking against them catches an error
//! anywhere in the chain and says where — which a loopback test between two copies of the
//! same wrong implementation cannot.

use sendspin::noise::cpace::{calculate_generator, scalar_mult_vfy, CPace, Role};
use serde_json::Value;

fn vectors() -> Value {
    let raw = include_str!("data/cpace_vectors.json");
    serde_json::from_str(raw).expect("vectors parse")
}

fn hex(value: &Value, key: &str) -> Vec<u8> {
    let text = value[key].as_str().unwrap_or_else(|| panic!("no {key}"));
    decode_hex(text)
}

fn decode_hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).expect("hex"))
        .collect()
}

fn array32(bytes: &[u8]) -> [u8; 32] {
    bytes.try_into().expect("32 bytes")
}

/// The generator is where a wrong Elligator2 or a wrong generator string shows up first.
///
/// Everything downstream is a scalar multiplication or a hash of it, so a correct `g`
/// against the draft's own value is the single strongest check available here.
#[test]
fn the_generator_matches_the_draft() {
    let v = &vectors()["G_25519"];
    let generator = calculate_generator(&hex(v, "PRS"), &hex(v, "CI"), &hex(v, "sid"));
    assert_eq!(generator.to_vec(), hex(v, "g"));
}

/// Both public shares, from the draft's fixed scalars.
#[test]
fn both_public_shares_match_the_draft() {
    let v = &vectors()["G_25519"];
    let (prs, ci, sid) = (hex(v, "PRS"), hex(v, "CI"), hex(v, "sid"));

    let a = CPace::with_scalar(
        Role::Initiator,
        &prs,
        &sid,
        &ci,
        &hex(v, "ADa"),
        array32(&hex(v, "ya")),
    )
    .unwrap();
    assert_eq!(a.public_share().to_vec(), hex(v, "Ya"), "Ya");

    let b = CPace::with_scalar(
        Role::Responder,
        &prs,
        &sid,
        &ci,
        &hex(v, "ADb"),
        array32(&hex(v, "yb")),
    )
    .unwrap();
    assert_eq!(b.public_share().to_vec(), hex(v, "Yb"), "Yb");
}

/// The initiator-responder ISK, which folds in the shared secret and the whole transcript.
///
/// `ISK_IR` rather than `ISK_SY`: Sendspin runs the ordered mode, where the server is `A`.
#[test]
fn the_initiator_responder_isk_matches_the_draft() {
    let v = &vectors()["G_25519"];
    let (prs, ci, sid) = (hex(v, "PRS"), hex(v, "CI"), hex(v, "sid"));
    let (ada, adb) = (hex(v, "ADa"), hex(v, "ADb"));

    let a = CPace::with_scalar(
        Role::Initiator,
        &prs,
        &sid,
        &ci,
        &ada,
        array32(&hex(v, "ya")),
    )
    .unwrap();
    let b = CPace::with_scalar(
        Role::Responder,
        &prs,
        &sid,
        &ci,
        &adb,
        array32(&hex(v, "yb")),
    )
    .unwrap();
    let (ya, yb) = (*a.public_share(), *b.public_share());

    let out_a = a.derive(&yb, &adb).unwrap();
    let out_b = b.derive(&ya, &ada).unwrap();

    assert_eq!(out_a.isk.to_vec(), hex(v, "ISK_IR"), "initiator ISK");
    assert_eq!(out_b.isk.to_vec(), hex(v, "ISK_IR"), "responder ISK");
}

/// Each side's tag verifies at the other, and neither verifies at itself.
#[test]
fn the_confirmation_tags_verify_across_the_exchange() {
    let v = &vectors()["G_25519"];
    let (prs, ci, sid) = (hex(v, "PRS"), hex(v, "CI"), hex(v, "sid"));
    let (ada, adb) = (hex(v, "ADa"), hex(v, "ADb"));

    let a = CPace::with_scalar(
        Role::Initiator,
        &prs,
        &sid,
        &ci,
        &ada,
        array32(&hex(v, "ya")),
    )
    .unwrap();
    let b = CPace::with_scalar(
        Role::Responder,
        &prs,
        &sid,
        &ci,
        &adb,
        array32(&hex(v, "yb")),
    )
    .unwrap();
    let (ya, yb) = (*a.public_share(), *b.public_share());
    let out_a = a.derive(&yb, &adb).unwrap();
    let out_b = b.derive(&ya, &ada).unwrap();

    assert!(out_a.verify(&out_b.own_tag), "A accepts B's tag");
    assert!(out_b.verify(&out_a.own_tag), "B accepts A's tag");
    // A tag authenticates its own side's share, so replaying it back is not a proof.
    assert!(!out_a.verify(&out_a.own_tag), "A rejects its own tag");
    assert!(!out_b.verify(&out_b.own_tag), "B rejects its own tag");
}

/// A different password yields a different ISK and tags that do not verify.
///
/// This is the property the whole exchange exists for: a wrong PIN fails at confirmation
/// rather than leaking whether it was close.
#[test]
fn a_wrong_password_fails_confirmation() {
    let sid = b"session";
    let a = CPace::start(Role::Initiator, b"12345678", sid, b"", b"server").unwrap();
    let b = CPace::start(Role::Responder, b"12345679", sid, b"", b"client").unwrap();
    let (ya, yb) = (*a.public_share(), *b.public_share());

    let out_a = a.derive(&yb, b"client").unwrap();
    let out_b = b.derive(&ya, b"server").unwrap();

    assert_ne!(out_a.isk, out_b.isk);
    assert!(!out_a.verify(&out_b.own_tag));
    assert!(!out_b.verify(&out_a.own_tag));
}

/// A correct password, freshly sampled scalars: the full round has to work end to end.
#[test]
fn a_matching_password_completes_the_round() {
    let sid = b"sendspin-pair-pake-v1-session";
    let a = CPace::start(Role::Initiator, b"470815", sid, b"", b"server").unwrap();
    let b = CPace::start(Role::Responder, b"470815", sid, b"", b"client").unwrap();
    let (ya, yb) = (*a.public_share(), *b.public_share());

    let out_a = a.derive(&yb, b"client").unwrap();
    let out_b = b.derive(&ya, b"server").unwrap();

    assert_eq!(out_a.isk, out_b.isk);
    assert!(out_a.verify(&out_b.own_tag));
    assert!(out_b.verify(&out_a.own_tag));
}

/// The draft's low-order point table, checked against its own expected outputs.
///
/// The draft is precise about which encodings must abort: `u0`-`u5` and `u7`, and no others.
/// `u6`, `u8`, `u9`, `ua` and `ub` are unusual encodings that still multiply to a useful
/// value, and it publishes what that value is. Refusing them would turn away peers the
/// draft considers conformant; accepting `u0`-`u5` or `u7` would accept a shared secret an
/// observer can predict. So both directions are asserted.
#[test]
fn the_low_order_point_table_behaves_exactly_as_the_draft_says() {
    // s from "Test vectors for G_X25519.scalar_mult_vfy: low order points".
    let scalar = array32(&decode_hex(
        "af46e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449aff",
    ));
    // (point, expected output) — an all-zero expectation is the abort case.
    let table = [
        ("Invalid Y0", ""),
        ("Invalid Y1", ""),
        ("Invalid Y2", ""),
        ("Invalid Y3", ""),
        ("Invalid Y4", ""),
        ("Invalid Y5", ""),
        (
            "Invalid Y6",
            "d8e2c776bbacd510d09fd9278b7edcd25fc5ae9adfba3b6e040e8d3b71b21806",
        ),
        ("Invalid Y7", ""),
        (
            "Invalid Y8",
            "c85c655ebe8be44ba9c0ffde69f2fe10194458d137f09bbff725ce58803cdb38",
        ),
        (
            "Invalid Y9",
            "db64dafa9b8fdd136914e61461935fe92aa372cb056314e1231bc4ec12417456",
        ),
        (
            "Invalid Y10",
            "e062dcd5376d58297be2618c7498f55baa07d7e03184e8aada20bca28888bf7a",
        ),
        (
            "Invalid Y11",
            "993c6ad11c4c29da9a56f7691fd0ff8d732e49de6250b6c2e80003ff4629a175",
        ),
    ];

    let points = &vectors()["X25519_points"];
    for (name, expected) in table {
        let share = array32(&hex(points, name));
        let actual = scalar_mult_vfy(&scalar, &share);
        if expected.is_empty() {
            assert!(actual.is_none(), "{name} must abort");
        } else {
            assert_eq!(
                actual.expect("must not abort").to_vec(),
                decode_hex(expected),
                "{name}"
            );
        }
    }
}

/// And the abort cases must abort through the exchange too, not only in the primitive.
#[test]
fn an_aborting_share_fails_the_exchange() {
    let points = &vectors()["X25519_points"];
    for name in ["Invalid Y0", "Invalid Y1", "Invalid Y5", "Invalid Y7"] {
        let side = CPace::start(Role::Responder, b"1234", b"sid", b"", b"client").unwrap();
        assert!(
            side.derive(&hex(points, name), b"server").is_err(),
            "{name} was accepted by derive()"
        );
    }
}

/// A share of the wrong length is refused before it reaches the curve.
#[test]
fn a_share_of_the_wrong_length_is_refused() {
    let side = CPace::start(Role::Responder, b"1234", b"sid", b"", b"client").unwrap();
    assert!(side.derive(&[0u8; 31], b"server").is_err());
}
