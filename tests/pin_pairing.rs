// ABOUTME: The Sendspin bindings around CPace, pinned to values the reference implementation
// ABOUTME: produced — a label off by one character fails here rather than in the field.

//! `cpace.rs` is checked against the IETF draft's vectors. This file checks the layer above
//! it, which the draft says nothing about: the session id, the PIN derivation, the nonce
//! commitment, and the key the new PSK travels under.
//!
//! Every expected value here was produced by `aiosendspin`, so a divergence in a label, a
//! field order, or a byte width shows up as a failing test rather than as a pairing that
//! never completes. That matters more here than almost anywhere else in the protocol: all
//! four derivations fail *silently* when they disagree — the tags simply do not verify, and
//! nothing says why.

use sendspin::noise::pin::{
    commit, commit_opens, derive_pin, dynamic_pin_needs_gesture, is_valid_static_pin,
    negotiated_pin_length, pin_length_acceptable, session_id, unwrap_psk, wrap_key, wrap_psk,
    MAX_PIN_DIGITS,
};
use sendspin::noise::CipherSuite;

fn decode_hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).expect("hex"))
        .collect()
}

fn hash() -> [u8; 32] {
    let mut h = [0u8; 32];
    for (i, b) in h.iter_mut().enumerate() {
        *b = i as u8;
    }
    h
}

fn nonce(base: u8) -> [u8; 32] {
    let mut n = [0u8; 32];
    for (i, b) in n.iter_mut().enumerate() {
        *b = base + i as u8;
    }
    n
}

fn isk() -> [u8; 64] {
    let mut k = [0u8; 64];
    for (i, b) in k.iter_mut().enumerate() {
        *b = i as u8;
    }
    k
}

/// The session id binds the PAKE to this connection and this attempt.
#[test]
fn the_session_id_matches_the_reference() {
    let expected = "73656e647370696e2d706169722d70616b652d7631\
                    000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\
                    00000007";
    assert_eq!(session_id(&hash(), 7), decode_hex(expected));
}

/// The counter is big-endian and four bytes wide, which is the sort of detail that produces
/// a working implementation against itself and a broken one against anything else.
#[test]
fn the_session_id_counter_is_a_big_endian_uint32() {
    let sid = session_id(&hash(), 1);
    assert_eq!(&sid[sid.len() - 4..], &[0, 0, 0, 1]);
    assert_ne!(session_id(&hash(), 1), session_id(&hash(), 2));
    // And a different connection is a different sid, which is the whole point.
    assert_ne!(session_id(&hash(), 1), session_id(&[9u8; 32], 1));
}

#[test]
fn the_commitment_matches_the_reference() {
    let expected = "f6d431646ea17a4488f6008d0da4dbd79b7c0a898c3631453fb6ffc912d29c18";
    assert_eq!(commit(&nonce(64)).to_vec(), decode_hex(expected));
}

#[test]
fn a_commitment_opens_only_to_its_own_nonce() {
    let commitment = commit(&nonce(64));
    assert!(commit_opens(&commitment, &nonce(64)));
    assert!(!commit_opens(&commitment, &nonce(65)));
    // A commitment of the wrong length is not a near miss, it is malformed.
    assert!(!commit_opens(&commitment[..31], &nonce(64)));
}

/// Every permitted length, against the reference.
///
/// The shorter PINs are suffixes of the longer ones, which is what reduction modulo a power
/// of ten does — worth seeing, because it means a short PIN leaks nothing extra about a long
/// one derived from the same inputs.
#[test]
fn the_derived_pins_match_the_reference() {
    let (h, na, nb) = (hash(), nonce(32), nonce(64));
    for (digits, expected) in [
        (4u8, "2858"),
        (6, "802858"),
        (8, "60802858"),
        (12, "652760802858"),
    ] {
        assert_eq!(derive_pin(&h, &na, &nb, digits).unwrap(), expected);
    }
}

/// A derived PIN is always exactly the requested width, zero-padded.
///
/// Reduction modulo `10^L` produces a small integer once in a while; formatting it without
/// padding would emit a shorter PIN than the operator was told to expect, and the two sides
/// would feed different byte strings into CPace.
#[test]
fn a_derived_pin_is_always_the_full_width() {
    for seed in 0..200u8 {
        let pin = derive_pin(&hash(), &nonce(seed), &nonce(64), 8).unwrap();
        assert_eq!(pin.len(), 8, "{pin}");
        assert!(pin.bytes().all(|b| b.is_ascii_digit()), "{pin}");
    }
}

#[test]
fn a_pin_length_outside_the_permitted_range_is_refused() {
    for digits in [0u8, 1, 3, 13, 255] {
        assert!(derive_pin(&hash(), &nonce(32), &nonce(64), digits).is_err());
    }
}

#[test]
fn the_wrap_key_matches_the_reference() {
    let expected = "0cad7c283b4d4957bf1652cbab83e8d9413e2bd25e068f09a32ee79358ba7ea8";
    assert_eq!(
        wrap_key(&session_id(&hash(), 7), &isk()).to_vec(),
        decode_hex(expected)
    );
}

/// The wrapped PSK, byte for byte, under both suites.
///
/// This is the strongest check in the file: it exercises the label, the sid, the ISK, the
/// AEAD choice, the all-zero nonce and the empty associated data all at once, and a mistake
/// in any of them changes the ciphertext.
#[test]
fn a_wrapped_psk_matches_the_reference_under_both_suites() {
    let sid = session_id(&hash(), 7);
    let psk = [0xABu8; 32];
    for (suite, expected) in [
        (
            CipherSuite::ChaChaPoly,
            "22b3fcc0ce6234a11349ea15f75401c03fb67d75d9a547252612ecfe42b4455a\
             7258d7199fce7f0fc8295836e90d94f3",
        ),
        (
            CipherSuite::AesGcm,
            "0f25baad3b30b7bbfc173723570919057c8870519edaffbb0439a6220fa2462f\
             a7b59ceca57dfe2aa815f01bd7b94a31",
        ),
    ] {
        let wrapped = wrap_psk(suite, &sid, &isk(), &psk).unwrap();
        assert_eq!(wrapped.len(), 48, "32 bytes plus a 16-byte tag");
        assert_eq!(
            wrapped,
            decode_hex(&expected.replace([' ', '\n'], "")),
            "{suite:?}"
        );
        assert_eq!(unwrap_psk(suite, &sid, &isk(), &wrapped).unwrap(), psk);
    }
}

/// A peer that could not complete the PAKE has a different ISK, and the seal does not open.
///
/// This is what makes it safe for the client to send `client/pair-finalize` without waiting
/// for a reply: the message is useless to anyone who failed the exchange.
#[test]
fn a_wrapped_psk_does_not_open_under_a_different_isk() {
    let sid = session_id(&hash(), 7);
    let wrapped = wrap_psk(CipherSuite::ChaChaPoly, &sid, &isk(), &[0xABu8; 32]).unwrap();

    let mut wrong = isk();
    wrong[0] ^= 1;
    assert!(unwrap_psk(CipherSuite::ChaChaPoly, &sid, &wrong, &wrapped).is_err());
    // A different attempt on the same connection is a different sid, and also does not open.
    assert!(unwrap_psk(
        CipherSuite::ChaChaPoly,
        &session_id(&hash(), 8),
        &isk(),
        &wrapped
    )
    .is_err());
    // Nor does the other suite's AEAD.
    assert!(unwrap_psk(CipherSuite::AesGcm, &sid, &isk(), &wrapped).is_err());
}

// =============================================================================
// Policy
// =============================================================================

#[test]
fn a_static_pin_is_exactly_eight_digits() {
    assert!(is_valid_static_pin("12345678"));
    for bad in ["1234567", "123456789", "1234567a", "", "١٢٣٤٥٦٧٨"] {
        assert!(!is_valid_static_pin(bad), "accepted {bad:?}");
    }
}

/// The session takes the larger of the two minimums, so neither side can be talked down.
#[test]
fn the_pin_length_is_the_larger_minimum_clamped() {
    assert_eq!(negotiated_pin_length(6, 4), 6);
    assert_eq!(negotiated_pin_length(4, 8), 8);
    assert_eq!(negotiated_pin_length(2, 2), 4, "clamped up to the floor");
    assert_eq!(
        negotiated_pin_length(20, 6),
        MAX_PIN_DIGITS,
        "and to the cap"
    );
}

/// The client checks the server's answer rather than trusting it.
#[test]
fn a_pin_length_below_the_clients_minimum_is_unacceptable() {
    assert!(pin_length_acceptable(6, 6));
    assert!(pin_length_acceptable(8, 6));
    assert!(!pin_length_acceptable(5, 6), "a weakening");
    assert!(!pin_length_acceptable(13, 6), "outside the spec");
}

/// Two independent reasons to demand a gesture, and either is enough.
#[test]
fn a_gesture_is_demanded_after_escalation_or_for_a_short_pin() {
    assert!(!dynamic_pin_needs_gesture(0, 6), "the ordinary case");
    assert!(dynamic_pin_needs_gesture(10, 6), "escalated");
    assert!(dynamic_pin_needs_gesture(0, 4), "short enough to guess");
    assert!(dynamic_pin_needs_gesture(9, 5), "short, not yet escalated");
    assert!(!dynamic_pin_needs_gesture(9, 12), "nine is not yet ten");
}
