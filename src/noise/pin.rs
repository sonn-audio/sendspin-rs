// ABOUTME: The Sendspin bindings around CPace — the session id, the derived PIN and its
// ABOUTME: commitment, and the key the new PSK travels under.

//! PIN pairing bindings.
//!
//! [`cpace`](crate::noise::cpace) is the PAKE itself, and knows nothing about Sendspin. This module
//! is everything that ties one run to one connection, and it is where a plausible-looking
//! implementation goes wrong without failing loudly:
//!
//! - The **session id** folds in the Noise handshake hash, so a PAKE run cannot be replayed
//!   onto a different connection.
//! - The **derived PIN** of the dynamic flow is a function of that same hash and both sides'
//!   nonces, so neither side alone chooses it.
//! - The **commitment** locks the client's nonce before the server's is known, which is what
//!   stops the client from grinding its own contribution once it has seen `nonce_A`.
//! - The **wrapping key** seals the new PSK under the CPace output, so a peer that could not
//!   complete the PAKE never learns it — even though the message carrying it goes out
//!   without waiting for a reply.

use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use super::constants::KEY_LEN;
use crate::error::Error;

/// Label under which the CPace session id is built.
const SID_LABEL: &[u8] = b"sendspin-pair-pake-v1";

/// Label under which a dynamic PIN is derived.
const PIN_DERIVE_LABEL: &[u8] = b"sendspin-pin-derive-v1";

/// Label under which the client commits to its nonce.
const COMMIT_LABEL: &[u8] = b"sendspin-pair-commit-v1";

/// Label under which the PSK wrapping key is derived.
const PSK_WRAP_LABEL: &[u8] = b"sendspin-pair-psk-wrap-v1";

/// CPace associated data for the server, which takes role `A`.
pub const AD_SERVER: &[u8] = b"server";

/// CPace associated data for the client, which takes role `B`.
pub const AD_CLIENT: &[u8] = b"client";

/// Bytes in each side's binding nonce, and in the commitment over one.
pub const NONCE_LEN: usize = 32;

/// The shortest dynamic PIN the spec allows.
pub const MIN_PIN_DIGITS: u8 = 4;

/// The longest dynamic PIN the spec allows.
pub const MAX_PIN_DIGITS: u8 = 12;

/// The dynamic PIN length below which every attempt is gesture-gated.
///
/// Short PINs are bought with an operator gesture: at four digits an online guess succeeds
/// once in ten thousand, which a patient attacker will pay.
pub const GESTURE_GATE_BELOW_DIGITS: u8 = 6;

/// A static PIN is always exactly this long.
pub const STATIC_PIN_DIGITS: usize = 8;

/// Failures after which the dynamic-PIN method escalates to gesture-gating.
pub const ESCALATION_THRESHOLD: u32 = 10;

/// The AEAD nonce the PSK is wrapped under: twelve zero bytes.
///
/// A fixed nonce is safe here and only here, because `K_wrap` is used for exactly one
/// message. Reusing the key would be the mistake; reusing the nonce under a single-use key
/// is not.
const PSK_WRAP_NONCE: [u8; 12] = [0u8; 12];

/// The CPace session id for one pairing attempt.
///
/// `h` is the Noise handshake hash, so the PAKE is bound to this connection: a run captured
/// elsewhere has a different `sid` and its transcript will not verify here. `counter` is how
/// many pairing activations have been sent since the last handshake, which separates two
/// attempts that share one connection.
pub fn session_id(handshake_hash: &[u8; 32], counter: u32) -> Vec<u8> {
    let mut sid = Vec::with_capacity(SID_LABEL.len() + 36);
    sid.extend_from_slice(SID_LABEL);
    sid.extend_from_slice(handshake_hash);
    sid.extend_from_slice(&counter.to_be_bytes());
    sid
}

/// The client's commitment to its nonce.
///
/// Sent in `client/pair-init`, before any value from the server is known, and opened in
/// `client/pair-confirm`. Without it the client could wait for `nonce_A` and then pick a
/// `nonce_B` that steers the derived PIN.
pub fn commit(nonce_b: &[u8; NONCE_LEN]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(COMMIT_LABEL);
    hasher.update(nonce_b);
    hasher.finalize().into()
}

/// Whether a revealed nonce opens a commitment.
///
/// A mismatch is a protocol error rather than a failed attempt: no conformant peer produces
/// one, so the connection closes without an application-level message.
pub fn commit_opens(commitment: &[u8], nonce_b: &[u8; NONCE_LEN]) -> bool {
    commitment.len() == 32 && bool::from(commit(nonce_b).ct_eq(commitment))
}

/// The dynamic PIN both sides derive, as exactly `digits` decimal characters.
///
/// Neither side chooses it: it falls out of the handshake hash and both nonces. The full
/// SHA-256 output is read as a big-endian 256-bit integer and reduced modulo `10^digits`,
/// then padded on the left — so a digest whose value is small still yields a full-length
/// PIN rather than a short one.
pub fn derive_pin(
    handshake_hash: &[u8; 32],
    nonce_a: &[u8; NONCE_LEN],
    nonce_b: &[u8; NONCE_LEN],
    digits: u8,
) -> Result<String, Error> {
    if !(MIN_PIN_DIGITS..=MAX_PIN_DIGITS).contains(&digits) {
        return Err(Error::Protocol(format!(
            "a PIN of {digits} digits is outside the permitted {MIN_PIN_DIGITS}-{MAX_PIN_DIGITS}"
        )));
    }
    let mut hasher = Sha256::new();
    hasher.update(PIN_DERIVE_LABEL);
    hasher.update(handshake_hash);
    hasher.update(nonce_a);
    hasher.update(nonce_b);
    let digest: [u8; 32] = hasher.finalize().into();

    // 10^12 fits in u64, so the reduction is a long division of the 256-bit digest by a
    // u64 modulus — done here as a byte-wise remainder rather than by pulling in a bignum.
    let modulus = 10u64.pow(u32::from(digits));
    let mut remainder: u128 = 0;
    for byte in digest {
        remainder = ((remainder << 8) | u128::from(byte)) % u128::from(modulus);
    }
    Ok(format!("{remainder:0width$}", width = digits as usize))
}

/// Whether `pin` is a well-formed static PIN: exactly eight ASCII decimal digits.
pub fn is_valid_static_pin(pin: &str) -> bool {
    pin.len() == STATIC_PIN_DIGITS && pin.bytes().all(|b| b.is_ascii_digit())
}

/// The PIN length one session uses: the larger of the two minimums, clamped to the range.
///
/// The server computes this and states it in the activation; the client checks the answer
/// rather than trusting it, because a server that names four digits to a client asking for
/// eight is asking for a weaker secret than the client agreed to offer.
pub fn negotiated_pin_length(client_min: u8, server_min: u8) -> u8 {
    client_min
        .max(server_min)
        .clamp(MIN_PIN_DIGITS, MAX_PIN_DIGITS)
}

/// Whether an activation's `pin_length` is acceptable to a client with this minimum.
///
/// Below the client's own minimum it is a weakening, and above twelve it is outside the
/// spec; either draws `pair/abort` with `pin_length_unacceptable`.
pub fn pin_length_acceptable(pin_length: u8, client_min: u8) -> bool {
    pin_length >= client_min && pin_length <= MAX_PIN_DIGITS
}

/// Whether a dynamic-PIN attempt has to wait for an operator gesture.
///
/// Two independent reasons, and either is enough: the method has escalated after repeated
/// failures, or this session's PIN is short enough that guessing it online is cheap.
pub fn dynamic_pin_needs_gesture(failures: u32, pin_length: u8) -> bool {
    failures >= ESCALATION_THRESHOLD || pin_length < GESTURE_GATE_BELOW_DIGITS
}

/// The key the new PSK is sealed under, derived from the CPace output.
///
/// Both sides can compute it and nobody else can: `ISK` is the PAKE's product, and a peer
/// that could not complete the PAKE has a different one.
pub fn wrap_key(sid: &[u8], isk: &[u8; 64]) -> [u8; KEY_LEN] {
    let mut hasher = Sha256::new();
    hasher.update(PSK_WRAP_LABEL);
    hasher.update(sid);
    hasher.update(isk);
    hasher.finalize().into()
}

/// Seal the new long-term PSK for `client/pair-finalize`.
///
/// The client sends this without waiting for a reply, so the sealing is what makes that
/// safe: a server that failed the PAKE receives 48 bytes it cannot open.
pub fn wrap_psk(
    suite: super::session::CipherSuite,
    sid: &[u8],
    isk: &[u8; 64],
    psk: &[u8; KEY_LEN],
) -> Result<Vec<u8>, Error> {
    aead(suite, &wrap_key(sid, isk), psk, true)
}

/// Open a wrapped PSK. The mirror of [`wrap_psk`], for a server or a loopback test.
pub fn unwrap_psk(
    suite: super::session::CipherSuite,
    sid: &[u8],
    isk: &[u8; 64],
    wrapped: &[u8],
) -> Result<[u8; KEY_LEN], Error> {
    let plaintext = aead(suite, &wrap_key(sid, isk), wrapped, false)?;
    plaintext
        .try_into()
        .map_err(|_| Error::Protocol("a wrapped PSK did not open to 32 bytes".into()))
}

/// The connection's negotiated AEAD, keyed by `K_wrap`, over an all-zero nonce and no
/// associated data.
fn aead(
    suite: super::session::CipherSuite,
    key: &[u8; KEY_LEN],
    input: &[u8],
    seal: bool,
) -> Result<Vec<u8>, Error> {
    use super::session::CipherSuite;
    use chacha20poly1305::aead::{Aead, KeyInit};

    let nonce = PSK_WRAP_NONCE.into();
    let failed = || Error::Protocol("wrapped PSK failed to decrypt".to_string());
    match suite {
        CipherSuite::ChaChaPoly => {
            let cipher = chacha20poly1305::ChaCha20Poly1305::new(key.into());
            if seal {
                cipher.encrypt(&nonce, input).map_err(|_| failed())
            } else {
                cipher.decrypt(&nonce, input).map_err(|_| failed())
            }
        }
        CipherSuite::AesGcm => {
            let cipher = aes_gcm::Aes256Gcm::new(key.into());
            if seal {
                cipher.encrypt(&nonce, input).map_err(|_| failed())
            } else {
                cipher.decrypt(&nonce, input).map_err(|_| failed())
            }
        }
    }
}
