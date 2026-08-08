// ABOUTME: CPACE-X25519-SHA512 per draft-irtf-cfrg-cpace-21, with the draft's explicit
// ABOUTME: mutual key confirmation — the PAKE the PIN pairing flows run.

//! CPace.
//!
//! A balanced PAKE: two peers who share a low-entropy secret — here a PIN — end up with a
//! high-entropy session key, and an eavesdropper or a man in the middle learns nothing that
//! makes guessing the PIN cheaper than guessing it online, one attempt at a time.
//!
//! This is `CPACE-X25519-SHA512` from
//! [draft-irtf-cfrg-cpace-21](https://datatracker.ietf.org/doc/draft-irtf-cfrg-cpace/21/),
//! run in initiator-responder mode with the draft's optional explicit Mutual Confirmation
//! Flow. Sendspin puts the server in role `A` and the client in role `B`.
//!
//! **Why this is written out rather than pulled in.** The only `cpace` on crates.io is a
//! single 0.1.0 from May 2020, years before revision 21, so it is wire-incompatible.
//! `curve25519-dalek` does not export the Elligator2 map this needs. What is *not*
//! hand-rolled is the arithmetic underneath: the field operations come from
//! `crypto-bigint`'s constant-time Montgomery forms and the scalar multiplication from
//! `x25519-dalek`. Only the draft's own composition lives here, and it is checked against
//! the draft's published test vectors.
//!
//! The map runs on a value derived from the password, so every step of it is constant time
//! with respect to that value — a branch on the Legendre symbol would leak which PINs make
//! the generator hash a square.

use crypto_bigint::modular::ConstMontyForm;
use crypto_bigint::{const_monty_params, U256};
use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha512};
use subtle::ConstantTimeEq;

use crate::error::Error;

const_monty_params!(
    Field,
    U256,
    "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed"
);

/// An element of GF(2^255 - 19).
type Fe = ConstMontyForm<Field, { U256::LIMBS }>;

/// Domain separation identifier for the X25519 group.
const DSI: &[u8] = b"CPace255";

/// Domain separation identifier for the ISK derivation.
const DSI_ISK: &[u8] = b"CPace255_ISK";

/// Label under which the confirmation MAC key is derived.
const MAC_LABEL: &[u8] = b"CPaceMac";

/// SHA-512's block size, which the generator string is padded against.
const SHA512_BLOCK_BYTES: usize = 128;

/// Curve25519's Montgomery curve coefficient.
const CURVE_A: u64 = 486_662;

/// The non-square Elligator2 uses on Curve25519.
const CURVE_Z: u64 = 2;

/// A public share, or the generator: a Curve25519 u-coordinate.
pub const SHARE_LEN: usize = 32;

/// A confirmation tag: HMAC-SHA-512 output.
pub const TAG_LEN: usize = 64;

/// Which side of the exchange this is.
///
/// The roles are not symmetric: the transcript orders the initiator's share first, and each
/// side's confirmation tag authenticates its *own* share. Getting the role wrong produces
/// tags that never verify rather than an obvious failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// Role `A`. Sendspin's server.
    Initiator,
    /// Role `B`. Sendspin's client.
    Responder,
}

/// Prefix `data` with its length, encoded as the draft's variable-length integer.
///
/// Seven bits per byte, low group first, high bit set on every byte but the last.
fn prepend_len(data: &[u8], out: &mut Vec<u8>) {
    let mut length = data.len();
    loop {
        let mut byte = (length & 0x7F) as u8;
        length >>= 7;
        if length != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if length == 0 {
            break;
        }
    }
    out.extend_from_slice(data);
}

/// Concatenate length-prefixed parts, which is how the draft makes its hash inputs
/// unambiguous.
fn lv_cat(parts: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    for part in parts {
        prepend_len(part, &mut out);
    }
    out
}

/// The string hashed into the generator.
///
/// The zero padding pushes the password past SHA-512's first block boundary, so that a
/// side-channel on the compression function cannot separate password material from the
/// rest of the input.
fn generator_string(prs: &[u8], ci: &[u8], sid: &[u8]) -> Vec<u8> {
    let mut prs_lv = Vec::new();
    prepend_len(prs, &mut prs_lv);
    let mut dsi_lv = Vec::new();
    prepend_len(DSI, &mut dsi_lv);
    let pad_len = SHA512_BLOCK_BYTES
        .saturating_sub(1)
        .saturating_sub(prs_lv.len())
        .saturating_sub(dsi_lv.len());
    let zpad = vec![0u8; pad_len];
    lv_cat(&[DSI, prs, &zpad, ci, sid])
}

/// Read a field element from a little-endian u-coordinate, ignoring the unused top bit.
fn decode_u(bytes: &[u8; 32]) -> Fe {
    let mut masked = *bytes;
    // RFC 7748: the field is 255 bits, so bit 255 carries no information.
    masked[31] &= 0x7F;
    Fe::new(&U256::from_le_slice(&masked))
}

/// Inversion that maps zero to zero, as RFC 9380's `inv0` requires.
///
/// Fermat rather than an extended-Euclid inverse, because `x^(p-2)` is already total and is
/// constant time; `crypto-bigint`'s `invert` would need a separate branch for zero.
fn inv0(x: &Fe) -> Fe {
    // p - 2
    let exp = U256::from_be_hex("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeb");
    x.pow(&exp)
}

/// The Legendre symbol as a field element: `1` for a non-zero square, `p-1` otherwise.
fn legendre(x: &Fe) -> Fe {
    // (p - 1) / 2
    let exp = U256::from_be_hex("3ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff6");
    x.pow(&exp)
}

/// Elligator2 onto Curve25519, mapping a field element to a u-coordinate.
///
/// Written from the draft's `map_to_curve` for `G_X25519`:
///
/// ```text
/// v   = -A / (1 + Z * r^2)
/// eps = legendre(v^3 + A * v^2 + v)
/// x   = eps * v - (1 - eps) * A / 2
/// ```
///
/// Every operation is a field operation on Montgomery forms, so the timing does not depend
/// on `r` — which matters because `r` comes from the password.
fn elligator2(r: &Fe) -> [u8; 32] {
    let a = Fe::new(&U256::from_u64(CURVE_A));
    let z = Fe::new(&U256::from_u64(CURVE_Z));
    let one = Fe::ONE;

    // v = -A * inv0(1 + Z * r^2)
    let denominator = one + z * r.square();
    let v = -a * inv0(&denominator);

    // eps = legendre(v^3 + A*v^2 + v), with B = 1.
    let v2 = v.square();
    let eps = legendre(&(v2 * v + a * v2 + v));

    // x = eps * v - (1 - eps) * A/2
    let half_a = a * inv0(&(one + one));
    let x = eps * v - (one - eps) * half_a;

    let mut out = [0u8; 32];
    out.copy_from_slice(&x.retrieve().to_le_bytes());
    out
}

/// The generator for one (password, channel, session) triple.
pub fn calculate_generator(prs: &[u8], ci: &[u8], sid: &[u8]) -> [u8; SHARE_LEN] {
    let hash = Sha512::digest(generator_string(prs, ci, sid));
    let mut head = [0u8; 32];
    head.copy_from_slice(&hash[..32]);
    elligator2(&decode_u(&head))
}

/// X25519 scalar multiplication that rejects a result encoding the identity.
///
/// The all-zero check is a MAY in RFC 7748 and a MUST here: a peer share whose product is
/// the identity would otherwise produce a shared secret every observer can predict.
///
/// This is the draft's abort condition and the whole of it. The draft's `u6`, `u8`, `u9`,
/// `ua` and `ub` are unusual encodings that still multiply to something useful, and it says
/// so explicitly — only `u0`–`u5` and `u7` must abort. Rejecting more than that would refuse
/// peers the draft considers conformant.
pub fn scalar_mult_vfy(scalar: &[u8; 32], point: &[u8; SHARE_LEN]) -> Option<[u8; 32]> {
    let shared = x25519_dalek::x25519(*scalar, *point);
    (shared != [0u8; 32]).then_some(shared)
}

/// One side of a CPace run.
pub struct CPace {
    role: Role,
    sid: Vec<u8>,
    ad: Vec<u8>,
    /// Consumed by `derive`, so a scalar is never reused.
    scalar: Option<[u8; 32]>,
    public_share: [u8; SHARE_LEN],
}

/// What a completed run yields.
pub struct CPaceOutput {
    /// The intermediate session key. Run it through a KDF before using it as a key.
    pub isk: [u8; 64],
    /// This side's confirmation tag, to send to the peer.
    pub own_tag: [u8; TAG_LEN],
    /// The tag this side expects from the peer.
    expected_peer_tag: [u8; TAG_LEN],
    /// True when both sides presented the same share and associated data, which no honest
    /// run produces.
    reflected: bool,
}

impl CPaceOutput {
    /// Whether `peer_tag` proves the peer knew the password.
    ///
    /// Compared in constant time. A reflected transcript always fails: an attacker who
    /// bounces this side's own share back would otherwise get a tag that verifies without
    /// ever knowing the password.
    pub fn verify(&self, peer_tag: &[u8]) -> bool {
        if self.reflected || peer_tag.len() != TAG_LEN {
            return false;
        }
        self.expected_peer_tag.ct_eq(peer_tag).into()
    }
}

impl CPace {
    /// Begin a run from an explicit scalar.
    ///
    /// Exposed for the draft's test vectors, which fix `ya` and `yb`. A real run uses
    /// [`CPace::start`], because a predictable scalar makes the exchange forgeable.
    pub fn with_scalar(
        role: Role,
        prs: &[u8],
        sid: &[u8],
        ci: &[u8],
        ad: &[u8],
        scalar: [u8; 32],
    ) -> Result<Self, Error> {
        let generator = calculate_generator(prs, ci, sid);
        let public_share = scalar_mult_vfy(&scalar, &generator)
            .ok_or_else(|| Error::Protocol("CPace generator encodes a low-order point".into()))?;
        Ok(Self {
            role,
            sid: sid.to_vec(),
            ad: ad.to_vec(),
            scalar: Some(scalar),
            public_share,
        })
    }

    /// Begin a run, sampling this side's scalar from the OS CSPRNG.
    pub fn start(role: Role, prs: &[u8], sid: &[u8], ci: &[u8], ad: &[u8]) -> Result<Self, Error> {
        // The private half of a fresh X25519 keypair is 32 CSPRNG bytes, which is what the
        // draft asks for — and reuses the one entropy source this crate already trusts.
        let scalar = *super::keys::Identity::generate()?.private_key();
        Self::with_scalar(role, prs, sid, ci, ad, scalar)
    }

    /// This side's public share, to send to the peer.
    pub fn public_share(&self) -> &[u8; SHARE_LEN] {
        &self.public_share
    }

    /// Ingest the peer's share, producing the session key and the confirmation tags.
    ///
    /// Consumes the run: the scalar is single-use, and calling twice would reuse it.
    pub fn derive(mut self, peer_share: &[u8], peer_ad: &[u8]) -> Result<CPaceOutput, Error> {
        let scalar = self
            .scalar
            .take()
            .ok_or_else(|| Error::Protocol("CPace run already derived".into()))?;
        let peer_share: [u8; SHARE_LEN] = peer_share
            .try_into()
            .map_err(|_| Error::Protocol("CPace peer share must be 32 bytes".into()))?;
        let shared = scalar_mult_vfy(&scalar, &peer_share)
            .ok_or_else(|| Error::Protocol("CPace peer share encodes a low-order point".into()))?;

        // The transcript always runs initiator-first, whichever side is assembling it.
        let (first, second) = match self.role {
            Role::Initiator => (
                (self.public_share, self.ad.clone()),
                (peer_share, peer_ad.to_vec()),
            ),
            Role::Responder => (
                (peer_share, peer_ad.to_vec()),
                (self.public_share, self.ad.clone()),
            ),
        };
        let mut transcript = lv_cat(&[&first.0, &first.1]);
        transcript.extend_from_slice(&lv_cat(&[&second.0, &second.1]));

        let mut isk_input = lv_cat(&[DSI_ISK, &self.sid, &shared]);
        isk_input.extend_from_slice(&transcript);
        let isk: [u8; 64] = Sha512::digest(&isk_input).into();

        let mut mac_key_input = Vec::from(MAC_LABEL);
        mac_key_input.extend_from_slice(&self.sid);
        mac_key_input.extend_from_slice(&isk);
        let mac_key: [u8; 64] = Sha512::digest(&mac_key_input).into();

        // Ta authenticates (Ya, ADa) and Tb authenticates (Yb, ADb), so which half of the
        // transcript a tag covers follows from the role rather than from who is asking.
        let tag = |share: &[u8], ad: &[u8]| -> [u8; TAG_LEN] {
            let mut mac = <Hmac<Sha512> as KeyInit>::new_from_slice(&mac_key)
                .expect("HMAC accepts a key of any length");
            mac.update(&lv_cat(&[share, ad]));
            mac.finalize().into_bytes().into()
        };
        let (own, peer) = match self.role {
            Role::Initiator => ((&first.0, &first.1), (&second.0, &second.1)),
            Role::Responder => ((&second.0, &second.1), (&first.0, &first.1)),
        };

        Ok(CPaceOutput {
            isk,
            own_tag: tag(own.0, own.1),
            expected_peer_tag: tag(peer.0, peer.1),
            reflected: first == second,
        })
    }
}
