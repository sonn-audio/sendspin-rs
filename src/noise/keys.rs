// ABOUTME: Identities, pre-shared keys and the psk_id derivation that lets a client
// ABOUTME: pick the right PSK from the server's first handshake message.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use sha2::{Digest, Sha256};

use super::constants::{B64_KEY_LEN, KEY_LEN, PSK_ID_LABEL, SENTINEL_PSK_LABEL};
use crate::error::Error;

/// Encode 32 bytes as base64url with no padding — the 43-character form the protocol
/// uses for identities and PSK ids.
pub fn b64_encode(bytes: &[u8; KEY_LEN]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Decode the 43-character base64url form back to 32 bytes.
///
/// Rejects anything that is not exactly 43 characters decoding to 32 bytes, so a
/// truncated or padded identity is a parse failure rather than a key that silently
/// differs from the peer's.
pub fn b64_decode(text: &str) -> Result<[u8; KEY_LEN], Error> {
    if text.len() != B64_KEY_LEN {
        return Err(Error::Protocol(format!(
            "expected a {B64_KEY_LEN}-character base64url value, got {}",
            text.len()
        )));
    }
    let raw = URL_SAFE_NO_PAD
        .decode(text)
        .map_err(|e| Error::Protocol(format!("invalid base64url: {e}")))?;
    raw.try_into()
        .map_err(|_| Error::Protocol("base64url value did not decode to 32 bytes".to_string()))
}

/// Which kind of PSK matched a handshake, and therefore what the session may be used for.
///
/// The three categories share one `psk_id` namespace precisely so a matched id maps to
/// exactly one trust level; the category a client stored alongside the key is what decides
/// how the session proceeds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PskCategory {
    /// The published constant, used before any pairing record exists. Authenticates
    /// nothing on its own — its value is public.
    Sentinel,
    /// A Sendspin Pairing PSK: per-device, long-lived, and only ever used to pair.
    Pairing,
    /// A long-term Sendspin PSK produced by a completed pairing.
    LongTerm,
}

/// A pre-shared key with the category it was stored under.
#[derive(Clone)]
pub struct Psk {
    key: [u8; KEY_LEN],
    category: PskCategory,
    /// The `server_id` this record is bound to, under the stored-pubkey model.
    ///
    /// `None` is the shared-PSK model: the `server_id` from `server/init` is taken at face
    /// value. Weaker, but it lets a storage-constrained client hold one key for several
    /// servers.
    server_id: Option<String>,
}

impl Psk {
    /// A PSK bound to one server's identity (stored-pubkey model).
    pub fn for_server(key: [u8; KEY_LEN], category: PskCategory, server_id: String) -> Self {
        Self {
            key,
            category,
            server_id: Some(server_id),
        }
    }

    /// A PSK not bound to any server (shared-PSK model).
    pub fn shared(key: [u8; KEY_LEN], category: PskCategory) -> Self {
        Self {
            key,
            category,
            server_id: None,
        }
    }

    /// The published Sentinel PSK: `SHA-256("sendspin-sentinel-psk-v1")`.
    ///
    /// Every client keeps this in its candidate set: it is what a server keys the first
    /// connection with, before there is anything else to key it with.
    pub fn sentinel() -> Self {
        Self {
            key: Sha256::digest(SENTINEL_PSK_LABEL).into(),
            category: PskCategory::Sentinel,
            server_id: None,
        }
    }

    /// The raw key material.
    pub fn key(&self) -> &[u8; KEY_LEN] {
        &self.key
    }

    /// The category this key was stored under.
    pub fn category(&self) -> PskCategory {
        self.category
    }

    /// The `server_id` this record is bound to, if any.
    pub fn server_id(&self) -> Option<&str> {
        self.server_id.as_deref()
    }

    /// This key's `psk_id`: `base64url(SHA-256("sendspin-psk-id-v1" || PSK))`.
    pub fn psk_id(&self) -> String {
        b64_encode(&psk_id_bytes(&self.key))
    }

    /// Whether this record may authenticate a server claiming `server_id`.
    ///
    /// Under the stored-pubkey model a mismatch fails the handshake; under the shared-PSK
    /// model there is nothing stored to compare against, so any server passes.
    pub fn accepts_server(&self, server_id: &str) -> bool {
        match &self.server_id {
            Some(bound) => bound == server_id,
            None => true,
        }
    }
}

impl std::fmt::Debug for Psk {
    /// Deliberately omits the key material, so a debug log of a connection cannot leak a
    /// long-term PSK.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Psk")
            .field("category", &self.category)
            .field("server_id", &self.server_id)
            .field("psk_id", &self.psk_id())
            .finish()
    }
}

/// Derive the raw 32-byte `psk_id` for a key.
pub fn psk_id_bytes(key: &[u8; KEY_LEN]) -> [u8; KEY_LEN] {
    let mut hasher = Sha256::new();
    hasher.update(PSK_ID_LABEL);
    hasher.update(key);
    hasher.finalize().into()
}

/// This client's static keypair. The public half *is* the `client_id`.
///
/// Long-lived by intent: because the identifier is the public key, rotating the keypair
/// makes this client look like a different client to every server it has paired with.
/// Persist the private key.
#[derive(Clone)]
pub struct Identity {
    private: [u8; KEY_LEN],
    public: [u8; KEY_LEN],
}

impl Identity {
    /// Generate a fresh keypair from the OS CSPRNG.
    ///
    /// Delegates the randomness to `snow`, which already owns a vetted CSPRNG for exactly
    /// this purpose, rather than introducing a second source of key material.
    pub fn generate() -> Result<Self, Error> {
        let params = super::session::CipherSuite::ChaChaPoly.noise_params()?;
        let keypair = snow::Builder::new(params)
            .generate_keypair()
            .map_err(|e| Error::Protocol(format!("key generation failed: {e}")))?;
        let private: [u8; KEY_LEN] = keypair
            .private
            .try_into()
            .map_err(|_| Error::Protocol("generated private key was not 32 bytes".to_string()))?;
        // Recompute the public half so it is derived from the private key we actually
        // keep, rather than trusted to match it.
        Ok(Self::from_private_key(private))
    }

    /// Rebuild an identity from a persisted private key.
    ///
    /// The public half is recomputed rather than stored, so a caller only has to persist
    /// 32 bytes and cannot persist a mismatched pair.
    pub fn from_private_key(private: [u8; KEY_LEN]) -> Self {
        let secret = x25519_dalek::StaticSecret::from(private);
        let public = x25519_dalek::PublicKey::from(&secret);
        Self {
            private,
            public: public.to_bytes(),
        }
    }

    /// The private half. Persist this; never send it.
    pub fn private_key(&self) -> &[u8; KEY_LEN] {
        &self.private
    }

    /// The public half.
    pub fn public_key(&self) -> &[u8; KEY_LEN] {
        &self.public
    }

    /// This client's `client_id`: the base64url-encoded public key.
    pub fn client_id(&self) -> String {
        b64_encode(&self.public)
    }
}

impl std::fmt::Debug for Identity {
    /// Omits the private key.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Identity")
            .field("client_id", &self.client_id())
            .finish()
    }
}
