// ABOUTME: The client's pairing records — what it has paired with, and which pairing
// ABOUTME: methods it currently offers.

use std::collections::HashMap;

use super::constants::KEY_LEN;
use super::keys::{b64_decode, b64_encode, Psk, PskCategory};
use crate::error::Error;

/// One pairing record: a long-term Sendspin PSK this client shares with a server.
///
/// Every record carries `user` trust level — that is what a record *is*. The two kinds
/// differ only in whether the PSK is bound to one server:
///
/// - **Stored-pubkey**: `server_id` is set. After a `psk_id` match the client checks the
///   server's identity against it, so authentication rests on both the static keys and the
///   PSK.
/// - **Shared-PSK**: `server_id` is `None`. Any server holding the PSK is accepted.
///   Convenient where storage is tight, and weaker for it.
#[derive(Debug, Clone)]
pub struct PairingRecord {
    /// The record's identifier, derived from the PSK.
    psk_id: String,
    /// The key itself.
    psk: [u8; KEY_LEN],
    /// The server this record is bound to, for stored-pubkey records.
    server_id: Option<String>,
}

impl PairingRecord {
    /// A record bound to one server.
    pub fn stored_pubkey(psk: [u8; KEY_LEN], server_id: String) -> Self {
        Self {
            psk_id: b64_encode(&super::keys::psk_id_bytes(&psk)),
            psk,
            server_id: Some(server_id),
        }
    }

    /// A record any server holding the PSK may use.
    pub fn shared(psk: [u8; KEY_LEN]) -> Self {
        Self {
            psk_id: b64_encode(&super::keys::psk_id_bytes(&psk)),
            psk,
            server_id: None,
        }
    }

    /// The record's `psk_id`.
    pub fn psk_id(&self) -> &str {
        &self.psk_id
    }

    /// The server this record is bound to, if any.
    pub fn server_id(&self) -> Option<&str> {
        self.server_id.as_deref()
    }

    /// The record as a handshake PSK candidate.
    pub fn as_psk(&self) -> Psk {
        match &self.server_id {
            Some(server_id) => Psk::for_server(self.psk, PskCategory::LongTerm, server_id.clone()),
            None => Psk::shared(self.psk, PskCategory::LongTerm),
        }
    }
}

/// Which pairing methods a client currently offers.
///
/// A method that is implemented but disabled is omitted from `client/hello` *and* its key is
/// excluded from the handshake candidate set, so a server naming it fails as a lookup miss
/// rather than pairing against a method the operator turned off.
#[derive(Debug, Clone)]
pub struct PairingConfig {
    /// The Pairing PSK, and whether the method is enabled.
    ///
    /// Per-device and generated from a CSPRNG — never a shared default, which would let
    /// anyone pair with any such device. It survives pairing: a successful pairing produces
    /// a separate long-term PSK rather than consuming this one, so one Pairing PSK can pair
    /// a client with any number of servers.
    pub pairing_psk: Option<[u8; KEY_LEN]>,
    /// Whether the client admits a server with no pairing record.
    pub unpaired_access: bool,
}

impl PairingConfig {
    /// Pairing PSK enabled with a fresh key, unpaired access off.
    ///
    /// Every client implements the Pairing PSK method, so this provisions one. The
    /// unpaired-access default is the manufacturer's call; off is the conservative end,
    /// given such sessions are open to a man in the middle.
    ///
    /// There is deliberately no `Default` impl: generating a key can fail, and a `Default`
    /// that cannot report failure would have to invent one.
    pub fn generate() -> Result<Self, Error> {
        Ok(Self {
            pairing_psk: Some(random_psk()?),
            unpaired_access: false,
        })
    }

    /// A configuration with no pairing method enabled and no unpaired access.
    pub fn disabled() -> Self {
        Self {
            pairing_psk: None,
            unpaired_access: false,
        }
    }
}

/// Where a client keeps its pairing records and pairing configuration.
///
/// Deliberately synchronous. A record is written at most once per pairing, so the cost is
/// irrelevant next to the round trips around it, and a synchronous trait stays usable behind
/// `dyn` — which an async one does not. An implementation that must reach slow storage should
/// keep records in memory and flush behind itself rather than block here.
pub trait PairingStore: Send + Sync {
    /// Every record held.
    fn records(&self) -> Result<Vec<PairingRecord>, Error>;

    /// Persist a record. Replaces any existing record with the same `psk_id`.
    fn add_record(&self, record: PairingRecord) -> Result<(), Error>;

    /// Forget a record. Removing one that is not there is not an error.
    fn remove_record(&self, psk_id: &str) -> Result<(), Error>;

    /// The current pairing configuration.
    fn pairing_config(&self) -> Result<PairingConfig, Error>;

    /// Replace the pairing configuration.
    fn set_pairing_config(&self, config: PairingConfig) -> Result<(), Error>;

    /// Note that a record authenticated a connection, for stores that track usage.
    fn mark_record_used(&self, _psk_id: &str) -> Result<(), Error> {
        Ok(())
    }

    /// Whether there is room for another record.
    ///
    /// A client that cannot store one may still pair by asking for a shared-PSK record;
    /// returning `false` is how it says so.
    fn can_store_record(&self) -> Result<bool, Error> {
        Ok(true)
    }
}

/// The PSKs a store offers as handshake candidates, in the order they should be tried.
///
/// This is the whole candidate set and the reason it is built here rather than by callers:
/// the Sentinel PSK must be present for a first connection to be possible at all, the
/// Pairing PSK must be present *whenever the method is enabled* rather than only during a
/// pairing attempt — a server's re-handshake to it succeeds only if the client already
/// recognizes its `psk_id` — and a disabled method's key must be absent.
pub fn handshake_candidates(store: &dyn PairingStore) -> Result<Vec<Psk>, Error> {
    let config = store.pairing_config()?;
    let mut candidates: Vec<Psk> = store.records()?.iter().map(PairingRecord::as_psk).collect();
    if let Some(key) = config.pairing_psk {
        candidates.push(Psk::shared(key, PskCategory::Pairing));
    }
    candidates.push(Psk::sentinel());
    Ok(candidates)
}

/// Generate a 32-byte key from the OS CSPRNG.
///
/// Used for the Pairing PSK and for the long-term PSK a client delivers when pairing.
///
/// Fallible on purpose. A key generator that cannot reach its entropy source has exactly one
/// correct answer, and it is not "return something": a substitute derived from anything
/// predictable would be a long-term PSK an attacker can guess, and it would look like a
/// working pairing.
pub fn random_psk() -> Result<[u8; KEY_LEN], Error> {
    // Reuse the keypair generator's randomness rather than introducing a second source: the
    // private half of a fresh X25519 keypair is 32 CSPRNG bytes.
    super::keys::Identity::generate().map(|identity| *identity.private_key())
}

/// Decode a 43-character base64url PSK from the wire.
pub fn psk_from_wire(text: &str) -> Result<[u8; KEY_LEN], Error> {
    b64_decode(text)
}

/// Encode a PSK for the wire.
pub fn psk_to_wire(psk: &[u8; KEY_LEN]) -> String {
    b64_encode(psk)
}

/// A [`PairingStore`] that keeps everything in memory.
///
/// Loses its records when the process exits, so a real client wants something durable —
/// the identity and the pairing records are exactly what has to survive a reboot for a
/// pairing to still mean anything.
#[derive(Debug)]
pub struct InMemoryPairingStore {
    inner: parking_lot::Mutex<Inner>,
}

#[derive(Debug)]
struct Inner {
    records: HashMap<String, PairingRecord>,
    config: PairingConfig,
}

impl InMemoryPairingStore {
    /// An empty store with a freshly generated Pairing PSK.
    pub fn new() -> Result<Self, Error> {
        Ok(Self::with_config(PairingConfig::generate()?))
    }

    /// An empty store with an explicit configuration.
    pub fn with_config(config: PairingConfig) -> Self {
        Self {
            inner: parking_lot::Mutex::new(Inner {
                records: HashMap::new(),
                config,
            }),
        }
    }
}

impl PairingStore for InMemoryPairingStore {
    fn records(&self) -> Result<Vec<PairingRecord>, Error> {
        Ok(self.inner.lock().records.values().cloned().collect())
    }

    fn add_record(&self, record: PairingRecord) -> Result<(), Error> {
        self.inner
            .lock()
            .records
            .insert(record.psk_id.clone(), record);
        Ok(())
    }

    fn remove_record(&self, psk_id: &str) -> Result<(), Error> {
        self.inner.lock().records.remove(psk_id);
        Ok(())
    }

    fn pairing_config(&self) -> Result<PairingConfig, Error> {
        Ok(self.inner.lock().config.clone())
    }

    fn set_pairing_config(&self, config: PairingConfig) -> Result<(), Error> {
        self.inner.lock().config = config;
        Ok(())
    }
}

impl std::fmt::Debug for PairingConfigRedacted<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PairingConfig")
            .field("pairing_psk_enabled", &self.0.pairing_psk.is_some())
            .field("unpaired_access", &self.0.unpaired_access)
            .finish()
    }
}

/// Wrapper that renders a [`PairingConfig`] without its key material.
pub struct PairingConfigRedacted<'a>(pub &'a PairingConfig);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_record_derives_its_own_psk_id() {
        let key = [0x5Au8; KEY_LEN];
        let record = PairingRecord::shared(key);
        assert_eq!(
            record.psk_id(),
            Psk::shared(key, PskCategory::LongTerm).psk_id()
        );
    }

    #[test]
    fn a_stored_pubkey_record_only_accepts_its_own_server() {
        let record = PairingRecord::stored_pubkey([1u8; KEY_LEN], "server-a".to_string());
        let psk = record.as_psk();
        assert!(psk.accepts_server("server-a"));
        assert!(!psk.accepts_server("server-b"));
        assert_eq!(psk.category(), PskCategory::LongTerm);
    }

    #[test]
    fn a_shared_record_accepts_any_server() {
        let psk = PairingRecord::shared([2u8; KEY_LEN]).as_psk();
        assert!(psk.accepts_server("anyone"));
    }

    #[test]
    fn candidates_always_include_the_sentinel_psk() {
        // Without it a client could not accept a first connection at all.
        let store = InMemoryPairingStore::new().unwrap();
        let ids: Vec<String> = handshake_candidates(&store)
            .unwrap()
            .iter()
            .map(Psk::psk_id)
            .collect();
        assert!(ids.contains(&Psk::sentinel().psk_id()));
    }

    #[test]
    fn candidates_include_the_pairing_psk_while_the_method_is_enabled() {
        // The server may re-handshake to it at any time, not only during an attempt, and
        // that only works if the client already recognizes the psk_id.
        let key = [0x77u8; KEY_LEN];
        let store = InMemoryPairingStore::with_config(PairingConfig {
            pairing_psk: Some(key),
            unpaired_access: false,
        });
        let candidates = handshake_candidates(&store).unwrap();
        let pairing = candidates
            .iter()
            .find(|p| p.category() == PskCategory::Pairing)
            .expect("pairing PSK must be offered");
        assert_eq!(pairing.key(), &key);
    }

    #[test]
    fn a_disabled_pairing_method_is_not_a_candidate() {
        let store = InMemoryPairingStore::with_config(PairingConfig::disabled());
        let candidates = handshake_candidates(&store).unwrap();
        assert!(!candidates
            .iter()
            .any(|p| p.category() == PskCategory::Pairing));
    }

    #[test]
    fn stored_records_become_candidates() {
        let store = InMemoryPairingStore::new().unwrap();
        store
            .add_record(PairingRecord::stored_pubkey(
                [9u8; KEY_LEN],
                "s1".to_string(),
            ))
            .unwrap();
        let candidates = handshake_candidates(&store).unwrap();
        let long_term: Vec<_> = candidates
            .iter()
            .filter(|p| p.category() == PskCategory::LongTerm)
            .collect();
        assert_eq!(long_term.len(), 1);
        assert!(long_term[0].accepts_server("s1"));
    }

    #[test]
    fn adding_a_record_twice_replaces_rather_than_duplicates() {
        let store = InMemoryPairingStore::new().unwrap();
        let key = [3u8; KEY_LEN];
        store
            .add_record(PairingRecord::stored_pubkey(key, "s1".to_string()))
            .unwrap();
        store.add_record(PairingRecord::shared(key)).unwrap();
        let records = store.records().unwrap();
        assert_eq!(records.len(), 1, "same psk_id must not yield two records");
        assert_eq!(records[0].server_id(), None, "the later record wins");
    }

    #[test]
    fn removing_an_absent_record_is_not_an_error() {
        let store = InMemoryPairingStore::new().unwrap();
        assert!(store.remove_record("nope").is_ok());
    }

    #[test]
    fn a_default_config_provisions_a_pairing_psk() {
        // Every client implements the method, so a default that left it unset would make an
        // unpairable client by accident.
        let a = PairingConfig::generate().unwrap();
        let b = PairingConfig::generate().unwrap();
        assert!(a.pairing_psk.is_some());
        assert_ne!(
            a.pairing_psk, b.pairing_psk,
            "each device must get its own key, never a shared default"
        );
        assert!(!a.unpaired_access);
    }

    #[test]
    fn random_psks_do_not_repeat() {
        let a = random_psk().unwrap();
        assert_ne!(a, [0u8; KEY_LEN]);
        assert_ne!(a, random_psk().unwrap());
    }

    #[test]
    fn a_psk_round_trips_through_the_wire_form() {
        let key = [0x1Fu8; KEY_LEN];
        let wire = psk_to_wire(&key);
        assert_eq!(wire.len(), super::super::constants::B64_KEY_LEN);
        assert_eq!(psk_from_wire(&wire).unwrap(), key);
    }

    #[test]
    fn a_redacted_config_does_not_render_key_material() {
        let config = PairingConfig {
            pairing_psk: Some([0xABu8; KEY_LEN]),
            unpaired_access: true,
        };
        let rendered = format!("{:?}", PairingConfigRedacted(&config));
        assert!(rendered.contains("pairing_psk_enabled: true"));
        assert!(!rendered.contains("171"), "{rendered}");
    }
}
