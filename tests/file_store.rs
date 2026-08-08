// ABOUTME: The durable pairing store: what survives a restart, what refuses to start fresh,
// ABOUTME: and who is allowed to read the file it keeps secrets in.

//! A store is only worth having if a restart cannot lose or reset what it holds, so that is
//! what these check rather than the accessors.
//!
//! Two properties carry the weight:
//!
//! - The dynamic-PIN failure counter survives. A store that forgets it hands an attacker a
//!   fresh guessing budget for the price of a power cycle, which is the exact attack the
//!   counter exists to stop.
//! - Unreadable state is an error, not a reason to regenerate. Starting fresh would drop
//!   every pairing and reset that same counter, quietly.

use sendspin::noise::file_store::{load_or_create_identity, FilePairingStore};
use sendspin::noise::trust_store::{PairingConfig, PairingRecord, PairingStore};

/// A scratch directory that removes itself, so a failing test cannot leak secrets into /tmp.
struct TempDir(std::path::PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        let base = std::env::temp_dir().join(format!(
            "sendspin-file-store-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        Self(base)
    }

    fn path(&self, name: &str) -> std::path::PathBuf {
        self.0.join(name)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The property the whole file exists for: a pairing outlives the process that made it.
#[test]
fn records_and_config_survive_a_restart() {
    let dir = TempDir::new("survive");
    let path = dir.path("pairing.json");

    let psk = [7u8; 32];
    let psk_id = {
        let store = FilePairingStore::open(&path).unwrap();
        let record = PairingRecord::stored_pubkey(psk, "server-1".to_string());
        let psk_id = record.psk_id().to_string();
        store.add_record(record).unwrap();
        store
            .set_pairing_config(PairingConfig {
                unpaired_access: true,
                ..store.pairing_config().unwrap()
            })
            .unwrap();
        psk_id
    };

    // A second store over the same path is what a restart looks like.
    let reopened = FilePairingStore::open(&path).unwrap();
    let records = reopened.records().unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].psk_id(), psk_id);
    assert_eq!(records[0].server_id(), Some("server-1"));
    assert_eq!(records[0].as_psk().key(), &psk);
    assert!(reopened.pairing_config().unwrap().unpaired_access);
}

/// Ten wrong guesses then a power cycle must not buy ten more.
#[test]
fn the_dynamic_pin_failure_counter_survives_a_restart() {
    let dir = TempDir::new("failures");
    let path = dir.path("pairing.json");

    {
        let store = FilePairingStore::open(&path).unwrap();
        let config = store.pairing_config().unwrap();
        assert_eq!(config.dynamic_pin_failures, 0, "a fresh store has none");
        store
            .set_pairing_config(PairingConfig {
                dynamic_pin_failures: 9,
                ..config
            })
            .unwrap();
    }

    let reopened = FilePairingStore::open(&path).unwrap();
    assert_eq!(reopened.pairing_config().unwrap().dynamic_pin_failures, 9);
}

/// The Pairing PSK is generated once and kept, or every restart would invalidate the token an
/// operator was given.
#[test]
fn the_pairing_psk_is_generated_once_and_then_kept() {
    let dir = TempDir::new("psk");
    let path = dir.path("pairing.json");

    let first = FilePairingStore::open(&path)
        .unwrap()
        .pairing_config()
        .unwrap()
        .pairing_psk;
    let second = FilePairingStore::open(&path)
        .unwrap()
        .pairing_config()
        .unwrap()
        .pairing_psk;
    assert!(first.is_some());
    assert_eq!(first, second, "reopening must not mint a new key");
}

/// `used` is part of the record, and `management/list-records` reports it.
#[test]
fn a_record_marked_used_stays_used() {
    let dir = TempDir::new("used");
    let path = dir.path("pairing.json");

    let psk_id = {
        let store = FilePairingStore::open(&path).unwrap();
        let record = PairingRecord::shared([3u8; 32]);
        let psk_id = record.psk_id().to_string();
        store.add_record(record).unwrap();
        assert!(!store.records().unwrap()[0].used());
        store.mark_record_used(&psk_id).unwrap();
        psk_id
    };

    let reopened = FilePairingStore::open(&path).unwrap();
    assert!(reopened.records().unwrap()[0].used());
    // Marking an absent record is not an error, and must not invent one.
    reopened.mark_record_used("not-a-real-psk-id").unwrap();
    assert_eq!(reopened.records().unwrap().len(), 1);

    reopened.remove_record(&psk_id).unwrap();
    assert!(FilePairingStore::open(&path)
        .unwrap()
        .records()
        .unwrap()
        .is_empty());
}

/// Corrupt state fails loudly. Starting fresh would drop every pairing and reset the failure
/// counter — the two things this store exists to prevent — and would do it silently.
#[test]
fn unreadable_state_is_an_error_rather_than_a_fresh_start() {
    let dir = TempDir::new("corrupt");
    let path = dir.path("pairing.json");
    std::fs::write(&path, "{ this is not json").unwrap();
    assert!(FilePairingStore::open(&path).is_err());

    // A newer format is refused for the same reason: a field this build cannot see is a
    // field it would drop on the next write.
    let newer = dir.path("newer.json");
    std::fs::write(
        &newer,
        r#"{"version":99,"config":{"unpaired_access":false,"dynamic_pin_enabled":true,
           "dynamic_pin_min_length":6,"dynamic_pin_failures":0},"records":[]}"#,
    )
    .unwrap();
    assert!(FilePairingStore::open(&newer).is_err());
}

/// The identity is the `client_id` under the encrypted transport, so a new one every boot is a
/// new device to every server this one has paired with.
#[test]
fn the_identity_is_generated_once_and_then_loaded() {
    let dir = TempDir::new("identity");
    let path = dir.path("identity.key");

    let first = load_or_create_identity(&path).unwrap();
    let second = load_or_create_identity(&path).unwrap();
    assert_eq!(first.client_id(), second.client_id());
    assert_eq!(first.private_key(), second.private_key());
}

/// Long-term PSKs and a private key are owner-only, including a file that arrived otherwise.
#[cfg(unix)]
#[test]
fn secrets_are_not_readable_by_anyone_else() {
    use std::os::unix::fs::PermissionsExt;

    let dir = TempDir::new("perms");
    let store_path = dir.path("pairing.json");
    let key_path = dir.path("identity.key");

    let _store = FilePairingStore::open(&store_path).unwrap();
    let _identity = load_or_create_identity(&key_path).unwrap();
    for path in [&store_path, &key_path] {
        let mode = std::fs::metadata(path).unwrap().permissions().mode();
        assert_eq!(mode & 0o077, 0, "{} is readable by others", path.display());
    }

    // A file copied in from somewhere laxer is narrowed on open rather than trusted. Refusing
    // it outright would strand a working device; leaving it is not an option.
    std::fs::set_permissions(&store_path, std::fs::Permissions::from_mode(0o644)).unwrap();
    let _reopened = FilePairingStore::open(&store_path).unwrap();
    let mode = std::fs::metadata(&store_path).unwrap().permissions().mode();
    assert_eq!(mode & 0o077, 0, "a lax file was left lax");
}
