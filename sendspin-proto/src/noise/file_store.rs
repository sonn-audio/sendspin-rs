// ABOUTME: A PairingStore that keeps records and configuration in a file, so a pairing and
// ABOUTME: the counters that protect it survive a restart.

//! Durable pairing state.
//!
//! [`InMemoryPairingStore`](crate::noise::trust_store::InMemoryPairingStore) forgets everything when
//! the process exits, which is fine for a test and wrong for a device: a pairing that does not
//! outlive a reboot never meant anything, and the dynamic-PIN failure counter forgetting
//! itself is exactly the reset an attacker wants — ten wrong guesses then a power cycle should
//! not buy ten more.
//!
//! Two things live here because they have the same lifetime and the same secrecy requirement:
//! the pairing state, and the static keypair whose public half *is* the `client_id` under the
//! encrypted transport. Losing either one loses the pairing.
//!
//! ```no_run
//! use sendspin_proto::noise::file_store::{load_or_create_identity, FilePairingStore};
//!
//! # fn main() -> Result<(), sendspin_proto::error::Error> {
//! let dir = std::path::Path::new("/var/lib/sendspin");
//! let identity = load_or_create_identity(&dir.join("identity.key"))?;
//! let store = FilePairingStore::open(dir.join("pairing.json"))?;
//! # Ok(())
//! # }
//! ```

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::keys::{b64_decode, b64_encode, Identity};
use super::trust_store::{PairingConfig, PairingRecord, PairingStore};
use crate::error::Error;

/// The on-disk shape, kept apart from the in-memory types on purpose.
///
/// A stored format is a compatibility surface and a struct layout is not; coupling them means
/// every internal rename is a migration. Every secret is base64 rather than raw bytes so the
/// file stays greppable and diffable when something has gone wrong.
#[derive(Debug, Serialize, Deserialize)]
struct StoredState {
    /// Format version, so a future change can be recognised rather than guessed at.
    version: u32,
    config: StoredConfig,
    #[serde(default)]
    records: Vec<StoredRecord>,
}

#[derive(Debug, Serialize, Deserialize)]
struct StoredConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pairing_psk: Option<String>,
    unpaired_access: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    static_pin: Option<String>,
    dynamic_pin_enabled: bool,
    dynamic_pin_min_length: u8,
    dynamic_pin_failures: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    record_mode_psk_id: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct StoredRecord {
    psk: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    server_id: Option<String>,
    #[serde(default)]
    used: bool,
}

/// The version this build writes.
const FORMAT_VERSION: u32 = 1;

impl StoredState {
    fn from_live(config: &PairingConfig, records: &[PairingRecord]) -> Self {
        Self {
            version: FORMAT_VERSION,
            config: StoredConfig {
                pairing_psk: config.pairing_psk.as_ref().map(b64_encode),
                unpaired_access: config.unpaired_access,
                static_pin: config.static_pin.clone(),
                dynamic_pin_enabled: config.dynamic_pin_enabled,
                dynamic_pin_min_length: config.dynamic_pin_min_length,
                dynamic_pin_failures: config.dynamic_pin_failures,
                record_mode_psk_id: config.record_mode_psk_id.clone(),
            },
            records: records
                .iter()
                .map(|record| StoredRecord {
                    psk: b64_encode(record.as_psk().key()),
                    server_id: record.server_id().map(str::to_string),
                    used: record.used(),
                })
                .collect(),
        }
    }

    fn into_live(self) -> Result<(PairingConfig, Vec<PairingRecord>), Error> {
        let config = PairingConfig {
            pairing_psk: self
                .config
                .pairing_psk
                .as_deref()
                .map(b64_decode)
                .transpose()?,
            unpaired_access: self.config.unpaired_access,
            static_pin: self.config.static_pin,
            dynamic_pin_enabled: self.config.dynamic_pin_enabled,
            dynamic_pin_min_length: self.config.dynamic_pin_min_length,
            dynamic_pin_failures: self.config.dynamic_pin_failures,
            record_mode_psk_id: self.config.record_mode_psk_id,
        };
        let records = self
            .records
            .into_iter()
            .map(|stored| {
                let psk = b64_decode(&stored.psk)?;
                let record = match stored.server_id {
                    Some(server_id) => PairingRecord::stored_pubkey(psk, server_id),
                    None => PairingRecord::shared(psk),
                };
                Ok(if stored.used {
                    record.into_used()
                } else {
                    record
                })
            })
            .collect::<Result<Vec<_>, Error>>()?;
        Ok((config, records))
    }
}

/// A [`PairingStore`] backed by a single JSON file.
///
/// State is held in memory and written through on every change, so a reader never sees a
/// half-applied update and a caller learns about a failed write instead of carrying on with
/// state the disk does not have. The file is replaced atomically and kept owner-only.
#[derive(Debug)]
pub struct FilePairingStore {
    path: PathBuf,
    inner: parking_lot::Mutex<Inner>,
}

#[derive(Debug)]
struct Inner {
    records: HashMap<String, PairingRecord>,
    config: PairingConfig,
}

impl FilePairingStore {
    /// Open the store at `path`, creating it with a freshly generated Pairing PSK if absent.
    ///
    /// Creates the parent directory as well. A file that exists but cannot be parsed is an
    /// error rather than a reason to start fresh: silently regenerating would drop every
    /// pairing this device holds and reset the failure counter, which is precisely the
    /// outcome the counter exists to prevent.
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, Error> {
        let path = path.into();
        if let Some(parent) = path.parent() {
            create_private_dir(parent)?;
        }
        let (config, records) = match std::fs::read_to_string(&path) {
            Ok(text) => {
                let stored: StoredState = serde_json::from_str(&text).map_err(|e| {
                    Error::Protocol(format!(
                        "{} is not readable pairing state: {e}",
                        path.display()
                    ))
                })?;
                if stored.version > FORMAT_VERSION {
                    return Err(Error::Protocol(format!(
                        "{} was written by a newer version (format {} > {FORMAT_VERSION})",
                        path.display(),
                        stored.version
                    )));
                }
                // A file written before a umask was tightened, or copied from elsewhere, is
                // narrowed on open rather than refused: refusing would strand a working
                // device, and leaving it is not an option when it holds long-term PSKs.
                restrict_permissions(&path)?;
                stored.into_live()?
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                (PairingConfig::generate()?, Vec::new())
            }
            Err(e) => {
                return Err(Error::Protocol(format!(
                    "could not read {}: {e}",
                    path.display()
                )))
            }
        };

        let store = Self {
            path,
            inner: parking_lot::Mutex::new(Inner {
                records: records
                    .into_iter()
                    .map(|record| (record.psk_id().to_string(), record))
                    .collect(),
                config,
            }),
        };
        // Written straight away so a first run fails here, where the operator is watching,
        // rather than at the moment a pairing completes and has nowhere to go.
        store.flush(&store.inner.lock())?;
        Ok(store)
    }

    /// The file this store is backed by.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Write the whole state out, replacing the file atomically.
    ///
    /// Temp file then rename, so a crash mid-write leaves the previous state intact rather
    /// than a truncated file that would fail to parse on the next boot.
    fn flush(&self, inner: &Inner) -> Result<(), Error> {
        let mut records: Vec<PairingRecord> = inner.records.values().cloned().collect();
        // Sorted so an unchanged store produces an unchanged file, which makes a backup
        // diff mean something.
        records.sort_by(|a, b| a.psk_id().cmp(b.psk_id()));
        let state = StoredState::from_live(&inner.config, &records);
        let json = serde_json::to_string_pretty(&state)
            .map_err(|e| Error::Protocol(format!("could not encode pairing state: {e}")))?;

        let temp = self.path.with_extension("tmp");
        write_private_file(&temp, json.as_bytes())?;
        std::fs::rename(&temp, &self.path).map_err(|e| {
            Error::Protocol(format!(
                "could not replace {} with {}: {e}",
                self.path.display(),
                temp.display()
            ))
        })
    }
}

impl PairingStore for FilePairingStore {
    fn records(&self) -> Result<Vec<PairingRecord>, Error> {
        Ok(self.inner.lock().records.values().cloned().collect())
    }

    fn add_record(&self, record: PairingRecord) -> Result<(), Error> {
        let mut inner = self.inner.lock();
        inner.records.insert(record.psk_id().to_string(), record);
        self.flush(&inner)
    }

    fn remove_record(&self, psk_id: &str) -> Result<(), Error> {
        let mut inner = self.inner.lock();
        inner.records.remove(psk_id);
        self.flush(&inner)
    }

    fn mark_record_used(&self, psk_id: &str) -> Result<(), Error> {
        let mut inner = self.inner.lock();
        let Some(record) = inner.records.remove(psk_id) else {
            return Ok(());
        };
        // Already used: put it back and skip the write, so an ordinary reconnect does not
        // rewrite the file on every handshake.
        if record.used() {
            inner.records.insert(psk_id.to_string(), record);
            return Ok(());
        }
        inner.records.insert(psk_id.to_string(), record.into_used());
        self.flush(&inner)
    }

    fn pairing_config(&self) -> Result<PairingConfig, Error> {
        Ok(self.inner.lock().config.clone())
    }

    fn set_pairing_config(&self, config: PairingConfig) -> Result<(), Error> {
        let mut inner = self.inner.lock();
        inner.config = config;
        self.flush(&inner)
    }
}

/// Load the static keypair at `path`, generating and storing one if it is not there.
///
/// Under the encrypted transport the public half of this key *is* the `client_id`, so a device
/// that mints a new one on every start looks like a new device to every server it has ever
/// paired with: it loses its group membership and its pairing together. That is the whole
/// reason this exists.
pub fn load_or_create_identity(path: impl AsRef<Path>) -> Result<Identity, Error> {
    let path = path.as_ref();
    if let Some(parent) = path.parent() {
        create_private_dir(parent)?;
    }
    match std::fs::read_to_string(path) {
        Ok(text) => {
            restrict_permissions(path)?;
            Ok(Identity::from_private_key(b64_decode(text.trim())?))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let identity = Identity::generate()?;
            let encoded = b64_encode(identity.private_key());
            let temp = path.with_extension("tmp");
            write_private_file(&temp, encoded.as_bytes())?;
            std::fs::rename(&temp, path)
                .map_err(|e| Error::Protocol(format!("could not write {}: {e}", path.display())))?;
            Ok(identity)
        }
        Err(e) => Err(Error::Protocol(format!(
            "could not read {}: {e}",
            path.display()
        ))),
    }
}

/// Create a directory only its owner can enter, if it is not already there.
fn create_private_dir(dir: &Path) -> Result<(), Error> {
    if dir.as_os_str().is_empty() {
        return Ok(());
    }
    std::fs::create_dir_all(dir)
        .map_err(|e| Error::Protocol(format!("could not create {}: {e}", dir.display())))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // 0700: the directory listing alone tells an attacker which servers this device has
        // paired with, before any file is opened.
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
            .map_err(|e| Error::Protocol(format!("could not secure {}: {e}", dir.display())))?;
    }
    Ok(())
}

/// Write `contents` to `path` such that only the owner can read it.
///
/// The permissions are set before the bytes are written, not after: a file created 0644 and
/// narrowed afterwards is readable for the window in between, and secrets do not get a window.
fn write_private_file(path: &Path, contents: &[u8]) -> Result<(), Error> {
    use std::io::Write;

    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .map_err(|e| Error::Protocol(format!("could not open {}: {e}", path.display())))?;
    file.write_all(contents)
        .map_err(|e| Error::Protocol(format!("could not write {}: {e}", path.display())))?;
    // Durable before the rename: otherwise a crash can leave the rename visible and the
    // contents not, which is the one outcome atomic replacement is meant to rule out.
    file.sync_all()
        .map_err(|e| Error::Protocol(format!("could not flush {}: {e}", path.display())))?;
    Ok(())
}

/// Narrow an existing file to owner-only.
fn restrict_permissions(path: &Path) -> Result<(), Error> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let current = std::fs::metadata(path)
            .map_err(|e| Error::Protocol(format!("could not stat {}: {e}", path.display())))?
            .permissions();
        if current.mode() & 0o077 != 0 {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).map_err(
                |e| Error::Protocol(format!("could not secure {}: {e}", path.display())),
            )?;
        }
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}
