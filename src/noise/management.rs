// ABOUTME: The management/* commands a paired server issues against this client's pairing
// ABOUTME: records and pairing config, and the pure handlers that answer them.

//! Management commands.
//!
//! A paired server with `management` in its activities may read and edit the pairing records
//! this client holds, and the pairing configuration around them. Every request is answered by
//! exactly one [`ManagementResult`]; at most one may be in flight per connection, which is why
//! no request identifier is carried — in-order WebSocket delivery makes the reply unambiguous.
//!
//! The handlers here are deliberately free of transport concerns. They take a store and a
//! payload and return the result to send plus a [`ManagementEffect`] telling the connection
//! what to do afterwards, so the whole surface is testable against an
//! [`InMemoryPairingStore`](crate::noise::InMemoryPairingStore).

use serde::{Deserialize, Serialize};

use super::trust_store::{psk_from_wire, PairingRecord, PairingStore};
use crate::error::Error;
use crate::protocol::messages::UnpairedAccess;

/// `server/unpair` — a paired server drops its own record and the connection ends.
///
/// Empty payload, and valid regardless of the current activities: a server revoking itself
/// should not need a management session to do it.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ServerUnpair {}

/// `management/list-records` — no payload fields.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ManagementListRecords {}

/// `management/add-record` — provision a record directly, without a pairing exchange.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManagementAddRecord {
    /// 43-character base64url 32-byte PSK, no padding.
    pub psk: String,
    /// Set for a stored-pubkey record; absent for a shared-PSK record.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_id: Option<String>,
}

/// `management/remove-record` — drop the record named by `psk_id`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManagementRemoveRecord {
    /// The record to remove.
    pub psk_id: String,
}

/// `management/get-pairing-config` — no payload fields.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ManagementGetPairingConfig {}

/// `management/open-pairing-window` — no payload fields.
///
/// Opens a pairing window in place of the operator gesture. Rejected as `invalid` while no
/// PIN method is enabled, which is this client's permanent answer until CPace lands.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ManagementOpenPairingWindow {}

/// The record mode: which shared-PSK record pairing falls back to when storage is full.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecordMode {
    /// The shared-PSK record used as the fallback.
    pub psk_id: String,
}

/// A patch on the Pairing PSK method. Absent fields are left unchanged.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SetPairingPsk {
    /// Whether the method is offered.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    /// Replacement Pairing PSK, 43-character base64url.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub psk: Option<String>,
}

/// A patch on the static-PIN method. Absent fields are left unchanged.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SetStaticPin {
    /// Whether the method is offered.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    /// Replacement static PIN, exactly 8 decimal digits.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pin: Option<String>,
    /// Only `false` is accepted, and it clears the lockout.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub locked_out: Option<bool>,
}

/// A patch on the dynamic-PIN method. Absent fields are left unchanged.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SetDynamicPin {
    /// Whether the method is offered.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    /// Only `false` is accepted, and it clears the lockout.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub locked_out: Option<bool>,
    /// Shortest dynamic PIN this client accepts, 4–12 digits.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_pin_length: Option<u8>,
}

/// A patch on unpaired access. Absent fields are left unchanged.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SetUnpairedAccess {
    /// Whether the client admits a server with no record.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
}

/// `management/set-pairing-config` — a patch, not a replacement.
///
/// Every absent field, including a whole absent method object, leaves the stored value alone.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ManagementSetPairingConfig {
    /// Pairing PSK method patch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pairing_psk: Option<SetPairingPsk>,
    /// Static PIN method patch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub static_pin: Option<SetStaticPin>,
    /// Dynamic PIN method patch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dynamic_pin: Option<SetDynamicPin>,
    /// Record mode patch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub record_mode: Option<RecordMode>,
    /// Unpaired access patch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unpaired_access: Option<SetUnpairedAccess>,
}

/// One entry in a `list-records` result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecordSummary {
    /// The record's identifier.
    pub psk_id: String,
    /// Set for a stored-pubkey record; absent for a shared-PSK record.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_id: Option<String>,
    /// Whether a server has authenticated a session with this record.
    pub used: bool,
}

/// One method's configuration in a `get-pairing-config` result. Secrets are never included.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairingMethodConfig {
    /// Whether the method is offered.
    pub enabled: bool,
    /// PIN methods only: whether the failure counter has escalated to gesture-gating.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub locked_out: Option<bool>,
    /// Dynamic PIN only: the shortest PIN this client accepts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_pin_length: Option<u8>,
}

/// Operation-specific data on a successful result.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ManagementResultData {
    /// `list-records` only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub records: Option<Vec<RecordSummary>>,
    /// `get-pairing-config` only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pairing_psk: Option<PairingMethodConfig>,
    /// `get-pairing-config`, and only when the client implements static PIN.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub static_pin: Option<PairingMethodConfig>,
    /// `get-pairing-config`, and only when the client implements dynamic PIN.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dynamic_pin: Option<PairingMethodConfig>,
    /// `get-pairing-config` only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub record_mode: Option<RecordMode>,
    /// `get-pairing-config` only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unpaired_access: Option<UnpairedAccess>,
}

/// Storage accounting attached to a result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageAccounting {
    /// Currently free space.
    pub free: u64,
    /// Total pool size. Present on `list-records` and `get-pairing-config`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capacity: Option<u64>,
    /// What a stored-pubkey record costs. Present on the same two.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cost_individual: Option<u64>,
    /// What a shared-PSK record costs. Present on the same two.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cost_shared: Option<u64>,
}

/// How a management request turned out.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ManagementResultCode {
    /// Completed, and any state change has been persisted.
    Ok,
    /// Issued outside a valid management session.
    PermissionDenied,
    /// Conflicts with something the client already holds.
    AlreadyExists,
    /// Malformed, out of range, missing a required field, or violating a constraint.
    Invalid,
    /// Names an identifier the client does not have.
    NotFound,
    /// Cannot be persisted: storage is full.
    StorageExhausted,
    /// A code this build does not know (forward compatibility).
    #[serde(other)]
    Unknown,
}

/// `management/result` — the single reply to any `management/*` request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManagementResult {
    /// The outcome.
    pub result: ManagementResultCode,
    /// Operation-specific payload, present only on `ok` and only where one is defined.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<ManagementResultData>,
    /// Storage accounting, on every result except `permission_denied`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub storage: Option<StorageAccounting>,
}

impl ManagementResult {
    /// A bare result code with no data.
    pub fn code(result: ManagementResultCode) -> Self {
        Self {
            result,
            data: None,
            storage: None,
        }
    }
}

/// What the connection does after sending the result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManagementEffect {
    /// Carry on.
    None,
    /// The requester removed its own record; close with `client/goodbye` reason
    /// `unauthorized` once the reply has flushed.
    GoodbyeUnauthorized,
}

/// The answer to one management request: what to send, and what to do next.
pub type Answer = (ManagementResult, ManagementEffect);

/// Handle `server/unpair`: drop the matched record, unless it is shared.
///
/// Three rules, all load-bearing. A shared-PSK record may back other servers, so revoking one
/// server must not take it away from the rest — only `management/remove-record` does that. A
/// connection whose trust level is `none` is mid-pairing and has nothing to revoke, so the
/// message is ignored. And the caller sends `client/goodbye` reason `unpaired` and closes
/// either way, because the server has said it is done regardless of what was stored.
pub fn handle_unpair(store: &dyn PairingStore, matched_psk_id: &str) -> Result<(), Error> {
    match store.record_by_psk_id(matched_psk_id)? {
        // Shared records survive; a stored-pubkey record is this server's alone.
        Some(record) if record.server_id().is_some() => store.remove_record(matched_psk_id),
        _ => Ok(()),
    }
}

/// Handle `management/list-records`.
pub fn handle_list_records(store: &dyn PairingStore) -> Result<Answer, Error> {
    let mut records: Vec<RecordSummary> = store
        .records()?
        .into_iter()
        .map(|record| RecordSummary {
            psk_id: record.psk_id().to_string(),
            server_id: record.server_id().map(str::to_string),
            used: record.used(),
        })
        .collect();
    // A store backed by a map has no order of its own; sorting keeps the reply reproducible.
    records.sort_by(|a, b| a.psk_id.cmp(&b.psk_id));
    Ok((
        ManagementResult {
            result: ManagementResultCode::Ok,
            data: Some(ManagementResultData {
                records: Some(records),
                ..Default::default()
            }),
            storage: None,
        },
        ManagementEffect::None,
    ))
}

/// Handle `management/add-record`.
pub fn handle_add_record(
    store: &dyn PairingStore,
    payload: &ManagementAddRecord,
) -> Result<Answer, Error> {
    let Ok(psk) = psk_from_wire(&payload.psk) else {
        return Ok(deny(ManagementResultCode::Invalid));
    };
    let record = match &payload.server_id {
        Some(server_id) => PairingRecord::stored_pubkey(psk, server_id.clone()),
        None => PairingRecord::shared(psk),
    };
    // A psk_id already known in *any* category collides: as a record, as the Sentinel PSK, or
    // as this client's own Pairing PSK. Silently replacing one would let a server overwrite
    // another server's access.
    if known_psk_id(store, record.psk_id())? {
        return Ok(deny(ManagementResultCode::AlreadyExists));
    }
    if !store.can_store_record()? {
        return Ok(deny(ManagementResultCode::StorageExhausted));
    }
    store.add_record(record)?;
    Ok(ok())
}

/// Handle `management/remove-record`.
pub fn handle_remove_record(
    store: &dyn PairingStore,
    payload: &ManagementRemoveRecord,
    requester_psk_id: Option<&str>,
) -> Result<Answer, Error> {
    if store.record_by_psk_id(&payload.psk_id)?.is_none() {
        return Ok(deny(ManagementResultCode::NotFound));
    }
    if !store.can_remove_record(&payload.psk_id)? {
        return Ok(deny(ManagementResultCode::Invalid));
    }
    // Removing the record that authenticated this very connection revokes the requester, so
    // the session cannot continue — but the reply goes out first.
    let effect = if requester_psk_id == Some(payload.psk_id.as_str()) {
        ManagementEffect::GoodbyeUnauthorized
    } else {
        ManagementEffect::None
    };
    store.remove_record(&payload.psk_id)?;
    Ok((ManagementResult::code(ManagementResultCode::Ok), effect))
}

/// Handle `management/get-pairing-config`.
///
/// A PIN method object is absent when the client does not implement the method, which is what
/// this client reports for both until CPace lands. Secrets are never returned: rotating one
/// goes through `set-pairing-config`.
pub fn handle_get_pairing_config(store: &dyn PairingStore) -> Result<Answer, Error> {
    let config = store.pairing_config()?;
    Ok((
        ManagementResult {
            result: ManagementResultCode::Ok,
            data: Some(ManagementResultData {
                pairing_psk: Some(PairingMethodConfig {
                    enabled: config.pairing_psk.is_some(),
                    locked_out: None,
                    min_pin_length: None,
                }),
                static_pin: None,
                dynamic_pin: None,
                record_mode: config
                    .record_mode_psk_id
                    .map(|psk_id| RecordMode { psk_id }),
                unpaired_access: Some(UnpairedAccess {
                    enabled: config.unpaired_access,
                }),
                ..Default::default()
            }),
            storage: None,
        },
        ManagementEffect::None,
    ))
}

/// Handle `management/set-pairing-config`.
///
/// Validation runs to completion before anything is written, so a patch that is rejected
/// halfway leaves no partial change behind.
pub fn handle_set_pairing_config(
    store: &dyn PairingStore,
    payload: &ManagementSetPairingConfig,
) -> Result<Answer, Error> {
    // A patch aimed at a method this client does not implement is invalid, not ignored: the
    // server asked for something that will never take effect and should hear so.
    if payload.static_pin.is_some() || payload.dynamic_pin.is_some() {
        return Ok(deny(ManagementResultCode::Invalid));
    }

    let mut config = store.pairing_config()?;
    let mut new_psk = None;
    if let Some(patch) = &payload.pairing_psk {
        if let Some(text) = &patch.psk {
            let Ok(psk) = psk_from_wire(text) else {
                return Ok(deny(ManagementResultCode::Invalid));
            };
            // The replacement must not collide with a record or the Sentinel PSK; colliding
            // with the *current* Pairing PSK is a no-op rotation, not a conflict.
            let psk_id = PairingRecord::shared(psk).psk_id().to_string();
            if known_psk_id(store, &psk_id)? {
                return Ok(deny(ManagementResultCode::AlreadyExists));
            }
            new_psk = Some(psk);
        }
    }
    if let Some(mode) = &payload.record_mode {
        if !is_shared_record(store, &mode.psk_id)? {
            return Ok(deny(ManagementResultCode::Invalid));
        }
    }

    // Everything above validated; nothing below can fail on the payload.
    if let Some(mode) = &payload.record_mode {
        config.record_mode_psk_id = Some(mode.psk_id.clone());
    }
    if let Some(patch) = &payload.unpaired_access {
        if let Some(enabled) = patch.enabled {
            config.unpaired_access = enabled;
        }
    }
    if let Some(patch) = &payload.pairing_psk {
        if let Some(psk) = new_psk {
            config.pairing_psk = Some(psk);
        }
        match patch.enabled {
            // Disabling drops the key: a disabled method's PSK must not stay in the handshake
            // candidate set, or a server could still pair against a method the operator
            // turned off.
            Some(false) => config.pairing_psk = None,
            Some(true) if config.pairing_psk.is_none() => {
                return Ok(deny(ManagementResultCode::Invalid))
            }
            _ => {}
        }
    }
    store.set_pairing_config(config)?;
    Ok(ok())
}

/// Handle `management/open-pairing-window`.
///
/// The window stands in for the operator gesture that gates a PIN pairing. With no PIN method
/// enabled there is nothing for it to gate, and the spec's answer is `invalid`.
pub fn handle_open_pairing_window() -> Answer {
    deny(ManagementResultCode::Invalid)
}

/// Attach storage accounting to a result, when the store reports any.
///
/// `free` rides on every result except `permission_denied`; the capacity and the per-kind
/// costs ride only on `list-records` and `get-pairing-config`, which is where a server needs
/// them to predict what will fit.
pub fn with_storage(
    result: &mut ManagementResult,
    store: &dyn PairingStore,
    include_static: bool,
) -> Result<(), Error> {
    if result.result == ManagementResultCode::PermissionDenied {
        return Ok(());
    }
    let Some(report) = store.storage_accounting()? else {
        return Ok(());
    };
    result.storage = Some(StorageAccounting {
        free: report.free,
        capacity: include_static.then_some(report.capacity),
        cost_individual: include_static.then_some(report.cost_individual),
        cost_shared: include_static.then_some(report.cost_shared),
    });
    Ok(())
}

/// Whether `psk_id` names something this client already holds, in any category.
fn known_psk_id(store: &dyn PairingStore, psk_id: &str) -> Result<bool, Error> {
    if store.record_by_psk_id(psk_id)?.is_some() {
        return Ok(true);
    }
    Ok(super::trust_store::handshake_candidates(store)?
        .iter()
        .any(|candidate| candidate.psk_id() == psk_id))
}

/// Whether `psk_id` names a shared-PSK record — the only kind record mode may point at.
fn is_shared_record(store: &dyn PairingStore, psk_id: &str) -> Result<bool, Error> {
    Ok(store
        .record_by_psk_id(psk_id)?
        .is_some_and(|record| record.server_id().is_none()))
}

/// A successful result with no data.
fn ok() -> Answer {
    (
        ManagementResult::code(ManagementResultCode::Ok),
        ManagementEffect::None,
    )
}

/// A rejection with no data.
fn deny(code: ManagementResultCode) -> Answer {
    (ManagementResult::code(code), ManagementEffect::None)
}
