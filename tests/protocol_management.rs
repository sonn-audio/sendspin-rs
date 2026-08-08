// ABOUTME: The management/* commands: the rules that decide each result code, and the wire
// ABOUTME: shapes they travel in. Pinned to the spec and to what aiosendspin implements.

use sendspin::noise::management::{
    handle_add_record, handle_get_pairing_config, handle_list_records, handle_open_pairing_window,
    handle_remove_record, handle_set_pairing_config, handle_unpair, with_storage,
    ManagementAddRecord, ManagementRemoveRecord, ManagementSetPairingConfig, RecordMode,
    SetDynamicPin, SetPairingPsk, SetStaticPin, SetUnpairedAccess,
};
use sendspin::noise::trust_store::{psk_to_wire, StorageReport};
use sendspin::noise::{
    InMemoryPairingStore, ManagementEffect, ManagementResultCode as Code, PairingConfig,
    PairingRecord, PairingStore, Psk,
};
use sendspin::protocol::messages::Message;
use std::sync::Arc;

/// A store with a Pairing PSK and no records, which is a freshly provisioned client.
fn store() -> Arc<dyn PairingStore> {
    Arc::new(InMemoryPairingStore::with_config(PairingConfig {
        pairing_psk: Some([7u8; 32]),
        unpaired_access: false,
        record_mode_psk_id: None,
        ..PairingConfig::disabled()
    }))
}

fn key(byte: u8) -> [u8; 32] {
    [byte; 32]
}

// =============================================================================
// Records
// =============================================================================

#[test]
fn list_records_reports_binding_and_use() {
    let store = store();
    store
        .add_record(PairingRecord::stored_pubkey(key(1), "server-a".to_string()))
        .unwrap();
    let shared = PairingRecord::shared(key(2));
    let shared_id = shared.psk_id().to_string();
    store.add_record(shared).unwrap();
    store.mark_record_used(&shared_id).unwrap();

    let (result, effect) = handle_list_records(store.as_ref()).unwrap();
    assert_eq!(result.result, Code::Ok);
    assert_eq!(effect, ManagementEffect::None);

    let records = result.data.unwrap().records.unwrap();
    assert_eq!(records.len(), 2);
    let shared = records.iter().find(|r| r.psk_id == shared_id).unwrap();
    // A shared-PSK record has no server_id; that absence is what makes it shared.
    assert!(shared.server_id.is_none());
    assert!(shared.used, "a record that keyed a session reports used");
    let bound = records.iter().find(|r| r.psk_id != shared_id).unwrap();
    assert_eq!(bound.server_id.as_deref(), Some("server-a"));
    assert!(!bound.used);
}

#[test]
fn add_record_accepts_both_kinds() {
    let store = store();
    let (result, _) = handle_add_record(
        store.as_ref(),
        &ManagementAddRecord {
            psk: psk_to_wire(&key(1)),
            server_id: Some("server-a".to_string()),
        },
    )
    .unwrap();
    assert_eq!(result.result, Code::Ok);

    let (result, _) = handle_add_record(
        store.as_ref(),
        &ManagementAddRecord {
            psk: psk_to_wire(&key(2)),
            server_id: None,
        },
    )
    .unwrap();
    assert_eq!(result.result, Code::Ok);
    assert_eq!(store.records().unwrap().len(), 2);
}

#[test]
fn add_record_rejects_a_psk_that_is_not_a_key() {
    let store = store();
    for bad in ["not base64!", "", &"A".repeat(10)] {
        let (result, _) = handle_add_record(
            store.as_ref(),
            &ManagementAddRecord {
                psk: bad.to_string(),
                server_id: None,
            },
        )
        .unwrap();
        assert_eq!(result.result, Code::Invalid, "accepted {bad:?}");
    }
}

/// A `psk_id` already known in *any* category collides — not just an existing record.
///
/// The Sentinel PSK is public, so a server offering it as a record would install a key
/// everyone holds; the client's own Pairing PSK is how it pairs with every *other* server.
/// Letting either be overwritten silently is how a management session turns into a downgrade.
#[test]
fn add_record_rejects_every_psk_the_client_already_knows() {
    let store = store();
    let existing = PairingRecord::shared(key(3));
    store.add_record(existing).unwrap();

    let collisions = [
        (psk_to_wire(&key(3)), "an existing record"),
        (psk_to_wire(&key(7)), "the client's own Pairing PSK"),
        (psk_to_wire(Psk::sentinel().key()), "the Sentinel PSK"),
    ];
    for (psk, what) in collisions {
        let (result, _) = handle_add_record(
            store.as_ref(),
            &ManagementAddRecord {
                psk,
                server_id: None,
            },
        )
        .unwrap();
        assert_eq!(result.result, Code::AlreadyExists, "accepted {what}");
    }
}

#[test]
fn remove_record_reports_a_psk_id_it_does_not_hold() {
    let store = store();
    let (result, effect) = handle_remove_record(
        store.as_ref(),
        &ManagementRemoveRecord {
            psk_id: "nope".to_string(),
        },
        None,
    )
    .unwrap();
    assert_eq!(result.result, Code::NotFound);
    assert_eq!(effect, ManagementEffect::None);
}

/// Removing the record that authenticated this connection revokes the requester.
///
/// The reply still goes out — the server asked, and gets its answer — but the session cannot
/// continue on a record that no longer exists.
#[test]
fn removing_your_own_record_ends_the_session() {
    let store = store();
    let record = PairingRecord::stored_pubkey(key(1), "server-a".to_string());
    let psk_id = record.psk_id().to_string();
    store.add_record(record).unwrap();

    let (result, effect) = handle_remove_record(
        store.as_ref(),
        &ManagementRemoveRecord {
            psk_id: psk_id.clone(),
        },
        Some(&psk_id),
    )
    .unwrap();
    assert_eq!(result.result, Code::Ok);
    assert_eq!(effect, ManagementEffect::GoodbyeUnauthorized);
    assert!(store.records().unwrap().is_empty());
}

#[test]
fn removing_someone_elses_record_leaves_the_session_alone() {
    let store = store();
    let mine = PairingRecord::stored_pubkey(key(1), "server-a".to_string());
    let mine_id = mine.psk_id().to_string();
    let theirs = PairingRecord::stored_pubkey(key(2), "server-b".to_string());
    let theirs_id = theirs.psk_id().to_string();
    store.add_record(mine).unwrap();
    store.add_record(theirs).unwrap();

    let (result, effect) = handle_remove_record(
        store.as_ref(),
        &ManagementRemoveRecord { psk_id: theirs_id },
        Some(&mine_id),
    )
    .unwrap();
    assert_eq!(result.result, Code::Ok);
    assert_eq!(effect, ManagementEffect::None);
}

/// The record mode's fallback cannot be removed while it is still referenced.
#[test]
fn a_record_the_record_mode_points_at_cannot_be_removed() {
    let shared = PairingRecord::shared(key(5));
    let psk_id = shared.psk_id().to_string();
    let store: Arc<dyn PairingStore> = Arc::new(InMemoryPairingStore::with_config(PairingConfig {
        pairing_psk: Some(key(7)),
        unpaired_access: false,
        record_mode_psk_id: Some(psk_id.clone()),
        ..PairingConfig::disabled()
    }));
    store.add_record(shared).unwrap();

    let (result, _) = handle_remove_record(
        store.as_ref(),
        &ManagementRemoveRecord {
            psk_id: psk_id.clone(),
        },
        None,
    )
    .unwrap();
    assert_eq!(result.result, Code::Invalid);
    assert_eq!(store.records().unwrap().len(), 1, "and it is still there");
}

// =============================================================================
// server/unpair
// =============================================================================

#[test]
fn unpair_drops_the_servers_own_record() {
    let store = store();
    let record = PairingRecord::stored_pubkey(key(1), "server-a".to_string());
    let psk_id = record.psk_id().to_string();
    store.add_record(record).unwrap();

    handle_unpair(store.as_ref(), &psk_id).unwrap();
    assert!(store.records().unwrap().is_empty());
}

/// A shared-PSK record may back other servers, so one server revoking itself must not take it
/// from the rest. Wholesale removal goes through `management/remove-record`.
#[test]
fn unpair_never_removes_a_shared_record() {
    let store = store();
    let shared = PairingRecord::shared(key(2));
    let psk_id = shared.psk_id().to_string();
    store.add_record(shared).unwrap();

    handle_unpair(store.as_ref(), &psk_id).unwrap();
    assert_eq!(store.records().unwrap().len(), 1);
}

// =============================================================================
// Pairing config
// =============================================================================

/// A PIN method object is absent when the client does not implement the method — which is
/// this client's answer for both until CPace lands. Secrets are never returned.
#[test]
fn get_pairing_config_omits_methods_that_are_not_implemented() {
    let store = store();
    let (result, _) = handle_get_pairing_config(store.as_ref()).unwrap();
    assert_eq!(result.result, Code::Ok);
    let data = result.data.unwrap();

    assert!(data.pairing_psk.unwrap().enabled);
    assert!(data.static_pin.is_none(), "static PIN is not implemented");
    assert!(data.dynamic_pin.is_none(), "dynamic PIN is not implemented");
    assert!(!data.unpaired_access.unwrap().enabled);

    let json = serde_json::to_string(&Message::ManagementResult(
        handle_get_pairing_config(store.as_ref()).unwrap().0,
    ))
    .unwrap();
    // The configured Pairing PSK is reported as enabled, never as its key material: rotating
    // a secret goes through set-pairing-config, and reading one back is not on offer.
    assert!(
        !json.contains(&psk_to_wire(&key(7))),
        "key material on the wire: {json}"
    );
}

#[test]
fn set_pairing_config_patches_only_what_it_names() {
    let store = store();
    let (result, _) = handle_set_pairing_config(
        store.as_ref(),
        &ManagementSetPairingConfig {
            unpaired_access: Some(SetUnpairedAccess {
                enabled: Some(true),
            }),
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(result.result, Code::Ok);

    let config = store.pairing_config().unwrap();
    assert!(config.unpaired_access, "the named field changed");
    assert_eq!(
        config.pairing_psk,
        Some(key(7)),
        "an absent field is left alone"
    );
}

#[test]
fn set_pairing_config_rotates_the_pairing_psk() {
    let store = store();
    let (result, _) = handle_set_pairing_config(
        store.as_ref(),
        &ManagementSetPairingConfig {
            pairing_psk: Some(SetPairingPsk {
                enabled: None,
                psk: Some(psk_to_wire(&key(9))),
            }),
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(result.result, Code::Ok);
    assert_eq!(store.pairing_config().unwrap().pairing_psk, Some(key(9)));
}

/// Disabling the method drops the key rather than parking it.
///
/// A disabled method's PSK must not stay in the handshake candidate set: a server naming it
/// should fail as a lookup miss, not pair against a method the operator turned off.
#[test]
fn disabling_the_pairing_psk_removes_the_key() {
    let store = store();
    let (result, _) = handle_set_pairing_config(
        store.as_ref(),
        &ManagementSetPairingConfig {
            pairing_psk: Some(SetPairingPsk {
                enabled: Some(false),
                psk: None,
            }),
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(result.result, Code::Ok);
    assert!(store.pairing_config().unwrap().pairing_psk.is_none());

    // And re-enabling with no key to enable is a request that cannot be honoured.
    let (result, _) = handle_set_pairing_config(
        store.as_ref(),
        &ManagementSetPairingConfig {
            pairing_psk: Some(SetPairingPsk {
                enabled: Some(true),
                psk: None,
            }),
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(result.result, Code::Invalid);
}

/// A patch aimed at a method this client does not implement is invalid, not ignored.
#[test]
fn set_pairing_config_rejects_pin_methods() {
    let store = store();
    let patches = [
        ManagementSetPairingConfig {
            static_pin: Some(SetStaticPin::default()),
            ..Default::default()
        },
        ManagementSetPairingConfig {
            dynamic_pin: Some(SetDynamicPin::default()),
            ..Default::default()
        },
    ];
    for patch in patches {
        let (result, _) = handle_set_pairing_config(store.as_ref(), &patch).unwrap();
        assert_eq!(result.result, Code::Invalid);
    }
}

/// `record_mode.psk_id` MUST name a shared-PSK record; the constraint is enforced here rather
/// than discovered later when a pairing tries to fall back onto it.
#[test]
fn record_mode_must_point_at_a_shared_record() {
    let store = store();
    let bound = PairingRecord::stored_pubkey(key(1), "server-a".to_string());
    let bound_id = bound.psk_id().to_string();
    let shared = PairingRecord::shared(key(2));
    let shared_id = shared.psk_id().to_string();
    store.add_record(bound).unwrap();
    store.add_record(shared).unwrap();

    for (psk_id, expected) in [
        (bound_id, Code::Invalid),
        ("missing".to_string(), Code::Invalid),
        (shared_id.clone(), Code::Ok),
    ] {
        let (result, _) = handle_set_pairing_config(
            store.as_ref(),
            &ManagementSetPairingConfig {
                record_mode: Some(RecordMode { psk_id }),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(result.result, expected);
    }
    assert_eq!(
        store.pairing_config().unwrap().record_mode_psk_id,
        Some(shared_id)
    );
}

/// The window stands in for the operator gesture that gates a PIN pairing. With no PIN method
/// there is nothing to gate.
#[test]
fn open_pairing_window_is_invalid_without_a_pin_method() {
    let (result, effect) = handle_open_pairing_window();
    assert_eq!(result.result, Code::Invalid);
    assert_eq!(effect, ManagementEffect::None);
}

// =============================================================================
// Storage accounting
// =============================================================================

/// A store that reports bounded storage, as a device with a fixed record slab would.
#[derive(Debug)]
struct BoundedStore(InMemoryPairingStore);

impl PairingStore for BoundedStore {
    fn records(&self) -> Result<Vec<PairingRecord>, sendspin::error::Error> {
        self.0.records()
    }
    fn add_record(&self, record: PairingRecord) -> Result<(), sendspin::error::Error> {
        self.0.add_record(record)
    }
    fn remove_record(&self, psk_id: &str) -> Result<(), sendspin::error::Error> {
        self.0.remove_record(psk_id)
    }
    fn pairing_config(&self) -> Result<PairingConfig, sendspin::error::Error> {
        self.0.pairing_config()
    }
    fn set_pairing_config(&self, config: PairingConfig) -> Result<(), sendspin::error::Error> {
        self.0.set_pairing_config(config)
    }
    fn can_store_record(&self) -> Result<bool, sendspin::error::Error> {
        Ok(self.0.records()?.len() < 2)
    }
    fn storage_accounting(&self) -> Result<Option<StorageReport>, sendspin::error::Error> {
        Ok(Some(StorageReport {
            capacity: 2,
            free: 2 - self.0.records()?.len() as u64,
            cost_individual: 1,
            cost_shared: 1,
        }))
    }
}

fn bounded() -> Arc<dyn PairingStore> {
    Arc::new(BoundedStore(InMemoryPairingStore::with_config(
        PairingConfig {
            pairing_psk: Some(key(7)),
            unpaired_access: false,
            record_mode_psk_id: None,
            ..PairingConfig::disabled()
        },
    )))
}

#[test]
fn a_full_store_refuses_another_record() {
    let store = bounded();
    for byte in 1..=2u8 {
        let (result, _) = handle_add_record(
            store.as_ref(),
            &ManagementAddRecord {
                psk: psk_to_wire(&key(byte)),
                server_id: None,
            },
        )
        .unwrap();
        assert_eq!(result.result, Code::Ok);
    }
    let (result, _) = handle_add_record(
        store.as_ref(),
        &ManagementAddRecord {
            psk: psk_to_wire(&key(3)),
            server_id: None,
        },
    )
    .unwrap();
    assert_eq!(result.result, Code::StorageExhausted);
}

/// `free` rides on every result; the capacity and per-kind costs ride only on the two reads a
/// server uses to plan ahead.
#[test]
fn storage_accounting_is_fuller_on_the_reads_that_plan_ahead() {
    let store = bounded();

    let (mut listed, _) = handle_list_records(store.as_ref()).unwrap();
    with_storage(&mut listed, store.as_ref(), true).unwrap();
    let storage = listed.storage.unwrap();
    assert_eq!(storage.free, 2);
    assert_eq!(storage.capacity, Some(2));
    assert_eq!(storage.cost_individual, Some(1));

    let (mut added, _) = handle_add_record(
        store.as_ref(),
        &ManagementAddRecord {
            psk: psk_to_wire(&key(1)),
            server_id: None,
        },
    )
    .unwrap();
    with_storage(&mut added, store.as_ref(), false).unwrap();
    let storage = added.storage.unwrap();
    assert_eq!(storage.free, 1, "and it reflects the record just written");
    assert!(storage.capacity.is_none());
    assert!(storage.cost_shared.is_none());
}

/// A store that cannot bound its storage reports nothing and lets `storage_exhausted` speak.
#[test]
fn an_unbounded_store_reports_no_accounting() {
    let store = store();
    let (mut result, _) = handle_list_records(store.as_ref()).unwrap();
    with_storage(&mut result, store.as_ref(), true).unwrap();
    assert!(result.storage.is_none());
}

/// `permission_denied` carries no accounting: it is the one result sent to a peer with no
/// business knowing how full this client is.
#[test]
fn permission_denied_carries_no_accounting() {
    let store = bounded();
    let mut denied = sendspin::noise::ManagementResult::code(Code::PermissionDenied);
    with_storage(&mut denied, store.as_ref(), true).unwrap();
    assert!(denied.storage.is_none());
}

// =============================================================================
// Wire shapes
// =============================================================================

#[test]
fn the_management_messages_use_the_names_the_spec_defines() {
    let cases = [
        (Message::ServerUnpair(Default::default()), "server/unpair"),
        (
            Message::ManagementListRecords(Default::default()),
            "management/list-records",
        ),
        (
            Message::ManagementGetPairingConfig(Default::default()),
            "management/get-pairing-config",
        ),
        (
            Message::ManagementOpenPairingWindow(Default::default()),
            "management/open-pairing-window",
        ),
        (
            Message::ManagementResult(sendspin::noise::ManagementResult::code(Code::Ok)),
            "management/result",
        ),
    ];
    for (message, name) in cases {
        let json = serde_json::to_string(&message).unwrap();
        assert!(json.contains(&format!(r#""type":"{name}""#)), "{json}");
    }
}

#[test]
fn a_bare_result_omits_its_optional_fields() {
    let json = serde_json::to_string(&Message::ManagementResult(
        sendspin::noise::ManagementResult::code(Code::Ok),
    ))
    .unwrap();
    assert_eq!(
        json,
        r#"{"type":"management/result","payload":{"result":"ok"}}"#
    );
}

/// An unknown result code must not take the whole message with it.
#[test]
fn an_unknown_result_code_does_not_lose_the_message() {
    let json = r#"{"type":"management/result","payload":{"result":"teapot"}}"#;
    match serde_json::from_str::<Message>(json).unwrap() {
        Message::ManagementResult(result) => assert_eq!(result.result, Code::Unknown),
        other => panic!("expected ManagementResult, got {other:?}"),
    }
}

/// An absent method object means "leave unchanged"; it must not deserialize into a default
/// patch that would then be applied.
#[test]
fn an_absent_method_object_stays_absent() {
    let json = r#"{"type":"management/set-pairing-config","payload":{}}"#;
    match serde_json::from_str::<Message>(json).unwrap() {
        Message::ManagementSetPairingConfig(patch) => {
            assert!(patch.pairing_psk.is_none());
            assert!(patch.static_pin.is_none());
            assert!(patch.record_mode.is_none());
            assert!(patch.unpaired_access.is_none());
        }
        other => panic!("expected ManagementSetPairingConfig, got {other:?}"),
    }
}
