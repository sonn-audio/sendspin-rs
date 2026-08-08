// ABOUTME: The Pairing PSK flow: the messages it exchanges, and the client-side driver
// ABOUTME: that turns a pairing activation into a persisted record.

use serde::{Deserialize, Serialize};

use super::constants::KEY_LEN;
use super::keys::PskCategory;
use super::trust_store::{psk_to_wire, random_psk, PairingRecord, PairingStore};
use crate::error::Error;
use crate::protocol::messages::PairMethod;

/// `client/pair-finalize` — delivers the long-term PSK for this (client, server) pair.
///
/// Exactly one field is present. The Pairing PSK flow carries the key directly, because the
/// handshake already authenticated both sides; the PIN flows carry it sealed under the PAKE
/// output, so a peer that cannot complete the PAKE cannot unwrap it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientPairFinalize {
    /// The new PSK, base64url with no padding. Pairing PSK flow only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub long_term_psk: Option<String>,
    /// The new PSK wrapped under the CPace output. PIN flows only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wrapped_psk: Option<String>,
}

impl ClientPairFinalize {
    /// Deliver a PSK directly, as the Pairing PSK flow does.
    pub fn direct(psk: &[u8; KEY_LEN]) -> Self {
        Self {
            long_term_psk: Some(psk_to_wire(psk)),
            wrapped_psk: None,
        }
    }
}

/// `server/pair-finalize` — the server has persisted its record.
///
/// Empty payload. Its arrival is the signal for the client to persist its own: doing so
/// earlier would leave a client holding a record for a pairing the server never completed.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ServerPairFinalize {}

/// `pair/abort` — ends a pairing attempt, started or not.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairAbort {
    /// Why the attempt ended.
    pub reason: PairAbortReason,
}

/// Why a pairing attempt was aborted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PairAbortReason {
    /// The attempt did not complete within the attempt timeout. Client only.
    AttemptTimeout,
    /// Another attempt is already in progress with this client. Client only.
    ///
    /// The one reason whose sender closes the connection afterwards.
    ConcurrentAttempt,
    /// The activity set and method are not a permitted combination for the matched PSK, or
    /// the method is one this client does not currently offer. Client only.
    MethodNotSupported,
    /// The activation's `pin_length` is below the client's minimum or outside 4–12.
    /// Client only.
    PinLengthUnacceptable,
    /// PAKE key confirmation failed, or the PIN binding check failed. Either side.
    PinMismatch,
    /// An operator aborted the pairing locally. Either side.
    UserCancelled,
    /// A reason this build does not know (forward compatibility).
    #[serde(other)]
    Unknown,
}

impl PairAbortReason {
    /// Whether the sender closes the connection after sending this reason.
    ///
    /// Only `concurrent_attempt` does; every other abort leaves the connection open so the
    /// server can re-activate or try a different method.
    pub fn closes_connection(self) -> bool {
        matches!(self, Self::ConcurrentAttempt)
    }
}

/// What the client should do about a pairing activation.
#[derive(Debug)]
pub enum PairingAction {
    /// Send this `client/pair-finalize`, then wait for `server/pair-finalize`.
    Finalize {
        /// The message to send.
        message: ClientPairFinalize,
        /// The record to persist once the server acknowledges — not before.
        record: PairingRecord,
    },
    /// Run a PIN pairing attempt for this method.
    ///
    /// The caller builds a [`PinPairing`](super::pin_flow::PinPairing) and drives it: this
    /// planner decides *whether* the attempt may start, and the flow decides what happens
    /// inside it.
    PinFlow(PairMethod),
    /// Abort with this reason. `closes_connection` says whether to hang up afterwards.
    Abort(PairAbortReason),
}

/// Decide what to do about a pairing activation for the Pairing PSK method.
///
/// `matched` is the category of the PSK that keyed *this connection*, and checking it is a
/// standing obligation rather than a formality: it is the receiving side of the invariant
/// that `pairing.method` is `pairing_psk` if and only if the matched PSK is the Pairing PSK.
/// A server that asks to pair over a Sentinel-keyed connection is asking the client to hand
/// a long-term key to a peer nothing has authenticated.
///
/// `can_store` decides which kind of record is produced: a client with no room for another
/// stored-pubkey record asks for a shared-PSK record instead of failing the pairing.
pub fn plan_pairing(
    method: PairMethod,
    matched: PskCategory,
    server_id: &str,
    store: &dyn PairingStore,
) -> Result<PairingAction, Error> {
    // The PIN flows key their PAKE off the connection rather than off a stored PSK, so they
    // are the one case where a Sentinel-keyed connection is the *expected* state: pairing
    // from scratch is exactly what they are for.
    if matches!(method, PairMethod::StaticPin | PairMethod::DynamicPin) {
        let config = store.pairing_config()?;
        let offered = match method {
            PairMethod::StaticPin => config.static_pin.is_some(),
            _ => config.dynamic_pin_enabled,
        };
        return Ok(if offered {
            PairingAction::PinFlow(method)
        } else {
            // Disabled since the hello advertised it. Declining by the spec's own route
            // leaves the connection open, so the server may offer another method.
            PairingAction::Abort(PairAbortReason::MethodNotSupported)
        });
    }
    if method != PairMethod::PairingPsk {
        return Ok(PairingAction::Abort(PairAbortReason::MethodNotSupported));
    }
    if matched != PskCategory::Pairing {
        return Ok(PairingAction::Abort(PairAbortReason::MethodNotSupported));
    }
    if store.pairing_config()?.pairing_psk.is_none() {
        // The operator disabled the method since the hello advertised it.
        return Ok(PairingAction::Abort(PairAbortReason::MethodNotSupported));
    }

    let psk = random_psk()?;
    let record = if store.can_store_record()? {
        PairingRecord::stored_pubkey(psk, server_id.to_string())
    } else {
        PairingRecord::shared(psk)
    };
    Ok(PairingAction::Finalize {
        message: ClientPairFinalize::direct(&psk),
        record,
    })
}

#[cfg(test)]
mod tests {
    use super::super::trust_store::{InMemoryPairingStore, PairingConfig};
    use super::*;

    /// A store that has no room for another record, to exercise the shared-PSK fallback.
    struct FullStore(InMemoryPairingStore);

    impl PairingStore for FullStore {
        fn records(&self) -> Result<Vec<PairingRecord>, Error> {
            self.0.records()
        }
        fn add_record(&self, record: PairingRecord) -> Result<(), Error> {
            self.0.add_record(record)
        }
        fn remove_record(&self, psk_id: &str) -> Result<(), Error> {
            self.0.remove_record(psk_id)
        }
        fn pairing_config(&self) -> Result<PairingConfig, Error> {
            self.0.pairing_config()
        }
        fn set_pairing_config(&self, config: PairingConfig) -> Result<(), Error> {
            self.0.set_pairing_config(config)
        }
        fn can_store_record(&self) -> Result<bool, Error> {
            Ok(false)
        }
    }

    #[test]
    fn a_pairing_psk_activation_produces_a_bound_record() {
        let store = InMemoryPairingStore::new().unwrap();
        let action = plan_pairing(
            PairMethod::PairingPsk,
            PskCategory::Pairing,
            "server-1",
            &store,
        )
        .unwrap();
        let PairingAction::Finalize { message, record } = action else {
            panic!("expected to finalize, got {action:?}");
        };
        assert!(message.long_term_psk.is_some());
        assert!(message.wrapped_psk.is_none(), "the PSK flow does not wrap");
        assert_eq!(record.server_id(), Some("server-1"));
        // The delivered key and the stored record must be the same key, or the next
        // handshake fails in a way that is very hard to read from either end.
        let delivered =
            super::super::trust_store::psk_from_wire(message.long_term_psk.as_ref().unwrap())
                .unwrap();
        assert_eq!(record.psk_id(), PairingRecord::shared(delivered).psk_id());
    }

    #[test]
    fn pairing_over_a_sentinel_connection_is_refused() {
        // The invariant that matters: pairing_psk implies the Pairing PSK matched. Handing a
        // long-term key to a peer authenticated by a published constant defeats the point.
        let store = InMemoryPairingStore::new().unwrap();
        let action =
            plan_pairing(PairMethod::PairingPsk, PskCategory::Sentinel, "s", &store).unwrap();
        assert!(matches!(
            action,
            PairingAction::Abort(PairAbortReason::MethodNotSupported)
        ));
    }

    #[test]
    fn pairing_over_a_long_term_connection_is_refused() {
        let store = InMemoryPairingStore::new().unwrap();
        let action =
            plan_pairing(PairMethod::PairingPsk, PskCategory::LongTerm, "s", &store).unwrap();
        assert!(matches!(
            action,
            PairingAction::Abort(PairAbortReason::MethodNotSupported)
        ));
    }

    /// A PIN method the client offers routes into its flow, whatever keyed the connection.
    ///
    /// This is the one case where a Sentinel-keyed connection is the *expected* state: the
    /// PIN flows key their PAKE off the connection rather than off a stored PSK, so pairing
    /// from scratch is exactly what they are for.
    #[test]
    fn an_offered_pin_method_routes_into_its_flow() {
        let store = InMemoryPairingStore::new().unwrap();
        for matched in [PskCategory::Sentinel, PskCategory::Pairing] {
            let action = plan_pairing(PairMethod::DynamicPin, matched, "s", &store).unwrap();
            assert!(
                matches!(action, PairingAction::PinFlow(PairMethod::DynamicPin)),
                "got {action:?} for {matched:?}"
            );
        }
    }

    /// A PIN method the client does not offer is declined, and the connection lives.
    ///
    /// The default configuration has no static PIN: it is factory-provisioned per device,
    /// and there is nothing this crate could invent that would not be a shared default.
    #[test]
    fn an_unoffered_pin_method_is_declined_without_dropping_the_connection() {
        let store = InMemoryPairingStore::new().unwrap();
        let action =
            plan_pairing(PairMethod::StaticPin, PskCategory::Pairing, "s", &store).unwrap();
        let PairingAction::Abort(reason) = action else {
            panic!("expected an abort, got {action:?}");
        };
        assert_eq!(reason, PairAbortReason::MethodNotSupported);
        assert!(
            !reason.closes_connection(),
            "declining a method must leave the connection open"
        );
    }

    #[test]
    fn a_configured_static_pin_makes_the_method_offerable() {
        let store = InMemoryPairingStore::with_config(PairingConfig {
            static_pin: Some("12345678".to_string()),
            ..PairingConfig::disabled()
        });
        let action =
            plan_pairing(PairMethod::StaticPin, PskCategory::Sentinel, "s", &store).unwrap();
        assert!(matches!(
            action,
            PairingAction::PinFlow(PairMethod::StaticPin)
        ));
    }

    #[test]
    fn a_method_disabled_since_the_hello_is_refused() {
        let store = InMemoryPairingStore::with_config(PairingConfig::disabled());
        let action =
            plan_pairing(PairMethod::PairingPsk, PskCategory::Pairing, "s", &store).unwrap();
        assert!(matches!(
            action,
            PairingAction::Abort(PairAbortReason::MethodNotSupported)
        ));
    }

    #[test]
    fn a_client_with_no_room_asks_for_a_shared_record() {
        let store = FullStore(InMemoryPairingStore::new().unwrap());
        let action = plan_pairing(
            PairMethod::PairingPsk,
            PskCategory::Pairing,
            "server-1",
            &store,
        )
        .unwrap();
        let PairingAction::Finalize { record, .. } = action else {
            panic!("expected to finalize");
        };
        assert_eq!(
            record.server_id(),
            None,
            "no capacity means a shared-PSK record, not a failed pairing"
        );
    }

    #[test]
    fn only_concurrent_attempt_closes_the_connection() {
        assert!(PairAbortReason::ConcurrentAttempt.closes_connection());
        for reason in [
            PairAbortReason::AttemptTimeout,
            PairAbortReason::MethodNotSupported,
            PairAbortReason::PinLengthUnacceptable,
            PairAbortReason::PinMismatch,
            PairAbortReason::UserCancelled,
            PairAbortReason::Unknown,
        ] {
            assert!(!reason.closes_connection(), "{reason:?}");
        }
    }

    #[test]
    fn abort_reasons_use_the_spec_spellings() {
        assert_eq!(
            serde_json::to_string(&PairAbortReason::MethodNotSupported).unwrap(),
            "\"method_not_supported\""
        );
        assert_eq!(
            serde_json::to_string(&PairAbortReason::PinLengthUnacceptable).unwrap(),
            "\"pin_length_unacceptable\""
        );
        // An unknown reason must not fail the message it arrives in.
        let parsed: PairAbortReason = serde_json::from_str("\"something_new\"").unwrap();
        assert_eq!(parsed, PairAbortReason::Unknown);
    }

    #[test]
    fn finalize_serializes_only_the_field_it_carries() {
        let json = serde_json::to_string(&ClientPairFinalize::direct(&[7u8; KEY_LEN])).unwrap();
        assert!(json.contains("long_term_psk"));
        assert!(!json.contains("wrapped_psk"), "{json}");
    }
}
