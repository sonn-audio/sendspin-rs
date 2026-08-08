// ABOUTME: The static and dynamic PIN pairing flows: the six messages they exchange, and
// ABOUTME: the client-side state machine that drives one attempt from activation to record.

//! PIN pairing flows.
//!
//! Two flows, one state machine. They differ in exactly two places: the dynamic flow adds a
//! `server/pair-init` carrying the server's nonce, and a commitment the client opens at the
//! end. Everything between — the CPace exchange and the mutual confirmation — is shared, so
//! it is written once and the differences are branches rather than a second implementation.
//!
//! ```text
//!            static PIN                       dynamic PIN
//!   --> client/pair-init              --> client/pair-init (commit_B)
//!                                     <-- server/pair-init (nonce_A)
//!                                         [client emits the derived PIN]
//!   <-- server/pair-auth  (Ya)        <-- server/pair-auth  (Ya)
//!   --> client/pair-auth  (Yb)        --> client/pair-auth  (Yb)
//!   <-- server/pair-confirm (Ta)      <-- server/pair-confirm (Ta)
//!   --> client/pair-confirm (Tb)      --> client/pair-confirm (Tb, nonce_B)
//!   --> client/pair-finalize (wrapped_psk), sent without waiting for a reply
//!   <-- server/pair-finalize          [only now does either side persist]
//! ```
//!
//! Two rules shape the whole thing and are easy to get backwards:
//!
//! - **The client verifies before it reveals.** `server_kc` is checked before
//!   `client/pair-confirm` goes out, so a server that does not know the PIN never receives a
//!   tag it could use offline.
//! - **A failed verification is not a protocol error.** It draws `pair/abort(pin_mismatch)`
//!   and leaves the connection open, because a mistyped PIN is an ordinary event. A
//!   malformed field or an unopened commitment *is* a protocol error, and closes the socket
//!   without an application-level message.

use serde::{Deserialize, Serialize};

use super::constants::KEY_LEN;
use super::cpace::{CPace, CPaceOutput, Role, SHARE_LEN, TAG_LEN};
use super::keys::{b64_decode_bytes, b64_encode_bytes};
use super::pairing::{ClientPairFinalize, PairAbortReason};
use super::pin;
use super::session::CipherSuite;
use super::trust_store::{random_psk, PairingRecord, PairingStore};
use crate::error::Error;
use crate::protocol::messages::PairMethod;

/// `client/pair-pending` — the attempt is gesture-gated and no window is open yet.
///
/// Does not start the attempt or its timeout; it exists so the server can tell "waiting for
/// a human" apart from "this client is not answering".
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientPairPending {
    /// Pairing activations received since the last Noise handshake.
    pub pairing_index: u32,
}

/// `client/pair-init` — starts the attempt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientPairInit {
    /// Pairing activations received since the last Noise handshake. Only a match starts the
    /// attempt; the server discards a lower value and treats a higher one as a protocol
    /// error.
    pub pairing_index: u32,
    /// The commitment to `nonce_B`. Dynamic PIN only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commit_b: Option<String>,
}

/// `server/pair-init` — the server's nonce. Dynamic PIN only.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerPairInit {
    /// 32 CSPRNG bytes, base64url.
    pub nonce_a: String,
}

/// `server/pair-auth` — the server's CPace public share.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerPairAuth {
    /// `Ya`, 32 bytes base64url.
    pub pake_msg_1: String,
}

/// `client/pair-auth` — the client's CPace public share.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientPairAuth {
    /// `Yb`, 32 bytes base64url.
    pub pake_msg_2: String,
}

/// `server/pair-confirm` — the server's MCF tag.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerPairConfirm {
    /// `Ta`, 64 bytes base64url.
    pub server_kc: String,
}

/// `client/pair-confirm` — the client's MCF tag, and the commitment's opening.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientPairConfirm {
    /// `Tb`, 64 bytes base64url.
    pub client_kc: String,
    /// The preimage of `commit_B`. Dynamic PIN only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nonce_b: Option<String>,
}

/// What the client does next in a PIN pairing attempt.
#[derive(Debug)]
pub enum PinStep {
    /// Send this message and wait for the next one from the server.
    Send(Box<crate::protocol::messages::Message>),
    /// Emit this PIN to the operator, then wait. Dynamic PIN only.
    ///
    /// The operator reads it off the device and types it into the server, which is what
    /// binds the pairing to the device in front of them.
    EmitPin(String),
    /// Send `client/pair-confirm` and then `client/pair-finalize` back to back, and persist
    /// the record once `server/pair-finalize` arrives — not before.
    Finalize {
        /// The confirmation, sent first.
        confirm: Box<ClientPairConfirm>,
        /// The wrapped PSK, sent immediately after without awaiting a reply.
        finalize: Box<ClientPairFinalize>,
        /// The record to persist on `server/pair-finalize`.
        record: Box<PairingRecord>,
    },
    /// Abort with this reason. The connection stays open unless the reason says otherwise.
    Abort(PairAbortReason),
    /// A protocol error: close the socket, send nothing, persist nothing.
    ProtocolError(String),
}

/// Where an attempt has got to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// Waiting for `server/pair-init` (dynamic) or `server/pair-auth` (static).
    Started,
    /// The PIN is known; waiting for `server/pair-auth`.
    PinKnown,
    /// `Yb` is out; waiting for `server/pair-confirm`.
    AwaitingConfirm,
    /// The attempt is over, one way or another.
    Done,
}

/// One client-side PIN pairing attempt.
///
/// Single-use: an attempt that aborts is finished, and a fresh activation starts a new one.
/// The client's nonce and CPace scalar never outlive it.
pub struct PinPairing {
    method: PairMethod,
    suite: CipherSuite,
    handshake_hash: [u8; 32],
    pairing_index: u32,
    pin_length: u8,
    server_id: String,
    /// The session id, fixed at construction because it binds this attempt to this
    /// connection.
    sid: Vec<u8>,
    /// The client's nonce, revealed only in `client/pair-confirm`. Dynamic PIN only.
    nonce_b: Option<[u8; pin::NONCE_LEN]>,
    /// The server's nonce, once it arrives. Dynamic PIN only.
    nonce_a: Option<[u8; pin::NONCE_LEN]>,
    /// The PIN both sides feed into CPace.
    pin: Option<String>,
    /// The CPace output, once the server's share has been ingested.
    output: Option<CPaceOutput>,
    phase: Phase,
}

impl PinPairing {
    /// Begin an attempt for a pairing activation.
    ///
    /// `pin_length` comes from the activation and is only meaningful for the dynamic flow;
    /// the caller checks it against its own minimum before getting here, because a value
    /// below that draws `pair/abort(pin_length_unacceptable)` rather than starting anything.
    ///
    /// `static_pin` is the configured secret and is required for the static flow.
    pub fn start(
        method: PairMethod,
        suite: CipherSuite,
        handshake_hash: [u8; 32],
        pairing_index: u32,
        pin_length: u8,
        server_id: &str,
        static_pin: Option<&str>,
    ) -> Result<(Self, ClientPairInit), Error> {
        let sid = pin::session_id(&handshake_hash, pairing_index);
        let mut attempt = Self {
            method,
            suite,
            handshake_hash,
            pairing_index,
            pin_length,
            server_id: server_id.to_string(),
            sid,
            nonce_b: None,
            nonce_a: None,
            pin: None,
            output: None,
            phase: Phase::Started,
        };

        let commit_b = match method {
            PairMethod::DynamicPin => {
                // Committed before any value from the server is known, which is the whole
                // point: after seeing nonce_A the client could otherwise search for a
                // nonce_B that steers the derived PIN somewhere convenient.
                let nonce = random_psk()?;
                attempt.nonce_b = Some(nonce);
                Some(b64_encode_bytes(&pin::commit(&nonce)))
            }
            PairMethod::StaticPin => {
                let pin_value = static_pin.ok_or_else(|| {
                    Error::Protocol("static PIN pairing needs a configured PIN".into())
                })?;
                if !pin::is_valid_static_pin(pin_value) {
                    return Err(Error::Protocol(
                        "the configured static PIN is not eight decimal digits".into(),
                    ));
                }
                attempt.pin = Some(pin_value.to_string());
                attempt.phase = Phase::PinKnown;
                None
            }
            other => {
                return Err(Error::Protocol(format!(
                    "{other:?} is not a PIN pairing method"
                )))
            }
        };

        Ok((
            attempt,
            ClientPairInit {
                pairing_index,
                commit_b,
            },
        ))
    }

    /// Handle `server/pair-init`: derive the PIN and hand it to the operator.
    pub fn on_server_pair_init(&mut self, message: &ServerPairInit) -> PinStep {
        if self.method != PairMethod::DynamicPin || self.phase != Phase::Started {
            return self.protocol_error("server/pair-init arrived out of sequence");
        }
        let Ok(nonce_a) = b64_decode_bytes::<{ pin::NONCE_LEN }>(&message.nonce_a) else {
            return self.protocol_error("server/pair-init nonce_A is not 32 base64url bytes");
        };
        let Some(nonce_b) = self.nonce_b else {
            return self.protocol_error("no client nonce for a dynamic PIN attempt");
        };

        match pin::derive_pin(&self.handshake_hash, &nonce_a, &nonce_b, self.pin_length) {
            Ok(pin_value) => {
                self.nonce_a = Some(nonce_a);
                self.pin = Some(pin_value.clone());
                self.phase = Phase::PinKnown;
                PinStep::EmitPin(pin_value)
            }
            Err(e) => self.protocol_error(&format!("could not derive the PIN: {e}")),
        }
    }

    /// Handle `server/pair-auth`: run this side of CPace and answer with `Yb`.
    pub fn on_server_pair_auth(&mut self, message: &ServerPairAuth) -> PinStep {
        if self.phase != Phase::PinKnown {
            return self.protocol_error("server/pair-auth arrived out of sequence");
        }
        let Ok(ya) = b64_decode_bytes::<SHARE_LEN>(&message.pake_msg_1) else {
            return self.protocol_error("server/pair-auth pake_msg_1 is not 32 base64url bytes");
        };
        let Some(pin_value) = self.pin.clone() else {
            return self.protocol_error("no PIN for the CPace run");
        };

        // The client is role B, and the PIN goes in as its literal decimal digits.
        let run = match CPace::start(
            Role::Responder,
            pin_value.as_bytes(),
            &self.sid,
            b"",
            pin::AD_CLIENT,
        ) {
            Ok(run) => run,
            Err(e) => return self.protocol_error(&format!("could not start CPace: {e}")),
        };
        let yb = *run.public_share();
        let output = match run.derive(&ya, pin::AD_SERVER) {
            Ok(output) => output,
            // A low-order or malformed share is a protocol error, not a wrong PIN: no
            // conformant server sends one.
            Err(e) => return self.protocol_error(&format!("server/pair-auth share: {e}")),
        };

        self.output = Some(output);
        self.phase = Phase::AwaitingConfirm;
        PinStep::Send(Box::new(
            crate::protocol::messages::Message::ClientPairAuth(ClientPairAuth {
                pake_msg_2: b64_encode_bytes(&yb),
            }),
        ))
    }

    /// Handle `server/pair-confirm`: verify the server's tag, then reveal this side's.
    ///
    /// Verifying first is what keeps a server that does not know the PIN from ever seeing
    /// `client_kc` — a tag it could otherwise take away and attack offline.
    pub fn on_server_pair_confirm(
        &mut self,
        message: &ServerPairConfirm,
        store: &dyn PairingStore,
    ) -> PinStep {
        if self.phase != Phase::AwaitingConfirm {
            return self.protocol_error("server/pair-confirm arrived out of sequence");
        }
        let Ok(server_kc) = b64_decode_bytes::<TAG_LEN>(&message.server_kc) else {
            return self.protocol_error("server/pair-confirm server_kc is not 64 base64url bytes");
        };
        let Some(output) = self.output.take() else {
            return self.protocol_error("no CPace output to confirm against");
        };

        if !output.verify(&server_kc) {
            // An ordinary wrong PIN. The connection stays open so the operator can retry,
            // and the caller increments the dynamic-PIN failure counter on this branch and
            // only this branch.
            self.phase = Phase::Done;
            return PinStep::Abort(PairAbortReason::PinMismatch);
        }

        let psk = match random_psk() {
            Ok(psk) => psk,
            Err(e) => return self.protocol_error(&format!("could not generate a PSK: {e}")),
        };
        let wrapped = match pin::wrap_psk(self.suite, &self.sid, &output.isk, &psk) {
            Ok(wrapped) => wrapped,
            Err(e) => return self.protocol_error(&format!("could not wrap the PSK: {e}")),
        };
        let record = match store.can_store_record() {
            Ok(true) => PairingRecord::stored_pubkey(psk, self.server_id.clone()),
            Ok(false) => PairingRecord::shared(psk),
            Err(e) => return self.protocol_error(&format!("could not read the store: {e}")),
        };

        self.phase = Phase::Done;
        PinStep::Finalize {
            confirm: Box::new(ClientPairConfirm {
                client_kc: b64_encode_bytes(&output.own_tag),
                // Revealed only now, and only for the dynamic flow.
                nonce_b: self.nonce_b.as_ref().map(b64_encode_bytes),
            }),
            finalize: Box::new(ClientPairFinalize {
                long_term_psk: None,
                wrapped_psk: Some(super::keys::b64_encode_slice(&wrapped)),
            }),
            record: Box::new(record),
        }
    }

    /// Whether this attempt's own verification of `server_kc` failed.
    ///
    /// The dynamic-PIN failure counter increments on exactly this event and resets on a
    /// success — not on an abort from the server, and not on a dropped connection.
    pub fn counts_as_failure(&self, step: &PinStep) -> bool {
        self.method == PairMethod::DynamicPin
            && matches!(step, PinStep::Abort(PairAbortReason::PinMismatch))
    }

    /// The pairing index this attempt belongs to.
    pub fn pairing_index(&self) -> u32 {
        self.pairing_index
    }

    /// End the attempt and report a protocol error.
    fn protocol_error(&mut self, reason: &str) -> PinStep {
        self.phase = Phase::Done;
        PinStep::ProtocolError(reason.to_string())
    }
}

/// The long-term PSK a wrapped `client/pair-finalize` carries, for a server or a test.
pub fn open_wrapped_psk(
    suite: CipherSuite,
    sid: &[u8],
    isk: &[u8; 64],
    wrapped_b64: &str,
) -> Result<[u8; KEY_LEN], Error> {
    let bytes = super::keys::b64_decode_slice(wrapped_b64)?;
    pin::unwrap_psk(suite, sid, isk, &bytes)
}
