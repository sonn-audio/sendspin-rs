// ABOUTME: The seam between protocol logic and the WebSocket: either frames pass through
// ABOUTME: as-is, or they travel as Noise ciphertexts in binary frames.

use tokio_tungstenite::tungstenite::Message as WsMessage;

use crate::error::Error;
use crate::noise::constants::MSG_TYPE_JSON_BODY;
use crate::noise::wire::{frame, Reassembler};
use crate::noise::NoiseSession;

/// A message the protocol wants to send, before it is known how it travels.
#[derive(Debug, Clone)]
pub(crate) enum Outbound {
    /// A JSON message body.
    Json(String),
    /// A binary role frame, message-type byte included.
    Binary(Vec<u8>),
}

/// A message that arrived, after the transport has unwrapped it.
#[derive(Debug)]
pub(crate) enum Inbound {
    /// A JSON message body.
    Json(String),
    /// A binary role frame, message-type byte included — the shape
    /// [`BinaryFrame::from_bytes`](crate::protocol::client::BinaryFrame::from_bytes) reads.
    Binary(Vec<u8>),
}

/// How this connection carries messages.
///
/// Under encryption every message becomes a WebSocket *binary* frame whose payload is a
/// Noise transport ciphertext, and the message-type byte moves inside the AEAD plaintext.
/// Keeping both shapes behind one type means the protocol logic above does not branch on
/// it: it hands over an [`Outbound`] and gets back [`Inbound`]s.
///
/// Noise keys both directions from one state object, so a single session is shared between
/// the reader and the writer. That is a lock on the send path, which is low-rate — the
/// high-rate direction is inbound audio, and it is decrypted on the socket task, never on
/// the audio thread.
pub(crate) enum Transport {
    /// Transition-mode: JSON in text frames, role data in binary frames, no encryption.
    ///
    /// Not a mode the current spec defines. It reaches servers that still send the legacy
    /// `server/hello`, and exists for exactly as long as those are around.
    Plain,
    /// The spec's transport: everything inside Noise.
    Encrypted {
        /// The transport-mode session.
        session: Box<NoiseSession>,
        /// Reassembly state for inbound fragmented messages.
        reassembler: Reassembler,
    },
}

impl Transport {
    /// An encrypted transport over a session that has reached transport mode.
    pub(crate) fn encrypted(session: NoiseSession) -> Result<Self, Error> {
        if !session.in_transport_mode() {
            return Err(Error::Protocol(
                "Noise session must be in transport mode before carrying messages".to_string(),
            ));
        }
        Ok(Self::Encrypted {
            session: Box::new(session),
            reassembler: Reassembler::new(),
        })
    }

    /// Whether this connection is encrypted.
    pub(crate) fn is_encrypted(&self) -> bool {
        matches!(self, Self::Encrypted { .. })
    }

    /// The current session's handshake hash — the prologue for a re-handshake.
    pub(crate) fn handshake_hash(&self) -> Result<[u8; 32], Error> {
        match self {
            Self::Plain => Err(Error::Protocol(
                "an unencrypted connection has no handshake to re-run".to_string(),
            )),
            Self::Encrypted { session, .. } => session.handshake_hash(),
        }
    }

    /// Replace the session after a re-handshake.
    ///
    /// Reassembly state is dropped with the old session, which is correct: no other message
    /// flows during the exchange, so nothing can be half-reassembled across it, and carrying
    /// a buffer over would mean carrying it across a key change.
    pub(crate) fn swap_session(&mut self, new_session: NoiseSession) -> Result<(), Error> {
        match self {
            Self::Plain => Err(Error::Protocol(
                "cannot install a Noise session on an unencrypted connection".to_string(),
            )),
            Self::Encrypted {
                session,
                reassembler,
            } => {
                if !new_session.in_transport_mode() {
                    return Err(Error::Protocol(
                        "the replacement session must be in transport mode".to_string(),
                    ));
                }
                **session = new_session;
                *reassembler = Reassembler::new();
                Ok(())
            }
        }
    }

    /// Turn one outbound message into the WebSocket frames that carry it.
    ///
    /// More than one frame comes back when the message had to be fragmented.
    pub(crate) fn encode(&mut self, outbound: Outbound) -> Result<Vec<WsMessage>, Error> {
        match self {
            Self::Plain => Ok(vec![match outbound {
                Outbound::Json(json) => WsMessage::Text(json.into()),
                Outbound::Binary(bytes) => WsMessage::Binary(bytes.into()),
            }]),
            Self::Encrypted { session, .. } => {
                let (msg_type, payload) = match &outbound {
                    Outbound::Json(json) => (MSG_TYPE_JSON_BODY, json.as_bytes()),
                    Outbound::Binary(bytes) => {
                        let (&first, rest) = bytes.split_first().ok_or_else(|| {
                            Error::Protocol("binary frame carried no message type".to_string())
                        })?;
                        (first, rest)
                    }
                };
                let mut out = Vec::new();
                for plaintext in frame(msg_type, payload)? {
                    out.push(WsMessage::Binary(session.encrypt(&plaintext)?.into()));
                }
                Ok(out)
            }
        }
    }

    /// Unwrap one WebSocket frame.
    ///
    /// `None` means the frame carried nothing for the protocol above — a ping, or a
    /// fragment that does not complete a message yet.
    pub(crate) fn decode(&mut self, message: &WsMessage) -> Result<Option<Inbound>, Error> {
        match self {
            Self::Plain => match message {
                WsMessage::Text(text) => Ok(Some(Inbound::Json(text.to_string()))),
                WsMessage::Binary(bytes) => Ok(Some(Inbound::Binary(bytes.to_vec()))),
                _ => Ok(None),
            },
            Self::Encrypted {
                session,
                reassembler,
            } => match message {
                WsMessage::Binary(bytes) => {
                    // An AEAD failure is fatal by spec: Noise's per-direction counter means
                    // a repeated or reordered frame cannot authenticate, so there is nothing
                    // to recover by skipping it.
                    let plaintext = session.decrypt(bytes)?;
                    match reassembler.accept(&plaintext)? {
                        None => Ok(None),
                        Some(frame) if frame.msg_type == MSG_TYPE_JSON_BODY => {
                            let json = String::from_utf8(frame.payload).map_err(|e| {
                                Error::Protocol(format!("JSON body was not valid UTF-8: {e}"))
                            })?;
                            Ok(Some(Inbound::Json(json)))
                        }
                        Some(frame) => {
                            // Hand the role frame back in wire shape, so the binary parsers
                            // above are identical on both transports.
                            let mut bytes = Vec::with_capacity(1 + frame.payload.len());
                            bytes.push(frame.msg_type);
                            bytes.extend_from_slice(&frame.payload);
                            Ok(Some(Inbound::Binary(bytes)))
                        }
                    }
                }
                // Once encrypted, a text frame is a protocol violation rather than a
                // fallback: cleartext after the handshake is exactly what encryption is
                // there to prevent.
                WsMessage::Text(_) => Err(Error::Protocol(
                    "received a cleartext text frame on an encrypted connection".to_string(),
                )),
                _ => Ok(None),
            },
        }
    }
}

impl std::fmt::Debug for Transport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Plain => f.write_str("Transport::Plain"),
            Self::Encrypted { .. } => f.write_str("Transport::Encrypted"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::noise::{CipherSuite, Identity, Psk};

    /// Two transports keyed as a matched pair, for round-tripping in both directions.
    fn encrypted_pair() -> (Transport, Transport) {
        let client = Identity::generate().unwrap();
        let server = Identity::generate().unwrap();
        let psk = Psk::sentinel();
        let prologue = b"test-prologue";

        let mut initiator = NoiseSession::initiator(
            CipherSuite::ChaChaPoly,
            server.private_key(),
            client.public_key(),
            prologue,
            psk.key(),
        )
        .unwrap();
        let mut responder = NoiseSession::responder(
            CipherSuite::ChaChaPoly,
            &client,
            server.public_key(),
            prologue,
            psk.key(),
        )
        .unwrap();

        let msg1 = initiator.write_handshake(br#"{"psk_id":"x"}"#).unwrap();
        responder.read_handshake(&msg1).unwrap();
        let msg2 = responder.write_handshake(b"{}").unwrap();
        initiator.read_handshake(&msg2).unwrap();
        responder.into_transport_mode().unwrap();
        initiator.into_transport_mode().unwrap();

        (
            Transport::encrypted(responder).unwrap(),
            Transport::encrypted(initiator).unwrap(),
        )
    }

    #[test]
    fn plain_passes_frames_through_unchanged() {
        let mut t = Transport::Plain;
        assert!(!t.is_encrypted());
        let frames = t.encode(Outbound::Json("{\"a\":1}".to_string())).unwrap();
        assert!(matches!(frames.as_slice(), [WsMessage::Text(_)]));
        let frames = t.encode(Outbound::Binary(vec![4, 1, 2])).unwrap();
        assert!(matches!(frames.as_slice(), [WsMessage::Binary(_)]));
    }

    #[test]
    fn a_json_message_round_trips_encrypted() {
        let (mut client, mut server) = encrypted_pair();
        assert!(client.is_encrypted());
        let json = r#"{"type":"client/hello","payload":{"name":"x"}}"#;
        let frames = client.encode(Outbound::Json(json.to_string())).unwrap();
        assert_eq!(frames.len(), 1);
        // The wire must be a binary frame, and must not contain the cleartext.
        let WsMessage::Binary(ref bytes) = frames[0] else {
            panic!("encrypted JSON must travel as a binary frame");
        };
        assert!(!bytes.windows(6).any(|w| w == b"client"));

        match server.decode(&frames[0]).unwrap() {
            Some(Inbound::Json(got)) => assert_eq!(got, json),
            other => panic!("expected JSON, got {other:?}"),
        }
    }

    #[test]
    fn a_binary_role_frame_keeps_its_type_byte() {
        let (mut client, mut server) = encrypted_pair();
        let mut payload = vec![12u8]; // source audio
        payload.extend_from_slice(&[0xAA; 64]);
        let frames = client.encode(Outbound::Binary(payload.clone())).unwrap();
        match server.decode(&frames[0]).unwrap() {
            Some(Inbound::Binary(got)) => assert_eq!(got, payload),
            other => panic!("expected binary, got {other:?}"),
        }
    }

    #[test]
    fn a_large_message_fragments_and_reassembles() {
        let (mut client, mut server) = encrypted_pair();
        let mut payload = vec![4u8];
        payload.extend((0..200_000).map(|i| (i % 251) as u8));
        let frames = client.encode(Outbound::Binary(payload.clone())).unwrap();
        assert!(frames.len() > 1, "should fragment");

        let mut delivered = None;
        for f in &frames {
            if let Some(inbound) = server.decode(f).unwrap() {
                delivered = Some(inbound);
            }
        }
        match delivered {
            Some(Inbound::Binary(got)) => assert_eq!(got, payload),
            other => panic!("expected the reassembled frame, got {other:?}"),
        }
    }

    #[test]
    fn a_text_frame_on_an_encrypted_connection_is_refused() {
        let (mut client, _) = encrypted_pair();
        let err = client
            .decode(&WsMessage::Text("{}".into()))
            .expect_err("cleartext must be refused");
        assert!(format!("{err}").contains("cleartext text frame"), "{err}");
    }

    #[test]
    fn pings_carry_nothing_for_the_protocol() {
        for mut t in [Transport::Plain, encrypted_pair().0] {
            assert!(t
                .decode(&WsMessage::Ping(Vec::new().into()))
                .unwrap()
                .is_none());
            assert!(t
                .decode(&WsMessage::Pong(Vec::new().into()))
                .unwrap()
                .is_none());
        }
    }

    #[test]
    fn a_session_still_handshaking_cannot_become_a_transport() {
        let client = Identity::generate().unwrap();
        let server = Identity::generate().unwrap();
        let session = NoiseSession::responder(
            CipherSuite::ChaChaPoly,
            &client,
            server.public_key(),
            b"p",
            Psk::sentinel().key(),
        )
        .unwrap();
        assert!(Transport::encrypted(session).is_err());
    }

    #[test]
    fn an_empty_binary_outbound_is_refused() {
        let (mut client, _) = encrypted_pair();
        assert!(client.encode(Outbound::Binary(Vec::new())).is_err());
    }
}
