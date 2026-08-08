// ABOUTME: The encrypted binary framing: message-type byte inside the AEAD plaintext,
// ABOUTME: plus the fragmentation and reassembly that carry messages past Noise's limit.

use super::constants::{
    MAX_FRAME_PAYLOAD, MAX_REASSEMBLED_MESSAGE_BYTES, MSG_TYPE_FRAGMENT_END, MSG_TYPE_FRAGMENT_MORE,
};
use crate::error::Error;

/// Split `payload` of type `msg_type` into the plaintext frames needed to carry it.
///
/// A message that fits goes out whole; the spec asks senders not to fragment what does not
/// need it. Anything larger becomes an opening fragment-more frame carrying `orig_type`,
/// then continuation fragment-more frames, then a fragment-end frame — never fewer than
/// one of each.
///
/// Each returned buffer is a complete AEAD plaintext, ready to encrypt.
pub fn frame(msg_type: u8, payload: &[u8]) -> Result<Vec<Vec<u8>>, Error> {
    if msg_type == MSG_TYPE_FRAGMENT_MORE || msg_type == MSG_TYPE_FRAGMENT_END {
        return Err(Error::Protocol(format!(
            "message type {msg_type} is a fragment type and cannot be fragmented content"
        )));
    }

    if payload.len() <= MAX_FRAME_PAYLOAD {
        let mut out = Vec::with_capacity(1 + payload.len());
        out.push(msg_type);
        out.extend_from_slice(payload);
        return Ok(vec![out]);
    }

    // The opening frame spends a second byte on orig_type, so it carries one less.
    let first_capacity = MAX_FRAME_PAYLOAD - 1;
    let mut frames = Vec::new();
    let mut first = Vec::with_capacity(2 + first_capacity);
    first.push(MSG_TYPE_FRAGMENT_MORE);
    first.push(msg_type);
    first.extend_from_slice(&payload[..first_capacity]);
    frames.push(first);

    let mut rest = &payload[first_capacity..];
    // Every remaining full-size chunk is a continuation; the tail closes the message.
    // Reserving one frame for the close keeps the "at least one more, then one end"
    // shape even when the remainder divides evenly.
    while rest.len() > MAX_FRAME_PAYLOAD {
        let (chunk, tail) = rest.split_at(MAX_FRAME_PAYLOAD);
        let mut f = Vec::with_capacity(1 + chunk.len());
        f.push(MSG_TYPE_FRAGMENT_MORE);
        f.extend_from_slice(chunk);
        frames.push(f);
        rest = tail;
    }

    let mut last = Vec::with_capacity(1 + rest.len());
    last.push(MSG_TYPE_FRAGMENT_END);
    last.extend_from_slice(rest);
    frames.push(last);

    Ok(frames)
}

/// A fully reassembled message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    /// The message type, taken from the frame byte or from a fragment's `orig_type`.
    pub msg_type: u8,
    /// The payload with the type byte(s) stripped.
    pub payload: Vec<u8>,
}

/// Reassembles inbound plaintexts, holding at most one fragmented message in flight.
///
/// The spec makes malformed fragment sequences protocol errors that MUST close the
/// connection, so every such case surfaces as an `Err` rather than a skipped frame.
#[derive(Debug, Default)]
pub struct Reassembler {
    in_flight: Option<InFlight>,
}

#[derive(Debug)]
struct InFlight {
    msg_type: u8,
    buffer: Vec<u8>,
}

impl Reassembler {
    /// A reassembler with nothing in flight.
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether a fragmented message is currently being reassembled.
    pub fn has_message_in_flight(&self) -> bool {
        self.in_flight.is_some()
    }

    /// Feed one decrypted plaintext.
    ///
    /// Returns `Some` when a complete message is available: immediately for an
    /// unfragmented frame, or on the fragment-end that closes a sequence.
    pub fn accept(&mut self, plaintext: &[u8]) -> Result<Option<Frame>, Error> {
        let (&msg_type, rest) = plaintext
            .split_first()
            .ok_or_else(|| Error::Protocol("empty Noise plaintext".to_string()))?;

        match msg_type {
            MSG_TYPE_FRAGMENT_MORE => self.accept_more(rest).map(|()| None),
            MSG_TYPE_FRAGMENT_END => self.accept_end(rest).map(Some),
            _ => {
                // A non-fragment frame arriving mid-message is a protocol error: the
                // sender is required to close its fragmented message first.
                if self.in_flight.is_some() {
                    return Err(Error::Protocol(format!(
                        "message type {msg_type} arrived while a fragmented message was in flight"
                    )));
                }
                Ok(Some(Frame {
                    msg_type,
                    payload: rest.to_vec(),
                }))
            }
        }
    }

    fn accept_more(&mut self, rest: &[u8]) -> Result<(), Error> {
        match &mut self.in_flight {
            // Already in flight: this is a continuation and carries only data.
            Some(state) => {
                Self::check_growth(state.buffer.len(), rest.len())?;
                state.buffer.extend_from_slice(rest);
                Ok(())
            }
            // Nothing in flight: this opens a message and carries orig_type first.
            None => {
                let (&orig_type, data) = rest.split_first().ok_or_else(|| {
                    Error::Protocol("opening fragment frame carried no orig_type byte".to_string())
                })?;
                if orig_type == MSG_TYPE_FRAGMENT_MORE || orig_type == MSG_TYPE_FRAGMENT_END {
                    return Err(Error::Protocol(format!(
                        "orig_type {orig_type} is itself a fragment type"
                    )));
                }
                Self::check_growth(0, data.len())?;
                self.in_flight = Some(InFlight {
                    msg_type: orig_type,
                    buffer: data.to_vec(),
                });
                Ok(())
            }
        }
    }

    fn accept_end(&mut self, rest: &[u8]) -> Result<Frame, Error> {
        let mut state = self.in_flight.take().ok_or_else(|| {
            Error::Protocol(
                "fragment-end frame arrived with no fragmented message in flight".to_string(),
            )
        })?;
        Self::check_growth(state.buffer.len(), rest.len())?;
        state.buffer.extend_from_slice(rest);
        Ok(Frame {
            msg_type: state.msg_type,
            payload: state.buffer,
        })
    }

    /// Bound the reassembly buffer, so a peer cannot stream fragments forever.
    fn check_growth(current: usize, incoming: usize) -> Result<(), Error> {
        if current.saturating_add(incoming) > MAX_REASSEMBLED_MESSAGE_BYTES {
            return Err(Error::Protocol(format!(
                "reassembled message would exceed {MAX_REASSEMBLED_MESSAGE_BYTES} bytes"
            )));
        }
        Ok(())
    }
}
