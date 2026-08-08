// ABOUTME: The binary wire format: type IDs, the nine-byte header, and the packers and parsers
// ABOUTME: for every binary frame the protocol defines, in both directions.

//! Binary frames.
//!
//! Everything on a Sendspin connection that is not JSON is one of these: a type byte, eight
//! bytes of big-endian timestamp, then a payload. Audio, artwork and visualizer data all share
//! that shape and differ only in the type ID and what the payload means.
//!
//! This lives in the core because the format has no direction. A player audio chunk is written
//! by a server and read by a client; a source audio chunk is written by a client and read by a
//! server; and the header is byte-for-byte the same either way. Keeping it in the client crate
//! meant the server could not reach it, and a server that needs to emit the format has only two
//! options — depend on the client, or write the layout out a second time. The second one is
//! what happened, and a duplicated wire format is the kind that stays correct right up until
//! one copy is fixed.
//!
//! The nine-byte header is not negotiable and not versioned: a reader that gets it wrong does
//! not fail loudly, it decodes noise or schedules audio at the wrong moment. That is why
//! [`pack`](crate::binary::pack) and the `from_bytes` parsers are written against each other here, where both sides
//! of the protocol use the same pair.

use std::sync::Arc;

use crate::error::Error;
use crate::messages::VisualizerDataType;

/// How many bytes precede the payload: one of type, eight of timestamp.
pub const HEADER_LEN: usize = 9;

/// Pack any binary frame: type byte, big-endian timestamp, payload.
///
/// The single writer for the format, so a new frame type cannot accidentally invent its own
/// header. [`BinaryFrame::from_bytes`] is its mirror.
pub fn pack(type_id: u8, timestamp_us: i64, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER_LEN + payload.len());
    out.push(type_id);
    out.extend_from_slice(&timestamp_us.to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// Pack one player audio chunk, server to client.
///
/// `timestamp_us` is the server-clock time the chunk's *first sample* is meant to be heard, not
/// the time it was sent: a player schedules on it, so it has to be far enough ahead for the
/// chunk to arrive, decode and reach the sound card first.
pub fn pack_player_audio(timestamp_us: i64, pcm: &[u8]) -> Vec<u8> {
    pack(binary_types::PLAYER_AUDIO, timestamp_us, pcm)
}

/// Binary message type IDs per Sendspin spec
pub mod binary_types {
    /// Player audio chunk (types 4-7, we use 4)
    pub const PLAYER_AUDIO: u8 = 0x04;
    /// Artwork channel 0 (type 8)
    pub const ARTWORK_CHANNEL_0: u8 = 0x08;
    /// Artwork channel 1 (type 9)
    pub const ARTWORK_CHANNEL_1: u8 = 0x09;
    /// Artwork channel 2 (type 10)
    pub const ARTWORK_CHANNEL_2: u8 = 0x0A;
    /// Artwork channel 3 (type 11)
    pub const ARTWORK_CHANNEL_3: u8 = 0x0B;
    /// Source audio chunk, client to server (type 12)
    pub const SOURCE_AUDIO: u8 = 0x0C;
    /// Visualizer loudness data (type 16).
    pub const VISUALIZER_LOUDNESS: u8 = 0x10;
    /// Visualizer beat data (type 17).
    pub const VISUALIZER_BEAT: u8 = 0x11;
    /// Visualizer dominant-frequency data (type 18).
    pub const VISUALIZER_F_PEAK: u8 = 0x12;
    /// Visualizer spectrum data (type 19).
    pub const VISUALIZER_SPECTRUM: u8 = 0x13;
    /// Visualizer energy-onset data (type 20).
    pub const VISUALIZER_PEAK: u8 = 0x14;
    /// Visualizer perceived-pitch data (type 21).
    pub const VISUALIZER_PITCH: u8 = 0x15;
    /// Check if a binary type ID is for artwork (8-11)
    pub fn is_artwork(type_id: u8) -> bool {
        (ARTWORK_CHANNEL_0..=ARTWORK_CHANNEL_3).contains(&type_id)
    }

    /// Get artwork channel number from type ID (0-3)
    pub fn artwork_channel(type_id: u8) -> Option<u8> {
        if is_artwork(type_id) {
            Some(type_id - ARTWORK_CHANNEL_0)
        } else {
            None
        }
    }

    /// Check if a binary type ID is for visualizer data (16-20).
    pub fn is_visualizer(type_id: u8) -> bool {
        (VISUALIZER_LOUDNESS..=VISUALIZER_PITCH).contains(&type_id)
    }
}

/// Pack one source audio frame, client to server.
///
/// The mirror of [`AudioChunk::from_bytes`], and separate from the sender so the
/// layout can be tested without a connection.
pub fn pack_source_audio(server_timestamp_us: i64, frame: &[u8]) -> Vec<u8> {
    pack(binary_types::SOURCE_AUDIO, server_timestamp_us, frame)
}

/// Audio chunk from server (binary type 4)
#[derive(Debug, Clone)]
pub struct AudioChunk {
    /// Server timestamp in microseconds
    pub timestamp: i64,
    /// Raw audio data bytes
    pub data: Arc<[u8]>,
}

impl AudioChunk {
    /// Parse from WebSocket binary frame (type 4 = player audio)
    pub fn from_bytes(frame: &[u8]) -> Result<Self, Error> {
        if frame.len() < 9 {
            return Err(Error::Protocol(format!(
                "Audio chunk too short: got {} bytes, need at least 9",
                frame.len()
            )));
        }

        // Per spec: player audio uses binary type 4
        if frame[0] != binary_types::PLAYER_AUDIO {
            return Err(Error::Protocol(format!(
                "Invalid audio chunk type: expected {}, got {}",
                binary_types::PLAYER_AUDIO,
                frame[0]
            )));
        }

        let timestamp = i64::from_be_bytes([
            frame[1], frame[2], frame[3], frame[4], frame[5], frame[6], frame[7], frame[8],
        ]);

        let data = Arc::from(&frame[9..]);

        Ok(Self { timestamp, data })
    }
}

/// Artwork chunk from server (binary types 8-11)
#[derive(Debug, Clone)]
pub struct ArtworkChunk {
    /// Artwork channel (0-3)
    pub channel: u8,
    /// Server timestamp in microseconds
    pub timestamp: i64,
    /// Image data bytes (JPEG, PNG, or BMP)
    /// Empty payload means clear the artwork
    pub data: Arc<[u8]>,
}

impl ArtworkChunk {
    /// Parse from WebSocket binary frame (types 8-11 = artwork channels 0-3)
    pub fn from_bytes(frame: &[u8]) -> Result<Self, Error> {
        if frame.len() < 9 {
            return Err(Error::Protocol(format!(
                "Artwork chunk too short: got {} bytes, need at least 9",
                frame.len()
            )));
        }

        let type_id = frame[0];
        let channel = binary_types::artwork_channel(type_id)
            .ok_or_else(|| Error::Protocol(format!("Invalid artwork chunk type: {}", type_id)))?;

        let timestamp = i64::from_be_bytes([
            frame[1], frame[2], frame[3], frame[4], frame[5], frame[6], frame[7], frame[8],
        ]);

        let data = Arc::from(&frame[9..]);

        Ok(Self {
            channel,
            timestamp,
            data,
        })
    }

    /// Check if this is a clear command (empty payload)
    pub fn is_clear(&self) -> bool {
        self.data.is_empty()
    }
}

/// Visualizer chunk from server (binary types 16-20).
#[derive(Debug, Clone)]
pub struct VisualizerChunk {
    /// Visualizer binary message type (16-20).
    pub type_id: u8,
    /// Server timestamp in microseconds.
    pub timestamp: i64,
    /// Raw visualization data bytes, left for the application to decode.
    pub data: Arc<[u8]>,
}

impl VisualizerChunk {
    /// Return the typed visualizer data kind represented by this chunk.
    ///
    /// Returns `None` if a chunk was constructed manually with an invalid
    /// `type_id`; frames parsed by [`Self::from_bytes`] always return `Some`.
    pub fn data_type(&self) -> Option<VisualizerDataType> {
        match self.type_id {
            binary_types::VISUALIZER_LOUDNESS => Some(VisualizerDataType::Loudness),
            binary_types::VISUALIZER_BEAT => Some(VisualizerDataType::Beat),
            binary_types::VISUALIZER_F_PEAK => Some(VisualizerDataType::FPeak),
            binary_types::VISUALIZER_SPECTRUM => Some(VisualizerDataType::Spectrum),
            binary_types::VISUALIZER_PEAK => Some(VisualizerDataType::Peak),
            binary_types::VISUALIZER_PITCH => Some(VisualizerDataType::Pitch),
            _ => None,
        }
    }

    /// Parse from a WebSocket binary frame (visualizer types 16-20).
    pub fn from_bytes(frame: &[u8]) -> Result<Self, Error> {
        if frame.len() < 9 {
            return Err(Error::Protocol(format!(
                "Visualizer chunk too short: got {} bytes, need at least 9",
                frame.len()
            )));
        }

        if !binary_types::is_visualizer(frame[0]) {
            return Err(Error::Protocol(format!(
                "Invalid visualizer chunk type: expected 16-21, got {}",
                frame[0]
            )));
        }

        let timestamp = i64::from_be_bytes([
            frame[1], frame[2], frame[3], frame[4], frame[5], frame[6], frame[7], frame[8],
        ]);

        let data = Arc::from(&frame[9..]);

        Ok(Self {
            type_id: frame[0],
            timestamp,
            data,
        })
    }
}

/// Binary frame from server (any type)
#[derive(Debug, Clone)]
pub enum BinaryFrame {
    /// Player audio (type 4)
    Audio(AudioChunk),
    /// Artwork image (types 8-11)
    Artwork(ArtworkChunk),
    /// Visualizer data (types 16-20)
    Visualizer(VisualizerChunk),
    /// Unknown binary type
    Unknown {
        /// The unknown type ID
        type_id: u8,
        /// Raw data after the type byte
        data: Arc<[u8]>,
    },
}

impl BinaryFrame {
    /// Parse any binary frame from WebSocket
    pub fn from_bytes(frame: &[u8]) -> Result<Self, Error> {
        if frame.is_empty() {
            return Err(Error::Protocol("Empty binary frame".to_string()));
        }

        let type_id = frame[0];

        match type_id {
            binary_types::PLAYER_AUDIO => Ok(BinaryFrame::Audio(AudioChunk::from_bytes(frame)?)),
            t if binary_types::is_artwork(t) => {
                Ok(BinaryFrame::Artwork(ArtworkChunk::from_bytes(frame)?))
            }
            t if binary_types::is_visualizer(t) => {
                Ok(BinaryFrame::Visualizer(VisualizerChunk::from_bytes(frame)?))
            }
            // The router warns when it sees the Unknown variant; parsing
            // itself stays quiet to avoid reporting the same frame twice.
            _ => Ok(BinaryFrame::Unknown {
                type_id,
                data: Arc::from(&frame[1..]),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The header is what every reader looks at before anything else, and the two directions
    /// have to agree on it exactly. Packing and parsing here are checked against each other
    /// rather than against a hand-written byte string, so neither can drift alone.
    #[test]
    fn a_packed_player_chunk_parses_back_to_what_went_in() {
        let framed = pack_player_audio(1_234_567, &[1, 2, 3, 4]);
        assert_eq!(framed[0], binary_types::PLAYER_AUDIO);
        assert_eq!(framed.len(), HEADER_LEN + 4);

        match BinaryFrame::from_bytes(&framed).expect("parse") {
            BinaryFrame::Audio(chunk) => {
                assert_eq!(chunk.timestamp, 1_234_567);
                assert_eq!(chunk.data.as_ref(), &[1, 2, 3, 4]);
            }
            other => panic!("a player chunk parsed as {other:?}"),
        }
    }

    /// Negative timestamps are ordinary: a server clock is monotonic from an arbitrary origin,
    /// so a chunk scheduled before that origin is representable and must survive the round trip
    /// rather than being read as an enormous positive time.
    #[test]
    fn a_negative_timestamp_survives_the_round_trip() {
        let framed = pack_player_audio(-42, &[9]);
        match BinaryFrame::from_bytes(&framed).expect("parse") {
            BinaryFrame::Audio(chunk) => assert_eq!(chunk.timestamp, -42),
            other => panic!("parsed as {other:?}"),
        }
    }

    /// A frame with a header and no payload is legal: an empty chunk is whole.
    #[test]
    fn an_empty_payload_is_not_an_error() {
        let framed = pack_player_audio(0, &[]);
        assert_eq!(framed.len(), HEADER_LEN);
        assert!(BinaryFrame::from_bytes(&framed).is_ok());
    }

    /// A truncated frame is refused rather than read past its end.
    #[test]
    fn a_short_frame_is_refused() {
        assert!(BinaryFrame::from_bytes(&[]).is_err());
        assert!(BinaryFrame::from_bytes(&[binary_types::PLAYER_AUDIO; 8]).is_err());
    }

    /// An unknown type is carried rather than rejected, so a newer peer using a frame this
    /// build predates does not take the connection down.
    #[test]
    fn an_unknown_type_is_carried_not_refused() {
        let framed = pack(0x7F, 5, &[1, 2]);
        match BinaryFrame::from_bytes(&framed).expect("parse") {
            BinaryFrame::Unknown { type_id, data } => {
                assert_eq!(type_id, 0x7F);
                assert_eq!(data.len(), framed.len() - 1);
            }
            other => panic!("parsed as {other:?}"),
        }
    }

    /// Both directions use one writer, so the client's source frames and the server's player
    /// frames cannot drift into different header layouts.
    #[test]
    fn both_directions_share_one_header_layout() {
        let player = pack_player_audio(77, &[3]);
        let source = pack_source_audio(77, &[3]);
        assert_eq!(player[1..], source[1..], "the headers disagreed");
        assert_eq!(source[0], binary_types::SOURCE_AUDIO);
    }
}
