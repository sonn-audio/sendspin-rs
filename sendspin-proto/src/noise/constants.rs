// ABOUTME: Protocol constants for the Sendspin Noise layer: labels, the published
// ABOUTME: Sentinel PSK, binary frame type tags, and the transport size limit.

/// Core message-format version carried in `client/init` and `server/init`.
///
/// An exact-match field, not a minimum: both sides send `1` and abort the handshake on
/// any other value. A future revision that changes the core format bumps this and defines
/// its own negotiation.
pub const PROTOCOL_VERSION: u32 = 1;

/// Label prefixed to a PSK before hashing to derive its `psk_id`.
///
/// The UTF-8 bytes of the literal characters — no NUL terminator, no quotes.
pub const PSK_ID_LABEL: &[u8] = b"sendspin-psk-id-v1";

/// Pre-image of the published Sentinel PSK.
pub const SENTINEL_PSK_LABEL: &[u8] = b"sendspin-sentinel-psk-v1";

/// Length of an X25519 public or private key, and of a PSK.
pub const KEY_LEN: usize = 32;

/// Length of a base64url-encoded 32-byte value with no padding.
pub const B64_KEY_LEN: usize = 43;

/// Binary frame type for a JSON message body (UTF-8), inside the AEAD plaintext.
pub const MSG_TYPE_JSON_BODY: u8 = 0;

/// Fragment frame carrying more to come. Bit 0 is the last-fragment flag.
pub const MSG_TYPE_FRAGMENT_MORE: u8 = 2;

/// Fragment frame closing a fragmented message.
pub const MSG_TYPE_FRAGMENT_END: u8 = 3;

/// Noise's 65535-byte transport message limit, less the 16-byte AEAD tag.
///
/// Both defined suites use a 16-byte tag, so this is the most plaintext one transport
/// message can carry — message type byte included.
pub const MAX_TRANSPORT_PLAINTEXT: usize = 65535 - 16;

/// Largest application payload in a single non-fragmented frame.
///
/// The type byte occupies the first plaintext byte, so anything longer than this has to
/// be fragmented.
pub const MAX_FRAME_PAYLOAD: usize = MAX_TRANSPORT_PLAINTEXT - 1;

/// Ceiling on a single reassembly buffer.
///
/// Bounds a peer that streams fragment-more frames without ever closing the message.
pub const MAX_REASSEMBLED_MESSAGE_BYTES: usize = 64 * 1024 * 1024;

/// Recommended per-message timeout for the prologue and handshake phases.
pub const HANDSHAKE_TIMEOUT_SECS: u64 = 30;
