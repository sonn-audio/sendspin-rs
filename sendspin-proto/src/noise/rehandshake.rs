// ABOUTME: The in-band re-handshake: swapping session keys without closing the socket,
// ABOUTME: which is how a pairing is promoted to the trust level it just earned.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;

use super::constants::KEY_LEN;
use super::keys::{Identity, Psk, PskCategory};
use super::models::{NoiseHandshake, NoiseMsg1Payload, NOISE_MSG2_PAYLOAD};
use super::session::{CipherSuite, NoiseSession};
use crate::error::Error;

/// What a completed re-handshake produced.
pub struct RehandshakeResult {
    /// The new session, already in transport mode.
    pub session: NoiseSession,
    /// Noise message 2, to send **encrypted under the old session's keys**.
    ///
    /// The ordering matters and is the one thing easy to get wrong here: message 2 still
    /// travels under the pre-re-handshake keys, and only the *next* frame each side sends
    /// uses the new ones. Encrypting it with the new session desynchronises both peers.
    pub reply: Vec<u8>,
    /// Which PSK category keyed the new session, i.e. the trust level it now carries.
    pub psk_category: PskCategory,
    /// The matched `psk_id`.
    pub psk_id: String,
}

impl std::fmt::Debug for RehandshakeResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RehandshakeResult")
            .field("psk_category", &self.psk_category)
            .field("psk_id", &self.psk_id)
            .finish_non_exhaustive()
    }
}

/// Run the client's side of an in-band re-handshake.
///
/// The server initiates, as it does for a first handshake, and `msg1_data` is the base64url
/// payload of the `noise/handshake` message that arrived — as an ordinary encrypted JSON
/// message, not a bare Noise frame, because the channel is already up.
///
/// Three things differ from a first handshake, all of them consequences of the socket
/// staying open:
///
/// - **The prologue is the previous handshake's hash**, not the init messages. `client/init`
///   and `server/init` are not re-sent; identity and suite carry over.
/// - **`psk_id` selects a possibly different PSK.** That is the point: a re-handshake is how
///   a server moves the session from the Sentinel PSK to a Pairing PSK, or from a Pairing PSK
///   to the long-term key a pairing just produced.
/// - **The reply goes out under the old keys.** See [`RehandshakeResult::reply`].
///
/// After the swap the connection restarts at `server/hello` → `client/hello` →
/// `server/activate`, so the caller re-runs that sequence rather than continuing mid-stream.
pub fn run_rehandshake_client(
    suite: CipherSuite,
    identity: &Identity,
    server_static: &[u8; KEY_LEN],
    previous_handshake_hash: &[u8; KEY_LEN],
    server_id: &str,
    candidates: &[Psk],
    msg1_data: &str,
) -> Result<RehandshakeResult, Error> {
    let msg1 = URL_SAFE_NO_PAD
        .decode(msg1_data)
        .map_err(|e| Error::Protocol(format!("noise/handshake data is not base64url: {e}")))?;

    // As in a first handshake, message 1 is readable before the PSK is mixed, so a throwaway
    // responder reads the announced psk_id and the real one is built once it is known.
    let probe_psk = [0u8; KEY_LEN];
    let mut probe = NoiseSession::responder(
        suite,
        identity,
        server_static,
        previous_handshake_hash,
        &probe_psk,
    )?;
    let payload = probe.read_handshake(&msg1)?;
    let announced: NoiseMsg1Payload = serde_json::from_slice(&payload)
        .map_err(|e| Error::Protocol(format!("malformed Noise message 1 payload: {e}")))?;

    let matched = candidates
        .iter()
        .find(|psk| psk.psk_id() == announced.psk_id)
        .ok_or_else(|| {
            Error::Protocol(format!(
                "no candidate PSK matches re-handshake psk_id {}",
                announced.psk_id
            ))
        })?;

    if !matched.accepts_server(server_id) {
        return Err(Error::Protocol(format!(
            "re-handshake PSK {} is bound to a different server_id",
            announced.psk_id
        )));
    }

    let mut session = NoiseSession::responder(
        suite,
        identity,
        server_static,
        previous_handshake_hash,
        matched.key(),
    )?;
    session.read_handshake(&msg1)?;
    let msg2 = session.write_handshake(NOISE_MSG2_PAYLOAD)?;
    if !session.handshake_finished() {
        return Err(Error::Protocol(
            "re-handshake did not complete after message 2".to_string(),
        ));
    }
    session.into_transport_mode()?;

    let reply = serde_json::to_vec(&crate::messages::Message::NoiseHandshake(NoiseHandshake {
        data: URL_SAFE_NO_PAD.encode(&msg2),
    }))
    .map_err(|e| Error::Protocol(format!("could not encode noise/handshake: {e}")))?;

    Ok(RehandshakeResult {
        session,
        reply,
        psk_category: matched.category(),
        psk_id: announced.psk_id,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::noise::trust_store::{random_psk, PairingRecord};

    /// Bring a pair of sessions up over an agreed prologue.
    fn first_handshake(
        client: &Identity,
        server: &Identity,
        psk: &Psk,
    ) -> (NoiseSession, NoiseSession) {
        let prologue = b"client-init||server-init";
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
            client,
            server.public_key(),
            prologue,
            psk.key(),
        )
        .unwrap();
        let payload = serde_json::to_vec(&NoiseMsg1Payload {
            psk_id: psk.psk_id(),
        })
        .unwrap();
        let msg1 = initiator.write_handshake(&payload).unwrap();
        responder.read_handshake(&msg1).unwrap();
        let msg2 = responder.write_handshake(NOISE_MSG2_PAYLOAD).unwrap();
        initiator.read_handshake(&msg2).unwrap();
        responder.into_transport_mode().unwrap();
        initiator.into_transport_mode().unwrap();
        (responder, initiator)
    }

    #[test]
    fn the_handshake_hash_survives_into_transport_mode() {
        // Without this a re-handshake has no prologue to work from.
        let client = Identity::generate().unwrap();
        let server = Identity::generate().unwrap();
        let (session, peer) = first_handshake(&client, &server, &Psk::sentinel());
        let a = session.handshake_hash().unwrap();
        let b = peer.handshake_hash().unwrap();
        assert_eq!(
            a, b,
            "both sides must agree on the prologue for the next one"
        );
        assert_ne!(a, [0u8; KEY_LEN]);
    }

    #[test]
    fn a_rehandshake_promotes_the_session_to_a_long_term_psk() {
        // The shape of a completed pairing: the session was keyed by the Pairing PSK, and the
        // server re-handshakes to the long-term key the client just delivered.
        let client = Identity::generate().unwrap();
        let server = Identity::generate().unwrap();
        let pairing_key = random_psk().unwrap();
        let pairing_psk = Psk::shared(pairing_key, PskCategory::Pairing);
        let (client_session, mut server_session) = first_handshake(&client, &server, &pairing_psk);
        let prologue = client_session.handshake_hash().unwrap();

        let long_term = random_psk().unwrap();
        let record = PairingRecord::stored_pubkey(long_term, server.client_id());
        let candidates = vec![pairing_psk.clone(), record.as_psk(), Psk::sentinel()];

        // The server builds message 1 for the new session over the old hash.
        let mut new_server = NoiseSession::initiator(
            CipherSuite::ChaChaPoly,
            server.private_key(),
            client.public_key(),
            &prologue,
            &long_term,
        )
        .unwrap();
        let payload = serde_json::to_vec(&NoiseMsg1Payload {
            psk_id: record.psk_id().to_string(),
        })
        .unwrap();
        let msg1 = new_server.write_handshake(&payload).unwrap();

        let result = run_rehandshake_client(
            CipherSuite::ChaChaPoly,
            &client,
            server.public_key(),
            &prologue,
            &server.client_id(),
            &candidates,
            &URL_SAFE_NO_PAD.encode(&msg1),
        )
        .unwrap();

        assert_eq!(result.psk_category, PskCategory::LongTerm);
        assert_eq!(result.psk_id, record.psk_id());
        assert!(result.session.in_transport_mode());

        // The reply travels under the OLD keys, which is what lets the server read it.
        let envelope: serde_json::Value = serde_json::from_slice(&result.reply).unwrap();
        assert_eq!(envelope["type"], "noise/handshake");
        let msg2 = URL_SAFE_NO_PAD
            .decode(envelope["payload"]["data"].as_str().unwrap())
            .unwrap();
        assert_eq!(
            new_server.read_handshake(&msg2).unwrap(),
            NOISE_MSG2_PAYLOAD
        );
        new_server.into_transport_mode().unwrap();

        // And the new keys carry traffic, while the old session is left behind.
        let mut new_client = result.session;
        let ciphertext = new_server.encrypt(&[0u8, b'{', b'}']).unwrap();
        assert_eq!(new_client.decrypt(&ciphertext).unwrap(), [0u8, b'{', b'}']);
        assert!(
            server_session.decrypt(&ciphertext).is_err(),
            "the superseded session must not read the new keys' traffic"
        );
    }

    #[test]
    fn a_rehandshake_to_an_unknown_psk_fails() {
        let client = Identity::generate().unwrap();
        let server = Identity::generate().unwrap();
        let (client_session, _) = first_handshake(&client, &server, &Psk::sentinel());
        let prologue = client_session.handshake_hash().unwrap();

        let unknown = random_psk().unwrap();
        let mut new_server = NoiseSession::initiator(
            CipherSuite::ChaChaPoly,
            server.private_key(),
            client.public_key(),
            &prologue,
            &unknown,
        )
        .unwrap();
        let payload = serde_json::to_vec(&NoiseMsg1Payload {
            psk_id: Psk::shared(unknown, PskCategory::LongTerm).psk_id(),
        })
        .unwrap();
        let msg1 = new_server.write_handshake(&payload).unwrap();

        let err = run_rehandshake_client(
            CipherSuite::ChaChaPoly,
            &client,
            server.public_key(),
            &prologue,
            &server.client_id(),
            &[Psk::sentinel()],
            &URL_SAFE_NO_PAD.encode(&msg1),
        )
        .expect_err("must not complete");
        assert!(
            format!("{err}").contains("no candidate PSK matches"),
            "{err}"
        );
    }

    #[test]
    fn a_rehandshake_over_the_wrong_prologue_fails() {
        // The prologue binds the re-handshake to the session it happens inside, so a peer
        // that used a different one cannot complete it.
        let client = Identity::generate().unwrap();
        let server = Identity::generate().unwrap();
        let (client_session, _) = first_handshake(&client, &server, &Psk::sentinel());
        let real_prologue = client_session.handshake_hash().unwrap();
        let wrong_prologue = [0x11u8; KEY_LEN];

        let mut new_server = NoiseSession::initiator(
            CipherSuite::ChaChaPoly,
            server.private_key(),
            client.public_key(),
            &wrong_prologue,
            Psk::sentinel().key(),
        )
        .unwrap();
        let payload = serde_json::to_vec(&NoiseMsg1Payload {
            psk_id: Psk::sentinel().psk_id(),
        })
        .unwrap();
        let msg1 = new_server.write_handshake(&payload).unwrap();

        let err = run_rehandshake_client(
            CipherSuite::ChaChaPoly,
            &client,
            server.public_key(),
            &real_prologue,
            &server.client_id(),
            &[Psk::sentinel()],
            &URL_SAFE_NO_PAD.encode(&msg1),
        )
        .expect_err("must not complete");
        assert!(format!("{err}").contains("handshake read failed"), "{err}");
    }

    #[test]
    fn a_rehandshake_psk_bound_elsewhere_is_refused() {
        let client = Identity::generate().unwrap();
        let server = Identity::generate().unwrap();
        let (client_session, _) = first_handshake(&client, &server, &Psk::sentinel());
        let prologue = client_session.handshake_hash().unwrap();

        let key = random_psk().unwrap();
        let mut new_server = NoiseSession::initiator(
            CipherSuite::ChaChaPoly,
            server.private_key(),
            client.public_key(),
            &prologue,
            &key,
        )
        .unwrap();
        let payload = serde_json::to_vec(&NoiseMsg1Payload {
            psk_id: Psk::shared(key, PskCategory::LongTerm).psk_id(),
        })
        .unwrap();
        let msg1 = new_server.write_handshake(&payload).unwrap();

        // A record for the same key, but belonging to some other server.
        let elsewhere = PairingRecord::stored_pubkey(key, "some-other-server".to_string());
        let err = run_rehandshake_client(
            CipherSuite::ChaChaPoly,
            &client,
            server.public_key(),
            &prologue,
            &server.client_id(),
            &[elsewhere.as_psk()],
            &URL_SAFE_NO_PAD.encode(&msg1),
        )
        .expect_err("must not complete");
        assert!(
            format!("{err}").contains("bound to a different server_id"),
            "{err}"
        );
    }
}
