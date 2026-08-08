// ABOUTME: Deciding which of a client's offered roles this server actually activates, which
// ABOUTME: is a promise rather than an acknowledgement.

//! Role negotiation.
//!
//! A client lists what it *can* do; the server decides what it *will* do, and `server/activate`
//! is that decision. The asymmetry matters: activating a role is a promise to serve it, and a
//! client granted `player@v1` that is then never sent audio has been lied to in a way that
//! looks, from the outside, exactly like a broken server.
//!
//! So this activates the intersection of what the client offers and what this server can
//! actually serve *right now*, and nothing else. That last part is why the servable set is a
//! parameter rather than a constant: whether this build implements a role and whether this
//! particular server was configured to feed one are different questions, and only the second
//! one decides whether the promise can be kept. A server compiled with the metadata role but
//! started without a metadata source has nothing to send, so it does not claim the role.

use crate::ServerConfig;

/// Roles this build implements at all.
///
/// Grows one entry at a time, and only when there is something behind it. Being listed here is
/// necessary but not sufficient — see [`servable`].
pub const IMPLEMENTED: &[&str] = &["player@v1", "metadata@v1"];

/// The roles this particular server can keep a promise about.
///
/// A role whose source is not configured is left out: activating it would grant a client
/// something that never arrives, which is indistinguishable from a server that is broken.
pub fn servable(config: &ServerConfig) -> Vec<&'static str> {
    let mut roles = Vec::new();
    if config.audio.is_some() {
        roles.push("player@v1");
    }
    if config.metadata.is_some() {
        roles.push("metadata@v1");
    }
    roles
}

/// The roles to activate for a client that offered `supported`.
///
/// Order follows the client's own list rather than this one, so a client that reads its
/// activation positionally sees what it expects.
pub fn negotiate(supported: &[String], servable: &[&str]) -> Vec<String> {
    supported
        .iter()
        .filter(|role| servable.contains(&role.as_str()))
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use sendspin_proto::messages::MetadataState;
    use sendspin_proto::noise::keys::Identity;
    use std::sync::Arc;

    fn roles(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| (*s).to_string()).collect()
    }

    /// Everything this build knows how to serve, for the tests that are about negotiation
    /// rather than about configuration.
    fn all() -> Vec<&'static str> {
        IMPLEMENTED.to_vec()
    }

    /// The intersection, and nothing more: a role this server cannot serve is not granted just
    /// because it was asked for.
    #[test]
    fn only_roles_this_server_implements_are_activated() {
        assert_eq!(
            negotiate(
                &roles(&["player@v1", "visualizer@v1", "artwork@v1"]),
                &all()
            ),
            roles(&["player@v1"])
        );
        assert!(negotiate(&roles(&["visualizer@v1"]), &all()).is_empty());
        assert!(negotiate(&[], &all()).is_empty());
    }

    /// A client that offers nothing this server has, or offers something it has never heard
    /// of, gets an empty activation rather than an error: it is a legitimate connection that
    /// this server has no work for.
    #[test]
    fn an_unknown_role_is_ignored_rather_than_refused() {
        assert!(negotiate(&roles(&["teleport@v9"]), &all()).is_empty());
        assert_eq!(
            negotiate(&roles(&["teleport@v9", "player@v1"]), &all()),
            roles(&["player@v1"])
        );
    }

    /// Versioning is part of the name: `player@v2` is a different role, not a newer one to be
    /// treated as compatible.
    #[test]
    fn the_version_is_part_of_the_role_name() {
        assert!(negotiate(&roles(&["player@v2"]), &all()).is_empty());
        assert!(negotiate(&roles(&["player"]), &all()).is_empty());
    }

    /// The client's ordering is preserved, so an activation read positionally is not surprising.
    #[test]
    fn the_clients_own_order_is_kept() {
        let offered = roles(&["metadata@v1", "player@v1"]);
        assert_eq!(negotiate(&offered, &["player@v1"]), roles(&["player@v1"]));
    }

    /// The distinction this module exists for: a role this build implements is still not
    /// granted when nothing is configured to feed it. A client told it has `metadata@v1` and
    /// then sent no metadata cannot tell that apart from a server that crashed.
    #[test]
    fn a_role_with_nothing_behind_it_is_not_promised() {
        struct Fixed;
        impl crate::MetadataSource for Fixed {
            fn current(&self) -> Option<MetadataState> {
                None
            }
        }

        let bare = ServerConfig::new(Identity::generate().unwrap(), "Test".to_string());
        assert!(
            servable(&bare).is_empty(),
            "a server with no audio and no metadata promised something anyway"
        );
        assert!(negotiate(&roles(&["player@v1", "metadata@v1"]), &servable(&bare)).is_empty());

        let with_metadata = ServerConfig::new(Identity::generate().unwrap(), "Test".to_string())
            .with_metadata(Arc::new(Fixed));
        assert_eq!(servable(&with_metadata), vec!["metadata@v1"]);
        assert_eq!(
            negotiate(
                &roles(&["player@v1", "metadata@v1"]),
                &servable(&with_metadata)
            ),
            roles(&["metadata@v1"]),
            "the player role was granted with no audio source behind it"
        );
    }
}
