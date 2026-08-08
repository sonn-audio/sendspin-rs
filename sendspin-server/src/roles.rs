// ABOUTME: Deciding which of a client's offered roles this server actually activates, which
// ABOUTME: is a promise rather than an acknowledgement.

//! Role negotiation.
//!
//! A client lists what it *can* do; the server decides what it *will* do, and `server/activate`
//! is that decision. The asymmetry matters: activating a role is a promise to serve it, and a
//! client granted `player@v1` that is then never sent audio has been lied to in a way that
//! looks, from the outside, exactly like a broken server.
//!
//! So this activates the intersection of what the client offers and what this server actually
//! implements, and nothing else. A role this build does not serve is simply not granted, even
//! when the client asks for it.

/// Roles this server implements today.
///
/// Grows one entry at a time, and only when there is something behind it.
pub const IMPLEMENTED: &[&str] = &["player@v1"];

/// The roles to activate for a client that offered `supported`.
///
/// Order follows the client's own list rather than this one, so a client that reads its
/// activation positionally sees what it expects.
pub fn negotiate(supported: &[String]) -> Vec<String> {
    supported
        .iter()
        .filter(|role| IMPLEMENTED.contains(&role.as_str()))
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roles(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| (*s).to_string()).collect()
    }

    /// The intersection, and nothing more: a role this server cannot serve is not granted just
    /// because it was asked for.
    #[test]
    fn only_roles_this_server_implements_are_activated() {
        assert_eq!(
            negotiate(&roles(&["player@v1", "visualizer@v1", "artwork@v1"])),
            roles(&["player@v1"])
        );
        assert!(negotiate(&roles(&["visualizer@v1"])).is_empty());
        assert!(negotiate(&[]).is_empty());
    }

    /// A client that offers nothing this server has, or offers something it has never heard
    /// of, gets an empty activation rather than an error: it is a legitimate connection that
    /// this server has no work for.
    #[test]
    fn an_unknown_role_is_ignored_rather_than_refused() {
        assert!(negotiate(&roles(&["teleport@v9"])).is_empty());
        assert_eq!(
            negotiate(&roles(&["teleport@v9", "player@v1"])),
            roles(&["player@v1"])
        );
    }

    /// Versioning is part of the name: `player@v2` is a different role, not a newer one to be
    /// treated as compatible.
    #[test]
    fn the_version_is_part_of_the_role_name() {
        assert!(negotiate(&roles(&["player@v2"])).is_empty());
        assert!(negotiate(&roles(&["player"])).is_empty());
    }

    /// The client's ordering is preserved, so an activation read positionally is not surprising.
    #[test]
    fn the_clients_own_order_is_kept() {
        let offered = roles(&["metadata@v1", "player@v1"]);
        assert_eq!(negotiate(&offered), roles(&["player@v1"]));
    }
}
