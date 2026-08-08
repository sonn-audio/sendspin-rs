// ABOUTME: mDNS advertisement for a client that waits to be connected to, so a server can
// ABOUTME: find it rather than being told where it is.

//! Client discovery.
//!
//! The spec has two directions and a client picks exactly one:
//!
//! - **Server-initiated.** The client advertises `_sendspin._tcp.local.` and waits. This is
//!   what [`ClientAdvertisement`](crate::protocol::discovery::ClientAdvertisement) does, and it pairs with
//!   [`ProtocolListener`](crate::protocol::listener::ProtocolListener).
//! - **Client-initiated.** The client discovers a server's `_sendspin-server._tcp.local.`
//!   and dials it, which is [`ProtocolClientBuilder::connect`](crate::ProtocolClientBuilder).
//!
//! Doing both at once is what the spec forbids — "Do not manually connect to servers if you
//! are advertising `_sendspin._tcp`" — because a client reachable from both sides can end up
//! holding two connections that each think they arbitrated correctly.
//!
//! Requires the `discovery` feature: an appliance whose address is configured has no use for
//! an mDNS daemon, and should not link one.

use mdns_sd::{ServiceDaemon, ServiceInfo};

use crate::error::Error;

/// The service type a Sendspin client advertises.
const SERVICE_TYPE: &str = "_sendspin._tcp.local.";

/// The port the spec recommends for a listening client.
pub const RECOMMENDED_PORT: u16 = 8928;

/// The endpoint the spec recommends, and the default `path` TXT value.
pub const RECOMMENDED_PATH: &str = "/sendspin";

/// An mDNS advertisement for a listening client.
///
/// Registered on construction and withdrawn on drop, so a client that stops listening stops
/// being advertised without the caller having to remember. A stale record is worse than no
/// record: a server will dial it, fail, and retry.
pub struct ClientAdvertisement {
    daemon: ServiceDaemon,
    fullname: String,
}

impl ClientAdvertisement {
    /// Advertise a client on `port`, at the recommended path.
    ///
    /// `instance` names the service instance and must be unique on the network — the
    /// `client_id` is the natural choice, being unique by construction. `name` is the
    /// friendly name; the spec makes it a discovery-time hint only, so a server that sees it
    /// differ from `client/hello` takes the latter.
    pub fn new(instance: &str, name: &str, port: u16) -> Result<Self, Error> {
        Self::with_path(instance, name, port, RECOMMENDED_PATH)
    }

    /// Advertise at an explicit WebSocket path.
    ///
    /// `path` is required by the spec rather than merely conventional: a server has no other
    /// way to know which endpoint to open.
    pub fn with_path(instance: &str, name: &str, port: u16, path: &str) -> Result<Self, Error> {
        let daemon = ServiceDaemon::new()
            .map_err(|e| Error::Connection(format!("could not start the mDNS daemon: {e}")))?;
        let service = ServiceInfo::new(
            SERVICE_TYPE,
            instance,
            // A host name derived from the instance, so two clients on one machine do not
            // collide on it.
            &format!("{instance}.local."),
            "",
            port,
            &[("path", path), ("name", name)][..],
        )
        .map_err(|e| Error::Connection(format!("invalid mDNS service description: {e}")))?
        // Let the daemon track the interface addresses: a client that moves between
        // networks, or comes up before DHCP, would otherwise advertise an address it no
        // longer has.
        .enable_addr_auto();

        let fullname = service.get_fullname().to_string();
        daemon
            .register(service)
            .map_err(|e| Error::Connection(format!("could not advertise over mDNS: {e}")))?;
        log::info!("Advertising {fullname} on port {port} at {path}");

        Ok(Self { daemon, fullname })
    }

    /// The full mDNS name this advertisement registered under.
    pub fn fullname(&self) -> &str {
        &self.fullname
    }

    /// Withdraw the advertisement and stop the daemon.
    ///
    /// Dropping does the same; this exists for a caller that wants the error rather than a
    /// log line.
    pub fn shutdown(self) -> Result<(), Error> {
        self.unregister()
    }

    fn unregister(&self) -> Result<(), Error> {
        self.daemon
            .unregister(&self.fullname)
            .map_err(|e| Error::Connection(format!("could not withdraw the advertisement: {e}")))?;
        Ok(())
    }
}

impl Drop for ClientAdvertisement {
    fn drop(&mut self) {
        // Best effort: the daemon is going away regardless, and a failure here would only be
        // a slightly slower expiry on the servers that cached the record.
        if let Err(e) = self.unregister() {
            log::debug!("mDNS withdrawal on drop: {e}");
        }
    }
}
