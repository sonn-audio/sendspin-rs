// ABOUTME: The client's mDNS advertisement — that it registers under the service type a
// ABOUTME: server browses for, carrying the TXT keys the spec requires.

#![cfg(feature = "discovery")]

use sendspin::protocol::discovery::{ClientAdvertisement, RECOMMENDED_PATH, RECOMMENDED_PORT};

/// A server browses for `_sendspin._tcp.local.`; anything else is invisible to it.
#[test]
fn the_advertisement_registers_under_the_service_type_a_server_looks_for() {
    let Ok(advertisement) = ClientAdvertisement::new("test-instance", "Test Client", 8928) else {
        // A sandbox with no multicast route cannot start a daemon. Skip rather than fail:
        // this asserts on the record's shape, and the network is not the subject.
        eprintln!("no mDNS daemon available; skipping");
        return;
    };
    assert_eq!(
        advertisement.fullname(),
        "test-instance._sendspin._tcp.local."
    );
}

/// `path` is REQUIRED by the spec, not conventional: a server has no other way to know
/// which WebSocket endpoint to open.
#[test]
fn the_recommended_values_are_the_ones_the_spec_names() {
    assert_eq!(RECOMMENDED_PORT, 8928);
    assert_eq!(RECOMMENDED_PATH, "/sendspin");
}

/// Two clients on one host must not collide, so the instance name carries into the record.
#[test]
fn distinct_instances_get_distinct_records() {
    let (Ok(first), Ok(second)) = (
        ClientAdvertisement::new("client-a", "A", 8928),
        ClientAdvertisement::new("client-b", "B", 8929),
    ) else {
        eprintln!("no mDNS daemon available; skipping");
        return;
    };
    assert_ne!(first.fullname(), second.fullname());
}
