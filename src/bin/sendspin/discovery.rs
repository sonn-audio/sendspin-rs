// ABOUTME: The `servers list` and `clients list` subcommands: browse mDNS and print what
// ABOUTME: answered, in a shape an operator can paste straight back into `--url`.

//! Network discovery listings.
//!
//! Two halves of the same question. A server advertises `_sendspin-server._tcp`, a client
//! waiting to be connected to advertises `_sendspin._tcp`, and an operator setting a system up
//! wants to see either without guessing addresses.

use std::time::Duration;

use sendspin::protocol::discovery::{browse_clients, browse_servers, Discovered};

/// Discover servers and print them.
pub fn list_servers(seconds: u64) -> Result<(), String> {
    let found = browse_servers(Duration::from_secs(seconds)).map_err(|e| e.to_string())?;
    print_found(&found, "server");
    Ok(())
}

/// Discover listening clients and print them.
pub fn list_clients(seconds: u64) -> Result<(), String> {
    let found = browse_clients(Duration::from_secs(seconds)).map_err(|e| e.to_string())?;
    print_found(&found, "client");
    Ok(())
}

/// The URL is printed on its own line because it is the line that gets copied: it is exactly
/// what `--url` takes, so finding a server and dialling it is two commands rather than a
/// transcription.
fn print_found(found: &[Discovered], kind: &str) {
    if found.is_empty() {
        println!("No Sendspin {kind}s found.");
        return;
    }
    println!("\nFound {} {kind}(s):\n", found.len());
    for entry in found {
        println!("  {}", entry.name);
        println!("    URL:  {}", entry.url());
        println!("    Host: {}:{}", entry.address, entry.port);
    }
}
