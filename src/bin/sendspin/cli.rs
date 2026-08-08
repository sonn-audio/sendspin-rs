// ABOUTME: The command-line surface, kept apart from what runs behind it so the flags can be
// ABOUTME: read as a contract rather than reconstructed from the code that consumes them.

//! Argument definitions for the `sendspin` binary.
//!
//! The names and meanings deliberately track `sendspin-cli`'s, because an operator who has
//! one in muscle memory should not have to learn the other. Where a flag cannot yet mean
//! everything it means there, the help text says so rather than accepting it and doing less.

use clap::{Parser, Subcommand};

/// Default port a client listens on for server-initiated connections. The spec recommends it,
/// and `sendspin-cli` uses the same one.
pub const DEFAULT_LISTEN_PORT: u16 = 8928;

#[derive(Parser, Debug)]
#[command(
    name = "sendspin",
    about = "Synchronized audio player for Sendspin servers",
    version
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Run as a headless audio player.
    ///
    /// By default this listens for incoming server connections and advertises itself over
    /// mDNS. Pass `--url` to dial a specific server instead.
    Daemon(DaemonArgs),
}

#[derive(Parser, Debug)]
pub struct DaemonArgs {
    /// WebSocket URL of the server to connect to.
    ///
    /// Omit to listen for incoming server connections instead, which is what a fixed
    /// appliance on a network with a discovering server wants.
    #[arg(long)]
    pub url: Option<String>,

    /// Port to listen on for incoming server connections.
    #[arg(long, default_value_t = DEFAULT_LISTEN_PORT)]
    pub port: u16,

    /// Friendly name for this client. Defaults to the hostname.
    #[arg(long)]
    pub name: Option<String>,

    /// Stable identifier for this client. Ignored unless `--no-encryption` is set.
    ///
    /// Under the encrypted transport the `client_id` is the public half of this device's
    /// keypair and cannot be chosen: it comes from the identity in the settings directory.
    #[arg(long)]
    pub id: Option<String>,

    /// Directory holding the identity key and pairing records.
    ///
    /// Both have to outlive a reboot for a pairing to still mean anything, and the failure
    /// counter that limits PIN guessing lives here too. Defaults to `$XDG_CONFIG_HOME/sendspin`,
    /// or `~/.config/sendspin`.
    #[arg(long)]
    pub settings_dir: Option<std::path::PathBuf>,

    /// Speak the legacy cleartext transport instead of the spec's encrypted one.
    ///
    /// Only for a server that has not implemented the Noise layer. It cannot pair, so it
    /// cannot reach anything gated on pairing, and a server that requires encryption will
    /// refuse the connection outright.
    #[arg(long)]
    pub no_encryption: bool,

    /// Logging level.
    #[arg(long, default_value = "info",
          value_parser = ["trace", "debug", "info", "warn", "error"])]
    pub log_level: String,

    /// Extra playback delay in milliseconds, applied after clock sync.
    ///
    /// For an external amplifier or speaker that adds latency the protocol cannot see. A
    /// server may override this with `server/command`.
    #[arg(long, default_value_t = 0.0)]
    pub static_delay_ms: f64,

    /// Manufacturer reported in `client/hello`.
    #[arg(long)]
    pub manufacturer: Option<String>,

    /// Product name reported in `client/hello`. Defaults to the detected platform.
    #[arg(long)]
    pub product_name: Option<String>,

    /// IP address of the network interface to bind the listener to.
    ///
    /// Only affects the listening socket. Unlike `sendspin-cli`, this does not yet restrict
    /// which interface mDNS advertises on, because the advertisement API takes no interface.
    #[arg(long)]
    pub interface: Option<String>,
}

/// The largest static delay the protocol allows, in milliseconds.
const MAX_STATIC_DELAY_MS: f64 = 5000.0;

impl DaemonArgs {
    /// The static delay as the protocol carries it, rejecting anything out of range.
    ///
    /// Taken as a float so `--static-delay-ms 12.5` is not a parse error for an operator who
    /// measured one, and rounded here because the wire field is whole milliseconds.
    pub fn static_delay(&self) -> Result<u16, String> {
        if !self.static_delay_ms.is_finite()
            || self.static_delay_ms < 0.0
            || self.static_delay_ms > MAX_STATIC_DELAY_MS
        {
            return Err(format!(
                "--static-delay-ms must be between 0 and {MAX_STATIC_DELAY_MS}, got {}",
                self.static_delay_ms
            ));
        }
        // `as` on a value already bounded above cannot wrap.
        Ok(self.static_delay_ms.round() as u16)
    }

    /// Where the listener binds: the requested interface, or every interface.
    pub fn bind_address(&self) -> String {
        match &self.interface {
            Some(ip) => format!("{ip}:{}", self.port),
            None => format!("0.0.0.0:{}", self.port),
        }
    }
}

impl DaemonArgs {
    /// Where the identity and the pairing records live.
    ///
    /// Follows the XDG base directory spec, because an operator who has set `XDG_CONFIG_HOME`
    /// meant it, and falls back to `~/.config` rather than the working directory — secrets
    /// should not land wherever the service happened to be started from.
    pub fn settings_dir(&self) -> Result<std::path::PathBuf, String> {
        if let Some(dir) = &self.settings_dir {
            return Ok(dir.clone());
        }
        if let Some(xdg) = std::env::var_os("XDG_CONFIG_HOME").filter(|v| !v.is_empty()) {
            return Ok(std::path::PathBuf::from(xdg).join("sendspin"));
        }
        let home = std::env::var_os("HOME")
            .filter(|v| !v.is_empty())
            .ok_or_else(|| {
                "no --settings-dir given and neither XDG_CONFIG_HOME nor HOME is set".to_string()
            })?;
        Ok(std::path::PathBuf::from(home)
            .join(".config")
            .join("sendspin"))
    }
}

/// This machine's hostname, or `unknown` when it cannot be read.
///
/// Used for both the default name and the default id, so an operator who sets neither still
/// gets something a server can tell apart from the box next to it.
pub fn hostname() -> String {
    std::env::var("HOSTNAME")
        .ok()
        .filter(|h| !h.is_empty())
        .or_else(|| {
            std::fs::read_to_string("/etc/hostname")
                .ok()
                .map(|h| h.trim().to_string())
                .filter(|h| !h.is_empty())
        })
        .unwrap_or_else(|| "unknown".to_string())
}

/// The platform name reported in `client/hello` when the operator names none.
pub fn default_product_name() -> String {
    format!(
        "sendspin-rs on {} {}",
        std::env::consts::OS,
        std::env::consts::ARCH
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args_from(argv: &[&str]) -> DaemonArgs {
        match Cli::parse_from(argv).command {
            Command::Daemon(args) => args,
        }
    }

    #[test]
    fn the_listener_binds_everywhere_unless_an_interface_is_named() {
        let args = args_from(&["sendspin", "daemon"]);
        assert_eq!(args.bind_address(), "0.0.0.0:8928");

        let args = args_from(&["sendspin", "daemon", "--interface", "192.168.1.4"]);
        assert_eq!(args.bind_address(), "192.168.1.4:8928");

        // The port applies to the named interface too, rather than only to the default bind.
        let args = args_from(&[
            "sendspin",
            "daemon",
            "--interface",
            "192.168.1.4",
            "--port",
            "9000",
        ]);
        assert_eq!(args.bind_address(), "192.168.1.4:9000");
    }

    /// A delay outside the protocol's range is refused rather than silently clamped: an
    /// operator who typed 50000 meant something, and it was not 5000.
    #[test]
    fn a_static_delay_is_held_to_the_range_the_protocol_defines() {
        assert_eq!(
            args_from(&["sendspin", "daemon", "--static-delay-ms", "12.4"])
                .static_delay()
                .unwrap(),
            12
        );
        assert_eq!(
            args_from(&["sendspin", "daemon", "--static-delay-ms", "12.6"])
                .static_delay()
                .unwrap(),
            13
        );
        assert_eq!(
            args_from(&["sendspin", "daemon", "--static-delay-ms", "5000"])
                .static_delay()
                .unwrap(),
            5000
        );
        // Joined with `=`: a bare `-1` is a flag to clap, not a value, so the separated form
        // fails at parse time and would never reach the range check under test.
        for bad in ["-1", "5000.1", "nan"] {
            assert!(
                args_from(&["sendspin", "daemon", &format!("--static-delay-ms={bad}")])
                    .static_delay()
                    .is_err(),
                "accepted {bad}"
            );
        }
    }

    #[test]
    fn the_default_listen_port_is_the_one_the_spec_recommends() {
        assert_eq!(args_from(&["sendspin", "daemon"]).port, DEFAULT_LISTEN_PORT);
        assert_eq!(DEFAULT_LISTEN_PORT, 8928);
    }
}
