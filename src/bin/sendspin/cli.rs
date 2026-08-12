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
    Daemon(Box<DaemonArgs>),

    /// Audio device utilities.
    AudioDevices {
        #[command(subcommand)]
        command: AudioDevicesCommand,
    },

    /// Run a Sendspin server.
    #[cfg(feature = "serve")]
    Serve(Box<ServeArgs>),

    /// Server discovery utilities.
    Servers {
        #[command(subcommand)]
        command: DiscoveryCommand,
    },

    /// Client discovery utilities.
    Clients {
        #[command(subcommand)]
        command: DiscoveryCommand,
    },
}

#[derive(Subcommand, Debug)]
pub enum AudioDevicesCommand {
    /// List the output devices this machine can play through, and exit.
    List,
}

#[derive(Subcommand, Debug)]
pub enum DiscoveryCommand {
    /// Discover what is on the network over mDNS, and exit.
    List {
        /// Seconds to listen for answers.
        ///
        /// A browse cannot know it has heard everything, so this is a window rather than a
        /// timeout: it always waits the full time, and a device that answers slowly is still
        /// one worth listing.
        #[arg(long, default_value_t = 3)]
        seconds: u64,
    },
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
    /// counter that limits PIN guessing lives here too. Defaults to `$STATE_DIRECTORY` under
    /// systemd, else `$XDG_CONFIG_HOME/sendspin`, else `~/.config/sendspin`.
    #[arg(long)]
    pub settings_dir: Option<std::path::PathBuf>,

    /// Let a server that has not paired with this client use it for playback.
    ///
    /// Off by default, which is what the protocol's conservative reading asks for: an unpaired
    /// session is authenticated by nothing and is open to a man in the middle. Until this is
    /// set, or a pairing completes, a server activates no roles and nothing plays. Persisted in
    /// the settings directory, so it is set once rather than on every start.
    #[arg(long)]
    pub allow_unpaired: bool,

    /// Speak the legacy cleartext transport instead of the spec's encrypted one.
    ///
    /// Only for a server that has not implemented the Noise layer. It cannot pair, so it
    /// cannot reach anything gated on pairing, and a server that requires encryption will
    /// refuse the connection outright.
    #[arg(long)]
    pub no_encryption: bool,

    /// Seconds to wait before redialling after `--url` loses its server. 0 disables it.
    ///
    /// A dedicated player has to come back on its own: a server that restarts should leave the
    /// speaker silent for a few seconds, not until someone notices. Backs off up to a minute so
    /// a server that is down for the night is not dialled fifty times a second, and resets once
    /// a connection comes up. Only meaningful with `--url`; the listening path already waits.
    #[arg(long, default_value_t = 5)]
    pub reconnect_secs: u64,

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

    /// Audio output device: an index from `audio-devices list`, or a name.
    ///
    /// A name matches an exact device id or description first, then any that starts with it —
    /// so `--audio-device HDA` picks the first HDA card without spelling out its full ALSA
    /// name. Omit to use the platform default.
    #[arg(long)]
    pub audio_device: Option<String>,

    /// Pin the stream format as `codec:sample_rate:bit_depth:channels`, e.g. `flac:48000:24:2`.
    ///
    /// This is the only format offered to the server, so it decides what gets sent rather than
    /// merely preferring it. Checked against the output device at startup: a device that
    /// cannot play it is an error here, not silence later.
    #[arg(long)]
    pub audio_format: Option<String>,

    /// Drive the sound card's own volume control instead of attenuating in software.
    ///
    /// Software attenuation throws away bits, and it shows a number that a knob on the front
    /// panel does not move. Takes an ALSA card name (`default`, `hw:0`); pass it bare to use
    /// the card the output device is on. Ignored when `--hook-set-volume` is set, since that
    /// already moves the level out of this process.
    #[arg(long, num_args = 0..=1, default_missing_value = "default")]
    pub hardware_volume: Option<String>,

    /// Command to run when an audio stream starts.
    ///
    /// Run through a shell, so it can be written as typed, and given the connection's details
    /// in `SENDSPIN_EVENT`, `SENDSPIN_SERVER_ID`, `SENDSPIN_SERVER_NAME`, `SENDSPIN_SERVER_URL`,
    /// `SENDSPIN_CLIENT_ID` and `SENDSPIN_CLIENT_NAME`. For waking an amplifier or closing a
    /// relay the protocol knows nothing about.
    #[arg(long)]
    pub hook_start: Option<String>,

    /// Command to run when an audio stream stops. Same environment as `--hook-start`.
    #[arg(long)]
    pub hook_stop: Option<String>,

    /// Script that applies volume externally, given the effective volume 0-100 as its last
    /// argument.
    ///
    /// Setting this moves attenuation out of this process entirely: the audio path stays at
    /// unity gain and the script owns the level, so it is not applied twice. Mute arrives as
    /// zero. Run without a shell and split at startup, because it takes a value from the
    /// network on every change.
    #[arg(long)]
    pub hook_set_volume: Option<String>,

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
    pub fn settings_dir(&self) -> Result<std::path::PathBuf, String> {
        settings_dir(self.settings_dir.as_deref())
    }
}

/// Where a client's or server's persistent state lives.
///
/// Follows the XDG base directory spec, because an operator who has set `XDG_CONFIG_HOME`
/// meant it, and falls back to `~/.config` rather than the working directory — secrets should
/// not land wherever the service happened to be started from.
pub fn settings_dir(explicit: Option<&std::path::Path>) -> Result<std::path::PathBuf, String> {
    {
        if let Some(dir) = explicit {
            return Ok(dir.to_path_buf());
        }
        // systemd sets this from `StateDirectory=` and creates it with the right owner. It
        // comes first because a system service usually has no HOME at all, and a daemon that
        // refused to start there would be a daemon that cannot be a system service.
        if let Some(state) = std::env::var_os("STATE_DIRECTORY").filter(|v| !v.is_empty()) {
            // The variable is colon-separated when several are configured; the first is ours.
            let first = std::env::split_paths(&state).next();
            if let Some(first) = first.filter(|p| !p.as_os_str().is_empty()) {
                return Ok(first);
            }
        }
        if let Some(xdg) = std::env::var_os("XDG_CONFIG_HOME").filter(|v| !v.is_empty()) {
            return Ok(std::path::PathBuf::from(xdg).join("sendspin"));
        }
        let home = std::env::var_os("HOME")
            .filter(|v| !v.is_empty())
            .ok_or_else(|| {
                "no --settings-dir given, and none of STATE_DIRECTORY, XDG_CONFIG_HOME or HOME \
                 is set"
                    .to_string()
            })?;
        Ok(std::path::PathBuf::from(home)
            .join(".config")
            .join("sendspin"))
    }
}

/// Arguments for `sendspin serve`.
#[cfg(feature = "serve")]
#[derive(Parser, Debug)]
pub struct ServeArgs {
    /// Port to listen on.
    #[arg(long, default_value_t = 8927)]
    pub port: u16,

    /// Friendly name sent in `server/hello` and advertised over mDNS.
    #[arg(long, default_value = "Sendspin Server")]
    pub name: String,

    /// Audio to play: a WAV or FLAC file, looped.
    ///
    /// Only those two formats. Anything else needs a general-purpose decoder, and linking one
    /// in would cost every player build a dependency it has no use for; convert the file
    /// first. The track's name is served to clients that activate `metadata@v1`.
    #[arg(long)]
    pub source: Option<String>,

    /// Play a 440 Hz test tone instead of a file.
    ///
    /// For proving a client's clock sync and playback path without needing any audio to hand.
    #[arg(long)]
    pub demo: bool,

    /// Do not advertise over mDNS.
    ///
    /// For a server that is reached at a configured address, on a network where an extra
    /// multicast responder is unwelcome.
    #[arg(long)]
    pub no_discovery: bool,

    /// Directory holding the server's identity key.
    ///
    /// The `server_id` is the public half of that key, so it has to outlive a restart: a
    /// server that generates a new one is a new server to every client that paired with it.
    #[arg(long)]
    pub settings_dir: Option<std::path::PathBuf>,

    /// Logging level.
    #[arg(long, default_value = "info",
          value_parser = ["trace", "debug", "info", "warn", "error"])]
    pub log_level: String,
}

#[cfg(feature = "serve")]
impl ServeArgs {
    /// Where the identity lives.
    pub fn settings_dir(&self) -> Result<std::path::PathBuf, String> {
        settings_dir(self.settings_dir.as_deref())
    }
}

/// This machine's hostname, or `unknown` when it cannot be read.
///
/// Used for both the default name and the default id, so an operator who sets neither still
/// gets something a server can tell apart from the box next to it.
///
/// Asked of the system rather than only of the environment. `$HOSTNAME` is a shell
/// convention that zsh does not export and `/etc/hostname` is a Linux one, so a Mac with
/// neither would introduce itself to every server on the network as `unknown` — and so would
/// the box beside it.
pub fn hostname() -> String {
    std::env::var("HOSTNAME")
        .ok()
        // Windows spells it differently, and spells it in the environment.
        .or_else(|| std::env::var("COMPUTERNAME").ok())
        .map(|name| name.trim().to_string())
        .filter(|name| !name.is_empty())
        .or_else(system_hostname)
        .or_else(|| {
            std::fs::read_to_string("/etc/hostname")
                .ok()
                .map(|h| h.trim().to_string())
                .filter(|h| !h.is_empty())
        })
        .unwrap_or_else(|| "unknown".to_string())
}

/// The name the kernel knows this machine by, via `gethostname(2)`.
#[cfg(unix)]
fn system_hostname() -> Option<String> {
    // Long enough for HOST_NAME_MAX on every Unix that matters, plus the terminator.
    let mut buffer = [0_u8; 256];
    // SAFETY: the pointer and the length describe a buffer this frame owns, and the call
    // writes at most `len` bytes into it.
    let result = unsafe { libc::gethostname(buffer.as_mut_ptr().cast(), buffer.len()) };
    if result != 0 {
        return None;
    }
    // A name that filled the buffer may not be terminated, so the end is the terminator or
    // the buffer, whichever comes first.
    let end = buffer
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(buffer.len());
    std::str::from_utf8(&buffer[..end])
        .ok()
        .map(|name| name.trim().to_string())
        .filter(|name| !name.is_empty())
}

#[cfg(not(unix))]
fn system_hostname() -> Option<String> {
    None
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
            Command::Daemon(args) => *args,
            other => panic!("expected a daemon invocation, got {other:?}"),
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
