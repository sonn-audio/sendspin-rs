// ABOUTME: Running the operator's scripts on stream lifecycle and on volume changes, with the
// ABOUTME: environment and argument contract sendspin-cli established.

//! External hooks.
//!
//! Three scripts, and they are how a daemon reaches hardware the protocol knows nothing about:
//! an amplifier that needs waking on `--hook-start`, a relay to drop on `--hook-stop`, a mixer
//! to drive from `--hook-set-volume`.
//!
//! The two halves have deliberately different contracts, matching `sendspin-cli`:
//!
//! - The lifecycle hooks run **through a shell**, because they are written as command lines —
//!   `amixer set Master unmute` has to work as typed — and they take their context from
//!   `SENDSPIN_*` environment variables.
//! - The volume hook runs **without a shell**, split into arguments once at startup, and takes
//!   the effective volume as its last argument. No shell, because this one runs on every
//!   volume change with a value from the network, and a value that reaches a shell is a value
//!   that can end a command and start another.

use std::collections::HashMap;
use std::process::Stdio;

use tokio::process::Command;

/// What a lifecycle hook is told about the connection it is firing for.
#[derive(Clone, Debug, Default)]
pub struct HookContext {
    /// The connected server's identity, absent before a connection exists.
    pub server_id: Option<String>,
    /// The connected server's friendly name.
    pub server_name: Option<String>,
    /// The URL this client dialled, absent when the server dialled instead.
    pub server_url: Option<String>,
    /// This client's identity.
    pub client_id: String,
    /// This client's friendly name.
    pub client_name: String,
}

impl HookContext {
    /// The `SENDSPIN_*` variables for `event`.
    ///
    /// Absent values are omitted rather than set empty, so a script can use `${VAR:-default}`
    /// and have it mean something.
    fn environment(&self, event: &str) -> HashMap<&'static str, String> {
        let mut env = HashMap::new();
        env.insert("SENDSPIN_EVENT", event.to_string());
        env.insert("SENDSPIN_CLIENT_ID", self.client_id.clone());
        env.insert("SENDSPIN_CLIENT_NAME", self.client_name.clone());
        if let Some(value) = &self.server_id {
            env.insert("SENDSPIN_SERVER_ID", value.clone());
        }
        if let Some(value) = &self.server_name {
            env.insert("SENDSPIN_SERVER_NAME", value.clone());
        }
        if let Some(value) = &self.server_url {
            env.insert("SENDSPIN_SERVER_URL", value.clone());
        }
        env
    }
}

/// The operator's scripts, resolved once so a bad `--hook-set-volume` fails at startup.
#[derive(Clone, Debug, Default)]
pub struct Hooks {
    /// Command line run when a stream starts.
    pub start: Option<String>,
    /// Command line run when a stream stops.
    pub stop: Option<String>,
    /// Argument vector run on every volume or mute change.
    pub set_volume: Option<Vec<String>>,
}

impl Hooks {
    /// Build from the flags, splitting the volume hook now rather than on first use.
    ///
    /// A quoting mistake in `--hook-set-volume` should be a startup error, not a surprise the
    /// first time someone turns the volume down.
    pub fn new(
        start: Option<String>,
        stop: Option<String>,
        set_volume: Option<&str>,
    ) -> Result<Self, String> {
        let set_volume = match set_volume {
            Some(command) => {
                let argv = shlex::split(command).ok_or_else(|| {
                    format!("--hook-set-volume is not valid shell quoting: {command:?}")
                })?;
                if argv.is_empty() {
                    return Err("--hook-set-volume must name a command".to_string());
                }
                Some(argv)
            }
            None => None,
        };
        Ok(Self {
            start,
            stop,
            set_volume,
        })
    }

    /// Whether volume is the operator's script's business rather than this process's.
    ///
    /// When it is, the audio path deliberately stays at unity gain: attenuating here *and*
    /// in the mixer would apply the setting twice, and the second one is inaudible in the
    /// wrong direction.
    pub fn volume_is_external(&self) -> bool {
        self.set_volume.is_some()
    }

    /// Fire the start hook, if there is one.
    pub fn on_stream_start(&self, context: &HookContext) {
        self.fire(self.start.as_deref(), "start", context);
    }

    /// Fire the stop hook, if there is one.
    pub fn on_stream_stop(&self, context: &HookContext) {
        self.fire(self.stop.as_deref(), "stop", context);
    }

    /// Spawn a lifecycle hook without waiting for it.
    ///
    /// Not awaited on purpose: a hook that blocks — a script waiting on an amplifier's serial
    /// port, say — must not hold up the audio path behind it. What it did is reported when it
    /// finishes.
    fn fire(&self, command: Option<&str>, event: &str, context: &HookContext) {
        let Some(command) = command else { return };
        let command = command.to_string();
        let event = event.to_string();
        let env = context.environment(&event);
        tokio::spawn(async move {
            log::debug!("Running the {event} hook: {command}");
            let output = shell_command(&command).envs(env).output().await;
            match output {
                Ok(output) if output.status.success() => {}
                Ok(output) => log::warn!(
                    "The {event} hook failed ({}): {}",
                    output.status,
                    String::from_utf8_lossy(&output.stderr).trim()
                ),
                Err(e) => log::warn!("Could not run the {event} hook: {e}"),
            }
        });
    }

    /// Hand the effective volume to the volume hook and wait for it.
    ///
    /// Awaited, unlike the lifecycle hooks: this is the only thing making the change audible,
    /// and reporting a volume the mixer has not taken yet would be a lie in `client/state`.
    ///
    /// Mute is expressed as zero rather than as a separate argument, because that is what a
    /// mixer understands. The logical volume is kept by the caller, so unmuting restores it.
    pub async fn set_volume(&self, volume: u8, muted: bool) {
        let Some(argv) = &self.set_volume else { return };
        let effective = if muted { 0 } else { volume };
        let output = Command::new(&argv[0])
            .args(&argv[1..])
            .arg(effective.to_string())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await;
        match output {
            Ok(output) if output.status.success() => {
                log::debug!("Volume hook set {effective}");
            }
            Ok(output) => log::warn!(
                "The volume hook failed ({}): {}",
                output.status,
                String::from_utf8_lossy(&output.stderr).trim()
            ),
            Err(e) => log::warn!("Could not run the volume hook: {e}"),
        }
    }
}

/// A command line run the way an operator wrote it.
#[cfg(unix)]
fn shell_command(command: &str) -> Command {
    let mut shell = Command::new("sh");
    shell
        .arg("-c")
        .arg(command)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    shell
}

#[cfg(windows)]
fn shell_command(command: &str) -> Command {
    let mut shell = Command::new("cmd");
    shell
        .arg("/C")
        .arg(command)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    shell
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_volume_hook_is_split_at_startup_so_bad_quoting_fails_there() {
        let hooks = Hooks::new(None, None, Some("/usr/bin/mixer --card 'Living Room'")).unwrap();
        assert_eq!(
            hooks.set_volume.unwrap(),
            vec!["/usr/bin/mixer", "--card", "Living Room"]
        );

        assert!(Hooks::new(None, None, Some("mixer --card 'unterminated")).is_err());
        assert!(Hooks::new(None, None, Some("   ")).is_err());
    }

    /// The presence of the hook is what moves attenuation out of the audio path, so this is
    /// the flag the playback loop reads rather than the command itself.
    #[test]
    fn a_volume_hook_takes_over_from_the_internal_gain() {
        assert!(!Hooks::default().volume_is_external());
        assert!(Hooks::new(None, None, Some("mixer"))
            .unwrap()
            .volume_is_external());
        // A lifecycle hook alone changes nothing about the gain.
        assert!(!Hooks::new(Some("wake-amp".into()), None, None)
            .unwrap()
            .volume_is_external());
    }

    #[test]
    fn the_environment_names_the_event_and_omits_what_is_unknown() {
        let context = HookContext {
            server_id: Some("server-1".into()),
            server_name: None,
            server_url: Some("ws://host:8927/sendspin".into()),
            client_id: "client-1".into(),
            client_name: "Kitchen".into(),
        };
        let env = context.environment("start");
        assert_eq!(env["SENDSPIN_EVENT"], "start");
        assert_eq!(env["SENDSPIN_SERVER_ID"], "server-1");
        assert_eq!(env["SENDSPIN_SERVER_URL"], "ws://host:8927/sendspin");
        assert_eq!(env["SENDSPIN_CLIENT_ID"], "client-1");
        assert_eq!(env["SENDSPIN_CLIENT_NAME"], "Kitchen");
        // Omitted rather than empty, so `${SENDSPIN_SERVER_NAME:-unknown}` works in a script.
        assert!(!env.contains_key("SENDSPIN_SERVER_NAME"));
    }

    /// A stop hook fires with `stop`, or a script switching on the event does the wrong thing.
    #[test]
    fn each_event_is_named_in_the_environment_it_fires_with() {
        let context = HookContext::default();
        assert_eq!(context.environment("stop")["SENDSPIN_EVENT"], "stop");
        assert_eq!(context.environment("start")["SENDSPIN_EVENT"], "start");
    }
}
