// ABOUTME: The `sendspin` command-line player: argument parsing, logging, and dispatch to the
// ABOUTME: subcommand that does the work.

//! A headless Sendspin player.
//!
//! Deliberately not a library concern: this lives behind the `cli` feature so that a device
//! embedding `sendspin` as a crate does not link an argument parser, a logger, or anything
//! else that only a command-line program needs.

mod audio;
mod cli;
mod daemon;
mod discovery;

#[cfg(feature = "serve")]
mod serve;

use clap::Parser;

#[tokio::main]
async fn main() -> std::process::ExitCode {
    let args = cli::Cli::parse();

    // The flag wins over the environment, but `RUST_LOG` is left usable for per-module
    // filtering, which is the thing a level alone cannot express.
    let level = match &args.command {
        cli::Command::Daemon(daemon) => daemon.log_level.clone(),
        #[cfg(feature = "serve")]
        cli::Command::Serve(serve) => serve.log_level.clone(),
        // A one-shot listing should print its list, not a log; anything it has to say it says
        // on stdout.
        cli::Command::AudioDevices { .. }
        | cli::Command::Servers { .. }
        | cli::Command::Clients { .. } => "warn".to_string(),
    };
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(level)).init();

    let result = match args.command {
        cli::Command::Daemon(daemon_args) => daemon::run(*daemon_args).await,
        #[cfg(feature = "serve")]
        cli::Command::Serve(serve_args) => serve::run(*serve_args).await,
        cli::Command::AudioDevices { command } => match command {
            cli::AudioDevicesCommand::List => audio::list_devices().map_err(Into::into),
        },
        // Blocking the runtime on purpose: this process exists to print one list, so there is
        // nothing else on it to starve.
        cli::Command::Servers { command } => match command {
            cli::DiscoveryCommand::List { seconds } => {
                discovery::list_servers(seconds).map_err(Into::into)
            }
        },
        cli::Command::Clients { command } => match command {
            cli::DiscoveryCommand::List { seconds } => {
                discovery::list_clients(seconds).map_err(Into::into)
            }
        },
    };
    match result {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            // On stderr rather than through the log, so a misconfiguration is visible even
            // when the level was turned down.
            eprintln!("error: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}
