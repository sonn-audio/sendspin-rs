// ABOUTME: The `sendspin` command-line player: argument parsing, logging, and dispatch to the
// ABOUTME: subcommand that does the work.

//! A headless Sendspin player.
//!
//! Deliberately not a library concern: this lives behind the `cli` feature so that a device
//! embedding `sendspin` as a crate does not link an argument parser, a logger, or anything
//! else that only a command-line program needs.

mod cli;
mod daemon;

use clap::Parser;

#[tokio::main]
async fn main() -> std::process::ExitCode {
    let args = cli::Cli::parse();
    let cli::Command::Daemon(daemon_args) = &args.command;

    // The flag wins over the environment, but `RUST_LOG` is left usable for per-module
    // filtering, which is the thing a level alone cannot express.
    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or(daemon_args.log_level.clone()),
    )
    .init();

    let cli::Command::Daemon(daemon_args) = args.command;
    match daemon::run(daemon_args).await {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            log::error!("{e}");
            std::process::ExitCode::FAILURE
        }
    }
}
