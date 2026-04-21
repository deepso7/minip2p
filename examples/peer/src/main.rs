//! `minip2p-peer`: CLI demo exercising the full minip2p stack.
//!
//! See `holepunch-plan.md` at the repo root for the full design.
//!
//! This file is the tiny dispatch layer: parse argv via [`cli`],
//! then hand off to one of the four mode runners. The mode runners
//! themselves (direct listen/dial, relay listen/dial) live in their
//! own modules so the state machines don't mix with the CLI plumbing.

mod cli;
mod direct;

use cli::{CliError, Mode};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();

    let mode = match cli::parse(args) {
        Ok(mode) => mode,
        Err(CliError(msg)) => {
            eprintln!("{msg}");
            std::process::exit(2);
        }
    };

    if let Err(e) = run(mode) {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

/// Dispatches to the mode runner. Relay modes are still stubs; they land
/// in the `relay` / `holepunch` modules in subsequent steps.
fn run(mode: Mode) -> Result<(), Box<dyn std::error::Error>> {
    match mode {
        Mode::DirectListen => direct::run_listen(),
        Mode::DirectDial { target } => direct::run_dial(target),
        Mode::RelayListen { relay } => not_yet_implemented(&format!(
            "relay listen via {relay}",
        )),
        Mode::RelayDial { relay, target } => not_yet_implemented(&format!(
            "relay dial via {relay} to peer {target}",
        )),
    }
}

fn not_yet_implemented(what: &str) -> Result<(), Box<dyn std::error::Error>> {
    eprintln!("[peer] mode '{what}' not yet implemented.");
    eprintln!("       see holepunch-plan.md for the rollout order.");
    std::process::exit(0);
}
