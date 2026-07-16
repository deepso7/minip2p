//! `minip2p-peer`: NAT-aware echo-ping demo for the minip2p stack.
//!
//! See `examples/peer/README.md` for usage examples.
//!
//! This file is the tiny dispatch layer: parse argv via [`cli`], then hand
//! off to `modes::run_listen` or `modes::run_dial`. Both runners drive the
//! NAT traversal agent, so the same two subcommands work on loopback,
//! across the open internet, and between two NATed hosts via a relay.

mod cli;
mod modes;

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

/// Dispatches to the mode runner.
fn run(mode: Mode) -> Result<(), Box<dyn std::error::Error>> {
    match mode {
        Mode::Listen { relay, options } => modes::run_listen(relay, options),
        Mode::Dial {
            target,
            relay,
            count,
            options,
        } => modes::run_dial(target, relay, count, options),
    }
}
