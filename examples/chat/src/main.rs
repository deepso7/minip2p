//! `minip2p-chat` — group chat over gossipsub, NAT traversal included.

mod cli;
mod modes;

use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mode = match cli::parse(args) {
        Ok(mode) => mode,
        Err(error) => {
            eprintln!("{error}");
            return ExitCode::from(2);
        }
    };

    let result = match mode {
        cli::Mode::Host { relay, chat } => modes::run_host(relay, chat),
        cli::Mode::Join {
            target,
            relay,
            chat,
        } => modes::run_join(target, relay, chat),
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}
