//! 41Swara Smart Contract Security Scanner — `41swara` binary entrypoint.
//!
//! The CLI implementation lives in the library (`solidity_scanner::cli`) and is shared
//! with the short-alias `41` binary (`src/bin/41.rs`). Edit `src/cli.rs` to change CLI
//! behaviour — it is the single source of truth.

fn main() {
    std::process::exit(solidity_scanner::cli::run());
}
