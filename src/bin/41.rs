//! 41Swara Smart Contract Security Scanner — short-alias `41` binary entrypoint.
//!
//! Identical to `41swara`; both delegate to `solidity_scanner::cli::run`.

fn main() {
    std::process::exit(solidity_scanner::cli::run());
}
