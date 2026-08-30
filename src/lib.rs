//! # 41Swara Smart Contract Security Scanner
//!
//! Static analysis for Solidity smart contracts, built for bug bounty hunters, audit
//! contestants, and security researchers.
//!
//! This crate is both a library and a pair of binaries (`41swara` and its short alias
//! `41`). The binaries are thin wrappers around [`cli::run`]; everything else here is
//! usable directly by embedders.
//!
//! ## Quick start
//!
//! ```no_run
//! use solidity_scanner::scanner::{ContractScanner, ScannerConfig};
//!
//! let scanner = ContractScanner::with_config(false, ScannerConfig::default());
//! let result = scanner.scan_file(std::path::Path::new("MyContract.sol"))?;
//! for vuln in &result.vulnerabilities {
//!     println!("{:?} {} at line {}", vuln.severity, vuln.title, vuln.line_number);
//! }
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! ## Module layout
//!
//! The public surface is the scan pipeline plus the reporters. Analysis internals are
//! `pub(crate)` so that the compiler keeps reporting genuinely unused code — making a
//! module `pub` silences the `dead_code` lint for every item inside it, which is how
//! this codebase previously accumulated a large vestigial surface.

// Public API — the surface an embedder needs to run a scan and render results.
pub mod config; // TOML-based custom rules and scanner settings
pub mod cvss; // CVSS 3.1 base score calculator
pub mod parser; // Solidity source parsing (line splitting, compiler version extraction)
pub mod scanner; // Core scanning orchestration engine
pub mod vulnerabilities; // Vulnerability types, categories, and severity definitions

// Reporters — output formats.
pub mod professional_reporter; // Professional audit-style report generation
pub mod reporter; // Terminal-based vulnerability report output
pub mod sarif; // SARIF 2.1.0 data model
pub mod sarif_report; // SARIF 2.1.0 output (GitHub Code Scanning integration)

// Scan entry points beyond a single file.
pub mod abi_scanner; // ABI JSON file vulnerability scanner
pub mod project_scanner; // Cross-file project-wide analysis

// Finding enrichment — referenced by types in the public API.
pub mod attack_path; // Attack narrative generator
pub mod exploit_db; // Real-world exploit reference database

// The CLI itself, so that both binaries can share one implementation.
pub mod cli;

// --- Analysis internals -------------------------------------------------------------
// Kept crate-private on purpose: see the module-layout note above. Promote a module to
// `pub` only when an embedder genuinely needs it, and expect the dead-code lint to go
// quiet for everything inside it when you do.

pub(crate) mod advanced_analysis; // DeFi/NFT/exploit pattern analyzers
pub(crate) mod ai; // Opt-in AI review layer (--ai)
pub(crate) mod ast; // AST/CFG/taint structural analysis
pub(crate) mod cache; // Incremental scan cache
pub(crate) mod defi; // AMM, lending, oracle, MEV protocol analyzers
pub(crate) mod dependency_analyzer; // Import/dependency CVE detection
pub(crate) mod eip_analyzer; // ERC/EIP standard compliance checks
pub(crate) mod false_positive_filter; // Multi-pass false positive reduction
pub(crate) mod inheritance; // Cross-file import and inheritance resolution
pub(crate) mod integrations; // Slither/Foundry correlation, dynamic analysis
pub(crate) mod logic_analyzer; // Business logic vulnerability detection
pub(crate) mod onchain; // Opt-in on-chain verified-source fetch (--fetch)
pub(crate) mod reachability_analyzer; // Dead-code / unreachable path filtering
pub(crate) mod threat_model; // Automatic threat model generation

// --- Convenience re-exports ---------------------------------------------------------

pub use scanner::{ContractScanner, ScanResult, ScannerConfig};
pub use vulnerabilities::{
    Vulnerability, VulnerabilityCategory, VulnerabilityConfidence, VulnerabilitySeverity,
};

/// The scanner version, taken from `Cargo.toml`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
