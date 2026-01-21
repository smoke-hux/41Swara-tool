//! Tool Integration Module
//!
//! Integrates with external security tools including:
//! - Foundry for PoC generation and test correlation
//! - Slither for finding correlation and merging

pub mod foundry;
pub mod slither;

pub use foundry::FoundryIntegration;
pub use slither::SlitherIntegration;
