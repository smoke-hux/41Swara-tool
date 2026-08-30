//! Tool Integration Module
//!
//! Integrates with external security tools including:
//! - Dynamic/fuzzing/symbolic/formal/monitoring tool orchestration
//! - Foundry for PoC generation and test correlation
//! - Slither for finding correlation and merging

pub mod dynamic;
pub mod foundry;
pub mod slither;
