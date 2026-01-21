//! DeFi-Specific Security Analysis
//!
//! Specialized analyzers for DeFi protocols including AMM/DEX, lending,
//! oracles, and MEV vulnerabilities.

pub mod amm_analyzer;
pub mod lending_analyzer;
pub mod oracle_analyzer;
pub mod mev_analyzer;

pub use amm_analyzer::AMMAnalyzer;
pub use lending_analyzer::LendingAnalyzer;
pub use oracle_analyzer::OracleAnalyzer;
pub use mev_analyzer::MEVAnalyzer;

use crate::vulnerabilities::{Vulnerability, VulnerabilitySeverity, VulnerabilityCategory};

/// Unified DeFi analyzer that runs all specialized analyzers
pub struct DeFiAnalyzer {
    amm_analyzer: AMMAnalyzer,
    lending_analyzer: LendingAnalyzer,
    oracle_analyzer: OracleAnalyzer,
    mev_analyzer: MEVAnalyzer,
}

impl DeFiAnalyzer {
    pub fn new() -> Self {
        Self {
            amm_analyzer: AMMAnalyzer::new(),
            lending_analyzer: LendingAnalyzer::new(),
            oracle_analyzer: OracleAnalyzer::new(),
            mev_analyzer: MEVAnalyzer::new(),
        }
    }

    /// Run all DeFi-specific analyses
    pub fn analyze(&self, content: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        // Determine protocol type
        let protocol_type = self.detect_protocol_type(content);

        // Run appropriate analyzers based on protocol type
        match protocol_type {
            ProtocolType::AMM | ProtocolType::DEX => {
                vulnerabilities.extend(self.amm_analyzer.analyze(content));
            }
            ProtocolType::Lending => {
                vulnerabilities.extend(self.lending_analyzer.analyze(content));
            }
            ProtocolType::Unknown => {
                // Run all analyzers for unknown protocols
                vulnerabilities.extend(self.amm_analyzer.analyze(content));
                vulnerabilities.extend(self.lending_analyzer.analyze(content));
            }
        }

        // Always run oracle and MEV analysis
        vulnerabilities.extend(self.oracle_analyzer.analyze(content));
        vulnerabilities.extend(self.mev_analyzer.analyze(content));

        vulnerabilities
    }

    /// Detect the type of DeFi protocol from code patterns
    fn detect_protocol_type(&self, content: &str) -> ProtocolType {
        // AMM/DEX patterns
        if content.contains("getReserves") ||
           content.contains("swapExact") ||
           content.contains("addLiquidity") ||
           content.contains("removeLiquidity") ||
           content.contains("UniswapV") ||
           content.contains("IUniswap") ||
           content.contains("Curve") ||
           content.contains("Balancer") {
            return ProtocolType::AMM;
        }

        // Lending patterns
        if content.contains("borrow") ||
           content.contains("repay") ||
           content.contains("liquidate") ||
           content.contains("collateral") ||
           content.contains("healthFactor") ||
           content.contains("Aave") ||
           content.contains("Compound") {
            return ProtocolType::Lending;
        }

        // DEX aggregator patterns
        if content.contains("swap") && content.contains("aggregat") {
            return ProtocolType::DEX;
        }

        ProtocolType::Unknown
    }
}

impl Default for DeFiAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum ProtocolType {
    AMM,
    DEX,
    Lending,
    Unknown,
}
