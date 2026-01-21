//! Oracle Security Analyzer
//!
//! Detects oracle-related vulnerabilities including Chainlink staleness,
//! L2 sequencer checks, TWAP validation, and multi-oracle fallbacks.

#![allow(dead_code)]

use regex::Regex;
use crate::vulnerabilities::{Vulnerability, VulnerabilitySeverity, VulnerabilityCategory};

/// Oracle security analyzer
pub struct OracleAnalyzer {
    chainlink_pattern: Regex,
    latest_round_pattern: Regex,
    twap_pattern: Regex,
    uniswap_oracle_pattern: Regex,
}

impl OracleAnalyzer {
    pub fn new() -> Self {
        Self {
            chainlink_pattern: Regex::new(r"AggregatorV3|priceFeed|PriceFeed|Chainlink").unwrap(),
            latest_round_pattern: Regex::new(r"latestRoundData\(\)").unwrap(),
            twap_pattern: Regex::new(r"TWAP|twap|timeWeightedAverage|observe\(").unwrap(),
            uniswap_oracle_pattern: Regex::new(r"consult|IUniswapV\dOracle").unwrap(),
        }
    }

    /// Analyze content for oracle-specific vulnerabilities
    pub fn analyze(&self, content: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        // Chainlink staleness checks
        vulnerabilities.extend(self.check_chainlink_staleness(content));

        // L2 sequencer uptime checks
        vulnerabilities.extend(self.check_l2_sequencer(content));

        // TWAP window validation
        vulnerabilities.extend(self.check_twap_window(content));

        // Multi-oracle fallback patterns
        vulnerabilities.extend(self.check_oracle_fallback(content));

        // Price deviation checks
        vulnerabilities.extend(self.check_price_deviation(content));

        // Zero price handling
        vulnerabilities.extend(self.check_zero_price(content));

        // Decimal handling
        vulnerabilities.extend(self.check_decimal_handling(content));

        vulnerabilities
    }

    /// Check for Chainlink staleness issues
    fn check_chainlink_staleness(&self, content: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        if !self.chainlink_pattern.is_match(content) {
            return vulnerabilities;
        }

        for (idx, line) in content.lines().enumerate() {
            if self.latest_round_pattern.is_match(line) {
                let func_context = self.get_function_context(content, idx);

                // Check for updatedAt validation
                if !func_context.contains("updatedAt") ||
                   (!func_context.contains("block.timestamp") &&
                    !func_context.contains("heartbeat") &&
                    !func_context.contains("STALENESS")) {
                    vulnerabilities.push(Vulnerability::high_confidence(
                        VulnerabilitySeverity::Critical,
                        VulnerabilityCategory::OracleManipulation,
                        "Chainlink Staleness Check Missing".to_string(),
                        "latestRoundData() called without checking updatedAt timestamp".to_string(),
                        idx + 1,
                        line.to_string(),
                        "Add: require(block.timestamp - updatedAt <= HEARTBEAT_SECONDS, 'Stale price')".to_string(),
                    ));
                }

                // Check for roundId validation
                if !func_context.contains("roundId") ||
                   !func_context.contains("answeredInRound") {
                    vulnerabilities.push(Vulnerability::new(
                        VulnerabilitySeverity::High,
                        VulnerabilityCategory::OracleManipulation,
                        "Chainlink Round Validation Missing".to_string(),
                        "latestRoundData() doesn't validate answeredInRound >= roundId".to_string(),
                        idx + 1,
                        line.to_string(),
                        "Add: require(answeredInRound >= roundId, 'Stale round')".to_string(),
                    ));
                }

                // Check for price > 0 validation
                if !func_context.contains("> 0") && !func_context.contains("!= 0") &&
                   !func_context.contains(">0") {
                    vulnerabilities.push(Vulnerability::new(
                        VulnerabilitySeverity::High,
                        VulnerabilityCategory::OracleManipulation,
                        "Chainlink Zero Price Not Checked".to_string(),
                        "latestRoundData() doesn't validate price > 0".to_string(),
                        idx + 1,
                        line.to_string(),
                        "Add: require(price > 0, 'Invalid price')".to_string(),
                    ));
                }
            }
        }

        vulnerabilities
    }

    /// Check for L2 sequencer uptime (Arbitrum, Optimism)
    fn check_l2_sequencer(&self, content: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        // Detect if this is for L2
        let is_l2_context = content.contains("Arbitrum") ||
                           content.contains("Optimism") ||
                           content.contains("L2") ||
                           content.contains("rollup");

        if is_l2_context && self.chainlink_pattern.is_match(content) {
            // Check for sequencer uptime feed
            if !content.contains("sequencerUptimeFeed") &&
               !content.contains("SEQUENCER") &&
               !content.contains("isSequencerUp") {
                vulnerabilities.push(Vulnerability::high_confidence(
                    VulnerabilitySeverity::Critical,
                    VulnerabilityCategory::OracleManipulation,
                    "L2 Sequencer Uptime Check Missing".to_string(),
                    "L2 deployment uses Chainlink without sequencer uptime validation".to_string(),
                    1,
                    "Chainlink oracle on L2".to_string(),
                    "Add Chainlink sequencer uptime feed check before using price data".to_string(),
                ));
            }

            // Check for grace period after sequencer comes back up
            if content.contains("sequencer") && !content.contains("GRACE_PERIOD") &&
               !content.contains("gracePeriod") {
                for (idx, line) in content.lines().enumerate() {
                    if line.contains("sequencer") {
                        vulnerabilities.push(Vulnerability::new(
                            VulnerabilitySeverity::High,
                            VulnerabilityCategory::OracleManipulation,
                            "L2 Sequencer Grace Period Missing".to_string(),
                            "No grace period after sequencer comes back online".to_string(),
                            idx + 1,
                            line.to_string(),
                            "Add grace period (e.g., 1 hour) after sequencer restarts before trusting prices".to_string(),
                        ));
                        break;
                    }
                }
            }
        }

        vulnerabilities
    }

    /// Check for TWAP window validation
    fn check_twap_window(&self, content: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        if self.twap_pattern.is_match(content) {
            for (idx, line) in content.lines().enumerate() {
                if line.contains("observe(") || line.contains("consult(") {
                    let func_context = self.get_function_context(content, idx);

                    // Check for minimum window
                    if !func_context.contains("MIN_TWAP") && !func_context.contains("minWindow") &&
                       !func_context.contains("WINDOW") {
                        // Try to find the window value
                        let window_pattern = Regex::new(r"(\d+)\s*(seconds?|minutes?|hours?)").unwrap();
                        if let Some(caps) = window_pattern.captures(&func_context) {
                            let value: u64 = caps.get(1).unwrap().as_str().parse().unwrap_or(0);
                            let unit = caps.get(2).unwrap().as_str();

                            let seconds = match unit {
                                u if u.starts_with("minute") => value * 60,
                                u if u.starts_with("hour") => value * 3600,
                                _ => value,
                            };

                            if seconds < 1800 {
                                // Less than 30 minutes
                                vulnerabilities.push(Vulnerability::new(
                                    VulnerabilitySeverity::High,
                                    VulnerabilityCategory::OracleManipulation,
                                    "TWAP Window Too Short".to_string(),
                                    format!("TWAP window of {} seconds is too short for security", seconds),
                                    idx + 1,
                                    line.to_string(),
                                    "Use TWAP window of at least 30 minutes for manipulation resistance".to_string(),
                                ));
                            }
                        }
                    }
                }

                // Check for TWAP observation length
                if line.contains("secondsAgo") || line.contains("secondsAgos") {
                    // Check if array has sufficient observations
                    let func_context = self.get_function_context(content, idx);
                    if func_context.contains("[0]") && !func_context.contains("[1]") {
                        vulnerabilities.push(Vulnerability::new(
                            VulnerabilitySeverity::Medium,
                            VulnerabilityCategory::OracleManipulation,
                            "Single TWAP Observation".to_string(),
                            "TWAP only uses single observation point".to_string(),
                            idx + 1,
                            line.to_string(),
                            "Use multiple observation points for more robust TWAP".to_string(),
                        ));
                    }
                }
            }
        }

        vulnerabilities
    }

    /// Check for multi-oracle fallback patterns
    fn check_oracle_fallback(&self, content: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        // Count oracle sources
        let mut oracle_count = 0;
        if self.chainlink_pattern.is_match(content) {
            oracle_count += 1;
        }
        if self.twap_pattern.is_match(content) || self.uniswap_oracle_pattern.is_match(content) {
            oracle_count += 1;
        }
        if content.contains("Band") || content.contains("DIA") || content.contains("API3") {
            oracle_count += 1;
        }

        // Single oracle without fallback
        if oracle_count == 1 && !content.contains("fallback") && !content.contains("Fallback") {
            // Check for try-catch around oracle calls
            let has_try_catch = content.contains("try") &&
                               (content.contains("latestRoundData") || content.contains("getPrice"));

            if !has_try_catch {
                vulnerabilities.push(Vulnerability::new(
                    VulnerabilitySeverity::Medium,
                    VulnerabilityCategory::OracleManipulation,
                    "Single Oracle Without Fallback".to_string(),
                    "Protocol relies on single oracle source without fallback mechanism".to_string(),
                    1,
                    "Oracle usage".to_string(),
                    "Implement fallback oracle (e.g., Chainlink + TWAP) or try-catch with circuit breaker".to_string(),
                ));
            }
        }

        // Check for oracle aggregation without proper weighting
        if oracle_count > 1 {
            if content.contains("average") || content.contains("median") {
                // Good - using aggregation
            } else if !content.contains("primary") && !content.contains("fallback") {
                vulnerabilities.push(Vulnerability::new(
                    VulnerabilitySeverity::Low,
                    VulnerabilityCategory::OracleManipulation,
                    "Multiple Oracles Without Aggregation Strategy".to_string(),
                    "Multiple oracle sources detected but no clear aggregation or fallback strategy".to_string(),
                    1,
                    "Oracle configuration".to_string(),
                    "Implement clear oracle priority or median-based aggregation".to_string(),
                ));
            }
        }

        vulnerabilities
    }

    /// Check for price deviation validation
    fn check_price_deviation(&self, content: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        // Check if protocol uses prices for critical operations
        let critical_price_usage = content.contains("liquidat") ||
                                   content.contains("collateral") ||
                                   content.contains("borrow") ||
                                   content.contains("swap") ||
                                   content.contains("exchange");

        if critical_price_usage && (self.chainlink_pattern.is_match(content) ||
                                    self.twap_pattern.is_match(content)) {
            // Check for deviation circuit breaker
            if !content.contains("deviation") && !content.contains("Deviation") &&
               !content.contains("priceDiff") && !content.contains("circuitBreaker") &&
               !content.contains("maxChange") {
                vulnerabilities.push(Vulnerability::new(
                    VulnerabilitySeverity::Medium,
                    VulnerabilityCategory::OracleManipulation,
                    "No Price Deviation Circuit Breaker".to_string(),
                    "Critical price operations without deviation checks - vulnerable to oracle failures".to_string(),
                    1,
                    "Price usage in critical operations".to_string(),
                    "Add circuit breaker that pauses on unusual price movements (e.g., >20% change)".to_string(),
                ));
            }
        }

        vulnerabilities
    }

    /// Check for zero/negative price handling
    fn check_zero_price(&self, content: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        // Find price variable assignments
        let price_pattern = Regex::new(r"(price|Price|rate|Rate)\s*=").unwrap();

        for (idx, line) in content.lines().enumerate() {
            if price_pattern.is_match(line) {
                // Check if there's validation nearby
                let func_context = self.get_function_context(content, idx);

                // Look for division by price without zero check
                if func_context.contains("/ price") || func_context.contains("/price") ||
                   func_context.contains("/ rate") || func_context.contains("/rate") {
                    if !func_context.contains("> 0") && !func_context.contains("!= 0") &&
                       !func_context.contains(">0") && !func_context.contains("!=0") {
                        vulnerabilities.push(Vulnerability::new(
                            VulnerabilitySeverity::High,
                            VulnerabilityCategory::ArithmeticIssues,
                            "Division by Price Without Zero Check".to_string(),
                            "Price used in division without checking for zero".to_string(),
                            idx + 1,
                            line.to_string(),
                            "Add: require(price > 0, 'Invalid price') before division".to_string(),
                        ));
                    }
                }
            }
        }

        vulnerabilities
    }

    /// Check for decimal handling in oracle prices
    fn check_decimal_handling(&self, content: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        // Check for mixed decimal handling
        let has_1e18 = content.contains("1e18") || content.contains("10**18");
        let has_1e8 = content.contains("1e8") || content.contains("10**8");
        let has_1e6 = content.contains("1e6") || content.contains("10**6");

        let decimal_count = [has_1e18, has_1e8, has_1e6].iter().filter(|&&x| x).count();

        if decimal_count > 1 {
            // Check for explicit decimal normalization
            if !content.contains("decimals()") && !content.contains("_decimals") &&
               !content.contains("normaliz") && !content.contains("scale") {
                vulnerabilities.push(Vulnerability::high_confidence(
                    VulnerabilitySeverity::Critical,
                    VulnerabilityCategory::DecimalPrecisionMismatch,
                    "Mixed Decimals Without Normalization".to_string(),
                    "Contract mixes different decimal precisions without explicit normalization".to_string(),
                    1,
                    "Multiple decimal standards detected".to_string(),
                    "Normalize all prices to same decimal precision before arithmetic operations".to_string(),
                ));
            }
        }

        // Check for Chainlink decimal handling
        if self.chainlink_pattern.is_match(content) {
            if !content.contains("decimals()") && !content.contains("PRICE_DECIMALS") {
                for (idx, line) in content.lines().enumerate() {
                    if self.latest_round_pattern.is_match(line) {
                        vulnerabilities.push(Vulnerability::new(
                            VulnerabilitySeverity::Medium,
                            VulnerabilityCategory::DecimalPrecisionMismatch,
                            "Chainlink Decimals Not Checked".to_string(),
                            "Using Chainlink price without checking feed decimals".to_string(),
                            idx + 1,
                            line.to_string(),
                            "Call priceFeed.decimals() and normalize price accordingly".to_string(),
                        ));
                        break;
                    }
                }
            }
        }

        vulnerabilities
    }

    // Helper methods
    fn get_function_context(&self, content: &str, line_idx: usize) -> String {
        let lines: Vec<&str> = content.lines().collect();
        let start = line_idx.saturating_sub(15);
        let end = (line_idx + 15).min(lines.len());
        lines[start..end].join("\n")
    }
}

impl Default for OracleAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}
