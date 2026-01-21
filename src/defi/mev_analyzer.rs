//! MEV (Maximal Extractable Value) Vulnerability Analyzer
//!
//! Detects MEV-related vulnerabilities including sandwich attacks,
//! frontrunning, backrunning, and commit-reveal pattern validation.

use regex::Regex;
use crate::vulnerabilities::{Vulnerability, VulnerabilitySeverity, VulnerabilityCategory};

/// MEV vulnerability analyzer
pub struct MEVAnalyzer {
    swap_pattern: Regex,
    liquidate_pattern: Regex,
    auction_pattern: Regex,
    commit_reveal_pattern: Regex,
}

impl MEVAnalyzer {
    pub fn new() -> Self {
        Self {
            swap_pattern: Regex::new(r"function\s+swap\w*\s*\([^)]*\)").unwrap(),
            liquidate_pattern: Regex::new(r"function\s+liquidate\w*\s*\([^)]*\)").unwrap(),
            auction_pattern: Regex::new(r"function\s+(bid|auction|mint)\w*\s*\([^)]*\)").unwrap(),
            commit_reveal_pattern: Regex::new(r"commit|reveal|hash|Commit|Reveal").unwrap(),
        }
    }

    /// Analyze content for MEV-specific vulnerabilities
    pub fn analyze(&self, content: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        // Sandwich vulnerable swaps
        vulnerabilities.extend(self.check_sandwich_vulnerability(content));

        // Public liquidation targets
        vulnerabilities.extend(self.check_liquidation_mev(content));

        // Oracle update frontrun opportunities
        vulnerabilities.extend(self.check_oracle_frontrun(content));

        // Commit-reveal pattern validation
        vulnerabilities.extend(self.check_commit_reveal(content));

        // NFT mint frontrunning
        vulnerabilities.extend(self.check_nft_mint_mev(content));

        // Auction frontrunning
        vulnerabilities.extend(self.check_auction_mev(content));

        // Time-based vulnerabilities
        vulnerabilities.extend(self.check_time_based_mev(content));

        vulnerabilities
    }

    /// Check for sandwich attack vulnerabilities
    fn check_sandwich_vulnerability(&self, content: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        for (idx, line) in content.lines().enumerate() {
            if self.swap_pattern.is_match(line) {
                // Check for slippage protection
                let has_slippage = line.contains("minAmount") ||
                                   line.contains("amountOutMin") ||
                                   line.contains("minReturn") ||
                                   line.contains("slippage");

                // Check for deadline
                let has_deadline = line.contains("deadline") ||
                                   line.contains("expiry") ||
                                   line.contains("validUntil");

                if !has_slippage && !has_deadline {
                    vulnerabilities.push(Vulnerability::high_confidence(
                        VulnerabilitySeverity::Critical,
                        VulnerabilityCategory::MEVExploitable,
                        "Sandwich Attack Vulnerable Swap".to_string(),
                        "Swap function without slippage AND deadline protection".to_string(),
                        idx + 1,
                        line.to_string(),
                        "Add BOTH minAmountOut AND deadline parameters to prevent sandwich attacks".to_string(),
                    ));
                } else if !has_slippage {
                    vulnerabilities.push(Vulnerability::new(
                        VulnerabilitySeverity::High,
                        VulnerabilityCategory::MEVExploitable,
                        "Missing Slippage Protection".to_string(),
                        "Swap function without minimum output protection".to_string(),
                        idx + 1,
                        line.to_string(),
                        "Add minAmountOut parameter to protect against price manipulation".to_string(),
                    ));
                } else if !has_deadline {
                    vulnerabilities.push(Vulnerability::new(
                        VulnerabilitySeverity::High,
                        VulnerabilityCategory::MEVExploitable,
                        "Missing Transaction Deadline".to_string(),
                        "Swap function without deadline - can be held for unfavorable execution".to_string(),
                        idx + 1,
                        line.to_string(),
                        "Add deadline parameter: require(block.timestamp <= deadline)".to_string(),
                    ));
                }

                // Check for zero slippage in the function body
                let func_body = self.extract_function_body(content, idx);
                if func_body.contains("amountOutMin = 0") ||
                   func_body.contains("minAmount = 0") ||
                   func_body.contains(", 0,") && func_body.contains("swap") {
                    vulnerabilities.push(Vulnerability::high_confidence(
                        VulnerabilitySeverity::Critical,
                        VulnerabilityCategory::MEVExploitable,
                        "Zero Slippage Tolerance".to_string(),
                        "Swap with zero minimum output - 100% sandwich profitable".to_string(),
                        idx + 1,
                        line.to_string(),
                        "NEVER hardcode zero slippage - calculate realistic minimum based on expected price".to_string(),
                    ));
                }
            }
        }

        // Check for router swaps without protection
        let router_patterns = [
            "swapExactTokensForTokens",
            "swapTokensForExactTokens",
            "swapExactETHForTokens",
            "swapExactTokensForETH",
        ];

        for pattern in router_patterns {
            for (idx, line) in content.lines().enumerate() {
                if line.contains(pattern) {
                    // Check for hardcoded zero
                    if line.contains(", 0,") || line.contains(",0,") {
                        vulnerabilities.push(Vulnerability::high_confidence(
                            VulnerabilitySeverity::Critical,
                            VulnerabilityCategory::MEVExploitable,
                            format!("Zero Slippage in {}", pattern),
                            "Router swap called with zero minimum output".to_string(),
                            idx + 1,
                            line.to_string(),
                            "Replace 0 with calculated minimum: amountOut * (100 - slippageBps) / 100".to_string(),
                        ));
                    }
                }
            }
        }

        vulnerabilities
    }

    /// Check for liquidation MEV vulnerabilities
    fn check_liquidation_mev(&self, content: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        for (idx, line) in content.lines().enumerate() {
            if self.liquidate_pattern.is_match(line) {
                let func_body = self.extract_function_body(content, idx);

                // Check for MEV protection mechanisms
                let has_mev_protection =
                    func_body.contains("flashbots") ||
                    func_body.contains("Flashbots") ||
                    func_body.contains("private") ||
                    func_body.contains("auction") ||
                    func_body.contains("Auction") ||
                    func_body.contains("dutch") ||
                    func_body.contains("Dutch") ||
                    content.contains("commit") ||
                    content.contains("reveal");

                if !has_mev_protection {
                    vulnerabilities.push(Vulnerability::new(
                        VulnerabilitySeverity::High,
                        VulnerabilityCategory::MEVExploitable,
                        "Public Liquidation - MEV Target".to_string(),
                        "Liquidation function is public mempool visible - will be frontrun".to_string(),
                        idx + 1,
                        line.to_string(),
                        "Consider: Dutch auction, Flashbots Protect, or liquidation incentive redesign".to_string(),
                    ));
                }

                // Check for liquidation bonus that incentivizes frontrunning
                if func_body.contains("bonus") || func_body.contains("incentive") {
                    let bonus_pattern = Regex::new(r"(\d+)\s*%|(\d+)\s*bps|10\s*\*\*").unwrap();
                    if let Some(_caps) = bonus_pattern.captures(&func_body) {
                        vulnerabilities.push(Vulnerability::new(
                            VulnerabilitySeverity::Medium,
                            VulnerabilityCategory::MEVExploitable,
                            "Liquidation Bonus Incentivizes MEV".to_string(),
                            "Fixed liquidation bonus creates predictable MEV opportunity".to_string(),
                            idx + 1,
                            line.to_string(),
                            "Consider variable bonus based on competition or Dutch auction".to_string(),
                        ));
                    }
                }
            }
        }

        vulnerabilities
    }

    /// Check for oracle update frontrunning
    fn check_oracle_frontrun(&self, content: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        // Check for oracle update functions
        let oracle_update_pattern = Regex::new(r"function\s+(setPrice|updatePrice|submitPrice|report)\w*\s*\(").unwrap();

        for (idx, line) in content.lines().enumerate() {
            if oracle_update_pattern.is_match(line) {
                let func_body = self.extract_function_body(content, idx);

                // Check for access control
                let has_access_control =
                    func_body.contains("onlyOwner") ||
                    func_body.contains("onlyOracle") ||
                    func_body.contains("onlyReporter") ||
                    func_body.contains("hasRole");

                if !has_access_control {
                    vulnerabilities.push(Vulnerability::high_confidence(
                        VulnerabilitySeverity::Critical,
                        VulnerabilityCategory::MEVExploitable,
                        "Public Oracle Update - Frontrunnable".to_string(),
                        "Oracle price update visible in mempool before execution".to_string(),
                        idx + 1,
                        line.to_string(),
                        "Use commit-reveal, threshold signatures, or private mempool for updates".to_string(),
                    ));
                }

                // Check for deviation limits
                if !func_body.contains("deviation") && !func_body.contains("maxChange") &&
                   !func_body.contains("threshold") {
                    vulnerabilities.push(Vulnerability::new(
                        VulnerabilitySeverity::Medium,
                        VulnerabilityCategory::OracleManipulation,
                        "Oracle Update Without Deviation Check".to_string(),
                        "Oracle can be updated with any price - no sanity check".to_string(),
                        idx + 1,
                        line.to_string(),
                        "Add maximum price deviation check per update".to_string(),
                    ));
                }
            }
        }

        vulnerabilities
    }

    /// Check for commit-reveal pattern issues
    fn check_commit_reveal(&self, content: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        if !self.commit_reveal_pattern.is_match(content) {
            return vulnerabilities;
        }

        // Find commit function
        let commit_pattern = Regex::new(r"function\s+commit\w*\s*\([^)]*\)").unwrap();
        let reveal_pattern = Regex::new(r"function\s+reveal\w*\s*\([^)]*\)").unwrap();

        let has_commit = commit_pattern.is_match(content);
        let has_reveal = reveal_pattern.is_match(content);

        if has_commit && has_reveal {
            for (idx, line) in content.lines().enumerate() {
                if commit_pattern.is_match(line) {
                    let func_body = self.extract_function_body(content, idx);

                    // Check for proper hash computation
                    if !func_body.contains("keccak256") && !func_body.contains("sha256") {
                        vulnerabilities.push(Vulnerability::new(
                            VulnerabilitySeverity::High,
                            VulnerabilityCategory::LogicError,
                            "Commit Without Hash".to_string(),
                            "Commit function doesn't use cryptographic hash".to_string(),
                            idx + 1,
                            line.to_string(),
                            "Commit should store keccak256(abi.encode(value, secret))".to_string(),
                        ));
                    }

                    // Check for block.number/timestamp in commit
                    if func_body.contains("block.number") || func_body.contains("block.timestamp") {
                        // Good - has timing
                    } else {
                        vulnerabilities.push(Vulnerability::new(
                            VulnerabilitySeverity::Medium,
                            VulnerabilityCategory::LogicError,
                            "Commit Without Timing".to_string(),
                            "Commit doesn't record block number/timestamp".to_string(),
                            idx + 1,
                            line.to_string(),
                            "Store commit block/time to enforce reveal timing".to_string(),
                        ));
                    }
                }

                if reveal_pattern.is_match(line) {
                    let func_body = self.extract_function_body(content, idx);

                    // Check for minimum reveal delay
                    if !func_body.contains("block.number") && !func_body.contains("block.timestamp") {
                        vulnerabilities.push(Vulnerability::new(
                            VulnerabilitySeverity::High,
                            VulnerabilityCategory::FrontRunning,
                            "Reveal Without Timing Check".to_string(),
                            "Reveal can be frontrun - no minimum delay enforced".to_string(),
                            idx + 1,
                            line.to_string(),
                            "Require minimum blocks/time between commit and reveal".to_string(),
                        ));
                    }

                    // Check for commit hash verification
                    if !func_body.contains("commit") || !func_body.contains("keccak256") {
                        vulnerabilities.push(Vulnerability::high_confidence(
                            VulnerabilitySeverity::Critical,
                            VulnerabilityCategory::LogicError,
                            "Reveal Without Commit Verification".to_string(),
                            "Reveal doesn't verify against stored commit hash".to_string(),
                            idx + 1,
                            line.to_string(),
                            "Verify: keccak256(abi.encode(value, secret)) == storedCommit".to_string(),
                        ));
                    }
                }
            }
        } else if has_commit != has_reveal {
            vulnerabilities.push(Vulnerability::new(
                VulnerabilitySeverity::Medium,
                VulnerabilityCategory::LogicError,
                "Incomplete Commit-Reveal Pattern".to_string(),
                format!("Has {} but not {}",
                    if has_commit { "commit" } else { "reveal" },
                    if has_commit { "reveal" } else { "commit" }),
                1,
                "Commit-reveal implementation".to_string(),
                "Implement complete commit-reveal pattern with both phases".to_string(),
            ));
        }

        vulnerabilities
    }

    /// Check for NFT mint frontrunning
    fn check_nft_mint_mev(&self, content: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        // Check for mint functions
        let mint_pattern = Regex::new(r"function\s+mint\w*\s*\([^)]*\)\s*(external|public)").unwrap();

        if content.contains("ERC721") || content.contains("ERC1155") {
            for (idx, line) in content.lines().enumerate() {
                if mint_pattern.is_match(line) {
                    let func_body = self.extract_function_body(content, idx);

                    // Check for whitelist/merkle proof
                    let has_whitelist =
                        func_body.contains("whitelist") ||
                        func_body.contains("merkle") ||
                        func_body.contains("Merkle") ||
                        func_body.contains("proof");

                    // Check for reveal pattern (for metadata)
                    let has_reveal = content.contains("reveal") || content.contains("Reveal");

                    if !has_whitelist {
                        vulnerabilities.push(Vulnerability::new(
                            VulnerabilitySeverity::Medium,
                            VulnerabilityCategory::FrontRunning,
                            "Public NFT Mint Without Whitelist".to_string(),
                            "Public mint function can be frontrun by bots".to_string(),
                            idx + 1,
                            line.to_string(),
                            "Consider whitelist phase or commit-reveal for fair mint".to_string(),
                        ));
                    }

                    // Check for batch mint without limit
                    if func_body.contains("amount") || func_body.contains("quantity") {
                        if !func_body.contains("maxMint") && !func_body.contains("MAX_") &&
                           !func_body.contains("limit") {
                            vulnerabilities.push(Vulnerability::new(
                                VulnerabilitySeverity::High,
                                VulnerabilityCategory::DoSAttacks,
                                "Unlimited Batch Mint".to_string(),
                                "Batch mint without limit - whales can mint entire supply".to_string(),
                                idx + 1,
                                line.to_string(),
                                "Add per-transaction and per-wallet mint limits".to_string(),
                            ));
                        }
                    }

                    // Check for block.timestamp randomness
                    if func_body.contains("block.timestamp") && func_body.contains("random") {
                        vulnerabilities.push(Vulnerability::high_confidence(
                            VulnerabilitySeverity::Critical,
                            VulnerabilityCategory::FrontRunning,
                            "Predictable NFT Randomness".to_string(),
                            "Using block.timestamp for randomness - miners can manipulate".to_string(),
                            idx + 1,
                            line.to_string(),
                            "Use Chainlink VRF or commit-reveal for fair randomness".to_string(),
                        ));
                    }
                }
            }
        }

        vulnerabilities
    }

    /// Check for auction frontrunning
    fn check_auction_mev(&self, content: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        for (idx, line) in content.lines().enumerate() {
            if self.auction_pattern.is_match(line) && line.contains("bid") {
                let func_body = self.extract_function_body(content, idx);

                // Check for sealed bid
                let is_sealed =
                    func_body.contains("commit") ||
                    func_body.contains("sealed") ||
                    func_body.contains("hash");

                if !is_sealed {
                    vulnerabilities.push(Vulnerability::new(
                        VulnerabilitySeverity::Medium,
                        VulnerabilityCategory::FrontRunning,
                        "Open Bid Auction - Frontrunnable".to_string(),
                        "Bids visible in mempool can be frontrun/outbid".to_string(),
                        idx + 1,
                        line.to_string(),
                        "Consider sealed-bid auction or Flashbots Protect for fair bidding".to_string(),
                    ));
                }

                // Check for last-block sniping protection
                if !func_body.contains("timeExtension") && !func_body.contains("extendAuction") &&
                   !func_body.contains("antiSnipe") {
                    vulnerabilities.push(Vulnerability::new(
                        VulnerabilitySeverity::Low,
                        VulnerabilityCategory::FrontRunning,
                        "Auction Without Anti-Snipe".to_string(),
                        "No time extension on late bids - vulnerable to last-second sniping".to_string(),
                        idx + 1,
                        line.to_string(),
                        "Extend auction end time if bid placed near deadline".to_string(),
                    ));
                }
            }
        }

        vulnerabilities
    }

    /// Check for time-based MEV vulnerabilities
    fn check_time_based_mev(&self, content: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        for (idx, line) in content.lines().enumerate() {
            // Check for timestamp-dependent logic
            if line.contains("block.timestamp") {
                let func_context = self.get_function_context(content, idx);

                // Check for strict equality (bad pattern)
                if line.contains("== block.timestamp") ||
                   line.contains("block.timestamp ==") {
                    vulnerabilities.push(Vulnerability::new(
                        VulnerabilitySeverity::High,
                        VulnerabilityCategory::FrontRunning,
                        "Strict Timestamp Equality".to_string(),
                        "Using exact timestamp match - easily manipulated by miners".to_string(),
                        idx + 1,
                        line.to_string(),
                        "Use >= or <= with reasonable tolerance instead of ==".to_string(),
                    ));
                }

                // Check for small time windows
                let small_window_pattern = Regex::new(r"(\d+)\s*(seconds?|minutes?)").unwrap();
                if let Some(caps) = small_window_pattern.captures(&func_context) {
                    let value: u64 = caps.get(1).unwrap().as_str().parse().unwrap_or(0);
                    let unit = caps.get(2).unwrap().as_str();

                    let seconds = if unit.starts_with("minute") { value * 60 } else { value };

                    if seconds < 900 && seconds > 0 {
                        // Less than 15 minutes
                        vulnerabilities.push(Vulnerability::new(
                            VulnerabilitySeverity::Medium,
                            VulnerabilityCategory::FrontRunning,
                            "Short Time Window".to_string(),
                            format!("Time window of {} seconds may be manipulable", seconds),
                            idx + 1,
                            line.to_string(),
                            "Use longer time windows (>15 min) for MEV-sensitive operations".to_string(),
                        ));
                    }
                }
            }

            // Check for block.number usage
            if line.contains("block.number") {
                if line.contains("== block.number") || line.contains("block.number ==") {
                    vulnerabilities.push(Vulnerability::new(
                        VulnerabilitySeverity::Medium,
                        VulnerabilityCategory::FrontRunning,
                        "Block Number Equality Check".to_string(),
                        "Exact block number comparison - can be targeted by miners".to_string(),
                        idx + 1,
                        line.to_string(),
                        "Use block number ranges or commit-reveal instead".to_string(),
                    ));
                }
            }
        }

        vulnerabilities
    }

    // Helper methods
    fn extract_function_body(&self, content: &str, start_line: usize) -> String {
        let lines: Vec<&str> = content.lines().collect();
        if start_line >= lines.len() {
            return String::new();
        }

        let mut brace_count = 0;
        let mut body = String::new();
        let mut started = false;

        for line in lines.iter().skip(start_line) {
            for c in line.chars() {
                if c == '{' {
                    brace_count += 1;
                    started = true;
                } else if c == '}' {
                    brace_count -= 1;
                }
            }

            body.push_str(line);
            body.push('\n');

            if started && brace_count == 0 {
                break;
            }
        }

        body
    }

    fn get_function_context(&self, content: &str, line_idx: usize) -> String {
        let lines: Vec<&str> = content.lines().collect();
        let start = line_idx.saturating_sub(10);
        let end = (line_idx + 10).min(lines.len());
        lines[start..end].join("\n")
    }
}

impl Default for MEVAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}
