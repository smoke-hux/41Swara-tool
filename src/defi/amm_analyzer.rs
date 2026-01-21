//! AMM/DEX Vulnerability Analyzer
//!
//! Detects vulnerabilities specific to Automated Market Makers and
//! Decentralized Exchanges including Uniswap, Curve, and Balancer patterns.

use regex::Regex;
use crate::vulnerabilities::{Vulnerability, VulnerabilitySeverity, VulnerabilityCategory};

/// AMM-specific vulnerability analyzer
pub struct AMMAnalyzer {
    // Uniswap V2 patterns
    uniswap_v2_callback: Regex,
    uniswap_v2_sync: Regex,

    // Uniswap V3 patterns
    uniswap_v3_callback: Regex,
    uniswap_v3_flash: Regex,

    // Curve patterns
    curve_reentrancy: Regex,
    curve_read_only: Regex,

    // General swap patterns
    swap_function: Regex,
    slippage_param: Regex,
    deadline_param: Regex,
}

impl AMMAnalyzer {
    pub fn new() -> Self {
        Self {
            uniswap_v2_callback: Regex::new(
                r"function\s+uniswapV2Call\s*\([^)]*\)"
            ).unwrap(),
            uniswap_v2_sync: Regex::new(
                r"\.sync\(\)|IUniswapV2Pair\([^)]*\)\.sync"
            ).unwrap(),
            uniswap_v3_callback: Regex::new(
                r"function\s+uniswapV3(Swap|Mint|Flash)Callback\s*\([^)]*\)"
            ).unwrap(),
            uniswap_v3_flash: Regex::new(
                r"IUniswapV3Pool\([^)]*\)\.flash"
            ).unwrap(),
            curve_reentrancy: Regex::new(
                r"ICurve\w*\([^)]*\)\.(exchange|add_liquidity|remove_liquidity)"
            ).unwrap(),
            curve_read_only: Regex::new(
                r"ICurve\w*\([^)]*\)\.(get_virtual_price|get_dy)"
            ).unwrap(),
            swap_function: Regex::new(
                r"function\s+swap\w*\s*\([^)]*\)"
            ).unwrap(),
            slippage_param: Regex::new(
                r"(minAmount|amountOutMin|minReturn|slippage|minOut)"
            ).unwrap(),
            deadline_param: Regex::new(
                r"(deadline|expiry|validUntil|timestamp)"
            ).unwrap(),
        }
    }

    /// Analyze content for AMM-specific vulnerabilities
    pub fn analyze(&self, content: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        // Uniswap V2/V3 callback reentrancy
        vulnerabilities.extend(self.check_uniswap_callback_reentrancy(content));

        // Curve read-only reentrancy
        vulnerabilities.extend(self.check_curve_read_only_reentrancy(content));

        // Missing slippage protection
        vulnerabilities.extend(self.check_slippage_protection(content));

        // Missing deadline protection
        vulnerabilities.extend(self.check_deadline_protection(content));

        // Sandwich attack surface
        vulnerabilities.extend(self.check_sandwich_attack_surface(content));

        // Price manipulation via reserve manipulation
        vulnerabilities.extend(self.check_reserve_manipulation(content));

        // LP token attacks
        vulnerabilities.extend(self.check_lp_token_attacks(content));

        vulnerabilities
    }

    /// Check for Uniswap callback reentrancy vulnerabilities
    fn check_uniswap_callback_reentrancy(&self, content: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();
        let has_reentrancy_guard = content.contains("nonReentrant") || content.contains("ReentrancyGuard");

        // Check V2 callbacks
        for (idx, line) in content.lines().enumerate() {
            if self.uniswap_v2_callback.is_match(line) {
                // Look for state changes in callback
                let callback_body = self.extract_function_body(content, idx);
                if self.has_state_changes(&callback_body) && !has_reentrancy_guard {
                    vulnerabilities.push(Vulnerability::high_confidence(
                        VulnerabilitySeverity::Critical,
                        VulnerabilityCategory::CallbackReentrancy,
                        "Uniswap V2 Callback Reentrancy Risk".to_string(),
                        "uniswapV2Call modifies state without reentrancy protection - attacker can reenter during flash swap".to_string(),
                        idx + 1,
                        line.to_string(),
                        "Add ReentrancyGuard and verify msg.sender is the expected pair".to_string(),
                    ));
                }

                // Check for sender validation
                if !callback_body.contains("msg.sender") || !callback_body.contains("pair") {
                    vulnerabilities.push(Vulnerability::new(
                        VulnerabilitySeverity::High,
                        VulnerabilityCategory::AccessControl,
                        "Uniswap V2 Callback Missing Sender Validation".to_string(),
                        "uniswapV2Call doesn't validate msg.sender is the expected pair".to_string(),
                        idx + 1,
                        line.to_string(),
                        "Add: require(msg.sender == pair, 'Invalid caller')".to_string(),
                    ));
                }
            }

            // Check V3 callbacks
            if self.uniswap_v3_callback.is_match(line) {
                let callback_body = self.extract_function_body(content, idx);

                // V3 callbacks MUST verify the caller
                if !callback_body.contains("verifyCallback") && !callback_body.contains("msg.sender == ") {
                    vulnerabilities.push(Vulnerability::high_confidence(
                        VulnerabilitySeverity::Critical,
                        VulnerabilityCategory::AccessControl,
                        "Uniswap V3 Callback Missing Verification".to_string(),
                        "V3 callback doesn't verify caller via CallbackValidation".to_string(),
                        idx + 1,
                        line.to_string(),
                        "Use CallbackValidation.verifyCallback() to verify msg.sender".to_string(),
                    ));
                }

                if self.has_state_changes(&callback_body) && !has_reentrancy_guard {
                    vulnerabilities.push(Vulnerability::new(
                        VulnerabilitySeverity::High,
                        VulnerabilityCategory::CallbackReentrancy,
                        "Uniswap V3 Callback State Modification".to_string(),
                        "V3 callback modifies state - ensure reentrancy protection".to_string(),
                        idx + 1,
                        line.to_string(),
                        "Add nonReentrant modifier and complete state changes before callback returns".to_string(),
                    ));
                }
            }
        }

        vulnerabilities
    }

    /// Check for Curve read-only reentrancy
    fn check_curve_read_only_reentrancy(&self, content: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        for (idx, line) in content.lines().enumerate() {
            // Check for Curve price reads
            if self.curve_read_only.is_match(line) {
                // Check if there's reentrancy protection or the call is in a vulnerable context
                let function_context = self.get_function_context(content, idx);

                // Check if this is used for pricing during a callback
                if function_context.contains("Callback") ||
                   function_context.contains("receive") ||
                   function_context.contains("fallback") {
                    vulnerabilities.push(Vulnerability::high_confidence(
                        VulnerabilitySeverity::Critical,
                        VulnerabilityCategory::OracleManipulation,
                        "Curve Read-Only Reentrancy Vulnerability".to_string(),
                        "Reading Curve virtual price in callback context - vulnerable to manipulation during remove_liquidity".to_string(),
                        idx + 1,
                        line.to_string(),
                        "Use Curve's reentrancy-safe price oracle or add ReentrancyGuard across all entry points".to_string(),
                    ));
                }
            }

            // Check for Curve exchange without reentrancy guard
            if self.curve_reentrancy.is_match(line) {
                if !content.contains("nonReentrant") && !content.contains("ReentrancyGuard") {
                    vulnerabilities.push(Vulnerability::new(
                        VulnerabilitySeverity::High,
                        VulnerabilityCategory::Reentrancy,
                        "Curve Interaction Without Reentrancy Guard".to_string(),
                        "Curve pool interaction can trigger callbacks via token transfers".to_string(),
                        idx + 1,
                        line.to_string(),
                        "Add ReentrancyGuard - Curve pools can call back during ETH/token transfers".to_string(),
                    ));
                }
            }
        }

        vulnerabilities
    }

    /// Check for missing slippage protection
    fn check_slippage_protection(&self, content: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        for (idx, line) in content.lines().enumerate() {
            if self.swap_function.is_match(line) {
                // Check if function has slippage parameter
                if !self.slippage_param.is_match(line) {
                    // Check function body for slippage check
                    let func_body = self.extract_function_body(content, idx);
                    if !self.slippage_param.is_match(&func_body) &&
                       !func_body.contains("require(") {
                        vulnerabilities.push(Vulnerability::high_confidence(
                            VulnerabilitySeverity::Critical,
                            VulnerabilityCategory::FrontRunning,
                            "Swap Without Slippage Protection".to_string(),
                            "Swap function lacks slippage protection - vulnerable to sandwich attacks".to_string(),
                            idx + 1,
                            line.to_string(),
                            "Add minAmountOut parameter and verify: require(amountOut >= minAmountOut)".to_string(),
                        ));
                    }
                }
            }
        }

        vulnerabilities
    }

    /// Check for missing deadline protection
    fn check_deadline_protection(&self, content: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        for (idx, line) in content.lines().enumerate() {
            if self.swap_function.is_match(line) || line.contains("addLiquidity") || line.contains("removeLiquidity") {
                // Check if function has deadline parameter
                if !self.deadline_param.is_match(line) {
                    let func_body = self.extract_function_body(content, idx);
                    if !self.deadline_param.is_match(&func_body) &&
                       !func_body.contains("block.timestamp") {
                        vulnerabilities.push(Vulnerability::new(
                            VulnerabilitySeverity::High,
                            VulnerabilityCategory::FrontRunning,
                            "Missing Transaction Deadline".to_string(),
                            "DEX operation lacks deadline - transactions can be held and executed at unfavorable prices".to_string(),
                            idx + 1,
                            line.to_string(),
                            "Add deadline parameter: require(block.timestamp <= deadline, 'Expired')".to_string(),
                        ));
                    }
                }
            }
        }

        vulnerabilities
    }

    /// Check for sandwich attack surface
    fn check_sandwich_attack_surface(&self, content: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        // Look for large swap patterns without protection
        let large_swap_patterns = [
            r"swapExactTokensForTokens\([^)]*\)",
            r"swapTokensForExactTokens\([^)]*\)",
            r"swapExactETHForTokens\([^)]*\)",
        ];

        for pattern in large_swap_patterns {
            let regex = Regex::new(pattern).unwrap();
            for (idx, line) in content.lines().enumerate() {
                if regex.is_match(line) {
                    // Check if the swap is protected
                    let func_context = self.get_function_context(content, idx);

                    // Check for commit-reveal or private mempool patterns
                    if !func_context.contains("commit") &&
                       !func_context.contains("reveal") &&
                       !func_context.contains("flashbots") &&
                       !func_context.contains("private") {
                        // Check slippage
                        if line.contains("0,") || line.contains(", 0,") || line.contains(",0)") {
                            vulnerabilities.push(Vulnerability::high_confidence(
                                VulnerabilitySeverity::Critical,
                                VulnerabilityCategory::MEVExploitable,
                                "Zero Slippage Swap - Extreme Sandwich Risk".to_string(),
                                "Swap with zero minimum output is guaranteed to be sandwiched".to_string(),
                                idx + 1,
                                line.to_string(),
                                "NEVER use 0 for amountOutMin - calculate realistic minimum with slippage tolerance".to_string(),
                            ));
                        }
                    }
                }
            }
        }

        vulnerabilities
    }

    /// Check for reserve manipulation vulnerabilities
    fn check_reserve_manipulation(&self, content: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        // Direct reserve reads for pricing
        if content.contains("getReserves()") {
            for (idx, line) in content.lines().enumerate() {
                if line.contains("getReserves") {
                    // Check if used for pricing without TWAP
                    let func_body = self.extract_function_body(content, idx);
                    if func_body.contains("price") || func_body.contains("Price") ||
                       func_body.contains("amount") || func_body.contains("value") {
                        if !content.contains("TWAP") && !content.contains("timeWeightedAverage") &&
                           !content.contains("Chainlink") && !content.contains("oracle") {
                            vulnerabilities.push(Vulnerability::high_confidence(
                                VulnerabilitySeverity::Critical,
                                VulnerabilityCategory::OracleManipulation,
                                "Spot Reserve Pricing Vulnerable to Flash Loans".to_string(),
                                "Using getReserves() for pricing without TWAP - trivially manipulable".to_string(),
                                idx + 1,
                                line.to_string(),
                                "Use Uniswap V2 TWAP oracle or Chainlink price feeds".to_string(),
                            ));
                        }
                    }
                }
            }
        }

        // Sync() manipulation
        if self.uniswap_v2_sync.is_match(content) {
            for (idx, line) in content.lines().enumerate() {
                if line.contains(".sync()") {
                    vulnerabilities.push(Vulnerability::new(
                        VulnerabilitySeverity::High,
                        VulnerabilityCategory::LiquidityManipulation,
                        "Direct Pair Sync Call".to_string(),
                        "Calling sync() directly can be used to manipulate reserves".to_string(),
                        idx + 1,
                        line.to_string(),
                        "Ensure sync() calls are protected and can't be abused for price manipulation".to_string(),
                    ));
                }
            }
        }

        vulnerabilities
    }

    /// Check for LP token attack vectors
    fn check_lp_token_attacks(&self, content: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        // First depositor / inflation attack
        if content.contains("totalSupply") && (content.contains("mint") || content.contains("deposit")) {
            for (idx, line) in content.lines().enumerate() {
                if line.contains("totalSupply() == 0") || line.contains("totalSupply == 0") {
                    // Check for virtual offset protection
                    let func_body = self.extract_function_body(content, idx);
                    if !func_body.contains("MINIMUM_LIQUIDITY") &&
                       !func_body.contains("INITIAL_") &&
                       !func_body.contains("virtualOffset") &&
                       !func_body.contains("_decimalsOffset") {
                        vulnerabilities.push(Vulnerability::high_confidence(
                            VulnerabilitySeverity::Critical,
                            VulnerabilityCategory::LogicError,
                            "First Depositor / LP Inflation Attack".to_string(),
                            "LP token vulnerable to first depositor attack when totalSupply is 0".to_string(),
                            idx + 1,
                            line.to_string(),
                            "Implement MINIMUM_LIQUIDITY or virtual shares offset to prevent inflation attack".to_string(),
                        ));
                    }
                }
            }
        }

        // LP token price manipulation via donation
        if content.contains("balanceOf(address(this))") {
            for (idx, line) in content.lines().enumerate() {
                if line.contains("balanceOf(address(this))") &&
                   (line.contains("/") || line.contains("price") || line.contains("share")) {
                    vulnerabilities.push(Vulnerability::new(
                        VulnerabilitySeverity::High,
                        VulnerabilityCategory::OracleManipulation,
                        "LP Price Manipulation via Donation".to_string(),
                        "Using contract balance for LP pricing - manipulable via direct token transfers".to_string(),
                        idx + 1,
                        line.to_string(),
                        "Track deposited amounts separately instead of using balanceOf".to_string(),
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
        let start = line_idx.saturating_sub(30);
        lines[start..=line_idx.min(lines.len() - 1)].join("\n")
    }

    fn has_state_changes(&self, body: &str) -> bool {
        // Check for common state change patterns
        body.contains("=") && !body.contains("==") &&
        (body.contains("balance") || body.contains("amount") ||
         body.contains("total") || body.contains("[") ||
         body.contains("mapping"))
    }
}

impl Default for AMMAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}
