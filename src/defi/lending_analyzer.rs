//! Lending Protocol Vulnerability Analyzer
//!
//! Detects vulnerabilities specific to lending protocols including
//! Aave, Compound, and similar platforms.

#![allow(dead_code)]

use regex::Regex;
use crate::vulnerabilities::{Vulnerability, VulnerabilitySeverity, VulnerabilityCategory};

/// Lending protocol vulnerability analyzer
pub struct LendingAnalyzer {
    borrow_function: Regex,
    repay_function: Regex,
    liquidate_function: Regex,
    collateral_pattern: Regex,
    health_factor_pattern: Regex,
    interest_rate_pattern: Regex,
    flash_loan_pattern: Regex,
}

impl LendingAnalyzer {
    pub fn new() -> Self {
        Self {
            borrow_function: Regex::new(r"function\s+borrow\w*\s*\([^)]*\)").unwrap(),
            repay_function: Regex::new(r"function\s+repay\w*\s*\([^)]*\)").unwrap(),
            liquidate_function: Regex::new(r"function\s+liquidate\w*\s*\([^)]*\)").unwrap(),
            collateral_pattern: Regex::new(r"collateral|Collateral").unwrap(),
            health_factor_pattern: Regex::new(r"healthFactor|health_factor|ltv|LTV").unwrap(),
            interest_rate_pattern: Regex::new(r"interestRate|interest_rate|borrowRate|supplyRate").unwrap(),
            flash_loan_pattern: Regex::new(r"flashLoan|flash_loan|executeOperation|onFlashLoan").unwrap(),
        }
    }

    /// Analyze content for lending-specific vulnerabilities
    pub fn analyze(&self, content: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        // Price oracle manipulation
        vulnerabilities.extend(self.check_oracle_manipulation(content));

        // Flash loan governance attacks
        vulnerabilities.extend(self.check_flash_loan_governance(content));

        // Liquidation frontrunning
        vulnerabilities.extend(self.check_liquidation_frontrunning(content));

        // Interest rate manipulation
        vulnerabilities.extend(self.check_interest_rate_manipulation(content));

        // Collateral handling issues
        vulnerabilities.extend(self.check_collateral_issues(content));

        // Borrowing issues
        vulnerabilities.extend(self.check_borrowing_issues(content));

        // Flash loan callback security
        vulnerabilities.extend(self.check_flash_loan_callback(content));

        vulnerabilities
    }

    /// Check for oracle manipulation vulnerabilities
    fn check_oracle_manipulation(&self, content: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        let unsafe_price_patterns = vec![
            ("balanceOf(address(this))", "Contract balance used as price source"),
            ("getReserves()", "Using spot reserves for collateral pricing"),
            (".price()", "Direct price call without staleness check"),
        ];

        for (idx, line) in content.lines().enumerate() {
            for (pattern, desc) in &unsafe_price_patterns {
                if line.contains(pattern) {
                    // Check if used in collateral/borrow context
                    let func_context = self.get_function_context(content, idx);
                    if self.collateral_pattern.is_match(&func_context) ||
                       func_context.contains("borrow") ||
                       func_context.contains("liquidat") {

                        // Check for TWAP or Chainlink
                        if !content.contains("TWAP") &&
                           !content.contains("Chainlink") &&
                           !content.contains("AggregatorV3") &&
                           !content.contains("latestRoundData") {
                            vulnerabilities.push(Vulnerability::high_confidence(
                                VulnerabilitySeverity::Critical,
                                VulnerabilityCategory::OracleManipulation,
                                "Lending Oracle Manipulation Risk".to_string(),
                                format!("{} - vulnerable to flash loan manipulation in lending context", desc),
                                idx + 1,
                                line.to_string(),
                                "Use Chainlink price feeds with proper staleness checks for lending protocols".to_string(),
                            ));
                        }
                    }
                }
            }
        }

        vulnerabilities
    }

    /// Check for flash loan governance attack vectors
    fn check_flash_loan_governance(&self, content: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        // Check for voting/governance functions
        let governance_patterns = [
            r"function\s+vote\w*\s*\(",
            r"function\s+propose\w*\s*\(",
            r"function\s+castVote\w*\s*\(",
        ];

        for pattern in governance_patterns {
            let regex = Regex::new(pattern).unwrap();
            for (idx, line) in content.lines().enumerate() {
                if regex.is_match(line) {
                    let func_body = self.extract_function_body(content, idx);

                    // Check for snapshot-based voting
                    if !func_body.contains("getPastVotes") &&
                       !func_body.contains("getPriorVotes") &&
                       !func_body.contains("snapshot") &&
                       !func_body.contains("checkpoint") {
                        vulnerabilities.push(Vulnerability::high_confidence(
                            VulnerabilitySeverity::Critical,
                            VulnerabilityCategory::GovernanceAttack,
                            "Flash Loan Governance Attack Vector".to_string(),
                            "Voting power can be manipulated via flash loans - no snapshot protection".to_string(),
                            idx + 1,
                            line.to_string(),
                            "Use getPastVotes() with snapshot at proposal creation block".to_string(),
                        ));
                    }
                }
            }
        }

        vulnerabilities
    }

    /// Check for liquidation frontrunning vulnerabilities
    fn check_liquidation_frontrunning(&self, content: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        for (idx, line) in content.lines().enumerate() {
            if self.liquidate_function.is_match(line) {
                let func_body = self.extract_function_body(content, idx);

                // Check for Dutch auction or MEV protection
                if !func_body.contains("auction") &&
                   !func_body.contains("Auction") &&
                   !func_body.contains("flashbots") &&
                   !func_body.contains("private") &&
                   !func_body.contains("commit") {
                    vulnerabilities.push(Vulnerability::new(
                        VulnerabilitySeverity::High,
                        VulnerabilityCategory::MEVExploitable,
                        "Liquidation Frontrunning Risk".to_string(),
                        "Public liquidation function without MEV protection - profitable liquidations will be frontrun".to_string(),
                        idx + 1,
                        line.to_string(),
                        "Consider Dutch auction mechanism, Flashbots Protect, or liquidation incentive design".to_string(),
                    ));
                }

                // Check for proper health factor validation
                if !func_body.contains("healthFactor") &&
                   !func_body.contains("health_factor") &&
                   !func_body.contains("isHealthy") &&
                   !func_body.contains("ltv") {
                    vulnerabilities.push(Vulnerability::new(
                        VulnerabilitySeverity::High,
                        VulnerabilityCategory::LogicError,
                        "Liquidation Without Health Check".to_string(),
                        "Liquidation function may not properly verify position is underwater".to_string(),
                        idx + 1,
                        line.to_string(),
                        "Add health factor check: require(healthFactor < LIQUIDATION_THRESHOLD)".to_string(),
                    ));
                }
            }
        }

        vulnerabilities
    }

    /// Check for interest rate manipulation
    fn check_interest_rate_manipulation(&self, content: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        if self.interest_rate_pattern.is_match(content) {
            for (idx, line) in content.lines().enumerate() {
                // Check for utilization-based rate calculations
                if line.contains("utilization") || line.contains("Utilization") {
                    // Check if rate can be manipulated
                    if line.contains("balanceOf") && !content.contains("timeWeighted") {
                        vulnerabilities.push(Vulnerability::new(
                            VulnerabilitySeverity::High,
                            VulnerabilityCategory::OracleManipulation,
                            "Interest Rate Manipulation Risk".to_string(),
                            "Interest rate based on spot utilization - manipulable via large deposits/withdrawals".to_string(),
                            idx + 1,
                            line.to_string(),
                            "Use time-weighted utilization or rate caps to prevent manipulation".to_string(),
                        ));
                    }
                }

                // Check for unbounded interest rates
                if line.contains("interestRate") && line.contains("*") {
                    let func_body = self.extract_function_body(content, idx);
                    if !func_body.contains("max") && !func_body.contains("MAX") &&
                       !func_body.contains("cap") && !func_body.contains("Cap") {
                        vulnerabilities.push(Vulnerability::new(
                            VulnerabilitySeverity::Medium,
                            VulnerabilityCategory::LogicError,
                            "Unbounded Interest Rate".to_string(),
                            "Interest rate calculation without upper bound - could cause extreme rates".to_string(),
                            idx + 1,
                            line.to_string(),
                            "Add maximum interest rate cap to prevent extreme scenarios".to_string(),
                        ));
                    }
                }
            }
        }

        vulnerabilities
    }

    /// Check for collateral handling issues
    fn check_collateral_issues(&self, content: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        // Check for collateral deposit functions
        let deposit_pattern = Regex::new(r"function\s+(deposit|addCollateral|supply)\w*\s*\(").unwrap();

        for (idx, line) in content.lines().enumerate() {
            if deposit_pattern.is_match(line) {
                let func_body = self.extract_function_body(content, idx);

                // Check for proper token handling
                if func_body.contains("transferFrom") && !func_body.contains("SafeERC20") &&
                   !func_body.contains("safeTransferFrom") {
                    vulnerabilities.push(Vulnerability::new(
                        VulnerabilitySeverity::High,
                        VulnerabilityCategory::UnusedReturnValues,
                        "Unsafe Collateral Transfer".to_string(),
                        "Collateral transfer doesn't use SafeERC20 - return value not checked".to_string(),
                        idx + 1,
                        line.to_string(),
                        "Use SafeERC20.safeTransferFrom() for collateral deposits".to_string(),
                    ));
                }

                // Check for rebase token handling
                if !func_body.contains("rebasing") && !func_body.contains("rebase") &&
                   content.contains("collateral") {
                    // This is informational - rebasing tokens need special handling
                    if content.contains("whitelist") || content.contains("Whitelist") ||
                       content.contains("supportedToken") {
                        // Has token whitelist - good
                    } else {
                        vulnerabilities.push(Vulnerability::new(
                            VulnerabilitySeverity::Medium,
                            VulnerabilityCategory::LogicError,
                            "Potential Rebasing Token Issue".to_string(),
                            "Lending protocol may not handle rebasing tokens correctly".to_string(),
                            idx + 1,
                            line.to_string(),
                            "Implement token whitelist or add special handling for rebasing tokens".to_string(),
                        ));
                    }
                }
            }
        }

        // Check collateral factor updates
        if content.contains("setCollateralFactor") || content.contains("updateCollateralFactor") {
            for (idx, line) in content.lines().enumerate() {
                if line.contains("CollateralFactor") && line.contains("function") {
                    let func_body = self.extract_function_body(content, idx);

                    // Check for timelock
                    if !func_body.contains("timelock") && !func_body.contains("Timelock") &&
                       !func_body.contains("delay") {
                        vulnerabilities.push(Vulnerability::new(
                            VulnerabilitySeverity::High,
                            VulnerabilityCategory::AccessControl,
                            "Collateral Factor Change Without Timelock".to_string(),
                            "Collateral factor can be changed instantly - users can't react".to_string(),
                            idx + 1,
                            line.to_string(),
                            "Add timelock delay for collateral factor changes".to_string(),
                        ));
                    }
                }
            }
        }

        vulnerabilities
    }

    /// Check for borrowing-related issues
    fn check_borrowing_issues(&self, content: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        for (idx, line) in content.lines().enumerate() {
            if self.borrow_function.is_match(line) {
                let func_body = self.extract_function_body(content, idx);

                // Check for collateral sufficiency validation
                if !func_body.contains("collateral") && !func_body.contains("healthFactor") &&
                   !func_body.contains("ltv") && !func_body.contains("LTV") {
                    vulnerabilities.push(Vulnerability::high_confidence(
                        VulnerabilitySeverity::Critical,
                        VulnerabilityCategory::LogicError,
                        "Borrow Without Collateral Check".to_string(),
                        "Borrow function doesn't verify sufficient collateral".to_string(),
                        idx + 1,
                        line.to_string(),
                        "Add collateral sufficiency check before allowing borrow".to_string(),
                    ));
                }

                // Check for borrow cap
                if !func_body.contains("borrowCap") && !func_body.contains("maxBorrow") &&
                   !func_body.contains("borrowLimit") {
                    vulnerabilities.push(Vulnerability::new(
                        VulnerabilitySeverity::Medium,
                        VulnerabilityCategory::DoSAttacks,
                        "No Borrow Cap Implemented".to_string(),
                        "Borrow function without cap - protocol can accumulate unlimited debt".to_string(),
                        idx + 1,
                        line.to_string(),
                        "Implement per-asset and global borrow caps".to_string(),
                    ));
                }

                // Check for reentrancy
                if !content.contains("nonReentrant") && !content.contains("ReentrancyGuard") {
                    vulnerabilities.push(Vulnerability::new(
                        VulnerabilitySeverity::High,
                        VulnerabilityCategory::Reentrancy,
                        "Borrow Function Reentrancy Risk".to_string(),
                        "Borrow function without reentrancy protection".to_string(),
                        idx + 1,
                        line.to_string(),
                        "Add nonReentrant modifier to borrow function".to_string(),
                    ));
                }
            }

            // Repay function checks
            if self.repay_function.is_match(line) {
                let func_body = self.extract_function_body(content, idx);

                // Check for debt accounting
                if !func_body.contains("debt") && !func_body.contains("borrow") {
                    vulnerabilities.push(Vulnerability::new(
                        VulnerabilitySeverity::High,
                        VulnerabilityCategory::LogicError,
                        "Repay Without Debt Update".to_string(),
                        "Repay function may not properly update debt accounting".to_string(),
                        idx + 1,
                        line.to_string(),
                        "Ensure repayment properly reduces user's debt balance".to_string(),
                    ));
                }
            }
        }

        vulnerabilities
    }

    /// Check for flash loan callback security
    fn check_flash_loan_callback(&self, content: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        for (idx, line) in content.lines().enumerate() {
            if self.flash_loan_pattern.is_match(line) && line.contains("function") {
                let func_body = self.extract_function_body(content, idx);

                // Check for initiator validation
                if !func_body.contains("initiator") && !func_body.contains("_initiator") {
                    vulnerabilities.push(Vulnerability::high_confidence(
                        VulnerabilitySeverity::Critical,
                        VulnerabilityCategory::FlashLoanAttack,
                        "Flash Loan Callback Missing Initiator Check".to_string(),
                        "Flash loan callback doesn't verify initiator - vulnerable to external calls".to_string(),
                        idx + 1,
                        line.to_string(),
                        "Add: require(initiator == address(this), 'Invalid initiator')".to_string(),
                    ));
                }

                // Check for msg.sender validation (pool address)
                if !func_body.contains("msg.sender") ||
                   (!func_body.contains("POOL") && !func_body.contains("lendingPool") &&
                    !func_body.contains("flashLoanProvider")) {
                    vulnerabilities.push(Vulnerability::high_confidence(
                        VulnerabilitySeverity::Critical,
                        VulnerabilityCategory::FlashLoanAttack,
                        "Flash Loan Callback Missing Pool Validation".to_string(),
                        "Flash loan callback doesn't verify msg.sender is the lending pool".to_string(),
                        idx + 1,
                        line.to_string(),
                        "Add: require(msg.sender == address(POOL), 'Invalid caller')".to_string(),
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
        let start = line_idx.saturating_sub(20);
        let end = (line_idx + 20).min(lines.len());
        lines[start..end].join("\n")
    }
}

impl Default for LendingAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}
