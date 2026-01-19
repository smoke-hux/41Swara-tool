use std::collections::{HashMap, HashSet};
use regex::Regex;
use crate::vulnerabilities::{Vulnerability, VulnerabilitySeverity, VulnerabilityCategory};

pub struct AdvancedAnalyzer {
    #[allow(dead_code)] // Reserved for future verbose diagnostic output
    verbose: bool,
}

impl AdvancedAnalyzer {
    pub fn new(verbose: bool) -> Self {
        Self { verbose }
    }

    // Analyze control flow patterns for complex vulnerabilities
    pub fn analyze_control_flow(&self, content: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        // Check for reentrancy patterns with state changes after external calls
        if let Some(vuln) = self.detect_reentrancy_pattern(content) {
            vulnerabilities.push(vuln);
        }

        // Check for flash loan attack vectors
        if let Some(vuln) = self.detect_flash_loan_vulnerability(content) {
            vulnerabilities.push(vuln);
        }

        // Check for sandwich attack vulnerabilities
        if let Some(vuln) = self.detect_sandwich_attack_vector(content) {
            vulnerabilities.push(vuln);
        }

        vulnerabilities
    }

    // Advanced reentrancy detection using control flow analysis
    fn detect_reentrancy_pattern(&self, content: &str) -> Option<Vulnerability> {
        // Skip if ReentrancyGuard is present
        if content.contains("ReentrancyGuard") || content.contains("nonReentrant") {
            return None;
        }

        let external_call_pattern = Regex::new(r"\.call\{|\.transfer\(|\.send\(").unwrap();
        let state_change_pattern = Regex::new(r"(\w+)\s*=\s*[^=]|\w+\[.*\]\s*=\s*|\+\+|--").unwrap();

        let lines: Vec<&str> = content.lines().collect();

        for (idx, line) in lines.iter().enumerate() {
            // Skip comments
            if line.trim().starts_with("//") || line.trim().starts_with("*") {
                continue;
            }

            if external_call_pattern.is_match(line) {
                // Check if this is in a try-catch (safer pattern)
                if idx > 0 && lines[idx-1].contains("try") {
                    continue;
                }

                // Check if there are state changes after this external call
                for future_idx in (idx + 1)..lines.len().min(idx + 10) {
                    let future_line = lines[future_idx];

                    // Skip closing braces and comments
                    if future_line.trim() == "}" || future_line.trim().starts_with("//") {
                        continue;
                    }

                    // Check for state changes (but not comparisons with ==)
                    if state_change_pattern.is_match(future_line) && !future_line.contains("==") {
                        // Make sure it's actual state modification, not local variable
                        if !future_line.contains("memory") && !future_line.contains("calldata") {
                            return Some(Vulnerability::high_confidence(
                                VulnerabilitySeverity::Critical,
                                VulnerabilityCategory::Reentrancy,
                                "Critical: State Change After External Call".to_string(),
                                "State modification detected after external call - violates Checks-Effects-Interactions pattern".to_string(),
                                idx + 1,
                                line.to_string(),
                                "Move all state changes before external calls to prevent reentrancy attacks".to_string(),
                            ));
                        }
                    }
                }
            }
        }

        None
    }

    // Detect flash loan attack vulnerabilities
    fn detect_flash_loan_vulnerability(&self, content: &str) -> Option<Vulnerability> {
        let flash_loan_pattern = Regex::new(r"flashLoan|executeOperation|onFlashLoan").unwrap();
        let price_dependency = Regex::new(r"getReserves|balanceOf\(address\(this\)\)").unwrap();

        if flash_loan_pattern.is_match(content) || price_dependency.is_match(content) {
            for (idx, line) in content.lines().enumerate() {
                if price_dependency.is_match(line) {
                    return Some(Vulnerability::high_confidence(
                        VulnerabilitySeverity::Critical,
                        VulnerabilityCategory::OracleManipulation,
                        "Flash Loan Attack Vector Detected".to_string(),
                        "Contract relies on manipulable price sources vulnerable to flash loans".to_string(),
                        idx + 1,
                        line.to_string(),
                        "Use TWAP oracles or Chainlink price feeds instead of spot prices".to_string(),
                    ));
                }
            }
        }

        None
    }

    // Detect MEV/sandwich attack vulnerabilities
    fn detect_sandwich_attack_vector(&self, content: &str) -> Option<Vulnerability> {
        let swap_pattern = Regex::new(r"function\s+swap|swapExact|swapTokens").unwrap();
        let slippage_pattern = Regex::new(r"amountOutMin|slippage").unwrap();

        if swap_pattern.is_match(content) && !slippage_pattern.is_match(content) {
            for (idx, line) in content.lines().enumerate() {
                if swap_pattern.is_match(line) {
                    return Some(Vulnerability::new(
                        VulnerabilitySeverity::High,
                        VulnerabilityCategory::FrontRunning,
                        "MEV/Sandwich Attack Vulnerability".to_string(),
                        "Swap function without slippage protection is vulnerable to sandwich attacks".to_string(),
                        idx + 1,
                        line.to_string(),
                        "Implement slippage protection and consider using commit-reveal pattern".to_string(),
                    ));
                }
            }
        }

        None
    }

    // Analyze function complexity
    pub fn analyze_complexity(&self, content: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();
        let function_pattern = Regex::new(r"function\s+(\w+)\s*\([^)]*\)[^{]*\{").unwrap();

        let mut in_function = false;
        let mut function_name = String::new();
        let mut function_start = 0;
        let mut brace_count = 0;
        let mut complexity = 0;

        for (idx, line) in content.lines().enumerate() {
            if let Some(captures) = function_pattern.captures(line) {
                in_function = true;
                function_name = captures.get(1).map_or("", |m| m.as_str()).to_string();
                function_start = idx + 1;
                brace_count = 1;
                complexity = 1; // Base complexity
            }

            if in_function {
                // Count control flow statements
                if line.contains("if ") || line.contains("if(") {
                    complexity += 1;
                }
                if line.contains("for ") || line.contains("for(") {
                    complexity += 1;
                }
                if line.contains("while ") || line.contains("while(") {
                    complexity += 1;
                }
                if line.contains(" && ") || line.contains(" || ") {
                    complexity += 1;
                }

                // Track braces
                for ch in line.chars() {
                    if ch == '{' {
                        brace_count += 1;
                    } else if ch == '}' {
                        brace_count -= 1;
                        if brace_count == 0 {
                            in_function = false;

                            if complexity > 10 {
                                vulnerabilities.push(Vulnerability::new(
                                    VulnerabilitySeverity::Low,
                                    VulnerabilityCategory::ComplexityIssues,
                                    format!("High Complexity in {}", function_name),
                                    format!("Function has cyclomatic complexity of {}", complexity),
                                    function_start,
                                    format!("function {}", function_name),
                                    "Consider breaking down complex functions into smaller pieces".to_string(),
                                ));
                            }
                        }
                    }
                }
            }
        }

        vulnerabilities
    }

    // Detect access control issues using data flow analysis
    pub fn analyze_access_control(&self, content: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        // Find all modifiers
        let modifier_pattern = Regex::new(r"modifier\s+(\w+)").unwrap();
        let mut modifiers = HashSet::new();

        for captures in modifier_pattern.captures_iter(content) {
            if let Some(name) = captures.get(1) {
                modifiers.insert(name.as_str().to_string());
            }
        }

        // Find critical functions without modifiers
        let critical_functions = vec![
            "withdraw", "transfer", "mint", "burn", "pause", "unpause",
            "setOwner", "changeOwner", "upgrade", "initialize", "destroy"
        ];

        let function_pattern = Regex::new(r"function\s+(\w+)\s*\([^)]*\)\s*(\w+\s+)*\{").unwrap();

        for (idx, line) in content.lines().enumerate() {
            if let Some(captures) = function_pattern.captures(line) {
                let function_name = captures.get(1).map_or("", |m| m.as_str());

                // Check if it's a critical function
                for critical in &critical_functions {
                    if function_name.to_lowercase().contains(critical) {
                        // Check if it has any modifier
                        let has_modifier = modifiers.iter().any(|m| line.contains(m));

                        if !has_modifier && !line.contains("private") && !line.contains("internal") {
                            vulnerabilities.push(Vulnerability::high_confidence(
                                VulnerabilitySeverity::Critical,
                                VulnerabilityCategory::AccessControl,
                                format!("Unprotected Critical Function: {}", function_name),
                                "Critical function lacks access control modifiers".to_string(),
                                idx + 1,
                                line.to_string(),
                                "Add appropriate access control modifiers (onlyOwner, onlyRole, etc.)".to_string(),
                            ));
                        }
                    }
                }
            }
        }

        vulnerabilities
    }

    // Detect storage layout issues in upgradeable contracts
    pub fn analyze_storage_layout(&self, content: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        // Check for upgradeable contract patterns
        if content.contains("Initializable") || content.contains("upgradeable") {
            // Check for proper storage gaps
            if !content.contains("uint256[50] private __gap") && !content.contains("__gap") {
                vulnerabilities.push(Vulnerability::new(
                    VulnerabilitySeverity::High,
                    VulnerabilityCategory::StateVariable,
                    "Missing Storage Gap in Upgradeable Contract".to_string(),
                    "Upgradeable contract lacks storage gap for future variables".to_string(),
                    1,
                    "contract ... is Upgradeable".to_string(),
                    "Add 'uint256[50] private __gap;' at the end of storage variables".to_string(),
                ));
            }

            // Check for constructor usage in upgradeable contracts
            if content.contains("constructor(") || content.contains("constructor (") {
                vulnerabilities.push(Vulnerability::high_confidence(
                    VulnerabilitySeverity::Critical,
                    VulnerabilityCategory::StateVariable,
                    "Constructor in Upgradeable Contract".to_string(),
                    "Upgradeable contracts should not use constructors".to_string(),
                    1,
                    "constructor()".to_string(),
                    "Use initializer functions instead of constructors in upgradeable contracts".to_string(),
                ));
            }
        }

        vulnerabilities
    }

    // Analyze gas optimization opportunities
    pub fn analyze_gas_optimization(&self, content: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        // Check for storage vs memory usage in loops
        let loop_pattern = Regex::new(r"for\s*\([^)]*\)").unwrap();
        let storage_read_pattern = Regex::new(r"storage\w+\[").unwrap();

        let lines: Vec<&str> = content.lines().collect();

        for (idx, line) in lines.iter().enumerate() {
            if loop_pattern.is_match(line) {
                // Check next few lines for storage reads
                for check_idx in (idx + 1)..lines.len().min(idx + 5) {
                    if storage_read_pattern.is_match(lines[check_idx]) {
                        vulnerabilities.push(Vulnerability::new(
                            VulnerabilitySeverity::Low,
                            VulnerabilityCategory::GasOptimization,
                            "Storage Read in Loop".to_string(),
                            "Reading from storage in loops is expensive".to_string(),
                            check_idx + 1,
                            lines[check_idx].to_string(),
                            "Cache storage values in memory variables before loops".to_string(),
                        ));
                        break;
                    }
                }
            }
        }

        // Check for multiple storage writes that could be batched
        let storage_write_pattern = Regex::new(r"(\w+)\s*=\s*").unwrap();
        let mut storage_writes = HashMap::new();

        for line in content.lines() {
            if storage_write_pattern.is_match(line) {
                *storage_writes.entry(line).or_insert(0) += 1;
            }
        }

        for (line, count) in storage_writes {
            if count > 2 {
                vulnerabilities.push(Vulnerability::new(
                    VulnerabilitySeverity::Info,
                    VulnerabilityCategory::GasOptimization,
                    "Multiple Storage Writes".to_string(),
                    format!("Variable written {} times - consider batching", count),
                    1,
                    line.to_string(),
                    "Batch storage operations to save gas".to_string(),
                ));
            }
        }

        // Check for string/bytes that could be bytes32
        let string_pattern = Regex::new(r#"string\s+(public\s+)?\w+\s*=\s*"[^"]{1,32}""#).unwrap();

        for (idx, line) in content.lines().enumerate() {
            if string_pattern.is_match(line) {
                vulnerabilities.push(Vulnerability::new(
                    VulnerabilitySeverity::Info,
                    VulnerabilityCategory::GasOptimization,
                    "Short String Could Be bytes32".to_string(),
                    "Short strings are more efficient as bytes32".to_string(),
                    idx + 1,
                    line.to_string(),
                    "Consider using bytes32 for short fixed-length strings".to_string(),
                ));
            }
        }

        vulnerabilities
    }

    // DeFi-specific vulnerability detection
    pub fn analyze_defi_vulnerabilities(&self, content: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        // Detect price oracle manipulation vulnerabilities
        if let Some(vuln) = self.detect_price_oracle_manipulation(content) {
            vulnerabilities.push(vuln);
        }

        // Detect slippage issues
        vulnerabilities.extend(self.detect_slippage_issues(content));

        // Detect liquidity pool vulnerabilities
        vulnerabilities.extend(self.detect_liquidity_vulnerabilities(content));

        // Detect yield farming issues
        vulnerabilities.extend(self.detect_yield_farming_issues(content));

        vulnerabilities
    }

    fn detect_price_oracle_manipulation(&self, content: &str) -> Option<Vulnerability> {
        let unsafe_price_sources = vec![
            ("balanceOf(address(this))", "Using contract balance as price source"),
            ("token.balanceOf(address(this))", "Using token balance as price oracle"),
            (".getReserves()", "Using spot reserves without TWAP"),
            (".token0()", "Spot price from pair without protection"),
        ];

        for (idx, line) in content.lines().enumerate() {
            for (pattern, desc) in &unsafe_price_sources {
                if line.contains(pattern) && (line.contains("price") || line.contains("Price") || line.contains("amount")) {
                    // Check if there's TWAP or price validation
                    if !content.contains("TWAP") && !content.contains("Chainlink") &&
                       !content.contains("priceValidation") && !content.contains("minPrice") {
                        return Some(Vulnerability::high_confidence(
                            VulnerabilitySeverity::Critical,
                            VulnerabilityCategory::OracleManipulation,
                            "Price Oracle Manipulation Risk".to_string(),
                            format!("{} - vulnerable to flash loan attacks", desc),
                            idx + 1,
                            line.to_string(),
                            "Use Chainlink price feeds, TWAP oracles, or multiple oracle sources".to_string(),
                        ));
                    }
                }
            }
        }

        None
    }

    fn detect_slippage_issues(&self, content: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();
        let swap_pattern = Regex::new(r"function\s+swap").unwrap();

        for (idx, line) in content.lines().enumerate() {
            if swap_pattern.is_match(line) {
                // Check if function has slippage protection parameters
                if !line.contains("minAmount") && !line.contains("amountOutMin") &&
                   !line.contains("slippage") && !line.contains("minReturn") {
                    vulnerabilities.push(Vulnerability::new(
                        VulnerabilitySeverity::High,
                        VulnerabilityCategory::FrontRunning,
                        "Missing Slippage Protection".to_string(),
                        "Swap function lacks slippage protection parameters".to_string(),
                        idx + 1,
                        line.to_string(),
                        "Add amountOutMin or similar slippage protection parameter".to_string(),
                    ));
                }
            }
        }

        vulnerabilities
    }

    fn detect_liquidity_vulnerabilities(&self, content: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        // Check for liquidity removal without checks
        let remove_liquidity_pattern = Regex::new(r"removeLiquidity|withdraw").unwrap();

        for (idx, line) in content.lines().enumerate() {
            if remove_liquidity_pattern.is_match(line) && line.contains("function") {
                // Look ahead for balance checks
                let next_lines: Vec<&str> = content.lines().skip(idx).take(15).collect();
                let has_balance_check = next_lines.iter().any(|l|
                    l.contains("require(amount") || l.contains("require(balance") || l.contains("if (amount")
                );

                if !has_balance_check {
                    vulnerabilities.push(Vulnerability::new(
                        VulnerabilitySeverity::Medium,
                        VulnerabilityCategory::DoSAttacks,
                        "Insufficient Balance Validation".to_string(),
                        "Liquidity removal function may not properly validate balances".to_string(),
                        idx + 1,
                        line.to_string(),
                        "Add proper balance validation before liquidity operations".to_string(),
                    ));
                }
            }
        }

        vulnerabilities
    }

    fn detect_yield_farming_issues(&self, content: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        // Detect reward calculation issues
        if content.contains("reward") || content.contains("Reward") {
            let reward_calc_pattern = Regex::new(r"reward\w*\s*=.*\*|reward\w*\s*=.*/").unwrap();

            for (idx, line) in content.lines().enumerate() {
                if reward_calc_pattern.is_match(line) {
                    // Check for proper precision handling
                    if !content.contains("1e18") && !content.contains("PRECISION") &&
                       !content.contains("MULTIPLIER") && line.contains("/") {
                        vulnerabilities.push(Vulnerability::new(
                            VulnerabilitySeverity::Medium,
                            VulnerabilityCategory::PrecisionLoss,
                            "Reward Calculation Precision Loss".to_string(),
                            "Reward calculations may lose precision without proper scaling".to_string(),
                            idx + 1,
                            line.to_string(),
                            "Use proper precision constants (e.g., 1e18) for reward calculations".to_string(),
                        ));
                    }
                }
            }
        }

        vulnerabilities
    }

    // NFT-specific vulnerability detection
    pub fn analyze_nft_vulnerabilities(&self, content: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        // Check if this is an NFT contract
        let is_nft = content.contains("ERC721") || content.contains("ERC1155");

        if is_nft {
            vulnerabilities.extend(self.detect_nft_minting_issues(content));
            vulnerabilities.extend(self.detect_nft_transfer_issues(content));
            vulnerabilities.extend(self.detect_nft_metadata_issues(content));
            vulnerabilities.extend(self.detect_nft_royalty_issues(content));
        }

        vulnerabilities
    }

    fn detect_nft_minting_issues(&self, content: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();
        let mint_pattern = Regex::new(r"function\s+mint").unwrap();

        for (idx, line) in content.lines().enumerate() {
            if mint_pattern.is_match(line) {
                // Check for supply cap
                let has_supply_cap = content.contains("maxSupply") || content.contains("MAX_SUPPLY") ||
                                    content.contains("totalSupply() <") || content.contains("require(_tokenId");

                if !has_supply_cap {
                    vulnerabilities.push(Vulnerability::new(
                        VulnerabilitySeverity::Medium,
                        VulnerabilityCategory::AccessControl,
                        "NFT Unlimited Minting".to_string(),
                        "Mint function lacks supply cap, allowing unlimited minting".to_string(),
                        idx + 1,
                        line.to_string(),
                        "Implement maximum supply check to prevent unlimited minting".to_string(),
                    ));
                }

                // Check for duplicate token ID protection
                let has_exists_check = content.contains("_exists(") || content.contains("ownerOf(tokenId)") ||
                                      content.contains("require(!_exists");

                if !has_exists_check {
                    vulnerabilities.push(Vulnerability::new(
                        VulnerabilitySeverity::High,
                        VulnerabilityCategory::AccessControl,
                        "NFT Duplicate Token ID Risk".to_string(),
                        "Mint function may not prevent duplicate token IDs".to_string(),
                        idx + 1,
                        line.to_string(),
                        "Add _exists() check before minting to prevent duplicates".to_string(),
                    ));
                }
            }
        }

        vulnerabilities
    }

    fn detect_nft_transfer_issues(&self, content: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        // Check for unsafe transfers
        if content.contains("transferFrom") && !content.contains("safeTransferFrom") {
            for (idx, line) in content.lines().enumerate() {
                if line.contains("transferFrom") && !line.contains("safeTransferFrom") {
                    vulnerabilities.push(Vulnerability::new(
                        VulnerabilitySeverity::Medium,
                        VulnerabilityCategory::UnsafeExternalCalls,
                        "Unsafe NFT Transfer".to_string(),
                        "Using transferFrom instead of safeTransferFrom can lead to locked NFTs".to_string(),
                        idx + 1,
                        line.to_string(),
                        "Use safeTransferFrom to ensure recipient can handle ERC721 tokens".to_string(),
                    ));
                }
            }
        }

        vulnerabilities
    }

    fn detect_nft_metadata_issues(&self, content: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        // Check for mutable metadata
        let token_uri_pattern = Regex::new(r"function\s+tokenURI").unwrap();

        for (idx, line) in content.lines().enumerate() {
            if token_uri_pattern.is_match(line) {
                // Check if metadata can be changed
                let next_lines: Vec<&str> = content.lines().skip(idx).take(10).collect();
                let has_mutable_metadata = next_lines.iter().any(|l|
                    l.contains("baseURI =") || l.contains("_tokenURIs[") || l.contains("setTokenURI")
                );

                if has_mutable_metadata {
                    vulnerabilities.push(Vulnerability::new(
                        VulnerabilitySeverity::Medium,
                        VulnerabilityCategory::AccessControl,
                        "Mutable NFT Metadata".to_string(),
                        "Token metadata can be changed after minting".to_string(),
                        idx + 1,
                        line.to_string(),
                        "Consider making metadata immutable or clearly document mutability risks".to_string(),
                    ));
                }
            }
        }

        vulnerabilities
    }

    fn detect_nft_royalty_issues(&self, content: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        // Check EIP-2981 royalty implementation
        if content.contains("royaltyInfo") || content.contains("ERC2981") {
            // Check for proper royalty validation
            let royalty_pattern = Regex::new(r"royalty|royaltyInfo").unwrap();

            for (idx, line) in content.lines().enumerate() {
                if royalty_pattern.is_match(line) {
                    // Check for percentage validation (should not exceed 100%)
                    let next_lines: Vec<&str> = content.lines().skip(idx).take(15).collect();
                    let has_validation = next_lines.iter().any(|l|
                        l.contains("require(") && (l.contains("10000") || l.contains("100") || l.contains("<="))
                    );

                    if !has_validation {
                        vulnerabilities.push(Vulnerability::new(
                            VulnerabilitySeverity::Medium,
                            VulnerabilityCategory::AccessControl,
                            "Uncapped NFT Royalty".to_string(),
                            "Royalty percentage lacks upper bound validation".to_string(),
                            idx + 1,
                            line.to_string(),
                            "Add require() to cap royalty percentage at 100% (10000 basis points)".to_string(),
                        ));
                    }
                }
            }
        }

        vulnerabilities
    }

    // Detect known exploit patterns from past attacks
    pub fn detect_known_exploits(&self, content: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        // DAO attack pattern (reentrancy in withdrawals)
        vulnerabilities.extend(self.detect_dao_attack_pattern(content));

        // Parity wallet bug pattern (delegatecall to user-controlled address)
        vulnerabilities.extend(self.detect_parity_bug_pattern(content));

        // Integer overflow in token transfers (pre-0.8.0)
        vulnerabilities.extend(self.detect_integer_overflow_token_pattern(content));

        // Unchecked external call pattern
        vulnerabilities.extend(self.detect_unchecked_call_pattern(content));

        vulnerabilities
    }

    fn detect_dao_attack_pattern(&self, content: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        // Look for withdraw pattern with external call before state update
        let withdraw_pattern = Regex::new(r"function\s+withdraw").unwrap();

        for (idx, line) in content.lines().enumerate() {
            if withdraw_pattern.is_match(line) {
                let func_body: Vec<&str> = content.lines().skip(idx).take(25).collect();

                let mut has_call = false;
                let mut call_line = 0;
                let mut has_state_update_after = false;

                for (i, body_line) in func_body.iter().enumerate() {
                    if body_line.contains(".call{value:") || body_line.contains(".call.value") {
                        has_call = true;
                        call_line = i;
                    }
                    if has_call && i > call_line {
                        if body_line.contains("balance") && body_line.contains("=") ||
                           body_line.contains("balances[") && body_line.contains("=") {
                            has_state_update_after = true;
                            break;
                        }
                    }
                }

                if has_call && has_state_update_after && !content.contains("nonReentrant") {
                    vulnerabilities.push(Vulnerability::high_confidence(
                        VulnerabilitySeverity::Critical,
                        VulnerabilityCategory::Reentrancy,
                        "DAO Attack Pattern Detected".to_string(),
                        "Classic DAO attack pattern: external call before balance update in withdraw function".to_string(),
                        idx + 1,
                        line.to_string(),
                        "Update balance before external call and use ReentrancyGuard".to_string(),
                    ));
                }
            }
        }

        vulnerabilities
    }

    fn detect_parity_bug_pattern(&self, content: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        // Detect delegatecall with user-controlled address
        let delegatecall_pattern = Regex::new(r"delegatecall").unwrap();

        for (idx, line) in content.lines().enumerate() {
            if delegatecall_pattern.is_match(line) {
                // Check if address comes from function parameter or storage without validation
                if (line.contains("msg.sender") || line.contains("_target") ||
                    line.contains("target") || line.contains("implementation")) &&
                   !line.contains("require(") {

                    vulnerabilities.push(Vulnerability::high_confidence(
                        VulnerabilitySeverity::Critical,
                        VulnerabilityCategory::DelegateCalls,
                        "Parity Wallet Bug Pattern".to_string(),
                        "Delegatecall with potentially user-controlled address without validation".to_string(),
                        idx + 1,
                        line.to_string(),
                        "Whitelist allowed delegatecall targets and validate all addresses".to_string(),
                    ));
                }
            }
        }

        vulnerabilities
    }

    fn detect_integer_overflow_token_pattern(&self, content: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        // Check if this is pre-0.8.0 and has token transfer with arithmetic
        if content.contains("pragma solidity") &&
           (content.contains("0.4.") || content.contains("0.5.") ||
            content.contains("0.6.") || content.contains("0.7.")) &&
           (content.contains("balanceOf") || content.contains("transfer")) &&
           !content.contains("SafeMath") {

            for (idx, line) in content.lines().enumerate() {
                if (line.contains("balances[") || line.contains("_balances[")) &&
                   (line.contains("+=") || line.contains("-=") || line.contains("+") || line.contains("-")) {

                    vulnerabilities.push(Vulnerability::high_confidence(
                        VulnerabilitySeverity::Critical,
                        VulnerabilityCategory::ArithmeticIssues,
                        "Token Integer Overflow Risk".to_string(),
                        "Token balance arithmetic without SafeMath in pre-0.8.0 Solidity".to_string(),
                        idx + 1,
                        line.to_string(),
                        "Use SafeMath library or upgrade to Solidity 0.8.0+".to_string(),
                    ));
                }
            }
        }

        vulnerabilities
    }

    fn detect_unchecked_call_pattern(&self, content: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        for (idx, line) in content.lines().enumerate() {
            if line.contains(".call(") || line.contains(".delegatecall(") || line.contains(".staticcall(") {
                // Check if return value is checked
                let is_checked = line.contains("(bool") || line.contains("require(") ||
                                line.contains("if (") || line.contains("if(");

                // Check next line too
                let lines_vec: Vec<&str> = content.lines().collect();
                let next_line_checked = if idx + 1 < lines_vec.len() {
                    lines_vec[idx + 1].contains("require(") || lines_vec[idx + 1].contains("if (")
                } else {
                    false
                };

                if !is_checked && !next_line_checked {
                    vulnerabilities.push(Vulnerability::new(
                        VulnerabilitySeverity::High,
                        VulnerabilityCategory::UncheckedReturnValues,
                        "Unchecked Low-Level Call".to_string(),
                        "Low-level call return value not checked - silent failures possible".to_string(),
                        idx + 1,
                        line.to_string(),
                        "Check return value: (bool success, ) = target.call(...); require(success);".to_string(),
                    ));
                }
            }
        }

        vulnerabilities
    }

    // ============================================================================
    // REKT.NEWS COMPREHENSIVE PATTERN DETECTION
    // High-severity real-world exploit patterns from $3.1B+ in losses (2024-2025)
    // ============================================================================

    pub fn analyze_rekt_news_patterns(&self, content: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_aevo_proxy_pattern(content));
        vulnerabilities.extend(self.detect_omni_callback_pattern(content));
        vulnerabilities.extend(self.detect_input_validation_patterns(content));
        vulnerabilities.extend(self.detect_signature_replay_patterns(content));
        vulnerabilities.extend(self.detect_mev_exploitation_patterns(content));
        vulnerabilities.extend(self.detect_precision_attack_patterns(content));

        vulnerabilities
    }

    // Aevo/Ribbon Finance Pattern ($2.7M - Dec 2025)
    // Unprotected proxy admin functions with oracle manipulation
    fn detect_aevo_proxy_pattern(&self, content: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        // Check for proxy pattern
        let is_proxy = content.contains("TransparentUpgradeableProxy") ||
                       content.contains("UUPSUpgradeable") ||
                       content.contains("Proxy") ||
                       content.contains("implementation");

        if !is_proxy {
            return vulnerabilities;
        }

        // Critical: transferOwnership without access control in proxy context
        let transfer_ownership_pattern = Regex::new(
            r"function\s+transferOwnership\s*\([^)]*\)\s+(external|public)\s*\{"
        ).unwrap();

        for (idx, line) in content.lines().enumerate() {
            if transfer_ownership_pattern.is_match(line) {
                // Check for access control in next 5 lines
                let next_lines: Vec<&str> = content.lines().skip(idx).take(5).collect();
                let has_access_control = next_lines.iter().any(|l|
                    l.contains("onlyOwner") || l.contains("onlyAdmin") ||
                    l.contains("require(msg.sender") || l.contains("onlyRole")
                );

                if !has_access_control {
                    vulnerabilities.push(Vulnerability::high_confidence(
                        VulnerabilitySeverity::Critical,
                        VulnerabilityCategory::ProxyAdminVulnerability,
                        "CRITICAL: Aevo-Pattern Proxy Vulnerability".to_string(),
                        "Unprotected transferOwnership in proxy contract - exact pattern from $2.7M Aevo exploit".to_string(),
                        idx + 1,
                        line.to_string(),
                        "URGENT: Add onlyOwner/onlyAdmin modifier - this is a known exploit pattern".to_string(),
                    ));
                }
            }
        }

        // Check for oracle manipulation surface in upgradeable contracts
        if content.contains("oracle") || content.contains("Oracle") {
            let set_oracle_pattern = Regex::new(r"function\s+set\w*Oracle\w*\([^)]*\)").unwrap();

            for (idx, line) in content.lines().enumerate() {
                if set_oracle_pattern.is_match(line) {
                    let next_lines: Vec<&str> = content.lines().skip(idx).take(5).collect();
                    let has_protection = next_lines.iter().any(|l|
                        l.contains("onlyOwner") || l.contains("timelock") || l.contains("governance")
                    );

                    if !has_protection {
                        vulnerabilities.push(Vulnerability::high_confidence(
                            VulnerabilitySeverity::Critical,
                            VulnerabilityCategory::OracleManipulation,
                            "Unprotected Oracle Configuration (Aevo Pattern)".to_string(),
                            "Oracle configuration functions must be protected - Aevo exploit modified oracle to manipulate prices".to_string(),
                            idx + 1,
                            line.to_string(),
                            "Add governance/timelock protection for oracle modifications".to_string(),
                        ));
                    }
                }
            }
        }

        vulnerabilities
    }

    // Omni NFT Pattern ($1.43M - 2024)
    // Callback reentrancy in ERC721/ERC1155 operations
    fn detect_omni_callback_pattern(&self, content: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        // Check if this is an NFT contract
        let is_nft = content.contains("ERC721") || content.contains("ERC1155");
        if !is_nft {
            return vulnerabilities;
        }

        // Check for ReentrancyGuard
        let has_reentrancy_guard = content.contains("ReentrancyGuard") ||
                                   content.contains("nonReentrant");

        // Critical pattern: State-changing functions using safeTransferFrom
        let lines: Vec<&str> = content.lines().collect();

        for (idx, line) in lines.iter().enumerate() {
            // Look for functions that borrow, lend, mint, or modify balances
            if line.contains("function") && (
                line.contains("borrow") || line.contains("lend") ||
                line.contains("mint") || line.contains("stake") ||
                line.contains("deposit")
            ) {
                // Check if function uses safeTransferFrom within it
                let func_body: Vec<&str> = lines.iter().skip(idx).take(30).map(|s| *s).collect();
                let uses_safe_transfer = func_body.iter().any(|l|
                    l.contains("safeTransferFrom") || l.contains("_safeMint")
                );

                if uses_safe_transfer && !has_reentrancy_guard {
                    // Check if state changes happen after the transfer
                    let mut transfer_idx = 0;
                    let mut state_change_after = false;

                    for (i, body_line) in func_body.iter().enumerate() {
                        if body_line.contains("safeTransferFrom") || body_line.contains("_safeMint") {
                            transfer_idx = i;
                        }
                        if i > transfer_idx && transfer_idx > 0 {
                            if body_line.contains("=") && !body_line.contains("==") &&
                               (body_line.contains("balance") || body_line.contains("amount") ||
                                body_line.contains("debt") || body_line.contains("collateral")) {
                                state_change_after = true;
                                break;
                            }
                        }
                    }

                    if state_change_after {
                        vulnerabilities.push(Vulnerability::high_confidence(
                            VulnerabilitySeverity::Critical,
                            VulnerabilityCategory::CallbackReentrancy,
                            "CRITICAL: Omni-Pattern Callback Reentrancy".to_string(),
                            "State changes after safeTransferFrom enable onERC721Received reentrancy - exact $1.43M Omni exploit pattern".to_string(),
                            idx + 1,
                            line.to_string(),
                            "URGENT: Add ReentrancyGuard OR move all state changes before safeTransferFrom".to_string(),
                        ));
                    }
                }
            }
        }

        vulnerabilities
    }

    // Input Validation Patterns (34.6% of all exploits - $69M in 2024)
    // Most common vulnerability in 2021, 2022, 2024
    fn detect_input_validation_patterns(&self, content: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        // Critical: Functions with calldata parameters (most dangerous)
        let calldata_pattern = Regex::new(
            r"function\s+(\w+)\s*\([^)]*calldata[^)]*\)\s+(external|public)"
        ).unwrap();

        for (idx, line) in content.lines().enumerate() {
            if let Some(captures) = calldata_pattern.captures(line) {
                let func_name = captures.get(1).map_or("", |m| m.as_str());

                // Check if there's validation in next 10 lines
                let next_lines: Vec<&str> = content.lines().skip(idx).take(10).collect();
                let has_validation = next_lines.iter().any(|l|
                    l.contains("require(") || l.contains("if (") ||
                    l.contains("revert") || l.contains("assert(")
                );

                if !has_validation {
                    vulnerabilities.push(Vulnerability::high_confidence(
                        VulnerabilitySeverity::Critical,
                        VulnerabilityCategory::InputValidationFailure,
                        format!("CRITICAL: Unchecked Calldata in {}", func_name),
                        "Calldata parameter without validation - #1 exploit vector (34.6% of hacks)".to_string(),
                        idx + 1,
                        line.to_string(),
                        "Decode and validate ALL calldata inputs before processing".to_string(),
                    ));
                }
            }
        }

        // Array parameter without length checks
        let array_pattern = Regex::new(
            r"function\s+(\w+)\s*\([^)]*\[\]\s+(\w+)[^)]*\)\s+(external|public)"
        ).unwrap();

        for (idx, line) in content.lines().enumerate() {
            if let Some(captures) = array_pattern.captures(line) {
                let func_name = captures.get(1).map_or("", |m| m.as_str());
                let array_param = captures.get(2).map_or("", |m| m.as_str());

                let next_lines: Vec<&str> = content.lines().skip(idx).take(10).collect();
                let has_length_check = next_lines.iter().any(|l|
                    l.contains(&format!("{}.length", array_param)) && l.contains("require")
                );

                if !has_length_check {
                    vulnerabilities.push(Vulnerability::new(
                        VulnerabilitySeverity::High,
                        VulnerabilityCategory::InputValidationFailure,
                        format!("Missing Array Length Validation in {}", func_name),
                        "Array parameter without length validation - enables DoS and manipulation".to_string(),
                        idx + 1,
                        line.to_string(),
                        "Add require(array.length > 0 && array.length <= MAX_LENGTH)".to_string(),
                    ));
                }
            }
        }

        vulnerabilities
    }

    // Signature Replay Patterns (Multiple cross-chain incidents)
    fn detect_signature_replay_patterns(&self, content: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        // Check for signature verification code
        if !content.contains("ecrecover") && !content.contains("ECDSA") {
            return vulnerabilities;
        }

        // Missing nonce tracking
        let ecrecover_pattern = Regex::new(r"ecrecover\s*\(").unwrap();
        let has_nonce_mapping = content.contains("mapping") && content.contains("nonce");

        for (idx, line) in content.lines().enumerate() {
            if ecrecover_pattern.is_match(line) {
                // Check for nonce in the signature verification function
                let func_body: Vec<&str> = content.lines().skip(idx.saturating_sub(15)).take(30).collect();
                let uses_nonce = func_body.iter().any(|l|
                    l.contains("nonce") && (l.contains("++") || l.contains("+="))
                );

                if !has_nonce_mapping || !uses_nonce {
                    vulnerabilities.push(Vulnerability::high_confidence(
                        VulnerabilitySeverity::Critical,
                        VulnerabilityCategory::SignatureReplay,
                        "Signature Replay Attack Risk".to_string(),
                        "Signature verification without nonce tracking allows replay attacks".to_string(),
                        idx + 1,
                        line.to_string(),
                        "Implement nonce mapping and increment after each signature use".to_string(),
                    ));
                }

                // Missing chain ID
                let uses_chainid = func_body.iter().any(|l|
                    l.contains("chainid") || l.contains("chainId") || l.contains("block.chainid")
                );

                if !uses_chainid {
                    vulnerabilities.push(Vulnerability::high_confidence(
                        VulnerabilitySeverity::Critical,
                        VulnerabilityCategory::CrossChainReplay,
                        "Cross-Chain Signature Replay Risk".to_string(),
                        "Signature verification without chain ID enables cross-chain replay attacks".to_string(),
                        idx + 1,
                        line.to_string(),
                        "Include block.chainid in EIP-712 domain separator".to_string(),
                    ));
                }
            }
        }

        vulnerabilities
    }

    // MEV Exploitation Patterns ($675M MEV profits in 2025, 19% YoY increase)
    fn detect_mev_exploitation_patterns(&self, content: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        // Swap functions without slippage AND deadline protection
        let swap_pattern = Regex::new(r"function\s+swap\w*\([^)]*\)").unwrap();

        for (idx, line) in content.lines().enumerate() {
            if swap_pattern.is_match(line) {
                let has_slippage = line.contains("minAmount") || line.contains("amountOutMin") ||
                                  line.contains("slippage");
                let has_deadline = line.contains("deadline");

                if !has_slippage || !has_deadline {
                    vulnerabilities.push(Vulnerability::high_confidence(
                        VulnerabilitySeverity::Critical,
                        VulnerabilityCategory::MEVExploitable,
                        "MEV Sandwich Attack Vulnerability".to_string(),
                        "Swap without slippage+deadline protection - vulnerable to $675M MEV attack surface".to_string(),
                        idx + 1,
                        line.to_string(),
                        "Add both minAmountOut AND deadline parameters, verify deadline <= block.timestamp".to_string(),
                    ));
                }
            }
        }

        // Public liquidation functions (MEV hotspot)
        let liquidate_pattern = Regex::new(r"function\s+liquidate\w*\([^)]*\)\s+(external|public)").unwrap();

        for (idx, line) in content.lines().enumerate() {
            if liquidate_pattern.is_match(line) {
                // Check if there's MEV protection
                let func_body: Vec<&str> = content.lines().skip(idx).take(20).collect();
                let has_mev_protection = func_body.iter().any(|l|
                    l.contains("Flashbots") || l.contains("private") ||
                    l.contains("commit") || l.contains("reveal")
                );

                if !has_mev_protection {
                    vulnerabilities.push(Vulnerability::new(
                        VulnerabilitySeverity::High,
                        VulnerabilityCategory::MEVExploitable,
                        "Public Liquidation MEV Target".to_string(),
                        "Public liquidation function is prime MEV target - bots will front-run profitable liquidations".to_string(),
                        idx + 1,
                        line.to_string(),
                        "Consider MEV protection: private mempool, Flashbots, or liquidation auctions".to_string(),
                    ));
                }
            }
        }

        vulnerabilities
    }

    // Precision Attack Patterns (Aevo decimal mismatch, numerous rounding exploits)
    fn detect_precision_attack_patterns(&self, content: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        // Mixing different decimal precisions (Aevo pattern)
        let decimal_1e18 = Regex::new(r"1e18|10\s*\*\*\s*18").unwrap();
        let decimal_1e8 = Regex::new(r"1e8|10\s*\*\*\s*8").unwrap();

        let has_1e18 = decimal_1e18.is_match(content);
        let has_1e8 = decimal_1e8.is_match(content);

        if has_1e18 && has_1e8 {
            vulnerabilities.push(Vulnerability::high_confidence(
                VulnerabilitySeverity::Critical,
                VulnerabilityCategory::DecimalPrecisionMismatch,
                "CRITICAL: Mixed Decimal Precision (Aevo Pattern)".to_string(),
                "Contract mixes 1e18 and 1e8 decimals - exact Aevo $2.7M exploit pattern".to_string(),
                1,
                "Multiple decimal standards detected".to_string(),
                "Normalize ALL values to single precision (preferably 1e18) before any operations".to_string(),
            ));
        }

        // Division before multiplication in pricing (precision loss)
        let price_calc_pattern = Regex::new(
            r"(price|Price|value|Value|rate|Rate)\w*\s*=\s*[^=]*\/[^=]*\*"
        ).unwrap();

        for (idx, line) in content.lines().enumerate() {
            if price_calc_pattern.is_match(line) {
                vulnerabilities.push(Vulnerability::new(
                    VulnerabilitySeverity::High,
                    VulnerabilityCategory::PrecisionLoss,
                    "Precision Loss in Price Calculation".to_string(),
                    "Division before multiplication loses precision in price/value calculations".to_string(),
                    idx + 1,
                    line.to_string(),
                    "Always multiply before dividing: (a * b) / c not (a / c) * b".to_string(),
                ));
            }
        }

        vulnerabilities
    }

    // ============================================================================
    // 2025 OWASP SMART CONTRACT TOP 10 ADVANCED ANALYSIS
    // Enhanced detection for recent exploits
    // ============================================================================

    /// Analyze 2025 OWASP Top 10 patterns with deep control flow analysis
    pub fn analyze_owasp_2025_patterns(&self, content: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        // Flash Loan Attack patterns (OWASP #4)
        vulnerabilities.extend(self.detect_flash_loan_patterns(content));

        // Logic Error patterns (OWASP #2)
        vulnerabilities.extend(self.detect_logic_error_patterns(content));

        // Meta-transaction/Forwarder patterns (KiloEx)
        vulnerabilities.extend(self.detect_meta_transaction_patterns(content));

        // Unchecked math patterns (Cetus)
        vulnerabilities.extend(self.detect_unchecked_math_patterns(content));

        // Governance attack patterns
        vulnerabilities.extend(self.detect_governance_attack_patterns(content));

        // Bridge vulnerability patterns
        vulnerabilities.extend(self.detect_bridge_vulnerability_patterns(content));

        vulnerabilities
    }

    // Flash Loan Attack Detection (OWASP #4 - $33.8M in 2024)
    fn detect_flash_loan_patterns(&self, content: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        // Check for flash loan callback without proper validation
        let callback_pattern = Regex::new(
            r"function\s+(executeOperation|onFlashLoan|uniswapV\d+Call|pancakeCall)\s*\([^)]*\)"
        ).unwrap();

        for (idx, line) in content.lines().enumerate() {
            if callback_pattern.is_match(line) {
                let func_body: Vec<&str> = content.lines().skip(idx).take(30).collect();

                // Check for initiator validation
                let has_initiator_check = func_body.iter().any(|l|
                    l.contains("initiator") && (l.contains("require") || l.contains("==") || l.contains("if"))
                );

                // Check for msg.sender validation (lending pool)
                let has_sender_check = func_body.iter().any(|l|
                    l.contains("msg.sender") && (l.contains("POOL") || l.contains("lendingPool") || l.contains("require"))
                );

                if !has_initiator_check || !has_sender_check {
                    vulnerabilities.push(Vulnerability::high_confidence(
                        VulnerabilitySeverity::Critical,
                        VulnerabilityCategory::FlashLoanAttack,
                        "Flash Loan Callback Missing Validation".to_string(),
                        "Flash loan callback lacks proper initiator/sender validation - enables arbitrary calls".to_string(),
                        idx + 1,
                        line.to_string(),
                        "Add: require(msg.sender == POOL); require(initiator == address(this));".to_string(),
                    ));
                }
            }
        }

        // Detect price manipulation via balance queries
        let balance_price_pattern = Regex::new(r"balanceOf\([^)]*\).*price|price.*balanceOf").unwrap();

        for (idx, line) in content.lines().enumerate() {
            if balance_price_pattern.is_match(line) && !content.contains("TWAP") && !content.contains("Chainlink") {
                vulnerabilities.push(Vulnerability::high_confidence(
                    VulnerabilitySeverity::Critical,
                    VulnerabilityCategory::FlashLoanAttack,
                    "Flash Loan Price Manipulation Vector".to_string(),
                    "Using balanceOf for pricing is manipulable via flash loans".to_string(),
                    idx + 1,
                    line.to_string(),
                    "Use TWAP oracles or Chainlink price feeds instead".to_string(),
                ));
            }
        }

        vulnerabilities
    }

    // Logic Error Detection (OWASP #2 - $63.8M in 2024)
    fn detect_logic_error_patterns(&self, content: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        // First depositor attack in vaults
        if content.contains("ERC4626") || content.contains("Vault") {
            let has_virtual_shares = content.contains("INITIAL_SHARES") ||
                                     content.contains("_decimalsOffset") ||
                                     content.contains("10 **");

            let mint_pattern = Regex::new(r"function\s+deposit\s*\(").unwrap();

            for (idx, line) in content.lines().enumerate() {
                if mint_pattern.is_match(line) {
                    let func_body: Vec<&str> = content.lines().skip(idx).take(20).collect();
                    let has_zero_check = func_body.iter().any(|l|
                        l.contains("totalSupply") && (l.contains("== 0") || l.contains("> 0"))
                    );

                    if has_zero_check && !has_virtual_shares {
                        vulnerabilities.push(Vulnerability::high_confidence(
                            VulnerabilitySeverity::Critical,
                            VulnerabilityCategory::LogicError,
                            "First Depositor Attack Vector (Vault)".to_string(),
                            "Vault has zero-supply special case without virtual shares protection".to_string(),
                            idx + 1,
                            line.to_string(),
                            "Add virtual shares offset: shares = assets + INITIAL_OFFSET".to_string(),
                        ));
                    }
                }
            }
        }

        // Incorrect state update order (CEI violation)
        let transfer_pattern = Regex::new(r"\.call\{value:|\.transfer\(|safeTransfer").unwrap();
        let state_update_pattern = Regex::new(r"\w+\s*=\s*[^=]|\w+\[.*\]\s*=").unwrap();

        let lines: Vec<&str> = content.lines().collect();
        for (idx, line) in lines.iter().enumerate() {
            if transfer_pattern.is_match(line) {
                // Check if state updates happen AFTER this transfer
                for future_idx in (idx + 1)..lines.len().min(idx + 10) {
                    let future_line = lines[future_idx];
                    if future_line.trim() == "}" {
                        break;
                    }
                    if state_update_pattern.is_match(future_line) &&
                       !future_line.contains("==") &&
                       !future_line.contains("memory") &&
                       (future_line.contains("balance") || future_line.contains("amount") ||
                        future_line.contains("shares") || future_line.contains("debt")) {

                        // Check if there's a reentrancy guard
                        if !content.contains("nonReentrant") && !content.contains("ReentrancyGuard") {
                            vulnerabilities.push(Vulnerability::high_confidence(
                                VulnerabilitySeverity::Critical,
                                VulnerabilityCategory::LogicError,
                                "CEI Violation - State After External Call".to_string(),
                                "State modification after external call without reentrancy guard".to_string(),
                                idx + 1,
                                line.to_string(),
                                "Move state updates before external calls or add ReentrancyGuard".to_string(),
                            ));
                            break;
                        }
                    }
                }
            }
        }

        vulnerabilities
    }

    // Meta-Transaction / Trusted Forwarder Patterns (KiloEx $7.4M)
    fn detect_meta_transaction_patterns(&self, content: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        // Check for MinimalForwarder usage
        if content.contains("MinimalForwarder") || content.contains("ForwardRequest") {
            // Check for proper signature validation
            let execute_pattern = Regex::new(r"function\s+execute\s*\(").unwrap();

            for (idx, line) in content.lines().enumerate() {
                if execute_pattern.is_match(line) {
                    let func_body: Vec<&str> = content.lines().skip(idx).take(25).collect();

                    let has_signature_check = func_body.iter().any(|l|
                        l.contains("ecrecover") || l.contains("ECDSA") || l.contains("verify")
                    );

                    let has_nonce_increment = func_body.iter().any(|l|
                        l.contains("nonce") && (l.contains("++") || l.contains("+= 1"))
                    );

                    if !has_signature_check {
                        vulnerabilities.push(Vulnerability::high_confidence(
                            VulnerabilitySeverity::Critical,
                            VulnerabilityCategory::MetaTransactionVulnerability,
                            "CRITICAL: KiloEx-Pattern Forwarder Exploit".to_string(),
                            "Forwarder execute() lacks signature verification - KiloEx $7.4M exploit".to_string(),
                            idx + 1,
                            line.to_string(),
                            "Verify signature matches (from, to, value, gas, nonce, data) hash".to_string(),
                        ));
                    }

                    if !has_nonce_increment {
                        vulnerabilities.push(Vulnerability::new(
                            VulnerabilitySeverity::High,
                            VulnerabilityCategory::MetaTransactionVulnerability,
                            "Meta-Transaction Replay Risk".to_string(),
                            "Execute function doesn't increment nonce - enables replay attacks".to_string(),
                            idx + 1,
                            line.to_string(),
                            "Increment nonce after successful execution: _nonces[from]++".to_string(),
                        ));
                    }
                }
            }
        }

        // Check for ERC2771Context issues
        if content.contains("_msgSender()") || content.contains("ERC2771Context") {
            // Check if trusted forwarder can be manipulated
            let set_forwarder = Regex::new(r"function\s+set\w*[Ff]orwarder").unwrap();

            for (idx, line) in content.lines().enumerate() {
                if set_forwarder.is_match(line) {
                    vulnerabilities.push(Vulnerability::new(
                        VulnerabilitySeverity::High,
                        VulnerabilityCategory::TrustedForwarderBypass,
                        "Mutable Trusted Forwarder".to_string(),
                        "Trusted forwarder can be changed - enables meta-tx hijacking".to_string(),
                        idx + 1,
                        line.to_string(),
                        "Make trustedForwarder immutable, set only in constructor".to_string(),
                    ));
                }
            }
        }

        vulnerabilities
    }

    // Unchecked Math Operations (Cetus $223M Pattern)
    fn detect_unchecked_math_patterns(&self, content: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        // Check for custom safe math implementations
        let custom_math_pattern = Regex::new(
            r"function\s+\w*(safe|checked|overflow)\w*(Add|Sub|Mul|Div|Shl|Shr)\w*\s*\("
        ).unwrap();

        for (idx, line) in content.lines().enumerate() {
            if custom_math_pattern.is_match(line) {
                vulnerabilities.push(Vulnerability::new(
                    VulnerabilitySeverity::High,
                    VulnerabilityCategory::UncheckedMathOperation,
                    "Custom Safe Math Implementation (Audit Required)".to_string(),
                    "Custom overflow checks found - Cetus $223M used flawed custom checks".to_string(),
                    idx + 1,
                    line.to_string(),
                    "Use battle-tested libraries (OpenZeppelin) or Solidity 0.8+ built-ins".to_string(),
                ));
            }
        }

        // Check for bit shift operations in critical calculations
        let shift_in_calc_pattern = Regex::new(
            r"(liquidity|price|amount|value|shares)\w*\s*=.*<<|>>\s*\d+"
        ).unwrap();

        for (idx, line) in content.lines().enumerate() {
            if shift_in_calc_pattern.is_match(line) {
                // Check if it's in unchecked block
                let prev_lines: Vec<&str> = content.lines().take(idx).collect();
                let in_unchecked = prev_lines.iter().rev().take(10).any(|l| l.contains("unchecked"));

                if in_unchecked {
                    vulnerabilities.push(Vulnerability::high_confidence(
                        VulnerabilitySeverity::Critical,
                        VulnerabilityCategory::UncheckedMathOperation,
                        "CRITICAL: Unchecked Bit Shift (Cetus Pattern)".to_string(),
                        "Bit shift in unchecked block - exact Cetus $223M vulnerability".to_string(),
                        idx + 1,
                        line.to_string(),
                        "Move bit shifts outside unchecked or add explicit bounds validation".to_string(),
                    ));
                }
            }
        }

        // Check for sqrt/exp in financial calculations
        let complex_math = Regex::new(r"(sqrt|exp|pow)\s*\(.*\)").unwrap();

        for (idx, line) in content.lines().enumerate() {
            if complex_math.is_match(line) {
                let prev_lines: Vec<&str> = content.lines().take(idx).collect();
                let in_unchecked = prev_lines.iter().rev().take(10).any(|l| l.contains("unchecked"));

                if in_unchecked {
                    vulnerabilities.push(Vulnerability::new(
                        VulnerabilitySeverity::High,
                        VulnerabilityCategory::UncheckedMathOperation,
                        "Complex Math in Unchecked Block".to_string(),
                        "sqrt/exp/pow operations in unchecked block can silently overflow".to_string(),
                        idx + 1,
                        line.to_string(),
                        "Validate input bounds before complex math, add explicit overflow checks".to_string(),
                    ));
                }
            }
        }

        vulnerabilities
    }

    // Governance Attack Patterns (Beanstalk $182M)
    fn detect_governance_attack_patterns(&self, content: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        // Check for governance voting functions
        let vote_pattern = Regex::new(r"function\s+(castVote|vote|propose)\w*\s*\(").unwrap();

        for (idx, line) in content.lines().enumerate() {
            if vote_pattern.is_match(line) {
                let func_body: Vec<&str> = content.lines().skip(idx).take(20).collect();

                // Check for flash loan protection
                let has_snapshot = func_body.iter().any(|l|
                    l.contains("snapshot") || l.contains("checkpoint") ||
                    l.contains("getPastVotes") || l.contains("block.number - 1")
                );

                let has_timelock = content.contains("TimelockController") ||
                                   content.contains("timelock") ||
                                   content.contains("delay");

                if !has_snapshot && !has_timelock {
                    vulnerabilities.push(Vulnerability::high_confidence(
                        VulnerabilitySeverity::Critical,
                        VulnerabilityCategory::GovernanceAttack,
                        "Flash Loan Governance Attack (Beanstalk Pattern)".to_string(),
                        "Voting without snapshot allows flash loan vote manipulation - Beanstalk $182M".to_string(),
                        idx + 1,
                        line.to_string(),
                        "Use getPastVotes with snapshot block, add proposal timelock".to_string(),
                    ));
                }
            }
        }

        // Check for emergency functions
        let emergency_pattern = Regex::new(r"function\s+emergency\w*\s*\([^)]*\)\s+(external|public)").unwrap();

        for (idx, line) in content.lines().enumerate() {
            if emergency_pattern.is_match(line) {
                let func_body: Vec<&str> = content.lines().skip(idx).take(10).collect();

                let has_multisig = func_body.iter().any(|l|
                    l.contains("multisig") || l.contains("onlyOwner") || l.contains("onlyRole")
                );

                let has_timelock = func_body.iter().any(|l|
                    l.contains("timelock") || l.contains("delay") || l.contains("cooldown")
                );

                if !has_multisig || !has_timelock {
                    vulnerabilities.push(Vulnerability::new(
                        VulnerabilitySeverity::High,
                        VulnerabilityCategory::GovernanceAttack,
                        "Emergency Function Without Safeguards".to_string(),
                        "Emergency function lacks multi-sig or timelock protection".to_string(),
                        idx + 1,
                        line.to_string(),
                        "Require multi-sig AND timelock for emergency functions".to_string(),
                    ));
                }
            }
        }

        vulnerabilities
    }

    // Bridge Vulnerability Patterns
    fn detect_bridge_vulnerability_patterns(&self, content: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        // Check for cross-chain message handlers
        let message_handler = Regex::new(
            r"function\s+(lzReceive|_nonblockingLzReceive|receiveWormholeMessages?|_execute)\s*\("
        ).unwrap();

        for (idx, line) in content.lines().enumerate() {
            if message_handler.is_match(line) {
                let func_body: Vec<&str> = content.lines().skip(idx).take(25).collect();

                // Check for source chain validation
                let has_chain_check = func_body.iter().any(|l|
                    l.contains("srcChainId") || l.contains("sourceChain") ||
                    l.contains("trustedRemote") || l.contains("_srcChainId")
                );

                // Check for source address validation
                let has_address_check = func_body.iter().any(|l|
                    l.contains("srcAddress") || l.contains("_srcAddress") ||
                    l.contains("trustedRemote[")
                );

                if !has_chain_check || !has_address_check {
                    vulnerabilities.push(Vulnerability::high_confidence(
                        VulnerabilitySeverity::Critical,
                        VulnerabilityCategory::BridgeVulnerability,
                        "Bridge Source Validation Missing".to_string(),
                        "Cross-chain message handler lacks source chain/address verification".to_string(),
                        idx + 1,
                        line.to_string(),
                        "Validate srcChainId AND trustedRemote[srcChainId] == srcAddress".to_string(),
                    ));
                }
            }
        }

        // Check for bridge claim functions
        let claim_pattern = Regex::new(r"function\s+\w*(claim|withdraw|redeem)\w*\s*\([^)]*proof").unwrap();

        for (idx, line) in content.lines().enumerate() {
            if claim_pattern.is_match(line) {
                let func_body: Vec<&str> = content.lines().skip(idx).take(20).collect();

                // Check for replay protection
                let has_replay_check = func_body.iter().any(|l|
                    l.contains("claimed[") || l.contains("processed[") ||
                    l.contains("used[") || l.contains("nonce")
                );

                if !has_replay_check {
                    vulnerabilities.push(Vulnerability::high_confidence(
                        VulnerabilitySeverity::Critical,
                        VulnerabilityCategory::BridgeVulnerability,
                        "Bridge Claim Replay Attack".to_string(),
                        "Bridge claim function lacks replay protection - same proof can be used twice".to_string(),
                        idx + 1,
                        line.to_string(),
                        "Mark proofs as claimed: require(!claimed[hash]); claimed[hash] = true;".to_string(),
                    ));
                }
            }
        }

        vulnerabilities
    }
}

// Cross-contract vulnerability detection (reserved for future project-wide analysis)
#[allow(dead_code)]
pub struct CrossContractAnalyzer {
    contracts: HashMap<String, String>,
}

#[allow(dead_code)]
impl CrossContractAnalyzer {
    pub fn new() -> Self {
        Self {
            contracts: HashMap::new(),
        }
    }

    pub fn add_contract(&mut self, name: String, content: String) {
        self.contracts.insert(name, content);
    }

    // Detect circular dependencies
    pub fn detect_circular_dependencies(&self) -> Vec<String> {
        let mut issues = Vec::new();
        let import_pattern = Regex::new(r#"import\s+["']([^"']+)["']"#).unwrap();

        for (contract_name, content) in &self.contracts {
            let mut imports = HashSet::new();

            for captures in import_pattern.captures_iter(content) {
                if let Some(import) = captures.get(1) {
                    imports.insert(import.as_str());
                }
            }

            // Check if imported contracts import this contract back
            for import in &imports {
                if let Some(imported_content) = self.contracts.get(*import) {
                    if imported_content.contains(&format!("import.*{}", contract_name)) {
                        issues.push(format!(
                            "Circular dependency detected: {} <-> {}",
                            contract_name, import
                        ));
                    }
                }
            }
        }

        issues
    }

    // Detect inheritance conflicts
    pub fn detect_inheritance_conflicts(&self) -> Vec<String> {
        let mut issues = Vec::new();
        let inheritance_pattern = Regex::new(r"contract\s+\w+\s+is\s+([^{]+)").unwrap();

        for (contract_name, content) in &self.contracts {
            if let Some(captures) = inheritance_pattern.captures(content) {
                let inherited = captures.get(1).map_or("", |m| m.as_str());
                let parents: Vec<&str> = inherited.split(',').map(|s| s.trim()).collect();

                if parents.len() > 1 {
                    // Check for diamond problem
                    issues.push(format!(
                        "Multiple inheritance detected in {}: {:?} - verify no conflicts",
                        contract_name, parents
                    ));
                }
            }
        }

        issues
    }
}