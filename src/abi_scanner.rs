use serde_json::Value;
use std::collections::{HashMap, HashSet};
use crate::vulnerabilities::{Vulnerability, VulnerabilitySeverity, VulnerabilityCategory};

#[derive(Debug, Clone)]
pub struct ABIFunction {
    pub name: String,
    pub state_mutability: String,
    pub inputs: Vec<ABIParameter>,
    pub selector: String,
}

#[derive(Debug, Clone)]
pub struct ABIEvent {
    pub name: String,
    pub inputs: Vec<ABIParameter>,
    pub anonymous: bool,
}

#[derive(Debug, Clone)]
pub struct ABIParameter {
    pub name: String,
    pub param_type: String,
    pub indexed: Option<bool>,
    pub components: Option<Vec<ABIParameter>>,
}

#[derive(Debug)]
pub struct ABIAnalysis {
    pub functions: Vec<ABIFunction>,
    pub events: Vec<ABIEvent>,
    pub contract_type: ContractType,
    pub security_score: u8,
    pub detected_patterns: Vec<PatternType>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ContractType {
    Unknown,
    ERC20,
    ERC721,
    ERC1155,
    ERC4626,
    Proxy,
    Governor,
    Timelock,
    DEX,
    Lending,
    Bridge,
    FlashLoan,
}

#[derive(Debug, Clone, PartialEq)]
pub enum PatternType {
    FlashLoanCapable,
    OracleDependent,
    DEXInteraction,
    AccessControlled,
    Pausable,
    Upgradeable,
    CallbackEnabled,
    CrossChainCapable,
    MEVExposed,
    PermitEnabled,
}

pub struct ABIScanner {
    verbose: bool,
}

impl ABIScanner {
    pub fn new(verbose: bool) -> Self {
        Self { verbose }
    }

    pub fn parse_abi(&self, content: &str) -> Result<ABIAnalysis, String> {
        let abi: Value = serde_json::from_str(content)
            .map_err(|e| format!("Invalid JSON: {}", e))?;

        let items = abi.as_array().ok_or("ABI must be an array")?;

        let mut functions = Vec::new();
        let mut events = Vec::new();

        for item in items {
            match item.get("type").and_then(|t| t.as_str()).unwrap_or("function") {
                "function" | "constructor" | "fallback" | "receive" => {
                    if let Some(func) = self.parse_function(item) {
                        functions.push(func);
                    }
                }
                "event" => {
                    if let Some(event) = self.parse_event(item) {
                        events.push(event);
                    }
                }
                _ => {}
            }
        }

        let contract_type = self.detect_contract_type(&functions);
        let detected_patterns = self.detect_patterns(&functions);
        let security_score = self.calculate_security_score(&functions, &detected_patterns);

        Ok(ABIAnalysis {
            functions,
            events,
            contract_type,
            security_score,
            detected_patterns,
        })
    }

    fn parse_function(&self, item: &Value) -> Option<ABIFunction> {
        let name = item.get("name").and_then(|n| n.as_str()).unwrap_or("").to_string();
        let state_mutability = item.get("stateMutability").and_then(|s| s.as_str()).unwrap_or("nonpayable").to_string();
        let inputs = self.parse_params(item.get("inputs"));
        let selector = self.compute_selector(&name, &inputs);

        Some(ABIFunction { name, state_mutability, inputs, selector })
    }

    fn parse_event(&self, item: &Value) -> Option<ABIEvent> {
        let name = item.get("name").and_then(|n| n.as_str()).unwrap_or("").to_string();
        let anonymous = item.get("anonymous").and_then(|a| a.as_bool()).unwrap_or(false);
        let inputs = self.parse_params(item.get("inputs"));

        Some(ABIEvent { name, inputs, anonymous })
    }

    fn parse_params(&self, params: Option<&Value>) -> Vec<ABIParameter> {
        let Some(arr) = params.and_then(|p| p.as_array()) else { return Vec::new() };

        arr.iter().filter_map(|p| {
            Some(ABIParameter {
                name: p.get("name").and_then(|n| n.as_str()).unwrap_or("").to_string(),
                param_type: p.get("type").and_then(|t| t.as_str()).unwrap_or("").to_string(),
                indexed: p.get("indexed").and_then(|i| i.as_bool()),
                components: p.get("components").map(|c| self.parse_params(Some(c))),
            })
        }).collect()
    }

    fn compute_selector(&self, name: &str, inputs: &[ABIParameter]) -> String {
        if name.is_empty() { return String::new() }
        let sig = format!("{}({})", name, inputs.iter().map(|p| self.canonical_type(&p.param_type, &p.components)).collect::<Vec<_>>().join(","));
        format!("0x{:08x}", sig.bytes().fold(0u32, |h, b| h.wrapping_mul(31).wrapping_add(b as u32)))
    }

    fn canonical_type(&self, t: &str, components: &Option<Vec<ABIParameter>>) -> String {
        if t == "tuple" || t.starts_with("tuple[") {
            if let Some(c) = components {
                let inner = c.iter().map(|p| self.canonical_type(&p.param_type, &p.components)).collect::<Vec<_>>().join(",");
                return if t.contains('[') { format!("({}){}", inner, &t[5..]) } else { format!("({})", inner) };
            }
        }
        t.to_string()
    }

    fn detect_contract_type(&self, functions: &[ABIFunction]) -> ContractType {
        let names: HashSet<_> = functions.iter().map(|f| f.name.as_str()).collect();

        // ERC-4626 Vault
        let erc4626 = ["asset", "totalAssets", "deposit", "withdraw", "redeem", "mint", "convertToShares", "convertToAssets"];
        if erc4626.iter().filter(|f| names.contains(*f)).count() >= 6 { return ContractType::ERC4626 }

        // ERC-1155
        if names.contains("balanceOfBatch") && names.contains("safeBatchTransferFrom") { return ContractType::ERC1155 }

        // ERC-721
        if names.contains("ownerOf") && names.contains("safeTransferFrom") { return ContractType::ERC721 }

        // ERC-20
        if names.contains("transfer") && names.contains("approve") && names.contains("balanceOf") { return ContractType::ERC20 }

        // Proxy
        if names.contains("upgradeTo") || names.contains("implementation") { return ContractType::Proxy }

        // Governor
        if names.contains("propose") && names.contains("castVote") { return ContractType::Governor }

        // Timelock
        if names.contains("schedule") && names.contains("execute") { return ContractType::Timelock }

        // DEX
        if names.contains("swap") || names.contains("addLiquidity") { return ContractType::DEX }

        // Lending
        if names.contains("borrow") && names.contains("repay") { return ContractType::Lending }

        // Bridge
        if names.contains("bridgeTo") || names.contains("relayMessage") { return ContractType::Bridge }

        // Flash Loan
        if names.contains("flashLoan") || names.contains("executeOperation") { return ContractType::FlashLoan }

        ContractType::Unknown
    }

    fn detect_patterns(&self, functions: &[ABIFunction]) -> Vec<PatternType> {
        let names: HashSet<_> = functions.iter().map(|f| f.name.as_str()).collect();
        let mut patterns = Vec::new();

        let flash = ["flashLoan", "executeOperation", "onFlashLoan", "receiveFlashLoan"];
        if flash.iter().any(|f| names.contains(f)) { patterns.push(PatternType::FlashLoanCapable) }

        let oracle = ["getPrice", "latestRoundData", "latestAnswer", "getReserves"];
        if oracle.iter().any(|f| names.contains(f)) { patterns.push(PatternType::OracleDependent) }

        let dex = ["swap", "addLiquidity", "removeLiquidity"];
        if dex.iter().any(|f| names.contains(f)) { patterns.push(PatternType::DEXInteraction) }

        if names.contains("owner") || names.contains("hasRole") { patterns.push(PatternType::AccessControlled) }
        if names.contains("pause") && names.contains("unpause") { patterns.push(PatternType::Pausable) }
        if names.contains("upgradeTo") || names.contains("initialize") { patterns.push(PatternType::Upgradeable) }
        if names.contains("permit") || names.contains("nonces") { patterns.push(PatternType::PermitEnabled) }

        let callbacks = ["onERC721Received", "onERC1155Received", "executeOperation", "uniswapV2Call"];
        if callbacks.iter().any(|f| names.contains(f)) { patterns.push(PatternType::CallbackEnabled) }

        let bridge = ["bridgeTo", "relayMessage", "ccipReceive", "lzReceive"];
        if bridge.iter().any(|f| names.contains(f)) { patterns.push(PatternType::CrossChainCapable) }

        if functions.iter().any(|f| f.name.contains("swap") && f.inputs.iter().any(|p| p.name.contains("deadline"))) {
            patterns.push(PatternType::MEVExposed);
        }

        patterns
    }

    fn calculate_security_score(&self, functions: &[ABIFunction], patterns: &[PatternType]) -> u8 {
        let names: HashSet<_> = functions.iter().map(|f| f.name.as_str()).collect();
        let mut score = 50u8;

        if names.contains("owner") || names.contains("hasRole") { score += 15 }
        if names.contains("renounceOwnership") { score += 5 }
        if patterns.contains(&PatternType::Pausable) { score += 10 }
        if patterns.contains(&PatternType::Upgradeable) { score = score.saturating_sub(10) }
        if patterns.contains(&PatternType::FlashLoanCapable) { score = score.saturating_sub(10) }
        if patterns.contains(&PatternType::OracleDependent) { score = score.saturating_sub(5) }

        score.min(100)
    }

    pub fn scan_abi(&self, analysis: &ABIAnalysis) -> Vec<Vulnerability> {
        let mut vulns = Vec::new();

        vulns.extend(self.check_functions(&analysis.functions));
        vulns.extend(self.check_events(&analysis.events));
        vulns.extend(self.check_patterns(analysis));
        vulns.extend(self.check_selectors(&analysis.functions));
        vulns.extend(self.check_defi_risks(&analysis.functions, &analysis.detected_patterns));
        vulns.extend(self.check_token_compliance(&analysis.functions, &analysis.events, &analysis.contract_type));

        if self.verbose {
            println!("\n\x1b[1;36mAdvanced ABI Analysis Complete:\x1b[0m");
            println!("   \x1b[36mContract Type:\x1b[0m {:?}", analysis.contract_type);
            println!("   \x1b[36mSecurity Score:\x1b[0m {}/100", analysis.security_score);
            println!("   \x1b[36mFunctions:\x1b[0m {}, \x1b[36mEvents:\x1b[0m {}", analysis.functions.len(), analysis.events.len());
            println!("   \x1b[36mPatterns Detected:\x1b[0m {}", analysis.detected_patterns.len());
            println!("   \x1b[33mVulnerabilities Found:\x1b[0m {}", vulns.len());
        }

        vulns
    }

    fn check_functions(&self, functions: &[ABIFunction]) -> Vec<Vulnerability> {
        let mut vulns = Vec::new();
        let names: HashSet<_> = functions.iter().map(|f| f.name.as_str()).collect();
        let has_pause = names.contains("pause");

        let critical_admin = [
            "mint", "burn", "transferOwnership", "grantRole", "revokeRole",
            "upgradeTo", "upgradeToAndCall", "initialize", "setOwner", "pause", "unpause",
            "withdraw", "emergencyWithdraw", "destroy", "kill", "selfdestruct"
        ];

        for func in functions {
            let name = func.name.as_str();

            // Critical admin functions
            if critical_admin.iter().any(|p| name.to_lowercase().contains(&p.to_lowercase())) {
                if func.state_mutability != "view" && func.state_mutability != "pure" {
                    vulns.push(self.vuln(
                        VulnerabilitySeverity::Critical,
                        VulnerabilityCategory::ABIAccessControl,
                        format!("Critical Admin Function: '{}'", name),
                        "Administrative function that modifies contract state. Verify proper access control.".into(),
                        self.sig(func),
                        "Implement onlyOwner, onlyRole, or multi-sig protection.".into(),
                    ));
                }
            }

            // Payable without clear purpose
            if func.state_mutability == "payable" && !["deposit", "fund", "donate", "buy", "purchase"].iter().any(|p| name.to_lowercase().contains(p)) {
                vulns.push(self.vuln(
                    VulnerabilitySeverity::High,
                    VulnerabilityCategory::ABIParameterValidation,
                    format!("Payable Function: '{}'", name),
                    "Accepts ETH without clear deposit purpose. Verify value handling.".into(),
                    self.sig(func),
                    "Validate msg.value and implement proper fund handling.".into(),
                ));
            }

            // Dangerous patterns
            if ["execute", "call", "delegatecall", "multicall"].iter().any(|p| name.to_lowercase().contains(p)) {
                if func.inputs.iter().any(|p| p.param_type == "bytes" || p.param_type == "bytes[]") {
                    vulns.push(self.vuln(
                        VulnerabilitySeverity::Critical,
                        VulnerabilityCategory::ABIArbitraryCall,
                        format!("Arbitrary Execution: '{}'", name),
                        "Accepts bytes data for execution. High risk for arbitrary code execution.".into(),
                        self.sig(func),
                        "Whitelist targets and function selectors. Add strict access control.".into(),
                    ));
                }
            }

            // Self-destruct
            if ["destroy", "kill", "selfdestruct"].contains(&name) {
                vulns.push(self.vuln(
                    VulnerabilitySeverity::Critical,
                    VulnerabilityCategory::ABISelfDestruct,
                    "Self-Destruct Capability".into(),
                    "Contract can be permanently destroyed. All funds will be lost.".into(),
                    self.sig(func),
                    "Remove self-destruct or add timelock with multi-sig.".into(),
                ));
            }

            // Address params in critical functions
            for param in &func.inputs {
                if param.param_type == "address" && critical_admin.iter().any(|p| name.to_lowercase().contains(&p.to_lowercase())) {
                    vulns.push(self.vuln(
                        VulnerabilitySeverity::High,
                        VulnerabilityCategory::ABIParameterValidation,
                        format!("Critical Address Parameter: {}.{}", name, param.name),
                        "Address parameter in administrative function requires validation.".into(),
                        format!("address {}", param.name),
                        "Validate: != address(0), != address(this). Consider whitelist.".into(),
                    ));
                }
            }
        }

        // Missing pause mechanism
        if !has_pause && functions.iter().any(|f| f.state_mutability == "nonpayable" || f.state_mutability == "payable") {
            vulns.push(self.vuln(
                VulnerabilitySeverity::Medium,
                VulnerabilityCategory::ABIEmergencyBypass,
                "Missing Emergency Pause".into(),
                "No pause mechanism detected. Cannot halt operations during exploit.".into(),
                "No pause/unpause functions".into(),
                "Implement OpenZeppelin Pausable pattern.".into(),
            ));
        }

        vulns
    }

    fn check_events(&self, events: &[ABIEvent]) -> Vec<Vulnerability> {
        let mut vulns = Vec::new();

        for event in events {
            // Anonymous events
            if event.anonymous {
                vulns.push(self.vuln(
                    VulnerabilitySeverity::Medium,
                    VulnerabilityCategory::ABIEventSecurity,
                    format!("Anonymous Event: '{}'", event.name),
                    "Anonymous events don't emit signature topic. Harder to filter and index.".into(),
                    format!("event {} anonymous", event.name),
                    "Remove 'anonymous' unless required for gas optimization.".into(),
                ));
            }

            // Sensitive data in events
            let sensitive = ["password", "secret", "private", "key", "seed", "mnemonic"];
            for param in &event.inputs {
                if sensitive.iter().any(|s| param.name.to_lowercase().contains(s)) {
                    vulns.push(self.vuln(
                        VulnerabilitySeverity::Critical,
                        VulnerabilityCategory::ABIEventSecurity,
                        format!("Sensitive Data in Event: {}.{}", event.name, param.name),
                        "Event parameter contains sensitive data. ALL events are publicly visible!".into(),
                        format!("{} {}", param.param_type, param.name),
                        "Never emit secrets. Use off-chain storage or encryption.".into(),
                    ));
                }
            }

            // Too many indexed params
            let indexed = event.inputs.iter().filter(|p| p.indexed.unwrap_or(false)).count();
            if indexed > 3 {
                vulns.push(self.vuln(
                    VulnerabilitySeverity::Low,
                    VulnerabilityCategory::ABIEventSecurity,
                    format!("Excess Indexed Parameters: '{}'", event.name),
                    format!("Event has {} indexed parameters. Maximum is 3.", indexed),
                    format!("event {}", event.name),
                    "Reduce indexed parameters to 3 or fewer.".into(),
                ));
            }
        }

        vulns
    }

    fn check_patterns(&self, analysis: &ABIAnalysis) -> Vec<Vulnerability> {
        let mut vulns = Vec::new();
        let names: HashSet<_> = analysis.functions.iter().map(|f| f.name.as_str()).collect();

        // Upgradeable risks
        if analysis.detected_patterns.contains(&PatternType::Upgradeable) {
            vulns.push(self.vuln(
                VulnerabilitySeverity::High,
                VulnerabilityCategory::ABIUpgradeability,
                "Upgradeable Contract".into(),
                "Contract can be upgraded. Risk of malicious implementation replacement.".into(),
                "upgradeTo/initialize detected".into(),
                "Use timelock, multi-sig. Initialize implementation immediately.".into(),
            ));

            if names.contains("initialize") && !names.contains("reinitialize") {
                vulns.push(self.vuln(
                    VulnerabilitySeverity::Critical,
                    VulnerabilityCategory::ABIInitializerVulnerability,
                    "Initializer Without Protection".into(),
                    "Initialize function detected. Vulnerable to re-initialization attacks.".into(),
                    "initialize(...)".into(),
                    "Use OpenZeppelin initializer modifier. Call _disableInitializers() in constructor.".into(),
                ));
            }
        }

        // Permit without nonces
        if names.contains("permit") && !names.contains("nonces") {
            vulns.push(self.vuln(
                VulnerabilitySeverity::Critical,
                VulnerabilityCategory::ABISignatureVulnerability,
                "Permit Without Nonces".into(),
                "Permit function without nonces(). Missing signature replay protection.".into(),
                "permit(...) without nonces()".into(),
                "Implement nonces mapping to prevent signature replay.".into(),
            ));
        }

        // Governance flash loan risk
        if analysis.contract_type == ContractType::Governor {
            if names.contains("getVotes") && !names.contains("getPastVotes") {
                vulns.push(self.vuln(
                    VulnerabilitySeverity::Critical,
                    VulnerabilityCategory::ABIGovernanceRisk,
                    "Flash Loan Governance Attack".into(),
                    "Governor uses getVotes() without snapshot. Vulnerable to flash loan voting.".into(),
                    "getVotes() without getPastVotes()".into(),
                    "Use getPastVotes with snapshot at proposal creation block.".into(),
                ));
            }
        }

        // Bridge risks
        if analysis.detected_patterns.contains(&PatternType::CrossChainCapable) {
            vulns.push(self.vuln(
                VulnerabilitySeverity::High,
                VulnerabilityCategory::ABIBridgeVulnerability,
                "Cross-Chain Bridge".into(),
                "Bridge functionality detected. High-value attack target.".into(),
                "Bridge functions detected".into(),
                "Implement rate limiting, message validation, multi-sig validators.".into(),
            ));
        }

        vulns
    }

    fn check_selectors(&self, functions: &[ABIFunction]) -> Vec<Vulnerability> {
        let mut vulns = Vec::new();
        let mut selectors: HashMap<&str, Vec<&str>> = HashMap::new();

        for func in functions {
            if !func.selector.is_empty() {
                selectors.entry(&func.selector).or_default().push(&func.name);
            }
        }

        for (sel, names) in selectors {
            if names.len() > 1 {
                vulns.push(self.vuln(
                    VulnerabilitySeverity::Critical,
                    VulnerabilityCategory::ABISelectorCollision,
                    format!("Selector Collision: {}", sel),
                    format!("Functions share selector: {}. Undefined behavior.", names.join(", ")),
                    names.join(", "),
                    "Rename functions to generate unique selectors.".into(),
                ));
            }
        }

        vulns
    }

    fn check_defi_risks(&self, functions: &[ABIFunction], patterns: &[PatternType]) -> Vec<Vulnerability> {
        let mut vulns = Vec::new();
        let names: HashSet<_> = functions.iter().map(|f| f.name.as_str()).collect();

        // Flash loan risks
        if patterns.contains(&PatternType::FlashLoanCapable) {
            if names.contains("flashLoan") {
                vulns.push(self.vuln(
                    VulnerabilitySeverity::High,
                    VulnerabilityCategory::ABIFlashLoanRisk,
                    "Flash Loan Provider".into(),
                    "Provides flash loans. Ensure proper fee collection and balance validation.".into(),
                    "flashLoan(...)".into(),
                    "Validate repayment atomically. Implement reentrancy guards.".into(),
                ));
            }
            if names.contains("executeOperation") || names.contains("onFlashLoan") {
                vulns.push(self.vuln(
                    VulnerabilitySeverity::Critical,
                    VulnerabilityCategory::ABIFlashLoanRisk,
                    "Flash Loan Callback".into(),
                    "Flash loan receiver callback. Validate initiator and msg.sender.".into(),
                    "executeOperation/onFlashLoan".into(),
                    "Verify msg.sender is expected lender. Validate initiator parameter.".into(),
                ));
            }
        }

        // Oracle risks
        if patterns.contains(&PatternType::OracleDependent) {
            vulns.push(self.vuln(
                VulnerabilitySeverity::High,
                VulnerabilityCategory::ABIOracleManipulation,
                "Oracle Dependency".into(),
                "Relies on price oracle. Vulnerable to manipulation via flash loans.".into(),
                "Price oracle functions detected".into(),
                "Use TWAP. Check price freshness. Implement circuit breakers.".into(),
            ));

            if names.contains("latestRoundData") {
                vulns.push(self.vuln(
                    VulnerabilitySeverity::Medium,
                    VulnerabilityCategory::ABIOracleManipulation,
                    "Chainlink Oracle".into(),
                    "Uses Chainlink. Verify roundId, answeredInRound, and updatedAt checks.".into(),
                    "latestRoundData()".into(),
                    "Check: answeredInRound >= roundId, updatedAt is recent.".into(),
                ));
            }
        }

        // DEX risks
        if patterns.contains(&PatternType::DEXInteraction) {
            for func in functions.iter().filter(|f| f.name.contains("swap")) {
                let has_slippage = func.inputs.iter().any(|p| p.name.contains("min") || p.name.contains("Max"));
                let has_deadline = func.inputs.iter().any(|p| p.name.contains("deadline"));

                if !has_slippage {
                    vulns.push(self.vuln(
                        VulnerabilitySeverity::High,
                        VulnerabilityCategory::ABIDEXInteraction,
                        format!("Missing Slippage Protection: '{}'", func.name),
                        "No minAmountOut parameter. Vulnerable to sandwich attacks.".into(),
                        self.sig(func),
                        "Add minAmountOut parameter to prevent MEV extraction.".into(),
                    ));
                }
                if !has_deadline {
                    vulns.push(self.vuln(
                        VulnerabilitySeverity::Medium,
                        VulnerabilityCategory::ABIDEXInteraction,
                        format!("Missing Deadline: '{}'", func.name),
                        "No deadline parameter. Transaction can be delayed and executed at unfavorable price.".into(),
                        self.sig(func),
                        "Add deadline parameter. Validate block.timestamp < deadline.".into(),
                    ));
                }
            }
        }

        // Permit risks
        if patterns.contains(&PatternType::PermitEnabled) {
            vulns.push(self.vuln(
                VulnerabilitySeverity::High,
                VulnerabilityCategory::ABIPermitVulnerability,
                "EIP-2612 Permit".into(),
                "Gasless approval pattern. Check for signature replay and malleability.".into(),
                "permit(...)".into(),
                "Include chainId in domain separator. Validate deadline strictly.".into(),
            ));
        }

        vulns
    }

    fn check_token_compliance(&self, functions: &[ABIFunction], events: &[ABIEvent], contract_type: &ContractType) -> Vec<Vulnerability> {
        let mut vulns = Vec::new();
        let func_names: HashSet<_> = functions.iter().map(|f| f.name.as_str()).collect();
        let event_names: HashSet<_> = events.iter().map(|e| e.name.as_str()).collect();

        match contract_type {
            ContractType::ERC20 => {
                let required = ["totalSupply", "balanceOf", "transfer", "transferFrom", "approve", "allowance"];
                for f in required {
                    if !func_names.contains(f) {
                        vulns.push(self.vuln(
                            VulnerabilitySeverity::High,
                            VulnerabilityCategory::ABITokenStandard,
                            format!("Missing ERC-20: {}", f),
                            "Required ERC-20 function not found.".into(),
                            format!("Missing: {}()", f),
                            "Implement all required ERC-20 functions.".into(),
                        ));
                    }
                }
                for e in ["Transfer", "Approval"] {
                    if !event_names.contains(e) {
                        vulns.push(self.vuln(
                            VulnerabilitySeverity::High,
                            VulnerabilityCategory::ABITokenStandard,
                            format!("Missing ERC-20 Event: {}", e),
                            "Required ERC-20 event not found.".into(),
                            format!("Missing: event {}", e),
                            "Add required ERC-20 events.".into(),
                        ));
                    }
                }
                if func_names.contains("approve") && !func_names.contains("increaseAllowance") {
                    vulns.push(self.vuln(
                        VulnerabilitySeverity::Medium,
                        VulnerabilityCategory::ABITokenStandard,
                        "Approve Race Condition".into(),
                        "No increaseAllowance/decreaseAllowance. Vulnerable to front-running.".into(),
                        "approve() only".into(),
                        "Add increaseAllowance() and decreaseAllowance().".into(),
                    ));
                }
            }
            ContractType::ERC721 => {
                let required = ["balanceOf", "ownerOf", "safeTransferFrom", "transferFrom", "approve", "setApprovalForAll", "getApproved", "isApprovedForAll"];
                for f in required {
                    if !func_names.contains(f) {
                        vulns.push(self.vuln(
                            VulnerabilitySeverity::High,
                            VulnerabilityCategory::ABITokenStandard,
                            format!("Missing ERC-721: {}", f),
                            "Required ERC-721 function not found.".into(),
                            format!("Missing: {}()", f),
                            "Implement all required ERC-721 functions.".into(),
                        ));
                    }
                }
            }
            ContractType::ERC4626 => {
                vulns.push(self.vuln(
                    VulnerabilitySeverity::High,
                    VulnerabilityCategory::ABITokenStandard,
                    "ERC-4626 Vault".into(),
                    "Tokenized vault detected. Vulnerable to inflation/donation attacks.".into(),
                    "ERC-4626 pattern".into(),
                    "Use virtual shares offset. Initialize with small deposit.".into(),
                ));
            }
            _ => {}
        }

        vulns
    }

    fn vuln(&self, severity: VulnerabilitySeverity, category: VulnerabilityCategory, title: String, desc: String, snippet: String, rec: String) -> Vulnerability {
        Vulnerability::new(severity, category, title, desc, 0, snippet, rec)
    }

    fn sig(&self, func: &ABIFunction) -> String {
        let params = func.inputs.iter().map(|p| format!("{} {}", p.param_type, p.name)).collect::<Vec<_>>().join(", ");
        format!("function {}({}) {}", func.name, params, func.state_mutability)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_erc20() {
        let scanner = ABIScanner::new(false);
        let abi = r#"[
            {"type":"function","name":"transfer","inputs":[{"name":"to","type":"address"},{"name":"amount","type":"uint256"}],"outputs":[{"type":"bool"}],"stateMutability":"nonpayable"},
            {"type":"function","name":"balanceOf","inputs":[{"name":"account","type":"address"}],"outputs":[{"type":"uint256"}],"stateMutability":"view"},
            {"type":"function","name":"approve","inputs":[{"name":"spender","type":"address"},{"name":"amount","type":"uint256"}],"outputs":[{"type":"bool"}],"stateMutability":"nonpayable"},
            {"type":"event","name":"Transfer","inputs":[{"name":"from","type":"address","indexed":true},{"name":"to","type":"address","indexed":true},{"name":"value","type":"uint256"}]}
        ]"#;
        let analysis = scanner.parse_abi(abi).unwrap();
        assert_eq!(analysis.contract_type, ContractType::ERC20);
    }

    #[test]
    fn test_detect_flash_loan() {
        let scanner = ABIScanner::new(false);
        let abi = r#"[{"type":"function","name":"flashLoan","inputs":[],"outputs":[],"stateMutability":"nonpayable"},{"type":"function","name":"executeOperation","inputs":[],"outputs":[],"stateMutability":"nonpayable"}]"#;
        let analysis = scanner.parse_abi(abi).unwrap();
        assert!(analysis.detected_patterns.contains(&PatternType::FlashLoanCapable));
    }

    #[test]
    fn test_detect_proxy() {
        let scanner = ABIScanner::new(false);
        let abi = r#"[{"type":"function","name":"upgradeTo","inputs":[{"name":"impl","type":"address"}],"outputs":[],"stateMutability":"nonpayable"},{"type":"function","name":"initialize","inputs":[],"outputs":[],"stateMutability":"nonpayable"}]"#;
        let analysis = scanner.parse_abi(abi).unwrap();
        assert_eq!(analysis.contract_type, ContractType::Proxy);
        assert!(analysis.detected_patterns.contains(&PatternType::Upgradeable));
    }

    #[test]
    fn test_security_score() {
        let scanner = ABIScanner::new(false);
        let abi = r#"[{"type":"function","name":"owner","inputs":[],"outputs":[{"type":"address"}],"stateMutability":"view"},{"type":"function","name":"pause","inputs":[],"outputs":[],"stateMutability":"nonpayable"},{"type":"function","name":"unpause","inputs":[],"outputs":[],"stateMutability":"nonpayable"}]"#;
        let analysis = scanner.parse_abi(abi).unwrap();
        assert!(analysis.security_score >= 70);
    }
}
