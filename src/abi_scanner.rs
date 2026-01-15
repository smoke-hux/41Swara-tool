use serde_json::Value;
use std::collections::{HashMap, HashSet};
use crate::vulnerabilities::{Vulnerability, VulnerabilitySeverity, VulnerabilityCategory};

// ============================================================================
// CORE DATA STRUCTURES
// ============================================================================

#[derive(Debug, Clone)]
pub struct ABIFunction {
    pub name: String,
    pub function_type: String,
    pub state_mutability: String,
    pub inputs: Vec<ABIParameter>,
    pub outputs: Vec<ABIParameter>,
    pub selector: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ABIEvent {
    pub name: String,
    pub inputs: Vec<ABIParameter>,
    pub anonymous: bool,
    #[allow(dead_code)] // Preserved for complete event analysis
    pub signature: Option<String>,
}

#[derive(Debug, Clone)]
#[allow(dead_code)] // Preserved for custom error analysis expansion
pub struct ABIError {
    pub name: String,
    pub inputs: Vec<ABIParameter>,
    pub selector: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ABIParameter {
    pub name: String,
    pub param_type: String,
    pub indexed: Option<bool>,
    pub components: Option<Vec<ABIParameter>>,
    #[allow(dead_code)] // Preserved for internal type analysis
    pub internal_type: Option<String>,
}

#[derive(Debug)]
pub struct ABIAnalysis {
    pub functions: Vec<ABIFunction>,
    pub events: Vec<ABIEvent>,
    #[allow(dead_code)] // Preserved for custom error analysis
    pub errors: Vec<ABIError>,
    pub contract_type: ContractType,
    pub security_score: SecurityScore,
    pub detected_patterns: Vec<DetectedPattern>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ContractType {
    Unknown,
    ERC20,
    ERC721,
    ERC1155,
    ERC4626,  // Tokenized vault
    Proxy,
    ProxyAdmin,
    Governor,
    Timelock,
    Multisig,
    DEX,
    Lending,
    Bridge,
    Oracle,
    FlashLoan,
    Staking,
    Vault,
    NFTMarketplace,
}

#[derive(Debug, Clone)]
pub struct DetectedPattern {
    pub pattern_type: PatternType,
    #[allow(dead_code)] // Preserved for confidence scoring reports
    pub confidence: f32,
    #[allow(dead_code)] // Preserved for detailed evidence reports
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
#[allow(dead_code)] // Pattern variants preserved for future pattern detection expansion
pub enum PatternType {
    // DeFi Patterns
    FlashLoanCapable,
    OracleDependent,
    DEXInteraction,
    LiquidityPool,
    YieldFarming,
    // Security Patterns
    AccessControlled,
    Pausable,
    Upgradeable,
    ReentrancyGuarded,
    TimeLocked,
    // Risk Patterns
    ArbitraryCall,
    DelegateCallUsage,
    SelfDestructCapable,
    CallbackEnabled,
    CrossChainCapable,
    MEVExposed,
    PermitEnabled,
}

#[derive(Debug, Clone)]
#[allow(dead_code)] // Preserved for detailed security reports
pub struct SecurityScore {
    pub overall: u8,
    pub access_control: u8,
    pub input_validation: u8,
    pub upgrade_safety: u8,
    pub defi_risk: u8,
    pub mev_exposure: u8,
}

// ============================================================================
// KNOWN FUNCTION SIGNATURES DATABASE
// ============================================================================

#[allow(dead_code)] // Preserved for comprehensive signature database
struct KnownSignatures {
    // Critical admin functions
    critical_admin: HashSet<&'static str>,
    // Flash loan signatures
    flash_loan: HashSet<&'static str>,
    // Oracle signatures
    oracle: HashSet<&'static str>,
    // DEX signatures
    dex: HashSet<&'static str>,
    // Callback signatures
    callbacks: HashSet<&'static str>,
    // Dangerous functions
    dangerous: HashSet<&'static str>,
    // Governance signatures
    governance: HashSet<&'static str>,
    // Bridge signatures
    bridge: HashSet<&'static str>,
    // ERC standards
    erc20: HashSet<&'static str>,
    erc721: HashSet<&'static str>,
    erc1155: HashSet<&'static str>,
    erc4626: HashSet<&'static str>,
}

impl KnownSignatures {
    fn new() -> Self {
        Self {
            critical_admin: [
                "transferOwnership", "renounceOwnership", "setOwner", "changeOwner",
                "grantRole", "revokeRole", "setAdmin", "changeAdmin",
                "upgradeTo", "upgradeToAndCall", "setImplementation",
                "pause", "unpause", "emergencyWithdraw", "emergencyPause",
                "setFee", "setFeeRecipient", "setTreasury",
                "mint", "burn", "burnFrom",
                "setMinter", "addMinter", "removeMinter",
                "setOperator", "addOperator", "removeOperator",
                "setWhitelist", "addToWhitelist", "removeFromWhitelist",
                "setBlacklist", "addToBlacklist", "removeFromBlacklist",
                "initialize", "reinitialize",
                "selfdestruct", "destroy", "kill",
            ].iter().cloned().collect(),

            flash_loan: [
                "flashLoan", "flashBorrow", "executeOperation",
                "onFlashLoan", "flashLoanSimple", "flashLoanCallback",
                "receiveFlashLoan", "uniswapV2Call", "uniswapV3FlashCallback",
                "pancakeCall", "BiswapCall", "callFunction", // dYdX
                "onDydxFlashLoan",
            ].iter().cloned().collect(),

            oracle: [
                "getPrice", "latestRoundData", "latestAnswer", "getRoundData",
                "getLatestPrice", "consult", "observe", "getAmountOut",
                "getAmountsOut", "quote", "getReserves", "slot0",
                "getTwap", "getSpotPrice", "peek", "peep", "read",
                "latestTimestamp", "getAnswer",
            ].iter().cloned().collect(),

            dex: [
                "swap", "swapExactTokensForTokens", "swapTokensForExactTokens",
                "swapExactETHForTokens", "swapTokensForExactETH",
                "swapExactTokensForETH", "swapETHForExactTokens",
                "addLiquidity", "removeLiquidity", "addLiquidityETH",
                "removeLiquidityETH", "removeLiquidityWithPermit",
                "exactInput", "exactOutput", "exactInputSingle", "exactOutputSingle",
                "multicall",
            ].iter().cloned().collect(),

            callbacks: [
                "onERC721Received", "onERC1155Received", "onERC1155BatchReceived",
                "tokensReceived", "tokensToSend", // ERC777
                "onTokenTransfer", // ERC677
                "receiveApproval", // ApproveAndCall
                "onFlashLoan", "executeOperation",
                "uniswapV2Call", "uniswapV3SwapCallback", "uniswapV3MintCallback",
                "hook", "beforeSwap", "afterSwap", "beforeAddLiquidity", "afterAddLiquidity",
                "fallback", "receive",
            ].iter().cloned().collect(),

            dangerous: [
                "delegatecall", "call", "staticcall",
                "execute", "executeTransaction", "exec",
                "multiCall", "batchExecute",
                "sweep", "withdrawAll", "drain",
                "setLogic", "setTarget", "setDestination",
            ].iter().cloned().collect(),

            governance: [
                "propose", "queue", "execute", "cancel",
                "castVote", "castVoteWithReason", "castVoteBySig",
                "delegate", "delegateBySig",
                "getVotes", "getPastVotes", "getPastTotalSupply",
                "proposalThreshold", "quorum", "votingDelay", "votingPeriod",
            ].iter().cloned().collect(),

            bridge: [
                "bridge", "bridgeTo", "sendMessage", "receiveMessage",
                "relayMessage", "finalizeDeposit", "finalizeWithdrawal",
                "deposit", "withdraw", "depositFor", "withdrawTo",
                "lock", "unlock", "mint", "burn",
                "ccipReceive", "ccipSend", // Chainlink CCIP
                "lzReceive", "send", // LayerZero
                "anySwapIn", "anySwapOut", // Multichain
            ].iter().cloned().collect(),

            erc20: [
                "name", "symbol", "decimals", "totalSupply",
                "balanceOf", "transfer", "transferFrom",
                "approve", "allowance",
                "increaseAllowance", "decreaseAllowance",
            ].iter().cloned().collect(),

            erc721: [
                "name", "symbol", "tokenURI", "baseURI",
                "balanceOf", "ownerOf",
                "safeTransferFrom", "transferFrom",
                "approve", "setApprovalForAll", "getApproved", "isApprovedForAll",
                "safeMint", "mint", "burn",
                "totalSupply", "tokenByIndex", "tokenOfOwnerByIndex",
            ].iter().cloned().collect(),

            erc1155: [
                "uri", "balanceOf", "balanceOfBatch",
                "setApprovalForAll", "isApprovedForAll",
                "safeTransferFrom", "safeBatchTransferFrom",
                "mint", "mintBatch", "burn", "burnBatch",
            ].iter().cloned().collect(),

            erc4626: [
                "asset", "totalAssets", "convertToShares", "convertToAssets",
                "maxDeposit", "maxMint", "maxWithdraw", "maxRedeem",
                "previewDeposit", "previewMint", "previewWithdraw", "previewRedeem",
                "deposit", "mint", "withdraw", "redeem",
            ].iter().cloned().collect(),
        }
    }
}

// ============================================================================
// MAIN ABI SCANNER
// ============================================================================

pub struct ABIScanner {
    verbose: bool,
    signatures: KnownSignatures,
}

impl ABIScanner {
    pub fn new(verbose: bool) -> Self {
        Self {
            verbose,
            signatures: KnownSignatures::new(),
        }
    }

    pub fn parse_abi(&self, abi_content: &str) -> Result<ABIAnalysis, String> {
        let abi: Value = serde_json::from_str(abi_content)
            .map_err(|e| format!("Invalid JSON format: {}", e))?;

        let abi_array = abi.as_array()
            .ok_or("ABI must be an array")?;

        let mut functions = Vec::new();
        let mut events = Vec::new();
        let mut errors = Vec::new();

        for item in abi_array {
            let item_type = item.get("type")
                .and_then(|t| t.as_str())
                .unwrap_or("function");

            match item_type {
                "function" | "constructor" | "fallback" | "receive" => {
                    if let Ok(func) = self.parse_function(item) {
                        functions.push(func);
                    }
                }
                "event" => {
                    if let Ok(event) = self.parse_event(item) {
                        events.push(event);
                    }
                }
                "error" => {
                    if let Ok(error) = self.parse_error(item) {
                        errors.push(error);
                    }
                }
                _ => {}
            }
        }

        // Detect contract type
        let contract_type = self.detect_contract_type(&functions, &events);

        // Detect patterns
        let detected_patterns = self.detect_patterns(&functions, &events);

        // Calculate security score
        let security_score = self.calculate_security_score(&functions, &events, &detected_patterns);

        Ok(ABIAnalysis {
            functions,
            events,
            errors,
            contract_type,
            security_score,
            detected_patterns,
        })
    }

    fn parse_function(&self, item: &Value) -> Result<ABIFunction, String> {
        let name = item.get("name")
            .and_then(|n| n.as_str())
            .unwrap_or("")
            .to_string();

        let function_type = item.get("type")
            .and_then(|t| t.as_str())
            .unwrap_or("function")
            .to_string();

        let state_mutability = item.get("stateMutability")
            .and_then(|s| s.as_str())
            .unwrap_or("nonpayable")
            .to_string();

        let inputs = self.parse_parameters(item.get("inputs"))?;
        let outputs = self.parse_parameters(item.get("outputs"))?;

        // Calculate function selector
        let selector = if !name.is_empty() {
            Some(self.calculate_selector(&name, &inputs))
        } else {
            None
        };

        Ok(ABIFunction {
            name,
            function_type,
            state_mutability,
            inputs,
            outputs,
            selector,
        })
    }

    fn parse_event(&self, item: &Value) -> Result<ABIEvent, String> {
        let name = item.get("name")
            .and_then(|n| n.as_str())
            .unwrap_or("")
            .to_string();

        let anonymous = item.get("anonymous")
            .and_then(|a| a.as_bool())
            .unwrap_or(false);

        let inputs = self.parse_parameters(item.get("inputs"))?;

        let signature = Some(self.calculate_event_signature(&name, &inputs));

        Ok(ABIEvent {
            name,
            inputs,
            anonymous,
            signature,
        })
    }

    fn parse_error(&self, item: &Value) -> Result<ABIError, String> {
        let name = item.get("name")
            .and_then(|n| n.as_str())
            .unwrap_or("")
            .to_string();

        let inputs = self.parse_parameters(item.get("inputs"))?;
        let selector = Some(self.calculate_selector(&name, &inputs));

        Ok(ABIError {
            name,
            inputs,
            selector,
        })
    }

    fn parse_parameters(&self, params: Option<&Value>) -> Result<Vec<ABIParameter>, String> {
        let empty_vec = Vec::new();
        let params_array = match params {
            Some(p) => p.as_array().unwrap_or(&empty_vec),
            None => return Ok(Vec::new()),
        };

        let mut parameters = Vec::new();

        for param in params_array {
            let name = param.get("name")
                .and_then(|n| n.as_str())
                .unwrap_or("")
                .to_string();

            let param_type = param.get("type")
                .and_then(|t| t.as_str())
                .unwrap_or("")
                .to_string();

            let indexed = param.get("indexed")
                .and_then(|i| i.as_bool());

            let internal_type = param.get("internalType")
                .and_then(|t| t.as_str())
                .map(|s| s.to_string());

            let components = if param.get("components").is_some() {
                Some(self.parse_parameters(param.get("components"))?)
            } else {
                None
            };

            parameters.push(ABIParameter {
                name,
                param_type,
                indexed,
                components,
                internal_type,
            });
        }

        Ok(parameters)
    }

    fn calculate_selector(&self, name: &str, inputs: &[ABIParameter]) -> String {
        let signature = format!("{}({})", name,
            inputs.iter()
                .map(|p| self.canonical_type(&p.param_type, &p.components))
                .collect::<Vec<_>>()
                .join(",")
        );

        // Simple hash simulation - in production use keccak256
        format!("0x{:08x}", self.simple_hash(&signature))
    }

    fn calculate_event_signature(&self, name: &str, inputs: &[ABIParameter]) -> String {
        format!("{}({})", name,
            inputs.iter()
                .map(|p| self.canonical_type(&p.param_type, &p.components))
                .collect::<Vec<_>>()
                .join(",")
        )
    }

    fn canonical_type(&self, param_type: &str, components: &Option<Vec<ABIParameter>>) -> String {
        if param_type == "tuple" || param_type.starts_with("tuple[") {
            if let Some(comps) = components {
                let inner = comps.iter()
                    .map(|c| self.canonical_type(&c.param_type, &c.components))
                    .collect::<Vec<_>>()
                    .join(",");
                if param_type.contains('[') {
                    let suffix = &param_type[5..]; // Get array suffix
                    format!("({}){}", inner, suffix)
                } else {
                    format!("({})", inner)
                }
            } else {
                param_type.to_string()
            }
        } else {
            param_type.to_string()
        }
    }

    fn simple_hash(&self, input: &str) -> u32 {
        let mut hash: u32 = 0;
        for byte in input.bytes() {
            hash = hash.wrapping_mul(31).wrapping_add(byte as u32);
        }
        hash
    }

    // ========================================================================
    // CONTRACT TYPE DETECTION
    // ========================================================================

    fn detect_contract_type(&self, functions: &[ABIFunction], events: &[ABIEvent]) -> ContractType {
        let func_names: HashSet<String> = functions.iter().map(|f| f.name.clone()).collect();
        let event_names: HashSet<String> = events.iter().map(|e| e.name.clone()).collect();

        // ERC-4626 Vault (check first as it extends ERC-20)
        if self.signatures.erc4626.iter().filter(|f| func_names.contains(&f.to_string())).count() >= 8 {
            return ContractType::ERC4626;
        }

        // ERC-1155
        if func_names.contains("balanceOfBatch") && func_names.contains("safeBatchTransferFrom") {
            return ContractType::ERC1155;
        }

        // ERC-721
        if func_names.contains("ownerOf") && func_names.contains("safeTransferFrom")
            && (func_names.contains("tokenURI") || func_names.contains("tokenOfOwnerByIndex")) {
            return ContractType::ERC721;
        }

        // ERC-20
        if func_names.contains("transfer") && func_names.contains("approve")
            && func_names.contains("allowance") && func_names.contains("balanceOf") {
            return ContractType::ERC20;
        }

        // Proxy patterns
        if func_names.contains("upgradeTo") || func_names.contains("upgradeToAndCall")
            || func_names.contains("implementation") {
            if func_names.contains("changeProxyAdmin") || func_names.contains("getProxyAdmin") {
                return ContractType::ProxyAdmin;
            }
            return ContractType::Proxy;
        }

        // Governor
        if func_names.contains("propose") && func_names.contains("castVote")
            && func_names.contains("execute") {
            return ContractType::Governor;
        }

        // Timelock
        if func_names.contains("schedule") && func_names.contains("execute")
            && (func_names.contains("getMinDelay") || func_names.contains("delay")) {
            return ContractType::Timelock;
        }

        // Multisig
        if func_names.contains("submitTransaction") && func_names.contains("confirmTransaction") {
            return ContractType::Multisig;
        }

        // DEX
        if func_names.contains("swap") || func_names.contains("addLiquidity")
            || func_names.contains("removeLiquidity") {
            return ContractType::DEX;
        }

        // Lending
        if func_names.contains("borrow") && func_names.contains("repay")
            && (func_names.contains("liquidate") || func_names.contains("liquidationCall")) {
            return ContractType::Lending;
        }

        // Bridge
        if (func_names.contains("deposit") && func_names.contains("withdraw"))
            || func_names.contains("bridgeTo") || func_names.contains("relayMessage") {
            if event_names.contains("Deposit") && event_names.contains("Withdrawal") {
                return ContractType::Bridge;
            }
        }

        // Oracle
        if func_names.contains("latestRoundData") || func_names.contains("getPrice")
            || func_names.contains("latestAnswer") {
            return ContractType::Oracle;
        }

        // Flash Loan
        if func_names.contains("flashLoan") || func_names.contains("executeOperation") {
            return ContractType::FlashLoan;
        }

        // Staking
        if func_names.contains("stake") && func_names.contains("unstake") {
            return ContractType::Staking;
        }

        // Vault
        if func_names.contains("deposit") && func_names.contains("withdraw")
            && func_names.contains("totalAssets") {
            return ContractType::Vault;
        }

        // NFT Marketplace
        if func_names.contains("listItem") || func_names.contains("buyItem")
            || func_names.contains("createAuction") {
            return ContractType::NFTMarketplace;
        }

        ContractType::Unknown
    }

    // ========================================================================
    // PATTERN DETECTION
    // ========================================================================

    fn detect_patterns(&self, functions: &[ABIFunction], events: &[ABIEvent]) -> Vec<DetectedPattern> {
        let mut patterns = Vec::new();
        let func_names: HashSet<String> = functions.iter().map(|f| f.name.clone()).collect();
        let _event_names: HashSet<String> = events.iter().map(|e| e.name.clone()).collect();

        // Flash Loan Capable
        let flash_evidence: Vec<String> = functions.iter()
            .filter(|f| self.signatures.flash_loan.contains(f.name.as_str()))
            .map(|f| f.name.clone())
            .collect();
        if !flash_evidence.is_empty() {
            patterns.push(DetectedPattern {
                pattern_type: PatternType::FlashLoanCapable,
                confidence: (flash_evidence.len() as f32 / 3.0).min(1.0),
                evidence: flash_evidence,
            });
        }

        // Oracle Dependent
        let oracle_evidence: Vec<String> = functions.iter()
            .filter(|f| self.signatures.oracle.contains(f.name.as_str()))
            .map(|f| f.name.clone())
            .collect();
        if !oracle_evidence.is_empty() {
            patterns.push(DetectedPattern {
                pattern_type: PatternType::OracleDependent,
                confidence: (oracle_evidence.len() as f32 / 2.0).min(1.0),
                evidence: oracle_evidence,
            });
        }

        // DEX Interaction
        let dex_evidence: Vec<String> = functions.iter()
            .filter(|f| self.signatures.dex.contains(f.name.as_str()))
            .map(|f| f.name.clone())
            .collect();
        if !dex_evidence.is_empty() {
            patterns.push(DetectedPattern {
                pattern_type: PatternType::DEXInteraction,
                confidence: (dex_evidence.len() as f32 / 3.0).min(1.0),
                evidence: dex_evidence,
            });
        }

        // Access Controlled
        if func_names.contains("owner") || func_names.contains("hasRole")
            || func_names.contains("getRoleAdmin") {
            patterns.push(DetectedPattern {
                pattern_type: PatternType::AccessControlled,
                confidence: 0.9,
                evidence: vec!["Access control functions detected".to_string()],
            });
        }

        // Pausable
        if func_names.contains("pause") && func_names.contains("unpause") {
            patterns.push(DetectedPattern {
                pattern_type: PatternType::Pausable,
                confidence: 1.0,
                evidence: vec!["pause".to_string(), "unpause".to_string()],
            });
        }

        // Upgradeable
        if func_names.contains("upgradeTo") || func_names.contains("upgradeToAndCall")
            || func_names.contains("initialize") {
            patterns.push(DetectedPattern {
                pattern_type: PatternType::Upgradeable,
                confidence: 0.95,
                evidence: vec!["Upgrade functions detected".to_string()],
            });
        }

        // Callback Enabled
        let callback_evidence: Vec<String> = functions.iter()
            .filter(|f| self.signatures.callbacks.contains(f.name.as_str()))
            .map(|f| f.name.clone())
            .collect();
        if !callback_evidence.is_empty() {
            patterns.push(DetectedPattern {
                pattern_type: PatternType::CallbackEnabled,
                confidence: 1.0,
                evidence: callback_evidence,
            });
        }

        // Arbitrary Call Risk
        let arbitrary_evidence: Vec<String> = functions.iter()
            .filter(|f| {
                f.name.contains("execute") || f.name.contains("call")
                || f.name.contains("multicall") || f.name.contains("batch")
            })
            .filter(|f| {
                f.inputs.iter().any(|p| p.param_type == "bytes" || p.param_type == "bytes[]")
            })
            .map(|f| f.name.clone())
            .collect();
        if !arbitrary_evidence.is_empty() {
            patterns.push(DetectedPattern {
                pattern_type: PatternType::ArbitraryCall,
                confidence: 0.8,
                evidence: arbitrary_evidence,
            });
        }

        // Permit Enabled (EIP-2612)
        if func_names.contains("permit") || func_names.contains("PERMIT_TYPEHASH")
            || func_names.contains("nonces") {
            patterns.push(DetectedPattern {
                pattern_type: PatternType::PermitEnabled,
                confidence: 0.95,
                evidence: vec!["EIP-2612 permit pattern detected".to_string()],
            });
        }

        // Cross-Chain Capable
        let bridge_evidence: Vec<String> = functions.iter()
            .filter(|f| self.signatures.bridge.contains(f.name.as_str()))
            .map(|f| f.name.clone())
            .collect();
        if !bridge_evidence.is_empty() {
            patterns.push(DetectedPattern {
                pattern_type: PatternType::CrossChainCapable,
                confidence: (bridge_evidence.len() as f32 / 2.0).min(1.0),
                evidence: bridge_evidence,
            });
        }

        // MEV Exposed (swap functions with deadline, slippage)
        let mev_evidence: Vec<String> = functions.iter()
            .filter(|f| {
                (f.name.contains("swap") || f.name.contains("trade"))
                && f.inputs.iter().any(|p|
                    p.name.contains("deadline") || p.name.contains("minAmount")
                    || p.name.contains("slippage")
                )
            })
            .map(|f| f.name.clone())
            .collect();
        if !mev_evidence.is_empty() {
            patterns.push(DetectedPattern {
                pattern_type: PatternType::MEVExposed,
                confidence: 0.7,
                evidence: mev_evidence,
            });
        }

        patterns
    }

    // ========================================================================
    // SECURITY SCORE CALCULATION
    // ========================================================================

    fn calculate_security_score(&self, functions: &[ABIFunction], _events: &[ABIEvent], patterns: &[DetectedPattern]) -> SecurityScore {
        let func_names: HashSet<String> = functions.iter().map(|f| f.name.clone()).collect();

        // Access Control Score (0-100)
        let mut access_control = 50u8;
        if func_names.contains("owner") || func_names.contains("hasRole") {
            access_control += 20;
        }
        if func_names.contains("renounceOwnership") {
            access_control += 10;
        }
        if patterns.iter().any(|p| p.pattern_type == PatternType::AccessControlled) {
            access_control += 20;
        }

        // Input Validation Score
        let mut input_validation = 60u8;
        let has_validation_errors = functions.iter()
            .any(|f| f.inputs.iter().any(|p| p.name.contains("_validated") || p.name.contains("_checked")));
        if has_validation_errors {
            input_validation += 20;
        }

        // Upgrade Safety Score
        let mut upgrade_safety = 80u8;
        if patterns.iter().any(|p| p.pattern_type == PatternType::Upgradeable) {
            upgrade_safety -= 20;
            if func_names.contains("initialize") && !func_names.contains("reinitialize") {
                upgrade_safety -= 10;
            }
        }

        // DeFi Risk Score (lower is riskier)
        let mut defi_risk = 80u8;
        if patterns.iter().any(|p| p.pattern_type == PatternType::FlashLoanCapable) {
            defi_risk -= 20;
        }
        if patterns.iter().any(|p| p.pattern_type == PatternType::OracleDependent) {
            defi_risk -= 15;
        }
        if patterns.iter().any(|p| p.pattern_type == PatternType::DEXInteraction) {
            defi_risk -= 10;
        }

        // MEV Exposure Score
        let mut mev_exposure = 90u8;
        if patterns.iter().any(|p| p.pattern_type == PatternType::MEVExposed) {
            mev_exposure -= 30;
        }
        if patterns.iter().any(|p| p.pattern_type == PatternType::DEXInteraction) {
            mev_exposure -= 15;
        }

        // Overall Score
        let overall = ((access_control as u16 + input_validation as u16 + upgrade_safety as u16
            + defi_risk as u16 + mev_exposure as u16) / 5) as u8;

        SecurityScore {
            overall,
            access_control,
            input_validation,
            upgrade_safety,
            defi_risk,
            mev_exposure,
        }
    }

    // ========================================================================
    // VULNERABILITY SCANNING
    // ========================================================================

    pub fn scan_abi(&self, analysis: &ABIAnalysis) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        // Core vulnerability checks
        vulnerabilities.extend(self.analyze_functions(&analysis.functions));
        vulnerabilities.extend(self.analyze_events(&analysis.events));
        vulnerabilities.extend(self.analyze_contract_patterns(analysis));

        // Advanced analysis
        vulnerabilities.extend(self.analyze_selector_collisions(&analysis.functions));
        vulnerabilities.extend(self.analyze_flash_loan_risks(&analysis.functions, &analysis.detected_patterns));
        vulnerabilities.extend(self.analyze_oracle_risks(&analysis.functions));
        vulnerabilities.extend(self.analyze_dex_risks(&analysis.functions));
        vulnerabilities.extend(self.analyze_signature_risks(&analysis.functions));
        vulnerabilities.extend(self.analyze_governance_risks(&analysis.functions, &analysis.contract_type));
        vulnerabilities.extend(self.analyze_mev_risks(&analysis.functions, &analysis.detected_patterns));
        vulnerabilities.extend(self.analyze_callback_risks(&analysis.functions));
        vulnerabilities.extend(self.analyze_cross_contract_risks(&analysis.functions));
        vulnerabilities.extend(self.analyze_upgrade_risks(&analysis.functions, &analysis.detected_patterns));
        vulnerabilities.extend(self.analyze_bridge_risks(&analysis.functions, &analysis.contract_type));
        vulnerabilities.extend(self.analyze_parameter_types(&analysis.functions));

        if self.verbose {
            println!("🔍 Advanced ABI Analysis Complete:");
            println!("   📊 Contract Type: {:?}", analysis.contract_type);
            println!("   🔐 Security Score: {}/100", analysis.security_score.overall);
            println!("   📝 Functions: {}, Events: {}", analysis.functions.len(), analysis.events.len());
            println!("   🎯 Patterns Detected: {}", analysis.detected_patterns.len());
            println!("   ⚠️  Vulnerabilities Found: {}", vulnerabilities.len());
        }

        vulnerabilities
    }

    // ========================================================================
    // FUNCTION ANALYSIS
    // ========================================================================

    fn analyze_functions(&self, functions: &[ABIFunction]) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();
        let func_names: HashSet<String> = functions.iter().map(|f| f.name.clone()).collect();

        let mut has_pause_functions = false;
        let mut has_ownership = false;

        for (idx, function) in functions.iter().enumerate() {
            // Critical admin function analysis
            if self.is_critical_admin_function(&function.name) {
                if function.state_mutability != "view" && function.state_mutability != "pure" {
                    vulnerabilities.push(Vulnerability {
                        severity: VulnerabilitySeverity::Critical,
                        category: VulnerabilityCategory::ABIAccessControl,
                        title: format!("Critical Admin Function: '{}'", function.name),
                        description: format!(
                            "Function '{}' is a critical administrative function that can modify contract state. \
                            Without access control, any address can call this function.",
                            function.name
                        ),
                        line_number: idx + 1,
                        code_snippet: self.format_function_signature(function),
                        recommendation: format!(
                            "Ensure '{}' has proper access control (onlyOwner, onlyRole, etc.). \
                            Consider timelock for critical operations.",
                            function.name
                        ),
                    });
                }
            }

            // Payable function analysis
            if function.state_mutability == "payable" {
                let risk_level = self.assess_payable_risk(function);
                if risk_level == "high" {
                    vulnerabilities.push(Vulnerability {
                        severity: VulnerabilitySeverity::High,
                        category: VulnerabilityCategory::ABIParameterValidation,
                        title: format!("High-Risk Payable Function: '{}'", function.name),
                        description: format!(
                            "Payable function '{}' accepts ETH. Without proper validation, \
                            funds could be locked or stolen.",
                            function.name
                        ),
                        line_number: idx + 1,
                        code_snippet: self.format_function_signature(function),
                        recommendation: "Implement value validation, reentrancy protection, and consider pull payment pattern.".to_string(),
                    });
                }
            }

            // State mutability analysis
            if self.should_be_readonly(&function.name) && function.state_mutability == "nonpayable" {
                vulnerabilities.push(Vulnerability {
                    severity: VulnerabilitySeverity::Medium,
                    category: VulnerabilityCategory::ABIFunctionVisibility,
                    title: format!("Potential Gas Optimization: '{}'", function.name),
                    description: format!(
                        "Function '{}' appears to be a getter but is not marked as view/pure. \
                        This costs unnecessary gas and may indicate state modification.",
                        function.name
                    ),
                    line_number: idx + 1,
                    code_snippet: self.format_function_signature(function),
                    recommendation: "Mark function as 'view' if it doesn't modify state, or 'pure' if it doesn't read state.".to_string(),
                });
            }

            // Dangerous function patterns
            if self.is_dangerous_function(&function.name) {
                vulnerabilities.push(Vulnerability {
                    severity: VulnerabilitySeverity::High,
                    category: VulnerabilityCategory::ABIArbitraryCall,
                    title: format!("Dangerous Function Pattern: '{}'", function.name),
                    description: format!(
                        "Function '{}' may allow arbitrary code execution or fund sweeping. \
                        This pattern is commonly exploited in attacks.",
                        function.name
                    ),
                    line_number: idx + 1,
                    code_snippet: self.format_function_signature(function),
                    recommendation: "Review function implementation carefully. Add strict access controls and input validation.".to_string(),
                });
            }

            // SelfDestruct detection
            if function.name == "destroy" || function.name == "kill" || function.name == "selfdestruct" {
                vulnerabilities.push(Vulnerability {
                    severity: VulnerabilitySeverity::Critical,
                    category: VulnerabilityCategory::ABISelfDestruct,
                    title: format!("Self-Destruct Function: '{}'", function.name),
                    description: "Contract has self-destruct capability. If exploited, all funds are lost permanently.".to_string(),
                    line_number: idx + 1,
                    code_snippet: self.format_function_signature(function),
                    recommendation: "Remove self-destruct or implement timelock with multi-sig requirement.".to_string(),
                });
            }

            // Track contract patterns
            if function.name.contains("pause") || function.name.contains("Pause") {
                has_pause_functions = true;
            }
            if function.name.contains("owner") || function.name.contains("Owner") {
                has_ownership = true;
            }
        }

        // Missing pause functionality
        if !has_pause_functions && self.has_critical_state_changing(functions) {
            vulnerabilities.push(Vulnerability {
                severity: VulnerabilitySeverity::Medium,
                category: VulnerabilityCategory::ABIEmergencyBypass,
                title: "Missing Emergency Pause Mechanism".to_string(),
                description: "Contract has critical state-changing functions but no pause/unpause mechanism. \
                    In case of an exploit, there's no way to halt operations.".to_string(),
                line_number: 1,
                code_snippet: "No pause/unpause functions in ABI".to_string(),
                recommendation: "Implement Pausable pattern from OpenZeppelin for emergency stops.".to_string(),
            });
        }

        // Missing ownership but has admin functions
        if !has_ownership && func_names.iter().any(|f| self.is_critical_admin_function(f)) {
            vulnerabilities.push(Vulnerability {
                severity: VulnerabilitySeverity::High,
                category: VulnerabilityCategory::ABIAccessControl,
                title: "Admin Functions Without Clear Ownership".to_string(),
                description: "Contract has administrative functions but no visible ownership pattern (owner, getOwner, etc.). \
                    Access control may be inadequate.".to_string(),
                line_number: 1,
                code_snippet: "No ownership functions detected".to_string(),
                recommendation: "Implement Ownable or AccessControl pattern for proper privilege management.".to_string(),
            });
        }

        vulnerabilities
    }

    // ========================================================================
    // EVENT ANALYSIS
    // ========================================================================

    fn analyze_events(&self, events: &[ABIEvent]) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();
        let event_names: HashSet<String> = events.iter().map(|e| e.name.to_lowercase()).collect();

        // Check for missing critical events based on function patterns
        let critical_events = vec![
            ("transfer", "Transfer event for tracking token movements"),
            ("approval", "Approval event for tracking allowance changes"),
            ("ownershiptransferred", "OwnershipTransferred for admin tracking"),
        ];

        for (event, description) in critical_events {
            if !event_names.contains(event) && !event_names.contains(&format!("{}ed", event)) {
                vulnerabilities.push(Vulnerability {
                    severity: VulnerabilitySeverity::Low,
                    category: VulnerabilityCategory::ABIEventSecurity,
                    title: format!("Missing Event: {}", event),
                    description: format!("Missing {}. Events are crucial for off-chain monitoring and indexing.", description),
                    line_number: 1,
                    code_snippet: format!("Expected: event {}(...)", event),
                    recommendation: format!("Add {} event to improve transparency and enable proper tracking.", event),
                });
            }
        }

        for (idx, event) in events.iter().enumerate() {
            // Anonymous events
            if event.anonymous {
                vulnerabilities.push(Vulnerability {
                    severity: VulnerabilitySeverity::Medium,
                    category: VulnerabilityCategory::ABIEventSecurity,
                    title: format!("Anonymous Event: '{}'", event.name),
                    description: "Anonymous events don't emit the event signature topic. \
                        This makes them harder to filter and can obscure malicious activity.".to_string(),
                    line_number: idx + 1,
                    code_snippet: format!("event {} anonymous", event.name),
                    recommendation: "Remove 'anonymous' modifier unless there's a specific gas optimization need.".to_string(),
                });
            }

            // Indexed parameter analysis
            let indexed_count = event.inputs.iter()
                .filter(|p| p.indexed.unwrap_or(false))
                .count();

            if indexed_count > 3 {
                vulnerabilities.push(Vulnerability {
                    severity: VulnerabilitySeverity::Low,
                    category: VulnerabilityCategory::ABIEventSecurity,
                    title: format!("Too Many Indexed Parameters: '{}'", event.name),
                    description: format!(
                        "Event '{}' has {} indexed parameters. Maximum is 3 (4 for anonymous).",
                        event.name, indexed_count
                    ),
                    line_number: idx + 1,
                    code_snippet: format!("event {}(...)", event.name),
                    recommendation: "Reduce indexed parameters to 3 or fewer.".to_string(),
                });
            }

            // Sensitive data in events
            for param in &event.inputs {
                let sensitive_patterns = ["password", "secret", "private", "key", "seed", "mnemonic"];
                if sensitive_patterns.iter().any(|p| param.name.to_lowercase().contains(p)) {
                    vulnerabilities.push(Vulnerability {
                        severity: VulnerabilitySeverity::Critical,
                        category: VulnerabilityCategory::ABIEventSecurity,
                        title: format!("Sensitive Data in Event: '{}' - '{}'", event.name, param.name),
                        description: format!(
                            "Event parameter '{}' appears to contain sensitive data. \
                            ALL event data is publicly visible on the blockchain!",
                            param.name
                        ),
                        line_number: idx + 1,
                        code_snippet: format!("event {}(...{} {}...)", event.name, param.param_type, param.name),
                        recommendation: "NEVER emit sensitive data. Use off-chain storage or encryption for private data.".to_string(),
                    });
                }
            }

            // Missing indexed on important parameters
            for param in &event.inputs {
                if !param.indexed.unwrap_or(false) {
                    if param.param_type == "address" &&
                        (param.name.contains("from") || param.name.contains("to") ||
                         param.name.contains("sender") || param.name.contains("recipient")) {
                        vulnerabilities.push(Vulnerability {
                            severity: VulnerabilitySeverity::Info,
                            category: VulnerabilityCategory::ABIEventSecurity,
                            title: format!("Non-Indexed Address Parameter: '{}.{}'", event.name, param.name),
                            description: format!(
                                "Address parameter '{}' in event '{}' is not indexed. \
                                Indexing address parameters enables efficient filtering.",
                                param.name, event.name
                            ),
                            line_number: idx + 1,
                            code_snippet: format!("address {}", param.name),
                            recommendation: "Consider adding 'indexed' to important address parameters for better queryability.".to_string(),
                        });
                    }
                }
            }
        }

        vulnerabilities
    }

    // ========================================================================
    // CONTRACT PATTERN ANALYSIS
    // ========================================================================

    fn analyze_contract_patterns(&self, analysis: &ABIAnalysis) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        // Token standard compliance
        match analysis.contract_type {
            ContractType::ERC20 => {
                vulnerabilities.extend(self.check_erc20_compliance(&analysis.functions, &analysis.events));
            }
            ContractType::ERC721 => {
                vulnerabilities.extend(self.check_erc721_compliance(&analysis.functions, &analysis.events));
            }
            ContractType::ERC1155 => {
                vulnerabilities.extend(self.check_erc1155_compliance(&analysis.functions, &analysis.events));
            }
            ContractType::ERC4626 => {
                vulnerabilities.extend(self.check_erc4626_compliance(&analysis.functions));
            }
            _ => {}
        }

        // Proxy pattern warnings
        if analysis.contract_type == ContractType::Proxy || analysis.contract_type == ContractType::ProxyAdmin {
            vulnerabilities.push(Vulnerability {
                severity: VulnerabilitySeverity::High,
                category: VulnerabilityCategory::ABIUpgradeability,
                title: "Proxy Pattern Detected".to_string(),
                description: "Contract uses proxy pattern. Improper implementation can lead to:\n\
                    - Storage collision between proxy and implementation\n\
                    - Unauthorized upgrades\n\
                    - Initialization attacks on implementation".to_string(),
                line_number: 1,
                code_snippet: "Proxy contract ABI".to_string(),
                recommendation: "Use OpenZeppelin's TransparentUpgradeableProxy or UUPS pattern. \
                    Ensure proper access control and initialization.".to_string(),
            });
        }

        vulnerabilities
    }

    // ========================================================================
    // SELECTOR COLLISION ANALYSIS
    // ========================================================================

    fn analyze_selector_collisions(&self, functions: &[ABIFunction]) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();
        let mut selector_map: HashMap<String, Vec<&ABIFunction>> = HashMap::new();

        for func in functions {
            if let Some(ref selector) = func.selector {
                selector_map.entry(selector.clone())
                    .or_default()
                    .push(func);
            }
        }

        for (selector, funcs) in selector_map {
            if funcs.len() > 1 {
                let names: Vec<String> = funcs.iter().map(|f| f.name.clone()).collect();
                vulnerabilities.push(Vulnerability {
                    severity: VulnerabilitySeverity::Critical,
                    category: VulnerabilityCategory::ABISelectorCollision,
                    title: format!("Function Selector Collision: {}", selector),
                    description: format!(
                        "Functions {} share the same selector '{}'. \
                        This can cause undefined behavior and potential exploits.",
                        names.join(", "), selector
                    ),
                    line_number: 1,
                    code_snippet: format!("Colliding functions: {}", names.join(", ")),
                    recommendation: "Rename functions to generate unique selectors.".to_string(),
                });
            }
        }

        // Check for known collision with critical functions
        let critical_selectors = [
            ("0xa9059cbb", "transfer(address,uint256)"),
            ("0x23b872dd", "transferFrom(address,address,uint256)"),
            ("0x095ea7b3", "approve(address,uint256)"),
        ];

        for func in functions {
            if let Some(ref selector) = func.selector {
                for (critical_sel, critical_func) in &critical_selectors {
                    if selector == *critical_sel && !func.name.starts_with("transfer") && !func.name.starts_with("approve") {
                        vulnerabilities.push(Vulnerability {
                            severity: VulnerabilitySeverity::Critical,
                            category: VulnerabilityCategory::ABISelectorCollision,
                            title: format!("Selector Collision with Critical Function: {}", func.name),
                            description: format!(
                                "Function '{}' has selector {} which collides with {}. \
                                This is a common attack vector!",
                                func.name, selector, critical_func
                            ),
                            line_number: 1,
                            code_snippet: self.format_function_signature(func),
                            recommendation: "Rename function immediately to avoid collision with ERC-20 standard functions.".to_string(),
                        });
                    }
                }
            }
        }

        vulnerabilities
    }

    // ========================================================================
    // FLASH LOAN RISK ANALYSIS
    // ========================================================================

    fn analyze_flash_loan_risks(&self, functions: &[ABIFunction], patterns: &[DetectedPattern]) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        let is_flash_loan_capable = patterns.iter()
            .any(|p| p.pattern_type == PatternType::FlashLoanCapable);

        if is_flash_loan_capable {
            // Flash loan provider
            let provider_funcs: Vec<&ABIFunction> = functions.iter()
                .filter(|f| f.name == "flashLoan" || f.name == "flashLoanSimple")
                .collect();

            for func in provider_funcs {
                vulnerabilities.push(Vulnerability {
                    severity: VulnerabilitySeverity::High,
                    category: VulnerabilityCategory::ABIFlashLoanRisk,
                    title: format!("Flash Loan Provider: '{}'", func.name),
                    description: "Contract provides flash loans. Ensure:\n\
                        - Proper fee collection\n\
                        - Reentrancy protection\n\
                        - Balance validation before and after loan".to_string(),
                    line_number: 1,
                    code_snippet: self.format_function_signature(func),
                    recommendation: "Implement checks-effects-interactions pattern. Validate loan repayment atomically.".to_string(),
                });
            }

            // Flash loan receiver
            let receiver_funcs: Vec<&ABIFunction> = functions.iter()
                .filter(|f| f.name == "executeOperation" || f.name == "onFlashLoan" || f.name == "receiveFlashLoan")
                .collect();

            for func in receiver_funcs {
                vulnerabilities.push(Vulnerability {
                    severity: VulnerabilitySeverity::Critical,
                    category: VulnerabilityCategory::ABIFlashLoanRisk,
                    title: format!("Flash Loan Receiver Callback: '{}'", func.name),
                    description: format!(
                        "Function '{}' is a flash loan callback. These are high-risk targets for:\n\
                        - Callback injection attacks\n\
                        - Unauthorized loan initiators\n\
                        - Price manipulation during callback",
                        func.name
                    ),
                    line_number: 1,
                    code_snippet: self.format_function_signature(func),
                    recommendation: "1. Validate msg.sender is expected lender\n\
                        2. Validate initiator parameter\n\
                        3. Use reentrancy guards\n\
                        4. Be aware of oracle manipulation during callback".to_string(),
                });
            }
        }

        // Check for functions vulnerable to flash loan attacks
        let func_names: HashSet<String> = functions.iter().map(|f| f.name.clone()).collect();
        if func_names.contains("liquidate") || func_names.contains("liquidationCall") {
            vulnerabilities.push(Vulnerability {
                severity: VulnerabilitySeverity::High,
                category: VulnerabilityCategory::ABIFlashLoanRisk,
                title: "Liquidation Function - Flash Loan Attack Surface".to_string(),
                description: "Liquidation functions are common targets for flash loan attacks. \
                    Attackers can manipulate prices, borrow large sums, trigger liquidations, and profit.".to_string(),
                line_number: 1,
                code_snippet: "Liquidation function detected".to_string(),
                recommendation: "Implement time-weighted average prices (TWAP) and flash loan guards.".to_string(),
            });
        }

        vulnerabilities
    }

    // ========================================================================
    // ORACLE RISK ANALYSIS
    // ========================================================================

    fn analyze_oracle_risks(&self, functions: &[ABIFunction]) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        let oracle_funcs: Vec<&ABIFunction> = functions.iter()
            .filter(|f| self.signatures.oracle.contains(f.name.as_str()))
            .collect();

        if !oracle_funcs.is_empty() {
            // Oracle consumer analysis
            for func in &oracle_funcs {
                vulnerabilities.push(Vulnerability {
                    severity: VulnerabilitySeverity::High,
                    category: VulnerabilityCategory::ABIOracleManipulation,
                    title: format!("Oracle Dependency: '{}'", func.name),
                    description: format!(
                        "Contract calls oracle function '{}'. Oracle manipulation is a leading cause of DeFi hacks.\n\
                        Risks include:\n\
                        - Spot price manipulation via flash loans\n\
                        - Stale price data\n\
                        - Oracle downtime",
                        func.name
                    ),
                    line_number: 1,
                    code_snippet: self.format_function_signature(func),
                    recommendation: "1. Use TWAP (Time-Weighted Average Price)\n\
                        2. Check price freshness (latestTimestamp)\n\
                        3. Implement circuit breakers for extreme price movements\n\
                        4. Use multiple oracle sources".to_string(),
                });
            }

            // Chainlink specific checks
            if oracle_funcs.iter().any(|f| f.name == "latestRoundData") {
                vulnerabilities.push(Vulnerability {
                    severity: VulnerabilitySeverity::Medium,
                    category: VulnerabilityCategory::ABIOracleManipulation,
                    title: "Chainlink Oracle Usage Detected".to_string(),
                    description: "Contract uses Chainlink's latestRoundData(). Common issues:\n\
                        - Not checking roundId for staleness\n\
                        - Not checking answeredInRound\n\
                        - Not handling sequencer downtime (L2s)".to_string(),
                    line_number: 1,
                    code_snippet: "latestRoundData()".to_string(),
                    recommendation: "Check all return values: (roundId, answer, startedAt, updatedAt, answeredInRound). \
                        Validate updatedAt is recent and answeredInRound >= roundId.".to_string(),
                });
            }
        }

        vulnerabilities
    }

    // ========================================================================
    // DEX RISK ANALYSIS
    // ========================================================================

    fn analyze_dex_risks(&self, functions: &[ABIFunction]) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        let dex_funcs: Vec<&ABIFunction> = functions.iter()
            .filter(|f| self.signatures.dex.contains(f.name.as_str()))
            .collect();

        for func in dex_funcs {
            // Check for slippage protection
            let has_slippage_param = func.inputs.iter()
                .any(|p| p.name.contains("min") || p.name.contains("Max") || p.name.contains("slippage"));
            let has_deadline = func.inputs.iter()
                .any(|p| p.name.contains("deadline") || p.name.contains("expiry"));

            if !has_slippage_param {
                vulnerabilities.push(Vulnerability {
                    severity: VulnerabilitySeverity::High,
                    category: VulnerabilityCategory::ABIDEXInteraction,
                    title: format!("DEX Function Without Slippage Protection: '{}'", func.name),
                    description: format!(
                        "DEX function '{}' has no visible slippage parameter. \
                        Without minAmountOut protection, transactions are vulnerable to sandwich attacks.",
                        func.name
                    ),
                    line_number: 1,
                    code_snippet: self.format_function_signature(func),
                    recommendation: "Add minAmountOut parameter to protect against slippage and MEV attacks.".to_string(),
                });
            }

            if !has_deadline {
                vulnerabilities.push(Vulnerability {
                    severity: VulnerabilitySeverity::Medium,
                    category: VulnerabilityCategory::ABIDEXInteraction,
                    title: format!("DEX Function Without Deadline: '{}'", func.name),
                    description: format!(
                        "DEX function '{}' has no deadline parameter. \
                        Transactions can be held by miners and executed at unfavorable times.",
                        func.name
                    ),
                    line_number: 1,
                    code_snippet: self.format_function_signature(func),
                    recommendation: "Add deadline parameter and validate block.timestamp < deadline.".to_string(),
                });
            }
        }

        vulnerabilities
    }

    // ========================================================================
    // SIGNATURE RISK ANALYSIS
    // ========================================================================

    fn analyze_signature_risks(&self, functions: &[ABIFunction]) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();
        let func_names: HashSet<String> = functions.iter().map(|f| f.name.clone()).collect();

        // Permit function analysis
        if func_names.contains("permit") {
            let permit_func = functions.iter().find(|f| f.name == "permit");
            if let Some(func) = permit_func {
                vulnerabilities.push(Vulnerability {
                    severity: VulnerabilitySeverity::High,
                    category: VulnerabilityCategory::ABIPermitVulnerability,
                    title: "EIP-2612 Permit Function Detected".to_string(),
                    description: "Contract implements permit() for gasless approvals. Potential issues:\n\
                        - Signature replay across chains (check chainId)\n\
                        - Signature malleability\n\
                        - Front-running of permit transactions\n\
                        - Deadline bypass".to_string(),
                    line_number: 1,
                    code_snippet: self.format_function_signature(func),
                    recommendation: "1. Include chainId in domain separator\n\
                        2. Use nonces to prevent replay\n\
                        3. Validate deadline strictly\n\
                        4. Consider using ECDSA library for signature validation".to_string(),
                });

                // Check for nonces
                if !func_names.contains("nonces") {
                    vulnerabilities.push(Vulnerability {
                        severity: VulnerabilitySeverity::Critical,
                        category: VulnerabilityCategory::ABISignatureVulnerability,
                        title: "Permit Without Nonces Function".to_string(),
                        description: "Contract has permit() but no visible nonces() function. \
                            This may indicate missing replay protection!".to_string(),
                        line_number: 1,
                        code_snippet: "Missing: nonces(address) view".to_string(),
                        recommendation: "Implement nonces mapping and increment after each permit use.".to_string(),
                    });
                }
            }
        }

        // Meta-transaction signatures
        let meta_tx_funcs: Vec<&ABIFunction> = functions.iter()
            .filter(|f| f.name.contains("BySig") || f.name.contains("WithSig") || f.name.contains("Meta"))
            .collect();

        for func in meta_tx_funcs {
            let has_sig_params = func.inputs.iter()
                .any(|p| p.name == "v" || p.name == "r" || p.name == "s" || p.name == "signature");

            if has_sig_params {
                vulnerabilities.push(Vulnerability {
                    severity: VulnerabilitySeverity::High,
                    category: VulnerabilityCategory::ABISignatureVulnerability,
                    title: format!("Meta-Transaction Function: '{}'", func.name),
                    description: format!(
                        "Function '{}' accepts signatures for meta-transactions. Common vulnerabilities:\n\
                        - Missing deadline/expiry check\n\
                        - Cross-chain replay (missing chainId)\n\
                        - Signature malleability\n\
                        - Missing nonce increment",
                        func.name
                    ),
                    line_number: 1,
                    code_snippet: self.format_function_signature(func),
                    recommendation: "Use EIP-712 typed structured data. Include nonce, chainId, contract address in signed message.".to_string(),
                });
            }
        }

        // DOMAIN_SEPARATOR detection
        if func_names.contains("DOMAIN_SEPARATOR") || func_names.contains("domainSeparator") {
            vulnerabilities.push(Vulnerability {
                severity: VulnerabilitySeverity::Info,
                category: VulnerabilityCategory::ABISignatureVulnerability,
                title: "EIP-712 Domain Separator Detected".to_string(),
                description: "Contract uses EIP-712 for typed structured data signing. \
                    Ensure domain separator includes chainId for cross-chain replay protection.".to_string(),
                line_number: 1,
                code_snippet: "DOMAIN_SEPARATOR()".to_string(),
                recommendation: "Validate DOMAIN_SEPARATOR includes: name, version, chainId, verifyingContract.".to_string(),
            });
        }

        vulnerabilities
    }

    // ========================================================================
    // GOVERNANCE RISK ANALYSIS
    // ========================================================================

    fn analyze_governance_risks(&self, functions: &[ABIFunction], contract_type: &ContractType) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();
        let func_names: HashSet<String> = functions.iter().map(|f| f.name.clone()).collect();

        if *contract_type == ContractType::Governor {
            // Flash loan governance attack
            if func_names.contains("getVotes") && !func_names.contains("getPastVotes") {
                vulnerabilities.push(Vulnerability {
                    severity: VulnerabilitySeverity::Critical,
                    category: VulnerabilityCategory::ABIGovernanceRisk,
                    title: "Governor Vulnerable to Flash Loan Attack".to_string(),
                    description: "Governor uses getVotes() without getPastVotes(). \
                        Attackers can flash loan tokens, vote, and return tokens in same transaction.".to_string(),
                    line_number: 1,
                    code_snippet: "getVotes(address) but missing getPastVotes(address, uint256)".to_string(),
                    recommendation: "Use getPastVotes with a snapshot at proposal creation block.".to_string(),
                });
            }

            // Quorum manipulation
            if func_names.contains("quorum") {
                vulnerabilities.push(Vulnerability {
                    severity: VulnerabilitySeverity::Medium,
                    category: VulnerabilityCategory::ABIGovernanceRisk,
                    title: "Governance Quorum Function".to_string(),
                    description: "Review quorum calculation. If based on current supply rather than snapshot, \
                        it may be manipulable through minting/burning.".to_string(),
                    line_number: 1,
                    code_snippet: "quorum(uint256 blockNumber)".to_string(),
                    recommendation: "Use fixed quorum or snapshot-based calculation.".to_string(),
                });
            }
        }

        // Timelock analysis
        if *contract_type == ContractType::Timelock || func_names.contains("schedule") {
            if !func_names.contains("cancel") {
                vulnerabilities.push(Vulnerability {
                    severity: VulnerabilitySeverity::High,
                    category: VulnerabilityCategory::ABITimelockBypass,
                    title: "Timelock Without Cancel Function".to_string(),
                    description: "Timelock has schedule but no cancel function. \
                        Malicious scheduled transactions cannot be stopped.".to_string(),
                    line_number: 1,
                    code_snippet: "Missing: cancel(bytes32 id)".to_string(),
                    recommendation: "Add cancel function with appropriate access control.".to_string(),
                });
            }

            if func_names.contains("updateDelay") || func_names.contains("setDelay") {
                vulnerabilities.push(Vulnerability {
                    severity: VulnerabilitySeverity::High,
                    category: VulnerabilityCategory::ABITimelockBypass,
                    title: "Timelock Delay Can Be Modified".to_string(),
                    description: "Timelock delay can be changed. If not properly protected, \
                        attackers could reduce delay to bypass protection.".to_string(),
                    line_number: 1,
                    code_snippet: "updateDelay(uint256)".to_string(),
                    recommendation: "Ensure delay changes are themselves time-locked with minimum delay.".to_string(),
                });
            }
        }

        vulnerabilities
    }

    // ========================================================================
    // MEV RISK ANALYSIS
    // ========================================================================

    fn analyze_mev_risks(&self, functions: &[ABIFunction], patterns: &[DetectedPattern]) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        // Check for MEV-exposed patterns
        if patterns.iter().any(|p| p.pattern_type == PatternType::MEVExposed) {
            vulnerabilities.push(Vulnerability {
                severity: VulnerabilitySeverity::High,
                category: VulnerabilityCategory::ABIMEVExposure,
                title: "Contract Exposed to MEV Attacks".to_string(),
                description: "Contract has swap/trade functions that are targets for:\n\
                    - Sandwich attacks (frontrun + backrun)\n\
                    - Just-in-time liquidity attacks\n\
                    - Arbitrage extraction".to_string(),
                line_number: 1,
                code_snippet: "DEX interaction functions detected".to_string(),
                recommendation: "1. Use private mempool (Flashbots Protect)\n\
                    2. Implement commit-reveal schemes\n\
                    3. Add slippage protection with tight bounds\n\
                    4. Consider MEV-resistant DEX aggregators".to_string(),
            });
        }

        // Frontrunning analysis
        for func in functions {
            // Functions that reveal intent
            let frontrun_indicators = ["bid", "reveal", "claim", "purchase", "buy", "sell"];
            if frontrun_indicators.iter().any(|i| func.name.to_lowercase().contains(i)) {
                if func.state_mutability == "payable" || func.state_mutability == "nonpayable" {
                    vulnerabilities.push(Vulnerability {
                        severity: VulnerabilitySeverity::Medium,
                        category: VulnerabilityCategory::ABIFrontrunningRisk,
                        title: format!("Frontrunning Target: '{}'", func.name),
                        description: format!(
                            "Function '{}' may be vulnerable to frontrunning. \
                            Pending transactions reveal user intent to attackers.",
                            func.name
                        ),
                        line_number: 1,
                        code_snippet: self.format_function_signature(func),
                        recommendation: "Consider commit-reveal pattern or private transaction submission.".to_string(),
                    });
                }
            }
        }

        vulnerabilities
    }

    // ========================================================================
    // CALLBACK RISK ANALYSIS
    // ========================================================================

    fn analyze_callback_risks(&self, functions: &[ABIFunction]) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        let callback_funcs: Vec<&ABIFunction> = functions.iter()
            .filter(|f| self.signatures.callbacks.contains(f.name.as_str()))
            .collect();

        for func in callback_funcs {
            let severity = if func.name.contains("FlashLoan") || func.name.contains("uniswap") {
                VulnerabilitySeverity::Critical
            } else {
                VulnerabilitySeverity::High
            };

            vulnerabilities.push(Vulnerability {
                severity,
                category: VulnerabilityCategory::ABICallbackInjection,
                title: format!("Callback Function: '{}'", func.name),
                description: format!(
                    "Callback function '{}' can be invoked by external contracts. Attack vectors:\n\
                    - Reentrancy through callback\n\
                    - Callback injection (malicious caller)\n\
                    - State manipulation during callback",
                    func.name
                ),
                line_number: 1,
                code_snippet: self.format_function_signature(func),
                recommendation: "1. Validate msg.sender is expected caller\n\
                    2. Use reentrancy guards\n\
                    3. Validate callback parameters\n\
                    4. Be cautious of state changes during callback".to_string(),
            });
        }

        // Fallback/Receive functions
        let fallback = functions.iter().find(|f| f.function_type == "fallback");
        let receive = functions.iter().find(|f| f.function_type == "receive");

        if fallback.is_some() {
            vulnerabilities.push(Vulnerability {
                severity: VulnerabilitySeverity::Medium,
                category: VulnerabilityCategory::ABICallbackInjection,
                title: "Fallback Function Present".to_string(),
                description: "Contract has a fallback function. This can:\n\
                    - Receive unexpected calls\n\
                    - Be exploited for reentrancy\n\
                    - Cause confusion with intended function calls".to_string(),
                line_number: 1,
                code_snippet: "fallback() external".to_string(),
                recommendation: "Ensure fallback has minimal logic. Consider explicit function routing.".to_string(),
            });
        }

        if receive.is_some() {
            vulnerabilities.push(Vulnerability {
                severity: VulnerabilitySeverity::Info,
                category: VulnerabilityCategory::ABICallbackInjection,
                title: "Receive Function Present".to_string(),
                description: "Contract can receive plain ETH transfers via receive().".to_string(),
                line_number: 1,
                code_snippet: "receive() external payable".to_string(),
                recommendation: "Ensure receive() only handles intended ETH deposits.".to_string(),
            });
        }

        vulnerabilities
    }

    // ========================================================================
    // CROSS-CONTRACT RISK ANALYSIS
    // ========================================================================

    fn analyze_cross_contract_risks(&self, functions: &[ABIFunction]) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        // Functions that take contract addresses as parameters
        for func in functions {
            let address_params: Vec<&ABIParameter> = func.inputs.iter()
                .filter(|p| p.param_type == "address")
                .filter(|p| {
                    let name = p.name.to_lowercase();
                    name.contains("contract") || name.contains("token") ||
                    name.contains("target") || name.contains("implementation")
                })
                .collect();

            for param in address_params {
                if func.state_mutability != "view" && func.state_mutability != "pure" {
                    vulnerabilities.push(Vulnerability {
                        severity: VulnerabilitySeverity::High,
                        category: VulnerabilityCategory::ABICrossContractRisk,
                        title: format!("External Contract Reference: '{}.{}'", func.name, param.name),
                        description: format!(
                            "Function '{}' accepts contract address '{}' as parameter. \
                            If not validated, attackers can inject malicious contracts.",
                            func.name, param.name
                        ),
                        line_number: 1,
                        code_snippet: self.format_function_signature(func),
                        recommendation: "1. Validate address is not zero\n\
                            2. Whitelist allowed contracts\n\
                            3. Verify contract code if possible\n\
                            4. Consider using registry pattern".to_string(),
                    });
                }
            }

            // Functions with bytes calldata (potential arbitrary calls)
            let has_bytes_data = func.inputs.iter()
                .any(|p| p.param_type == "bytes" || p.param_type == "bytes[]");
            let is_execute = func.name.contains("execute") || func.name.contains("call")
                || func.name.contains("multicall");

            if has_bytes_data && is_execute {
                vulnerabilities.push(Vulnerability {
                    severity: VulnerabilitySeverity::Critical,
                    category: VulnerabilityCategory::ABIArbitraryCall,
                    title: format!("Arbitrary Call Function: '{}'", func.name),
                    description: format!(
                        "Function '{}' accepts bytes data for execution. \
                        This pattern enables arbitrary function calls and is extremely dangerous.",
                        func.name
                    ),
                    line_number: 1,
                    code_snippet: self.format_function_signature(func),
                    recommendation: "1. Strict access control (onlyOwner minimum)\n\
                        2. Whitelist allowed target contracts\n\
                        3. Whitelist allowed function selectors\n\
                        4. Consider timelock for dangerous operations".to_string(),
                });
            }
        }

        vulnerabilities
    }

    // ========================================================================
    // UPGRADE RISK ANALYSIS
    // ========================================================================

    fn analyze_upgrade_risks(&self, functions: &[ABIFunction], patterns: &[DetectedPattern]) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();
        let func_names: HashSet<String> = functions.iter().map(|f| f.name.clone()).collect();

        if patterns.iter().any(|p| p.pattern_type == PatternType::Upgradeable) {
            // Initialize function without initializer modifier
            if func_names.contains("initialize") {
                vulnerabilities.push(Vulnerability {
                    severity: VulnerabilitySeverity::Critical,
                    category: VulnerabilityCategory::ABIInitializerVulnerability,
                    title: "Initialize Function Detected".to_string(),
                    description: "Upgradeable contract has initialize(). Common vulnerabilities:\n\
                        - Missing initializer modifier (can be called multiple times)\n\
                        - Implementation contract not initialized (takeover risk)\n\
                        - Missing _disableInitializers in constructor".to_string(),
                    line_number: 1,
                    code_snippet: "initialize(...)".to_string(),
                    recommendation: "1. Use initializer modifier from OpenZeppelin\n\
                        2. Call _disableInitializers() in implementation constructor\n\
                        3. Initialize implementation immediately after deployment".to_string(),
                });
            }

            // reinitialize for version upgrades
            if func_names.contains("reinitialize") {
                vulnerabilities.push(Vulnerability {
                    severity: VulnerabilitySeverity::High,
                    category: VulnerabilityCategory::ABIInitializerVulnerability,
                    title: "Reinitialize Function Detected".to_string(),
                    description: "Contract has reinitialize() for upgrade migrations. \
                        Ensure proper version tracking and access control.".to_string(),
                    line_number: 1,
                    code_snippet: "reinitialize(uint8 version)".to_string(),
                    recommendation: "Use reinitializer modifier with proper version parameter.".to_string(),
                });
            }

            // Upgrade access control
            if func_names.contains("upgradeTo") || func_names.contains("upgradeToAndCall") {
                vulnerabilities.push(Vulnerability {
                    severity: VulnerabilitySeverity::Critical,
                    category: VulnerabilityCategory::ABIUpgradeability,
                    title: "Upgrade Functions Present".to_string(),
                    description: "Contract can be upgraded. If upgrade functions lack proper access control, \
                        attackers can replace implementation with malicious code.".to_string(),
                    line_number: 1,
                    code_snippet: "upgradeTo(address newImplementation)".to_string(),
                    recommendation: "1. Restrict upgrades to owner/governance\n\
                        2. Consider timelock for upgrades\n\
                        3. Implement upgrade voting for community contracts\n\
                        4. Test upgrade path thoroughly".to_string(),
                });
            }
        }

        vulnerabilities
    }

    // ========================================================================
    // BRIDGE RISK ANALYSIS
    // ========================================================================

    fn analyze_bridge_risks(&self, functions: &[ABIFunction], contract_type: &ContractType) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        if *contract_type == ContractType::Bridge {
            vulnerabilities.push(Vulnerability {
                severity: VulnerabilitySeverity::Critical,
                category: VulnerabilityCategory::ABIBridgeVulnerability,
                title: "Bridge Contract Detected".to_string(),
                description: "Bridge contracts are high-value targets. Common attack vectors:\n\
                    - Validator key compromise\n\
                    - Message replay across chains\n\
                    - Deposit/withdrawal accounting errors\n\
                    - Oracle manipulation\n\
                    - Signature verification bypass".to_string(),
                line_number: 1,
                code_snippet: "Bridge contract ABI".to_string(),
                recommendation: "1. Multi-sig for validator operations\n\
                    2. Rate limiting on withdrawals\n\
                    3. Delay for large withdrawals\n\
                    4. Proper nonce tracking\n\
                    5. Circuit breakers".to_string(),
            });

            // Check for relayer/message functions
            let func_names: HashSet<String> = functions.iter().map(|f| f.name.clone()).collect();

            if func_names.contains("relayMessage") || func_names.contains("receiveMessage") {
                vulnerabilities.push(Vulnerability {
                    severity: VulnerabilitySeverity::Critical,
                    category: VulnerabilityCategory::ABIBridgeVulnerability,
                    title: "Message Relay Function".to_string(),
                    description: "Bridge has message relay. Ensure:\n\
                        - Message source chain validation\n\
                        - Message hash uniqueness\n\
                        - Proper signature verification\n\
                        - Replay protection".to_string(),
                    line_number: 1,
                    code_snippet: "relayMessage(...)".to_string(),
                    recommendation: "Implement proper message validation with source chain ID and unique nonces.".to_string(),
                });
            }
        }

        vulnerabilities
    }

    // ========================================================================
    // PARAMETER TYPE ANALYSIS
    // ========================================================================

    fn analyze_parameter_types(&self, functions: &[ABIFunction]) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        for func in functions {
            for param in &func.inputs {
                // Array without bounds
                if param.param_type.contains("[]") && !param.param_type.contains("[") {
                    vulnerabilities.push(Vulnerability {
                        severity: VulnerabilitySeverity::Medium,
                        category: VulnerabilityCategory::ABIParameterValidation,
                        title: format!("Unbounded Array: '{}.{}'", func.name, param.name),
                        description: format!(
                            "Parameter '{}' is an unbounded dynamic array. \
                            Large arrays can cause DoS through gas exhaustion.",
                            param.name
                        ),
                        line_number: 1,
                        code_snippet: format!("{} {}", param.param_type, param.name),
                        recommendation: "Add array length validation or use pagination.".to_string(),
                    });
                }

                // Address parameters in critical functions
                if param.param_type == "address" && self.is_critical_admin_function(&func.name) {
                    vulnerabilities.push(Vulnerability {
                        severity: VulnerabilitySeverity::High,
                        category: VulnerabilityCategory::ABIParameterValidation,
                        title: format!("Critical Address Parameter: '{}.{}'", func.name, param.name),
                        description: format!(
                            "Address parameter '{}' in critical function '{}'. \
                            Missing validation can lead to fund loss or privilege escalation.",
                            param.name, func.name
                        ),
                        line_number: 1,
                        code_snippet: format!("address {}", param.name),
                        recommendation: "Validate: address != 0, address != address(this), consider whitelist.".to_string(),
                    });
                }

                // Bytes32 that might be sensitive
                if param.param_type == "bytes32" {
                    let sensitive = ["hash", "secret", "password", "key", "seed"];
                    if sensitive.iter().any(|s| param.name.to_lowercase().contains(s)) {
                        vulnerabilities.push(Vulnerability {
                            severity: VulnerabilitySeverity::High,
                            category: VulnerabilityCategory::ABIParameterValidation,
                            title: format!("Sensitive bytes32 Parameter: '{}'", param.name),
                            description: format!(
                                "Parameter '{}' appears to handle sensitive data. \
                                Remember: ALL transaction data is publicly visible!",
                                param.name
                            ),
                            line_number: 1,
                            code_snippet: format!("bytes32 {}", param.name),
                            recommendation: "Use commit-reveal pattern for secrets. Never pass raw secrets as parameters.".to_string(),
                        });
                    }
                }

                // uint256 amounts without bounds indication
                if (param.param_type == "uint256" || param.param_type == "uint")
                    && param.name.contains("amount")
                    && func.state_mutability != "view"
                    && func.state_mutability != "pure" {
                    vulnerabilities.push(Vulnerability {
                        severity: VulnerabilitySeverity::Medium,
                        category: VulnerabilityCategory::ABIParameterValidation,
                        title: format!("Amount Parameter: '{}.{}'", func.name, param.name),
                        description: format!(
                            "Amount parameter '{}' in state-changing function. \
                            Ensure proper bounds checking to prevent overflow/underflow and economic exploits.",
                            param.name
                        ),
                        line_number: 1,
                        code_snippet: format!("uint256 {}", param.name),
                        recommendation: "Validate amount > 0, amount <= balance, amount <= maxLimit.".to_string(),
                    });
                }
            }
        }

        vulnerabilities
    }

    // ========================================================================
    // TOKEN STANDARD COMPLIANCE
    // ========================================================================

    fn check_erc20_compliance(&self, functions: &[ABIFunction], events: &[ABIEvent]) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();
        let func_names: HashSet<String> = functions.iter().map(|f| f.name.clone()).collect();
        let event_names: HashSet<String> = events.iter().map(|e| e.name.clone()).collect();

        let required = [
            ("totalSupply", "view"),
            ("balanceOf", "view"),
            ("transfer", "nonpayable"),
            ("transferFrom", "nonpayable"),
            ("approve", "nonpayable"),
            ("allowance", "view"),
        ];

        for (func_name, expected_mutability) in &required {
            if !func_names.contains(*func_name) {
                vulnerabilities.push(Vulnerability {
                    severity: VulnerabilitySeverity::High,
                    category: VulnerabilityCategory::ABITokenStandard,
                    title: format!("Missing ERC-20 Function: {}", func_name),
                    description: format!("ERC-20 requires {} function. Missing functions break compatibility.", func_name),
                    line_number: 1,
                    code_snippet: format!("Expected: function {}(...) {}", func_name, expected_mutability),
                    recommendation: "Implement all required ERC-20 functions for standard compliance.".to_string(),
                });
            }
        }

        // Check events
        if !event_names.contains("Transfer") {
            vulnerabilities.push(Vulnerability {
                severity: VulnerabilitySeverity::High,
                category: VulnerabilityCategory::ABITokenStandard,
                title: "Missing Transfer Event".to_string(),
                description: "ERC-20 requires Transfer event for tracking token movements.".to_string(),
                line_number: 1,
                code_snippet: "Expected: event Transfer(address indexed from, address indexed to, uint256 value)".to_string(),
                recommendation: "Add Transfer event and emit on all transfers including mint/burn.".to_string(),
            });
        }

        if !event_names.contains("Approval") {
            vulnerabilities.push(Vulnerability {
                severity: VulnerabilitySeverity::High,
                category: VulnerabilityCategory::ABITokenStandard,
                title: "Missing Approval Event".to_string(),
                description: "ERC-20 requires Approval event for tracking allowance changes.".to_string(),
                line_number: 1,
                code_snippet: "Expected: event Approval(address indexed owner, address indexed spender, uint256 value)".to_string(),
                recommendation: "Add Approval event and emit on approve().".to_string(),
            });
        }

        // Check for approve race condition vulnerability
        if func_names.contains("approve") && !func_names.contains("increaseAllowance") {
            vulnerabilities.push(Vulnerability {
                severity: VulnerabilitySeverity::Medium,
                category: VulnerabilityCategory::ABITokenStandard,
                title: "ERC-20 Approve Race Condition".to_string(),
                description: "Contract has approve() but no increaseAllowance/decreaseAllowance. \
                    Users are vulnerable to front-running when changing allowances.".to_string(),
                line_number: 1,
                code_snippet: "approve(address spender, uint256 amount)".to_string(),
                recommendation: "Add increaseAllowance() and decreaseAllowance() functions.".to_string(),
            });
        }

        vulnerabilities
    }

    fn check_erc721_compliance(&self, functions: &[ABIFunction], events: &[ABIEvent]) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();
        let func_names: HashSet<String> = functions.iter().map(|f| f.name.clone()).collect();
        let event_names: HashSet<String> = events.iter().map(|e| e.name.clone()).collect();

        let required = [
            "balanceOf", "ownerOf", "safeTransferFrom", "transferFrom",
            "approve", "setApprovalForAll", "getApproved", "isApprovedForAll"
        ];

        for func_name in &required {
            if !func_names.contains(*func_name) {
                vulnerabilities.push(Vulnerability {
                    severity: VulnerabilitySeverity::High,
                    category: VulnerabilityCategory::ABITokenStandard,
                    title: format!("Missing ERC-721 Function: {}", func_name),
                    description: format!("ERC-721 requires {} function.", func_name),
                    line_number: 1,
                    code_snippet: format!("Missing: {}", func_name),
                    recommendation: "Implement all required ERC-721 functions.".to_string(),
                });
            }
        }

        // Check for safe transfer callback
        if func_names.contains("safeTransferFrom") && !func_names.contains("onERC721Received") {
            // This is fine for NFT contracts, but receivers need it
        }

        // Events
        let required_events = ["Transfer", "Approval", "ApprovalForAll"];
        for event_name in &required_events {
            if !event_names.contains(*event_name) {
                vulnerabilities.push(Vulnerability {
                    severity: VulnerabilitySeverity::High,
                    category: VulnerabilityCategory::ABITokenStandard,
                    title: format!("Missing ERC-721 Event: {}", event_name),
                    description: format!("ERC-721 requires {} event.", event_name),
                    line_number: 1,
                    code_snippet: format!("Missing: event {}", event_name),
                    recommendation: "Add required ERC-721 events.".to_string(),
                });
            }
        }

        vulnerabilities
    }

    fn check_erc1155_compliance(&self, functions: &[ABIFunction], events: &[ABIEvent]) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();
        let func_names: HashSet<String> = functions.iter().map(|f| f.name.clone()).collect();
        let event_names: HashSet<String> = events.iter().map(|e| e.name.clone()).collect();

        let required = [
            "balanceOf", "balanceOfBatch", "setApprovalForAll",
            "isApprovedForAll", "safeTransferFrom", "safeBatchTransferFrom"
        ];

        for func_name in &required {
            if !func_names.contains(*func_name) {
                vulnerabilities.push(Vulnerability {
                    severity: VulnerabilitySeverity::High,
                    category: VulnerabilityCategory::ABITokenStandard,
                    title: format!("Missing ERC-1155 Function: {}", func_name),
                    description: format!("ERC-1155 requires {} function.", func_name),
                    line_number: 1,
                    code_snippet: format!("Missing: {}", func_name),
                    recommendation: "Implement all required ERC-1155 functions.".to_string(),
                });
            }
        }

        let required_events = ["TransferSingle", "TransferBatch", "ApprovalForAll", "URI"];
        for event_name in &required_events {
            if !event_names.contains(*event_name) {
                vulnerabilities.push(Vulnerability {
                    severity: VulnerabilitySeverity::High,
                    category: VulnerabilityCategory::ABITokenStandard,
                    title: format!("Missing ERC-1155 Event: {}", event_name),
                    description: format!("ERC-1155 requires {} event.", event_name),
                    line_number: 1,
                    code_snippet: format!("Missing: event {}", event_name),
                    recommendation: "Add required ERC-1155 events.".to_string(),
                });
            }
        }

        vulnerabilities
    }

    fn check_erc4626_compliance(&self, functions: &[ABIFunction]) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();
        let func_names: HashSet<String> = functions.iter().map(|f| f.name.clone()).collect();

        let required = [
            "asset", "totalAssets", "convertToShares", "convertToAssets",
            "maxDeposit", "previewDeposit", "deposit",
            "maxMint", "previewMint", "mint",
            "maxWithdraw", "previewWithdraw", "withdraw",
            "maxRedeem", "previewRedeem", "redeem"
        ];

        for func_name in &required {
            if !func_names.contains(*func_name) {
                vulnerabilities.push(Vulnerability {
                    severity: VulnerabilitySeverity::High,
                    category: VulnerabilityCategory::ABITokenStandard,
                    title: format!("Missing ERC-4626 Function: {}", func_name),
                    description: format!("ERC-4626 tokenized vault requires {} function.", func_name),
                    line_number: 1,
                    code_snippet: format!("Missing: {}", func_name),
                    recommendation: "Implement all required ERC-4626 functions for vault compliance.".to_string(),
                });
            }
        }

        // ERC-4626 inflation attack warning
        vulnerabilities.push(Vulnerability {
            severity: VulnerabilitySeverity::High,
            category: VulnerabilityCategory::ABITokenStandard,
            title: "ERC-4626 Vault Inflation Attack Risk".to_string(),
            description: "ERC-4626 vaults are vulnerable to inflation attacks where first depositor can steal funds. \
                Attacker donates large amount directly to vault, inflating share price.".to_string(),
            line_number: 1,
            code_snippet: "ERC-4626 Vault Pattern".to_string(),
            recommendation: "1. Use virtual shares/assets offset\n\
                2. Initialize vault with small deposit\n\
                3. Implement minimum deposit requirement".to_string(),
        });

        vulnerabilities
    }

    // ========================================================================
    // HELPER FUNCTIONS
    // ========================================================================

    fn is_critical_admin_function(&self, name: &str) -> bool {
        self.signatures.critical_admin.iter()
            .any(|pattern| name.to_lowercase().contains(&pattern.to_lowercase()))
    }

    fn is_dangerous_function(&self, name: &str) -> bool {
        self.signatures.dangerous.iter()
            .any(|pattern| name.to_lowercase().contains(&pattern.to_lowercase()))
    }

    fn should_be_readonly(&self, name: &str) -> bool {
        let readonly_prefixes = ["get", "is", "has", "check", "view", "read", "can"];
        let readonly_exact = [
            "name", "symbol", "decimals", "totalSupply", "balanceOf",
            "allowance", "owner", "paused", "nonces", "DOMAIN_SEPARATOR"
        ];

        readonly_prefixes.iter().any(|p| name.to_lowercase().starts_with(p))
            || readonly_exact.contains(&name)
    }

    fn assess_payable_risk(&self, func: &ABIFunction) -> &str {
        let safe_payable = ["deposit", "fund", "donate", "contribute", "buyTokens", "purchase"];

        if safe_payable.iter().any(|p| func.name.to_lowercase().contains(p)) {
            "medium"
        } else if func.name == "receive" || func.name == "fallback" {
            "medium"
        } else {
            "high"
        }
    }

    fn has_critical_state_changing(&self, functions: &[ABIFunction]) -> bool {
        functions.iter().any(|f| {
            (f.state_mutability == "nonpayable" || f.state_mutability == "payable")
                && self.is_critical_admin_function(&f.name)
        })
    }

    fn format_function_signature(&self, func: &ABIFunction) -> String {
        let params = func.inputs.iter()
            .map(|p| format!("{} {}", p.param_type, p.name))
            .collect::<Vec<_>>()
            .join(", ");

        let returns = if !func.outputs.is_empty() {
            let ret_types = func.outputs.iter()
                .map(|p| p.param_type.clone())
                .collect::<Vec<_>>()
                .join(", ");
            format!(" returns ({})", ret_types)
        } else {
            String::new()
        };

        format!("function {}({}) {}{}",
            func.name, params, func.state_mutability, returns)
    }
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_erc20_abi() {
        let scanner = ABIScanner::new(false);
        let abi_json = r#"[
            {"type": "function", "name": "transfer", "inputs": [{"name": "to", "type": "address"}, {"name": "amount", "type": "uint256"}], "outputs": [{"name": "", "type": "bool"}], "stateMutability": "nonpayable"},
            {"type": "function", "name": "balanceOf", "inputs": [{"name": "account", "type": "address"}], "outputs": [{"name": "", "type": "uint256"}], "stateMutability": "view"},
            {"type": "function", "name": "approve", "inputs": [{"name": "spender", "type": "address"}, {"name": "amount", "type": "uint256"}], "outputs": [{"name": "", "type": "bool"}], "stateMutability": "nonpayable"},
            {"type": "function", "name": "allowance", "inputs": [{"name": "owner", "type": "address"}, {"name": "spender", "type": "address"}], "outputs": [{"name": "", "type": "uint256"}], "stateMutability": "view"},
            {"type": "function", "name": "totalSupply", "inputs": [], "outputs": [{"name": "", "type": "uint256"}], "stateMutability": "view"},
            {"type": "function", "name": "transferFrom", "inputs": [{"name": "from", "type": "address"}, {"name": "to", "type": "address"}, {"name": "amount", "type": "uint256"}], "outputs": [{"name": "", "type": "bool"}], "stateMutability": "nonpayable"},
            {"type": "event", "name": "Transfer", "inputs": [{"name": "from", "type": "address", "indexed": true}, {"name": "to", "type": "address", "indexed": true}, {"name": "value", "type": "uint256"}]},
            {"type": "event", "name": "Approval", "inputs": [{"name": "owner", "type": "address", "indexed": true}, {"name": "spender", "type": "address", "indexed": true}, {"name": "value", "type": "uint256"}]}
        ]"#;

        let analysis = scanner.parse_abi(abi_json).unwrap();
        assert_eq!(analysis.contract_type, ContractType::ERC20);
        assert_eq!(analysis.functions.len(), 6);
        assert_eq!(analysis.events.len(), 2);
    }

    #[test]
    fn test_detect_flash_loan() {
        let scanner = ABIScanner::new(false);
        let abi_json = r#"[
            {"type": "function", "name": "flashLoan", "inputs": [{"name": "receiver", "type": "address"}, {"name": "token", "type": "address"}, {"name": "amount", "type": "uint256"}, {"name": "data", "type": "bytes"}], "outputs": [{"name": "", "type": "bool"}], "stateMutability": "nonpayable"},
            {"type": "function", "name": "executeOperation", "inputs": [{"name": "assets", "type": "address[]"}, {"name": "amounts", "type": "uint256[]"}, {"name": "premiums", "type": "uint256[]"}, {"name": "initiator", "type": "address"}, {"name": "params", "type": "bytes"}], "outputs": [{"name": "", "type": "bool"}], "stateMutability": "nonpayable"}
        ]"#;

        let analysis = scanner.parse_abi(abi_json).unwrap();
        assert!(analysis.detected_patterns.iter().any(|p| p.pattern_type == PatternType::FlashLoanCapable));
    }

    #[test]
    fn test_detect_proxy() {
        let scanner = ABIScanner::new(false);
        let abi_json = r#"[
            {"type": "function", "name": "upgradeTo", "inputs": [{"name": "newImplementation", "type": "address"}], "outputs": [], "stateMutability": "nonpayable"},
            {"type": "function", "name": "implementation", "inputs": [], "outputs": [{"name": "", "type": "address"}], "stateMutability": "view"},
            {"type": "function", "name": "initialize", "inputs": [{"name": "owner", "type": "address"}], "outputs": [], "stateMutability": "nonpayable"}
        ]"#;

        let analysis = scanner.parse_abi(abi_json).unwrap();
        assert_eq!(analysis.contract_type, ContractType::Proxy);
        assert!(analysis.detected_patterns.iter().any(|p| p.pattern_type == PatternType::Upgradeable));
    }

    #[test]
    fn test_critical_function_detection() {
        let scanner = ABIScanner::new(false);
        assert!(scanner.is_critical_admin_function("mint"));
        assert!(scanner.is_critical_admin_function("transferOwnership"));
        assert!(scanner.is_critical_admin_function("grantRole"));
        assert!(!scanner.is_critical_admin_function("balanceOf"));
    }

    #[test]
    fn test_security_score() {
        let scanner = ABIScanner::new(false);
        let abi_json = r#"[
            {"type": "function", "name": "owner", "inputs": [], "outputs": [{"name": "", "type": "address"}], "stateMutability": "view"},
            {"type": "function", "name": "pause", "inputs": [], "outputs": [], "stateMutability": "nonpayable"},
            {"type": "function", "name": "unpause", "inputs": [], "outputs": [], "stateMutability": "nonpayable"},
            {"type": "function", "name": "renounceOwnership", "inputs": [], "outputs": [], "stateMutability": "nonpayable"}
        ]"#;

        let analysis = scanner.parse_abi(abi_json).unwrap();
        assert!(analysis.security_score.access_control >= 70);
        assert!(analysis.security_score.overall >= 50);
    }
}
