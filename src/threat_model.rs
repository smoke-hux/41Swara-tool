//! Threat Model Generator
//!
//! Automatically generates threat models based on contract type,
//! identified patterns, and attack surface analysis.

#![allow(dead_code)]

use std::collections::HashSet;
use regex::Regex;
use crate::vulnerabilities::{Vulnerability, VulnerabilitySeverity, VulnerabilityCategory};

/// Contract type classification
#[derive(Debug, Clone, PartialEq)]
pub enum ContractType {
    ERC20Token,
    ERC721NFT,
    ERC1155MultiToken,
    ERC4626Vault,
    DEXRouter,
    AMMPool,
    LendingProtocol,
    Staking,
    Governance,
    Bridge,
    Multisig,
    Proxy,
    ProxyAdmin,
    Factory,
    Oracle,
    PaymentSplitter,
    Timelock,
    Unknown,
}

/// Threat category for the model
#[derive(Debug, Clone, PartialEq)]
pub enum ThreatCategory {
    FinancialLoss,
    AssetTheft,
    Manipulation,
    Denial,
    PrivilegeEscalation,
    DataBreach,
    Replay,
    FrontRunning,
    OracleManipulation,
    GovernanceAttack,
    SupplyChainAttack,
}

/// Represents a potential threat
#[derive(Debug, Clone)]
pub struct Threat {
    pub category: ThreatCategory,
    pub name: String,
    pub description: String,
    pub attack_vectors: Vec<String>,
    pub impact: ThreatImpact,
    pub likelihood: ThreatLikelihood,
    pub mitigations: Vec<String>,
    pub affected_functions: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ThreatImpact {
    Critical,  // Complete loss of funds
    High,      // Significant financial loss
    Medium,    // Limited loss or degraded functionality
    Low,       // Minor impact
}

#[derive(Debug, Clone, PartialEq)]
pub enum ThreatLikelihood {
    VeryLikely,    // Easy to exploit, requires minimal skill
    Likely,        // Moderate difficulty
    Possible,      // Requires specific conditions
    Unlikely,      // Requires significant effort/luck
}

/// Generated threat model
#[derive(Debug)]
pub struct ThreatModel {
    pub contract_type: ContractType,
    pub secondary_types: Vec<ContractType>,
    pub attack_surface: AttackSurface,
    pub threats: Vec<Threat>,
    pub trust_boundaries: Vec<TrustBoundary>,
    pub data_flows: Vec<DataFlow>,
    pub assets: Vec<Asset>,
    pub risk_summary: RiskSummary,
}

/// Attack surface analysis
#[derive(Debug)]
pub struct AttackSurface {
    pub external_functions: usize,
    pub payable_functions: usize,
    pub admin_functions: usize,
    pub oracle_dependencies: usize,
    pub external_calls: usize,
    pub entry_points: Vec<String>,
}

/// Trust boundary in the contract
#[derive(Debug, Clone)]
pub struct TrustBoundary {
    pub name: String,
    pub description: String,
    pub crossing_functions: Vec<String>,
}

/// Data flow representation
#[derive(Debug, Clone)]
pub struct DataFlow {
    pub from: String,
    pub to: String,
    pub data_type: String,
    pub is_sensitive: bool,
}

/// Asset that needs protection
#[derive(Debug, Clone)]
pub struct Asset {
    pub name: String,
    pub asset_type: AssetType,
    pub value_estimate: String,
    pub protection_mechanisms: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum AssetType {
    NativeToken,
    ERC20Token,
    NFT,
    GovernanceRights,
    AdminPrivilege,
    UserData,
    ContractState,
}

/// Overall risk summary
#[derive(Debug)]
pub struct RiskSummary {
    pub overall_risk: RiskLevel,
    pub critical_threats: usize,
    pub high_threats: usize,
    pub medium_threats: usize,
    pub low_threats: usize,
    pub recommendations: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum RiskLevel {
    Critical,
    High,
    Medium,
    Low,
}

pub struct ThreatModelGenerator {
    verbose: bool,
}

impl ThreatModelGenerator {
    pub fn new(verbose: bool) -> Self {
        Self { verbose }
    }

    /// Generate a complete threat model for a contract
    pub fn generate(&self, content: &str) -> ThreatModel {
        let contract_type = self.classify_contract(content);
        let secondary_types = self.detect_secondary_types(content, &contract_type);
        let attack_surface = self.analyze_attack_surface(content);
        let assets = self.identify_assets(content, &contract_type);
        let trust_boundaries = self.identify_trust_boundaries(content);
        let data_flows = self.analyze_data_flows(content);
        let threats = self.generate_threats(content, &contract_type, &secondary_types, &attack_surface);

        let risk_summary = self.calculate_risk_summary(&threats);

        ThreatModel {
            contract_type,
            secondary_types,
            attack_surface,
            threats,
            trust_boundaries,
            data_flows,
            assets,
            risk_summary,
        }
    }

    /// Classify the primary contract type
    fn classify_contract(&self, content: &str) -> ContractType {
        // Check patterns in order of specificity
        if content.contains("ERC4626") || (content.contains("deposit") && content.contains("shares") && content.contains("assets")) {
            return ContractType::ERC4626Vault;
        }
        if content.contains("borrow") && content.contains("collateral") && content.contains("liquidat") {
            return ContractType::LendingProtocol;
        }
        if (content.contains("swap") && content.contains("reserve")) || content.contains("addLiquidity") {
            return ContractType::AMMPool;
        }
        if content.contains("Router") && (content.contains("swap") || content.contains("path")) {
            return ContractType::DEXRouter;
        }
        if content.contains("bridge") || content.contains("Bridge") || content.contains("crossChain") {
            return ContractType::Bridge;
        }
        if content.contains("propose") && content.contains("vote") && content.contains("execute") {
            return ContractType::Governance;
        }
        if content.contains("stake") && content.contains("reward") {
            return ContractType::Staking;
        }
        if content.contains("_IMPLEMENTATION_SLOT") || content.contains("upgradeTo") {
            return ContractType::Proxy;
        }
        if content.contains("ProxyAdmin") {
            return ContractType::ProxyAdmin;
        }
        if content.contains("ERC1155") {
            return ContractType::ERC1155MultiToken;
        }
        if content.contains("ERC721") || (content.contains("tokenURI") && content.contains("ownerOf")) {
            return ContractType::ERC721NFT;
        }
        if content.contains("ERC20") || (content.contains("balanceOf") && content.contains("transfer") && content.contains("allowance")) {
            return ContractType::ERC20Token;
        }
        if content.contains("multisig") || content.contains("Multisig") || content.contains("confirmTransaction") {
            return ContractType::Multisig;
        }
        if content.contains("oracle") || content.contains("Oracle") || content.contains("getLatestPrice") {
            return ContractType::Oracle;
        }
        if content.contains("createClone") || content.contains("create2") || content.contains("factory") {
            return ContractType::Factory;
        }
        if content.contains("timelock") || content.contains("Timelock") || content.contains("delay") && content.contains("queue") {
            return ContractType::Timelock;
        }
        if content.contains("PaymentSplitter") || content.contains("shares") && content.contains("release") {
            return ContractType::PaymentSplitter;
        }

        ContractType::Unknown
    }

    /// Detect secondary contract types (mixins)
    fn detect_secondary_types(&self, content: &str, primary: &ContractType) -> Vec<ContractType> {
        let mut types = Vec::new();

        // Check for common mixins
        if content.contains("Pausable") || content.contains("whenNotPaused") {
            // Not a type but a feature
        }

        // An AMM might also have governance
        if primary != &ContractType::Governance && content.contains("vote") && content.contains("proposal") {
            types.push(ContractType::Governance);
        }

        // A lending protocol might also be a vault
        if primary != &ContractType::ERC4626Vault && content.contains("deposit") && content.contains("withdraw") && content.contains("shares") {
            types.push(ContractType::ERC4626Vault);
        }

        // Check for proxy patterns in other contracts
        if primary != &ContractType::Proxy && (content.contains("upgradeTo") || content.contains("_IMPLEMENTATION_SLOT")) {
            types.push(ContractType::Proxy);
        }

        // Check for oracle usage
        if primary != &ContractType::Oracle && content.contains("latestRoundData") {
            types.push(ContractType::Oracle);
        }

        types
    }

    /// Analyze the attack surface
    fn analyze_attack_surface(&self, content: &str) -> AttackSurface {
        let external_pattern = Regex::new(r"function\s+\w+\s*\([^)]*\)\s*external").unwrap();
        let public_pattern = Regex::new(r"function\s+\w+\s*\([^)]*\)\s*(?:public|external)").unwrap();
        let payable_pattern = Regex::new(r"function\s+\w+\s*\([^)]*\)[^{]*payable").unwrap();
        let admin_pattern = Regex::new(r"function\s+(set|update|change|modify|withdraw|transfer|mint|burn|pause|upgrade)\w*").unwrap();

        let external_count = external_pattern.captures_iter(content).count();
        let public_count = public_pattern.captures_iter(content).count();
        let payable_count = payable_pattern.captures_iter(content).count();
        let admin_count = admin_pattern.captures_iter(content).count();

        // Count oracle dependencies
        let oracle_patterns = vec!["latestRoundData", "getPrice", "oracle", "Oracle", "Chainlink"];
        let oracle_count = oracle_patterns.iter()
            .filter(|p| content.contains(*p))
            .count();

        // Count external calls
        let external_call_pattern = Regex::new(r"\.call\{|\.delegatecall\(|\.staticcall\(").unwrap();
        let external_calls = external_call_pattern.captures_iter(content).count();

        // Extract entry point names
        let entry_points: Vec<String> = public_pattern.captures_iter(content)
            .filter_map(|_| {
                let func_name_pattern = Regex::new(r"function\s+(\w+)").unwrap();
                func_name_pattern.captures(content)
                    .and_then(|c| c.get(1))
                    .map(|m| m.as_str().to_string())
            })
            .take(20) // Limit to first 20
            .collect();

        AttackSurface {
            external_functions: external_count.max(public_count),
            payable_functions: payable_count,
            admin_functions: admin_count,
            oracle_dependencies: oracle_count,
            external_calls,
            entry_points,
        }
    }

    /// Identify assets that need protection
    fn identify_assets(&self, content: &str, contract_type: &ContractType) -> Vec<Asset> {
        let mut assets = Vec::new();

        // Check for ETH handling
        if content.contains("payable") || content.contains("msg.value") || content.contains(".transfer(") {
            assets.push(Asset {
                name: "Native Token (ETH)".to_string(),
                asset_type: AssetType::NativeToken,
                value_estimate: "Variable - depends on contract balance".to_string(),
                protection_mechanisms: self.find_protection_mechanisms(content, "ETH"),
            });
        }

        // Check for ERC20 handling
        if content.contains("IERC20") || content.contains("ERC20") || content.contains("safeTransfer") {
            assets.push(Asset {
                name: "ERC20 Tokens".to_string(),
                asset_type: AssetType::ERC20Token,
                value_estimate: "Variable - TVL dependent".to_string(),
                protection_mechanisms: self.find_protection_mechanisms(content, "ERC20"),
            });
        }

        // Check for NFT assets
        if content.contains("ERC721") || content.contains("ERC1155") {
            assets.push(Asset {
                name: "NFT Assets".to_string(),
                asset_type: AssetType::NFT,
                value_estimate: "Variable - depends on collection value".to_string(),
                protection_mechanisms: self.find_protection_mechanisms(content, "NFT"),
            });
        }

        // Check for governance rights
        if content.contains("vote") || content.contains("proposal") || content.contains("governance") {
            assets.push(Asset {
                name: "Governance Rights".to_string(),
                asset_type: AssetType::GovernanceRights,
                value_estimate: "Protocol value / voting power".to_string(),
                protection_mechanisms: self.find_protection_mechanisms(content, "governance"),
            });
        }

        // Admin privileges
        if content.contains("onlyOwner") || content.contains("onlyAdmin") || content.contains("onlyRole") {
            assets.push(Asset {
                name: "Admin Privileges".to_string(),
                asset_type: AssetType::AdminPrivilege,
                value_estimate: "Full protocol control".to_string(),
                protection_mechanisms: self.find_protection_mechanisms(content, "admin"),
            });
        }

        // Contract-type specific assets
        match contract_type {
            ContractType::ERC4626Vault => {
                assets.push(Asset {
                    name: "Vault Shares".to_string(),
                    asset_type: AssetType::ERC20Token,
                    value_estimate: "Based on underlying assets".to_string(),
                    protection_mechanisms: vec!["Share/asset conversion".to_string(), "Deposit limits".to_string()],
                });
            }
            ContractType::LendingProtocol => {
                assets.push(Asset {
                    name: "Collateral".to_string(),
                    asset_type: AssetType::ERC20Token,
                    value_estimate: "Based on collateral factor".to_string(),
                    protection_mechanisms: vec!["Health factor checks".to_string(), "Liquidation mechanism".to_string()],
                });
            }
            ContractType::AMMPool => {
                assets.push(Asset {
                    name: "Liquidity Pool Tokens".to_string(),
                    asset_type: AssetType::ERC20Token,
                    value_estimate: "Based on pool reserves".to_string(),
                    protection_mechanisms: vec!["K-value invariant".to_string(), "Slippage protection".to_string()],
                });
            }
            _ => {}
        }

        assets
    }

    /// Find protection mechanisms for an asset type
    fn find_protection_mechanisms(&self, content: &str, asset_type: &str) -> Vec<String> {
        let mut mechanisms = Vec::new();

        match asset_type {
            "ETH" => {
                if content.contains("nonReentrant") { mechanisms.push("ReentrancyGuard".to_string()); }
                if content.contains("require(msg.value") { mechanisms.push("Value validation".to_string()); }
                if content.contains("onlyOwner") { mechanisms.push("Access control".to_string()); }
            }
            "ERC20" => {
                if content.contains("SafeERC20") { mechanisms.push("SafeERC20".to_string()); }
                if content.contains("approve") && content.contains("== 0") { mechanisms.push("Approval check".to_string()); }
            }
            "NFT" => {
                if content.contains("_exists") { mechanisms.push("Existence check".to_string()); }
                if content.contains("safeTransferFrom") { mechanisms.push("Safe transfer".to_string()); }
            }
            "governance" => {
                if content.contains("Timelock") { mechanisms.push("Timelock".to_string()); }
                if content.contains("quorum") { mechanisms.push("Quorum requirement".to_string()); }
            }
            "admin" => {
                if content.contains("Ownable") { mechanisms.push("Ownable pattern".to_string()); }
                if content.contains("AccessControl") { mechanisms.push("Role-based access".to_string()); }
                if content.contains("renounceOwnership") { mechanisms.push("Ownership renouncement".to_string()); }
            }
            _ => {}
        }

        if mechanisms.is_empty() {
            mechanisms.push("None identified".to_string());
        }

        mechanisms
    }

    /// Identify trust boundaries
    fn identify_trust_boundaries(&self, content: &str) -> Vec<TrustBoundary> {
        let mut boundaries = Vec::new();

        // External to internal
        if content.contains("external") {
            boundaries.push(TrustBoundary {
                name: "External Entry Points".to_string(),
                description: "Boundary between external callers and contract logic".to_string(),
                crossing_functions: self.find_external_functions(content),
            });
        }

        // User to admin
        if content.contains("onlyOwner") || content.contains("onlyAdmin") {
            boundaries.push(TrustBoundary {
                name: "User/Admin Privilege Boundary".to_string(),
                description: "Separation between user and admin functionality".to_string(),
                crossing_functions: self.find_admin_functions(content),
            });
        }

        // Contract to external protocols
        if content.contains(".call") || content.contains("IERC20") || content.contains("oracle") {
            boundaries.push(TrustBoundary {
                name: "External Protocol Integration".to_string(),
                description: "Interaction with external contracts and oracles".to_string(),
                crossing_functions: self.find_external_call_functions(content),
            });
        }

        // Cross-chain boundary
        if content.contains("bridge") || content.contains("crossChain") || content.contains("LayerZero") {
            boundaries.push(TrustBoundary {
                name: "Cross-Chain Boundary".to_string(),
                description: "Messages and assets crossing between chains".to_string(),
                crossing_functions: vec!["send".to_string(), "receive".to_string(), "bridge".to_string()],
            });
        }

        boundaries
    }

    fn find_external_functions(&self, content: &str) -> Vec<String> {
        let pattern = Regex::new(r"function\s+(\w+)\s*\([^)]*\)\s*(?:external|public)").unwrap();
        pattern.captures_iter(content)
            .filter_map(|c| c.get(1).map(|m| m.as_str().to_string()))
            .take(10)
            .collect()
    }

    fn find_admin_functions(&self, content: &str) -> Vec<String> {
        let pattern = Regex::new(r"function\s+(\w+)\s*\([^)]*\)[^{]*(onlyOwner|onlyAdmin|onlyRole)").unwrap();
        pattern.captures_iter(content)
            .filter_map(|c| c.get(1).map(|m| m.as_str().to_string()))
            .take(10)
            .collect()
    }

    fn find_external_call_functions(&self, content: &str) -> Vec<String> {
        let mut functions = Vec::new();
        let lines: Vec<&str> = content.lines().collect();
        let func_pattern = Regex::new(r"function\s+(\w+)").unwrap();

        let mut current_function = String::new();
        for line in &lines {
            if let Some(caps) = func_pattern.captures(line) {
                current_function = caps.get(1).map(|m| m.as_str().to_string()).unwrap_or_default();
            }
            if !current_function.is_empty() &&
               (line.contains(".call") || line.contains(".transfer(") || line.contains("IERC20")) {
                if !functions.contains(&current_function) {
                    functions.push(current_function.clone());
                }
            }
        }

        functions.into_iter().take(10).collect()
    }

    /// Analyze data flows
    fn analyze_data_flows(&self, content: &str) -> Vec<DataFlow> {
        let mut flows = Vec::new();

        // User input flows
        if content.contains("msg.sender") && content.contains("balances") {
            flows.push(DataFlow {
                from: "msg.sender".to_string(),
                to: "balances mapping".to_string(),
                data_type: "uint256".to_string(),
                is_sensitive: true,
            });
        }

        // Price data flows
        if content.contains("oracle") || content.contains("getPrice") {
            flows.push(DataFlow {
                from: "Oracle".to_string(),
                to: "Price calculations".to_string(),
                data_type: "int256/uint256".to_string(),
                is_sensitive: true,
            });
        }

        // Token transfer flows
        if content.contains("transfer") {
            flows.push(DataFlow {
                from: "sender".to_string(),
                to: "recipient".to_string(),
                data_type: "ERC20 tokens".to_string(),
                is_sensitive: true,
            });
        }

        // Signature flows
        if content.contains("ecrecover") || content.contains("ECDSA") {
            flows.push(DataFlow {
                from: "Off-chain signer".to_string(),
                to: "On-chain verification".to_string(),
                data_type: "bytes signature".to_string(),
                is_sensitive: true,
            });
        }

        flows
    }

    /// Generate threats based on contract analysis
    fn generate_threats(
        &self,
        content: &str,
        contract_type: &ContractType,
        secondary_types: &[ContractType],
        attack_surface: &AttackSurface,
    ) -> Vec<Threat> {
        let mut threats = Vec::new();

        // Generic threats based on attack surface
        if attack_surface.payable_functions > 0 {
            threats.push(Threat {
                category: ThreatCategory::FinancialLoss,
                name: "ETH Drainage".to_string(),
                description: "Contract holds ETH that could be drained through vulnerabilities".to_string(),
                attack_vectors: vec![
                    "Reentrancy attack".to_string(),
                    "Logic error in withdrawal".to_string(),
                    "Access control bypass".to_string(),
                ],
                impact: ThreatImpact::Critical,
                likelihood: if content.contains("nonReentrant") { ThreatLikelihood::Unlikely } else { ThreatLikelihood::Likely },
                mitigations: vec!["ReentrancyGuard".to_string(), "CEI pattern".to_string(), "Access control".to_string()],
                affected_functions: vec!["withdraw".to_string(), "transfer".to_string()],
            });
        }

        if attack_surface.external_calls > 0 {
            threats.push(Threat {
                category: ThreatCategory::Manipulation,
                name: "External Call Manipulation".to_string(),
                description: "External calls could be manipulated or fail unexpectedly".to_string(),
                attack_vectors: vec![
                    "Reentrancy via callback".to_string(),
                    "Return value not checked".to_string(),
                    "Gas griefing".to_string(),
                ],
                impact: ThreatImpact::High,
                likelihood: ThreatLikelihood::Possible,
                mitigations: vec!["Check return values".to_string(), "Use try/catch".to_string(), "ReentrancyGuard".to_string()],
                affected_functions: attack_surface.entry_points.clone(),
            });
        }

        if attack_surface.oracle_dependencies > 0 {
            threats.push(Threat {
                category: ThreatCategory::OracleManipulation,
                name: "Oracle Price Manipulation".to_string(),
                description: "Contract depends on external price data that could be manipulated".to_string(),
                attack_vectors: vec![
                    "Flash loan price manipulation".to_string(),
                    "Stale price data".to_string(),
                    "Oracle failure".to_string(),
                ],
                impact: ThreatImpact::Critical,
                likelihood: if content.contains("TWAP") { ThreatLikelihood::Unlikely } else { ThreatLikelihood::Likely },
                mitigations: vec!["Use TWAP".to_string(), "Multiple oracles".to_string(), "Staleness check".to_string()],
                affected_functions: vec!["getPrice".to_string(), "calculate".to_string()],
            });
        }

        if attack_surface.admin_functions > 0 {
            threats.push(Threat {
                category: ThreatCategory::PrivilegeEscalation,
                name: "Admin Key Compromise".to_string(),
                description: "Compromised admin key could be used for malicious actions".to_string(),
                attack_vectors: vec![
                    "Private key theft".to_string(),
                    "Social engineering".to_string(),
                    "Insider threat".to_string(),
                ],
                impact: ThreatImpact::Critical,
                likelihood: ThreatLikelihood::Possible,
                mitigations: vec!["Multisig".to_string(), "Timelock".to_string(), "Key rotation".to_string()],
                affected_functions: self.find_admin_functions(content),
            });
        }

        // Contract-type specific threats
        threats.extend(self.generate_type_specific_threats(content, contract_type));

        for secondary in secondary_types {
            threats.extend(self.generate_type_specific_threats(content, secondary));
        }

        // Deduplicate by name
        let mut seen_names = HashSet::new();
        threats.retain(|t| seen_names.insert(t.name.clone()));

        threats
    }

    /// Generate threats specific to contract type
    fn generate_type_specific_threats(&self, content: &str, contract_type: &ContractType) -> Vec<Threat> {
        let mut threats = Vec::new();

        match contract_type {
            ContractType::ERC4626Vault => {
                threats.push(Threat {
                    category: ThreatCategory::FinancialLoss,
                    name: "First Depositor Inflation Attack".to_string(),
                    description: "Attacker can manipulate share price for subsequent depositors".to_string(),
                    attack_vectors: vec!["Donate assets before first deposit".to_string(), "Front-run first depositor".to_string()],
                    impact: ThreatImpact::Critical,
                    likelihood: if content.contains("virtual") && content.contains("shares") { ThreatLikelihood::Unlikely } else { ThreatLikelihood::Likely },
                    mitigations: vec!["Virtual shares offset".to_string(), "Minimum deposit".to_string(), "Dead shares".to_string()],
                    affected_functions: vec!["deposit".to_string(), "mint".to_string()],
                });
            }
            ContractType::AMMPool => {
                threats.push(Threat {
                    category: ThreatCategory::FrontRunning,
                    name: "Sandwich Attack".to_string(),
                    description: "Swaps can be sandwiched for MEV extraction".to_string(),
                    attack_vectors: vec!["Front-run with large swap".to_string(), "Back-run to extract value".to_string()],
                    impact: ThreatImpact::High,
                    likelihood: ThreatLikelihood::VeryLikely,
                    mitigations: vec!["Slippage protection".to_string(), "Deadline parameter".to_string(), "Private mempool".to_string()],
                    affected_functions: vec!["swap".to_string(), "addLiquidity".to_string()],
                });
            }
            ContractType::LendingProtocol => {
                threats.push(Threat {
                    category: ThreatCategory::FinancialLoss,
                    name: "Bad Debt Accumulation".to_string(),
                    description: "Protocol could accumulate bad debt from failed liquidations".to_string(),
                    attack_vectors: vec!["Price crash".to_string(), "Liquidation frontrunning".to_string(), "Oracle manipulation".to_string()],
                    impact: ThreatImpact::Critical,
                    likelihood: ThreatLikelihood::Possible,
                    mitigations: vec!["Insurance fund".to_string(), "Liquidation incentives".to_string(), "Position limits".to_string()],
                    affected_functions: vec!["liquidate".to_string(), "borrow".to_string()],
                });
            }
            ContractType::Bridge => {
                threats.push(Threat {
                    category: ThreatCategory::Replay,
                    name: "Cross-Chain Message Replay".to_string(),
                    description: "Messages could be replayed on different chains".to_string(),
                    attack_vectors: vec!["Replay on another chain".to_string(), "Replay after upgrade".to_string()],
                    impact: ThreatImpact::Critical,
                    likelihood: if content.contains("chainId") { ThreatLikelihood::Unlikely } else { ThreatLikelihood::Likely },
                    mitigations: vec!["Include chainId".to_string(), "Nonce tracking".to_string(), "Message hashing".to_string()],
                    affected_functions: vec!["sendMessage".to_string(), "receiveMessage".to_string()],
                });
            }
            ContractType::Governance => {
                threats.push(Threat {
                    category: ThreatCategory::GovernanceAttack,
                    name: "Flash Loan Governance Attack".to_string(),
                    description: "Attacker could use flash loan to gain voting power".to_string(),
                    attack_vectors: vec!["Borrow tokens via flash loan".to_string(), "Vote immediately".to_string(), "Repay in same transaction".to_string()],
                    impact: ThreatImpact::Critical,
                    likelihood: if content.contains("checkpoint") || content.contains("getPastVotes") { ThreatLikelihood::Unlikely } else { ThreatLikelihood::Likely },
                    mitigations: vec!["Voting snapshots".to_string(), "Time-weighted voting".to_string(), "Voting delay".to_string()],
                    affected_functions: vec!["propose".to_string(), "vote".to_string()],
                });
            }
            ContractType::Proxy => {
                threats.push(Threat {
                    category: ThreatCategory::PrivilegeEscalation,
                    name: "Unauthorized Upgrade".to_string(),
                    description: "Attacker could upgrade implementation to malicious contract".to_string(),
                    attack_vectors: vec!["Admin key compromise".to_string(), "Selector collision".to_string(), "Uninitialized implementation".to_string()],
                    impact: ThreatImpact::Critical,
                    likelihood: if content.contains("onlyOwner") && content.contains("upgradeTo") { ThreatLikelihood::Unlikely } else { ThreatLikelihood::Possible },
                    mitigations: vec!["Timelock for upgrades".to_string(), "Multisig admin".to_string(), "Upgrade monitoring".to_string()],
                    affected_functions: vec!["upgradeTo".to_string(), "upgradeToAndCall".to_string()],
                });
            }
            _ => {}
        }

        threats
    }

    /// Calculate overall risk summary
    fn calculate_risk_summary(&self, threats: &[Threat]) -> RiskSummary {
        let critical = threats.iter().filter(|t| t.impact == ThreatImpact::Critical && t.likelihood != ThreatLikelihood::Unlikely).count();
        let high = threats.iter().filter(|t| t.impact == ThreatImpact::High && t.likelihood != ThreatLikelihood::Unlikely).count();
        let medium = threats.iter().filter(|t| t.impact == ThreatImpact::Medium).count();
        let low = threats.iter().filter(|t| t.impact == ThreatImpact::Low).count();

        let overall = if critical > 0 {
            RiskLevel::Critical
        } else if high > 0 {
            RiskLevel::High
        } else if medium > 0 {
            RiskLevel::Medium
        } else {
            RiskLevel::Low
        };

        let mut recommendations = Vec::new();

        if critical > 0 {
            recommendations.push("URGENT: Address critical threats before deployment".to_string());
        }
        if high > 0 {
            recommendations.push("Implement additional security controls for high-impact threats".to_string());
        }

        // Add specific recommendations based on threats
        for threat in threats {
            if threat.impact == ThreatImpact::Critical && threat.likelihood == ThreatLikelihood::VeryLikely {
                recommendations.push(format!("Priority: Mitigate '{}' immediately", threat.name));
            }
        }

        recommendations.push("Conduct professional security audit before mainnet deployment".to_string());
        recommendations.push("Implement monitoring and alerting for anomalous activity".to_string());

        RiskSummary {
            overall_risk: overall,
            critical_threats: critical,
            high_threats: high,
            medium_threats: medium,
            low_threats: low,
            recommendations,
        }
    }

    /// Convert threat model to vulnerabilities for consistent reporting
    pub fn to_vulnerabilities(&self, threat_model: &ThreatModel) -> Vec<Vulnerability> {
        threat_model.threats.iter()
            .filter(|t| t.likelihood != ThreatLikelihood::Unlikely)
            .map(|t| {
                let severity = match t.impact {
                    ThreatImpact::Critical => VulnerabilitySeverity::Critical,
                    ThreatImpact::High => VulnerabilitySeverity::High,
                    ThreatImpact::Medium => VulnerabilitySeverity::Medium,
                    ThreatImpact::Low => VulnerabilitySeverity::Low,
                };

                Vulnerability::new(
                    severity,
                    VulnerabilityCategory::LogicError,
                    format!("[Threat Model] {}", t.name),
                    format!("{}\n\nAttack vectors: {}\nAffected functions: {}",
                           t.description,
                           t.attack_vectors.join(", "),
                           t.affected_functions.join(", ")),
                    1,
                    format!("Threat: {}", t.name),
                    format!("Mitigations: {}", t.mitigations.join(", ")),
                )
            })
            .collect()
    }
}
