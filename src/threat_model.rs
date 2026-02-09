//! Threat Model Generator
//!
//! Automatically generates STRIDE-based threat models for Solidity smart contracts.
//! This module performs the following analyses:
//!
//! 1. **Contract classification** - Identifies the contract type (ERC20, AMM, Lending, etc.)
//!    based on keyword/pattern heuristics to tailor threat analysis.
//! 2. **Attack surface analysis** - Counts external/payable/admin functions, oracle
//!    dependencies, and external calls to quantify exposure.
//! 3. **Asset identification** - Discovers what valuable assets (ETH, tokens, NFTs,
//!    governance rights, admin privileges) the contract manages.
//! 4. **Trust boundary mapping** - Identifies boundaries between external callers and
//!    contract internals, user vs. admin privileges, and cross-protocol integrations.
//! 5. **Data flow analysis** - Traces sensitive data paths (balances, price feeds,
//!    token transfers, signatures) through the contract.
//! 6. **Threat generation** - Produces concrete threats with attack vectors, impact/
//!    likelihood ratings, and recommended mitigations, both generic (based on attack
//!    surface) and contract-type-specific.
//! 7. **Risk summary** - Aggregates threats into an overall risk level with prioritized
//!    recommendations.
//!
//! The generated `ThreatModel` can be converted into `Vulnerability` findings via
//! `to_vulnerabilities()` for unified reporting alongside pattern-based detections.

#![allow(dead_code)]

use std::collections::HashSet;
use regex::Regex;
use crate::vulnerabilities::{Vulnerability, VulnerabilitySeverity, VulnerabilityCategory};

/// Primary classification of a smart contract based on its functionality.
///
/// Used to select contract-type-specific threat patterns. The classifier
/// checks patterns in order of specificity (e.g., ERC4626 before generic ERC20)
/// so that more specialized types take priority.
#[derive(Debug, Clone, PartialEq)]
pub enum ContractType {
    /// Standard fungible token (ERC-20)
    ERC20Token,
    /// Non-fungible token (ERC-721)
    ERC721NFT,
    /// Multi-token standard (ERC-1155)
    ERC1155MultiToken,
    /// Tokenized vault with deposit/withdraw and share accounting (ERC-4626)
    ERC4626Vault,
    /// Decentralized exchange router that routes swaps through multiple pools
    DEXRouter,
    /// Automated market maker liquidity pool (e.g., Uniswap-style)
    AMMPool,
    /// Lending/borrowing protocol with collateral and liquidation mechanics
    LendingProtocol,
    /// Staking contract that distributes rewards to depositors
    Staking,
    /// On-chain governance with proposal/vote/execute lifecycle
    Governance,
    /// Cross-chain bridge for transferring assets between networks
    Bridge,
    /// Multi-signature wallet requiring N-of-M confirmations
    Multisig,
    /// Upgradeable proxy contract (UUPS, Transparent, or Beacon pattern)
    Proxy,
    /// Administrative contract that manages proxy upgrades
    ProxyAdmin,
    /// Factory contract that deploys new contract instances (e.g., via CREATE2)
    Factory,
    /// Price oracle or data feed provider
    Oracle,
    /// Contract that splits payments among multiple recipients by shares
    PaymentSplitter,
    /// Time-delayed execution contract for governance or admin actions
    Timelock,
    /// Contract that does not match any known classification pattern
    Unknown,
}

/// Threat category following the STRIDE model adapted for smart contracts.
///
/// Each category represents a class of attack that can target a contract:
/// - Financial categories (loss, theft) cover direct value extraction.
/// - Manipulation covers logic/state corruption.
/// - Denial covers availability attacks (DoS).
/// - Privilege escalation covers unauthorized access elevation.
/// - Domain-specific categories (front-running, oracle, governance, supply chain)
///   address blockchain-specific attack patterns.
#[derive(Debug, Clone, PartialEq)]
pub enum ThreatCategory {
    /// Direct loss of funds through logic errors or exploits
    FinancialLoss,
    /// Unauthorized transfer/extraction of assets
    AssetTheft,
    /// Corruption of contract state or computation results
    Manipulation,
    /// Denial-of-service preventing normal contract operation
    Denial,
    /// Gaining unauthorized admin or elevated privileges
    PrivilegeEscalation,
    /// Leaking sensitive on-chain or off-chain data
    DataBreach,
    /// Replaying transactions or messages (especially cross-chain)
    Replay,
    /// MEV-based attacks: sandwich, front-running, back-running
    FrontRunning,
    /// Manipulating price feeds or oracle data to exploit dependent logic
    OracleManipulation,
    /// Exploiting governance mechanisms (flash loan voting, proposal hijacking)
    GovernanceAttack,
    /// Compromising dependencies, libraries, or upstream contracts
    SupplyChainAttack,
}

/// Represents a single identified threat with its full analysis.
///
/// Each threat includes the attack category, concrete attack vectors,
/// a risk assessment (impact x likelihood), suggested mitigations,
/// and the specific contract functions that are affected.
#[derive(Debug, Clone)]
pub struct Threat {
    /// The broad threat category this falls under
    pub category: ThreatCategory,
    /// Short human-readable name for the threat (e.g., "Sandwich Attack")
    pub name: String,
    /// Detailed description of the threat scenario
    pub description: String,
    /// Concrete attack vectors an adversary could use to exploit this threat
    pub attack_vectors: Vec<String>,
    /// Worst-case impact if the threat is realized
    pub impact: ThreatImpact,
    /// Estimated likelihood of exploitation, adjusted by detected mitigations
    pub likelihood: ThreatLikelihood,
    /// Recommended countermeasures to reduce risk
    pub mitigations: Vec<String>,
    /// Names of contract functions that are vulnerable to this threat
    pub affected_functions: Vec<String>,
}

/// Severity of damage if a threat is successfully exploited.
#[derive(Debug, Clone, PartialEq)]
pub enum ThreatImpact {
    Critical,  // Complete loss of funds
    High,      // Significant financial loss
    Medium,    // Limited loss or degraded functionality
    Low,       // Minor impact
}

/// Estimated probability of a threat being exploited.
///
/// Likelihood is adjusted downward when known mitigations (e.g., ReentrancyGuard,
/// TWAP oracles, voting snapshots) are detected in the contract source.
#[derive(Debug, Clone, PartialEq)]
pub enum ThreatLikelihood {
    VeryLikely,    // Easy to exploit, requires minimal skill
    Likely,        // Moderate difficulty
    Possible,      // Requires specific conditions
    Unlikely,      // Requires significant effort/luck
}

/// The complete threat model output for a single contract.
///
/// Aggregates all analysis results: contract classification, attack surface metrics,
/// identified assets, trust boundaries, data flows, threats, and an overall risk summary.
/// This is the primary output of `ThreatModelGenerator::generate()`.
#[derive(Debug)]
pub struct ThreatModel {
    /// The primary detected contract type (most specific match)
    pub contract_type: ContractType,
    /// Additional contract type patterns detected as secondary roles (mixins)
    pub secondary_types: Vec<ContractType>,
    /// Quantified attack surface: counts of exposed functions, calls, and dependencies
    pub attack_surface: AttackSurface,
    /// All identified threats with risk assessments and mitigations
    pub threats: Vec<Threat>,
    /// Trust boundaries where privilege levels or trust assumptions change
    pub trust_boundaries: Vec<TrustBoundary>,
    /// Sensitive data flows through the contract
    pub data_flows: Vec<DataFlow>,
    /// Valuable assets managed by the contract that need protection
    pub assets: Vec<Asset>,
    /// Aggregated risk summary with overall risk level and recommendations
    pub risk_summary: RiskSummary,
}

/// Quantified attack surface metrics for a contract.
///
/// These counts help assess the contract's overall exposure to external interaction.
/// Higher counts in any category generally indicate a larger attack surface.
#[derive(Debug)]
pub struct AttackSurface {
    /// Number of external/public functions callable by anyone
    pub external_functions: usize,
    /// Number of functions that accept ETH (payable modifier)
    pub payable_functions: usize,
    /// Number of privileged/admin functions (set*, update*, mint, burn, pause, etc.)
    pub admin_functions: usize,
    /// Number of oracle-related keywords found (latestRoundData, getPrice, etc.)
    pub oracle_dependencies: usize,
    /// Number of low-level external calls (.call, .delegatecall, .staticcall)
    pub external_calls: usize,
    /// Names of public/external functions that serve as entry points
    pub entry_points: Vec<String>,
}

/// A trust boundary where privilege or trust assumptions change.
///
/// Trust boundaries are critical security points -- vulnerabilities often occur
/// at boundary crossings where input validation or access control may be insufficient.
#[derive(Debug, Clone)]
pub struct TrustBoundary {
    /// Short label for this boundary (e.g., "User/Admin Privilege Boundary")
    pub name: String,
    /// Explanation of what this boundary separates
    pub description: String,
    /// Functions that cross this boundary (entry/exit points)
    pub crossing_functions: Vec<String>,
}

/// Represents a data flow path through the contract.
///
/// Tracks how sensitive data moves between components. Sensitive flows
/// (e.g., balance updates, price data, signatures) are flagged for
/// closer scrutiny in the threat model.
#[derive(Debug, Clone)]
pub struct DataFlow {
    /// Source of the data (e.g., "msg.sender", "Oracle", "Off-chain signer")
    pub from: String,
    /// Destination of the data (e.g., "balances mapping", "Price calculations")
    pub to: String,
    /// The Solidity type or semantic type of the data being transferred
    pub data_type: String,
    /// Whether this flow carries sensitive data that could be exploited
    pub is_sensitive: bool,
}

/// An asset managed by the contract that has value and needs protection.
///
/// Assets are the "crown jewels" -- what attackers ultimately want to steal,
/// manipulate, or destroy. Each asset lists the protection mechanisms
/// currently detected in the contract source.
#[derive(Debug, Clone)]
pub struct Asset {
    /// Human-readable name (e.g., "Native Token (ETH)", "Vault Shares")
    pub name: String,
    /// Classification of the asset type
    pub asset_type: AssetType,
    /// Rough estimate of value or how value is determined
    pub value_estimate: String,
    /// Security mechanisms currently protecting this asset
    pub protection_mechanisms: Vec<String>,
}

/// Classification of asset types managed by smart contracts.
#[derive(Debug, Clone, PartialEq)]
pub enum AssetType {
    /// Native chain token (ETH, MATIC, etc.)
    NativeToken,
    /// ERC-20 fungible tokens
    ERC20Token,
    /// Non-fungible tokens (ERC-721 or ERC-1155)
    NFT,
    /// Voting power and proposal rights in governance systems
    GovernanceRights,
    /// Owner/admin privileges that control contract behavior
    AdminPrivilege,
    /// Sensitive user data stored on-chain
    UserData,
    /// Critical contract state variables (e.g., prices, balances, configs)
    ContractState,
}

/// Aggregated risk summary computed from all identified threats.
///
/// Provides a high-level view of the contract's security posture: overall risk
/// level, threat counts by severity, and prioritized recommendations. The overall
/// risk is determined by the highest-severity non-unlikely threat.
#[derive(Debug)]
pub struct RiskSummary {
    /// Overall risk level (driven by the worst critical/high threat)
    pub overall_risk: RiskLevel,
    /// Count of critical-impact threats with non-unlikely likelihood
    pub critical_threats: usize,
    /// Count of high-impact threats with non-unlikely likelihood
    pub high_threats: usize,
    /// Count of medium-impact threats
    pub medium_threats: usize,
    /// Count of low-impact threats
    pub low_threats: usize,
    /// Prioritized security recommendations based on identified threats
    pub recommendations: Vec<String>,
}

/// Overall risk level for the contract, derived from threat analysis.
#[derive(Debug, Clone, PartialEq)]
pub enum RiskLevel {
    /// At least one critical-impact threat is exploitable
    Critical,
    /// At least one high-impact threat is exploitable
    High,
    /// Only medium-impact threats exist
    Medium,
    /// All threats are low-impact or unlikely
    Low,
}

/// The main threat model generator that orchestrates all analysis phases.
///
/// Instantiated with a verbosity flag and used to generate a `ThreatModel`
/// from raw Solidity source code. The generator runs all analysis phases
/// in sequence: classification, attack surface, assets, trust boundaries,
/// data flows, threats, and risk summary.
pub struct ThreatModelGenerator {
    /// Whether to produce verbose/debug output during analysis
    verbose: bool,
}

impl ThreatModelGenerator {
    /// Create a new threat model generator.
    ///
    /// # Arguments
    /// * `verbose` - If true, enables verbose output during analysis
    pub fn new(verbose: bool) -> Self {
        Self { verbose }
    }

    /// Generate a complete threat model for a Solidity contract.
    ///
    /// This is the main entry point. It runs all analysis phases in order:
    /// 1. Classify the contract type (ERC20, AMM, Lending, etc.)
    /// 2. Detect secondary types (e.g., an AMM with governance features)
    /// 3. Analyze the attack surface (external functions, payable, admin, etc.)
    /// 4. Identify valuable assets and their existing protections
    /// 5. Map trust boundaries (external/internal, user/admin, cross-protocol)
    /// 6. Trace data flows (balances, prices, tokens, signatures)
    /// 7. Generate threats (generic + type-specific) and deduplicate
    /// 8. Compute the overall risk summary with recommendations
    ///
    /// # Arguments
    /// * `content` - The raw Solidity source code to analyze
    ///
    /// # Returns
    /// A `ThreatModel` containing the full analysis results
    pub fn generate(&self, content: &str) -> ThreatModel {
        // Phase 1: Determine what kind of contract this is
        let contract_type = self.classify_contract(content);
        // Phase 2: Check for additional contract roles (e.g., governance in an AMM)
        let secondary_types = self.detect_secondary_types(content, &contract_type);
        // Phase 3: Quantify the attack surface
        let attack_surface = self.analyze_attack_surface(content);
        // Phase 4: Find valuable assets and their protections
        let assets = self.identify_assets(content, &contract_type);
        // Phase 5: Map trust boundaries
        let trust_boundaries = self.identify_trust_boundaries(content);
        // Phase 6: Trace sensitive data flows
        let data_flows = self.analyze_data_flows(content);
        // Phase 7: Generate threats using both generic and type-specific rules
        let threats = self.generate_threats(content, &contract_type, &secondary_types, &attack_surface);

        // Phase 8: Aggregate threats into a risk summary
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

    /// Classify the primary contract type based on keyword heuristics.
    ///
    /// Checks patterns in decreasing order of specificity so that more specialized
    /// types (e.g., ERC4626Vault) are matched before generic ones (e.g., ERC20Token).
    /// Returns `ContractType::Unknown` if no patterns match.
    fn classify_contract(&self, content: &str) -> ContractType {
        // Check patterns in order of specificity -- most specific first to avoid
        // a generic match shadowing a more precise one.

        // ERC4626 vault: explicit interface name or deposit/shares/assets triad
        if content.contains("ERC4626") || (content.contains("deposit") && content.contains("shares") && content.contains("assets")) {
            return ContractType::ERC4626Vault;
        }
        // Lending: requires borrow + collateral + liquidation keywords together
        if content.contains("borrow") && content.contains("collateral") && content.contains("liquidat") {
            return ContractType::LendingProtocol;
        }
        // AMM pool: swap+reserve combo or addLiquidity function
        if (content.contains("swap") && content.contains("reserve")) || content.contains("addLiquidity") {
            return ContractType::AMMPool;
        }
        // DEX router: "Router" name with swap or path routing
        if content.contains("Router") && (content.contains("swap") || content.contains("path")) {
            return ContractType::DEXRouter;
        }
        // Bridge: explicit bridge/crossChain keywords
        if content.contains("bridge") || content.contains("Bridge") || content.contains("crossChain") {
            return ContractType::Bridge;
        }
        // Governance: requires the propose/vote/execute lifecycle
        if content.contains("propose") && content.contains("vote") && content.contains("execute") {
            return ContractType::Governance;
        }
        // Staking: stake + reward combination
        if content.contains("stake") && content.contains("reward") {
            return ContractType::Staking;
        }
        // Proxy: implementation slot or upgrade function
        if content.contains("_IMPLEMENTATION_SLOT") || content.contains("upgradeTo") {
            return ContractType::Proxy;
        }
        // ProxyAdmin: explicit contract name
        if content.contains("ProxyAdmin") {
            return ContractType::ProxyAdmin;
        }
        // ERC1155: explicit interface name
        if content.contains("ERC1155") {
            return ContractType::ERC1155MultiToken;
        }
        // ERC721: explicit interface or tokenURI+ownerOf combo
        if content.contains("ERC721") || (content.contains("tokenURI") && content.contains("ownerOf")) {
            return ContractType::ERC721NFT;
        }
        // ERC20: explicit interface or balanceOf+transfer+allowance triad
        if content.contains("ERC20") || (content.contains("balanceOf") && content.contains("transfer") && content.contains("allowance")) {
            return ContractType::ERC20Token;
        }
        // Multisig: explicit naming or confirmTransaction pattern
        if content.contains("multisig") || content.contains("Multisig") || content.contains("confirmTransaction") {
            return ContractType::Multisig;
        }
        // Oracle: explicit naming or getLatestPrice function
        if content.contains("oracle") || content.contains("Oracle") || content.contains("getLatestPrice") {
            return ContractType::Oracle;
        }
        // Factory: clone/create2 deployment or factory naming
        if content.contains("createClone") || content.contains("create2") || content.contains("factory") {
            return ContractType::Factory;
        }
        // Timelock: explicit naming or delay+queue combo
        if content.contains("timelock") || content.contains("Timelock") || content.contains("delay") && content.contains("queue") {
            return ContractType::Timelock;
        }
        // PaymentSplitter: explicit naming or shares+release combo
        if content.contains("PaymentSplitter") || content.contains("shares") && content.contains("release") {
            return ContractType::PaymentSplitter;
        }

        ContractType::Unknown
    }

    /// Detect secondary contract types that co-exist with the primary type.
    ///
    /// Many contracts combine multiple roles (e.g., a lending protocol that also
    /// acts as a vault, or an AMM with governance features). This method identifies
    /// these secondary "mixin" types, skipping any that match the primary type
    /// to avoid duplication.
    fn detect_secondary_types(&self, content: &str, primary: &ContractType) -> Vec<ContractType> {
        let mut types = Vec::new();

        // Note: Pausable is a feature/modifier, not a contract type, so it's skipped
        if content.contains("Pausable") || content.contains("whenNotPaused") {
            // Not a type but a feature
        }

        // Check if a non-governance contract also has governance features
        if primary != &ContractType::Governance && content.contains("vote") && content.contains("proposal") {
            types.push(ContractType::Governance);
        }

        // Check if a non-vault contract also implements vault-like deposit/withdraw/shares
        if primary != &ContractType::ERC4626Vault && content.contains("deposit") && content.contains("withdraw") && content.contains("shares") {
            types.push(ContractType::ERC4626Vault);
        }

        // Check if a non-proxy contract contains upgrade patterns
        if primary != &ContractType::Proxy && (content.contains("upgradeTo") || content.contains("_IMPLEMENTATION_SLOT")) {
            types.push(ContractType::Proxy);
        }

        // Check if a non-oracle contract depends on oracle feeds
        if primary != &ContractType::Oracle && content.contains("latestRoundData") {
            types.push(ContractType::Oracle);
        }

        types
    }

    /// Analyze the attack surface by counting exposed functions and dependencies.
    ///
    /// Counts external/public functions, payable functions, admin-like functions
    /// (by prefix heuristic), oracle dependencies, and low-level external calls.
    /// Also extracts the names of public entry point functions (up to 20).
    fn analyze_attack_surface(&self, content: &str) -> AttackSurface {
        // Match functions with the `external` visibility modifier
        let external_pattern = Regex::new(r"function\s+\w+\s*\([^)]*\)\s*external").unwrap();
        // Match functions with `public` or `external` visibility
        let public_pattern = Regex::new(r"function\s+\w+\s*\([^)]*\)\s*(?:public|external)").unwrap();
        // Match functions with the `payable` modifier (accepts ETH)
        let payable_pattern = Regex::new(r"function\s+\w+\s*\([^)]*\)[^{]*payable").unwrap();
        // Match admin-like functions by common naming prefixes
        let admin_pattern = Regex::new(r"function\s+(set|update|change|modify|withdraw|transfer|mint|burn|pause|upgrade)\w*").unwrap();

        let external_count = external_pattern.captures_iter(content).count();
        let public_count = public_pattern.captures_iter(content).count();
        let payable_count = payable_pattern.captures_iter(content).count();
        let admin_count = admin_pattern.captures_iter(content).count();

        // Count oracle dependencies by checking for common oracle-related keywords
        let oracle_patterns = vec!["latestRoundData", "getPrice", "oracle", "Oracle", "Chainlink"];
        let oracle_count = oracle_patterns.iter()
            .filter(|p| content.contains(*p))
            .count();

        // Count low-level external calls that bypass Solidity's safety checks
        let external_call_pattern = Regex::new(r"\.call\{|\.delegatecall\(|\.staticcall\(").unwrap();
        let external_calls = external_call_pattern.captures_iter(content).count();

        // Extract function names that serve as public entry points.
        // Note: This currently re-captures from the start of content for each match,
        // so it may return the same name repeatedly. Limited to 20 entries.
        let entry_points: Vec<String> = public_pattern.captures_iter(content)
            .filter_map(|_| {
                let func_name_pattern = Regex::new(r"function\s+(\w+)").unwrap();
                func_name_pattern.captures(content)
                    .and_then(|c| c.get(1))
                    .map(|m| m.as_str().to_string())
            })
            .take(20)
            .collect();

        AttackSurface {
            // Use the higher of external-only and public+external counts
            external_functions: external_count.max(public_count),
            payable_functions: payable_count,
            admin_functions: admin_count,
            oracle_dependencies: oracle_count,
            external_calls,
            entry_points,
        }
    }

    /// Identify valuable assets the contract manages and their existing protections.
    ///
    /// Scans for patterns indicating ETH handling, ERC20 tokens, NFTs, governance
    /// rights, and admin privileges. Also adds contract-type-specific assets
    /// (e.g., vault shares for ERC4626, collateral for lending protocols,
    /// LP tokens for AMM pools).
    fn identify_assets(&self, content: &str, contract_type: &ContractType) -> Vec<Asset> {
        let mut assets = Vec::new();

        // Detect native ETH handling via payable/msg.value/transfer patterns
        if content.contains("payable") || content.contains("msg.value") || content.contains(".transfer(") {
            assets.push(Asset {
                name: "Native Token (ETH)".to_string(),
                asset_type: AssetType::NativeToken,
                value_estimate: "Variable - depends on contract balance".to_string(),
                protection_mechanisms: self.find_protection_mechanisms(content, "ETH"),
            });
        }

        // Detect ERC20 token handling via interface references or SafeERC20 usage
        if content.contains("IERC20") || content.contains("ERC20") || content.contains("safeTransfer") {
            assets.push(Asset {
                name: "ERC20 Tokens".to_string(),
                asset_type: AssetType::ERC20Token,
                value_estimate: "Variable - TVL dependent".to_string(),
                protection_mechanisms: self.find_protection_mechanisms(content, "ERC20"),
            });
        }

        // Detect NFT assets via ERC721 or ERC1155 references
        if content.contains("ERC721") || content.contains("ERC1155") {
            assets.push(Asset {
                name: "NFT Assets".to_string(),
                asset_type: AssetType::NFT,
                value_estimate: "Variable - depends on collection value".to_string(),
                protection_mechanisms: self.find_protection_mechanisms(content, "NFT"),
            });
        }

        // Detect governance rights via voting/proposal keywords
        if content.contains("vote") || content.contains("proposal") || content.contains("governance") {
            assets.push(Asset {
                name: "Governance Rights".to_string(),
                asset_type: AssetType::GovernanceRights,
                value_estimate: "Protocol value / voting power".to_string(),
                protection_mechanisms: self.find_protection_mechanisms(content, "governance"),
            });
        }

        // Detect admin/owner privileges via access control modifiers
        if content.contains("onlyOwner") || content.contains("onlyAdmin") || content.contains("onlyRole") {
            assets.push(Asset {
                name: "Admin Privileges".to_string(),
                asset_type: AssetType::AdminPrivilege,
                value_estimate: "Full protocol control".to_string(),
                protection_mechanisms: self.find_protection_mechanisms(content, "admin"),
            });
        }

        // Add contract-type-specific assets that may not be caught by generic checks
        match contract_type {
            ContractType::ERC4626Vault => {
                // Vault shares represent claims on the underlying asset pool
                assets.push(Asset {
                    name: "Vault Shares".to_string(),
                    asset_type: AssetType::ERC20Token,
                    value_estimate: "Based on underlying assets".to_string(),
                    protection_mechanisms: vec!["Share/asset conversion".to_string(), "Deposit limits".to_string()],
                });
            }
            ContractType::LendingProtocol => {
                // Collateral is the key asset at risk during liquidation events
                assets.push(Asset {
                    name: "Collateral".to_string(),
                    asset_type: AssetType::ERC20Token,
                    value_estimate: "Based on collateral factor".to_string(),
                    protection_mechanisms: vec!["Health factor checks".to_string(), "Liquidation mechanism".to_string()],
                });
            }
            ContractType::AMMPool => {
                // LP tokens represent claims on the pool's reserve assets
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

    /// Find existing protection mechanisms for a given asset type.
    ///
    /// Checks the contract source for known security patterns (e.g., ReentrancyGuard
    /// for ETH, SafeERC20 for tokens, Timelock for governance). Returns
    /// `["None identified"]` if no protections are found.
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

        // Default to "None identified" if no mechanisms were found
        if mechanisms.is_empty() {
            mechanisms.push("None identified".to_string());
        }

        mechanisms
    }

    /// Identify trust boundaries in the contract.
    ///
    /// Trust boundaries are points where the level of trust changes -- for example,
    /// between untrusted external callers and the contract's internal logic, or
    /// between regular users and admin-privileged functions. Vulnerabilities
    /// commonly occur at these boundary crossings.
    fn identify_trust_boundaries(&self, content: &str) -> Vec<TrustBoundary> {
        let mut boundaries = Vec::new();

        // Boundary: external callers -> contract internal logic
        if content.contains("external") {
            boundaries.push(TrustBoundary {
                name: "External Entry Points".to_string(),
                description: "Boundary between external callers and contract logic".to_string(),
                crossing_functions: self.find_external_functions(content),
            });
        }

        // Boundary: regular users -> admin-privileged operations
        if content.contains("onlyOwner") || content.contains("onlyAdmin") {
            boundaries.push(TrustBoundary {
                name: "User/Admin Privilege Boundary".to_string(),
                description: "Separation between user and admin functionality".to_string(),
                crossing_functions: self.find_admin_functions(content),
            });
        }

        // Boundary: this contract -> external protocols/contracts
        if content.contains(".call") || content.contains("IERC20") || content.contains("oracle") {
            boundaries.push(TrustBoundary {
                name: "External Protocol Integration".to_string(),
                description: "Interaction with external contracts and oracles".to_string(),
                crossing_functions: self.find_external_call_functions(content),
            });
        }

        // Boundary: this chain -> other chains (cross-chain messaging)
        if content.contains("bridge") || content.contains("crossChain") || content.contains("LayerZero") {
            boundaries.push(TrustBoundary {
                name: "Cross-Chain Boundary".to_string(),
                description: "Messages and assets crossing between chains".to_string(),
                crossing_functions: vec!["send".to_string(), "receive".to_string(), "bridge".to_string()],
            });
        }

        boundaries
    }

    /// Extract names of external/public functions from the contract source.
    /// Returns up to 10 function names.
    fn find_external_functions(&self, content: &str) -> Vec<String> {
        let pattern = Regex::new(r"function\s+(\w+)\s*\([^)]*\)\s*(?:external|public)").unwrap();
        pattern.captures_iter(content)
            .filter_map(|c| c.get(1).map(|m| m.as_str().to_string()))
            .take(10)
            .collect()
    }

    /// Extract names of admin-restricted functions (those guarded by onlyOwner/onlyAdmin/onlyRole).
    /// Returns up to 10 function names.
    fn find_admin_functions(&self, content: &str) -> Vec<String> {
        let pattern = Regex::new(r"function\s+(\w+)\s*\([^)]*\)[^{]*(onlyOwner|onlyAdmin|onlyRole)").unwrap();
        pattern.captures_iter(content)
            .filter_map(|c| c.get(1).map(|m| m.as_str().to_string()))
            .take(10)
            .collect()
    }

    /// Extract names of functions that make external calls (.call, .transfer, IERC20).
    ///
    /// Walks through the source line-by-line, tracking the current function scope.
    /// When an external call pattern is found on a line, the enclosing function
    /// name is recorded. Returns up to 10 unique function names.
    fn find_external_call_functions(&self, content: &str) -> Vec<String> {
        let mut functions = Vec::new();
        let lines: Vec<&str> = content.lines().collect();
        let func_pattern = Regex::new(r"function\s+(\w+)").unwrap();

        // Track which function we are currently inside
        let mut current_function = String::new();
        for line in &lines {
            // Update the current function when we encounter a new function declaration
            if let Some(caps) = func_pattern.captures(line) {
                current_function = caps.get(1).map(|m| m.as_str().to_string()).unwrap_or_default();
            }
            // If this line contains an external call, attribute it to the current function
            if !current_function.is_empty() &&
               (line.contains(".call") || line.contains(".transfer(") || line.contains("IERC20")) {
                if !functions.contains(&current_function) {
                    functions.push(current_function.clone());
                }
            }
        }

        functions.into_iter().take(10).collect()
    }

    /// Analyze data flows to identify sensitive data paths through the contract.
    ///
    /// Detects four categories of sensitive data flow:
    /// - User balance updates (msg.sender -> balances mapping)
    /// - Oracle price data (Oracle -> price calculations)
    /// - Token transfers (sender -> recipient)
    /// - Cryptographic signatures (off-chain signer -> on-chain verification)
    fn analyze_data_flows(&self, content: &str) -> Vec<DataFlow> {
        let mut flows = Vec::new();

        // User input -> balance state: msg.sender interacting with balance mappings
        if content.contains("msg.sender") && content.contains("balances") {
            flows.push(DataFlow {
                from: "msg.sender".to_string(),
                to: "balances mapping".to_string(),
                data_type: "uint256".to_string(),
                is_sensitive: true,
            });
        }

        // External oracle -> internal price calculations
        if content.contains("oracle") || content.contains("getPrice") {
            flows.push(DataFlow {
                from: "Oracle".to_string(),
                to: "Price calculations".to_string(),
                data_type: "int256/uint256".to_string(),
                is_sensitive: true,
            });
        }

        // Token transfers between parties
        if content.contains("transfer") {
            flows.push(DataFlow {
                from: "sender".to_string(),
                to: "recipient".to_string(),
                data_type: "ERC20 tokens".to_string(),
                is_sensitive: true,
            });
        }

        // Off-chain signature -> on-chain verification (ecrecover/ECDSA)
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

    /// Generate threats based on the contract's attack surface and type.
    ///
    /// Produces two categories of threats:
    /// 1. **Generic threats** -- derived from attack surface metrics (payable functions,
    ///    external calls, oracle dependencies, admin functions). These apply to any
    ///    contract with the corresponding attack surface features.
    /// 2. **Type-specific threats** -- tailored to the primary and secondary contract
    ///    types (e.g., first-depositor attack for vaults, sandwich attacks for AMMs).
    ///
    /// Likelihood is adjusted downward when known mitigations are detected in the
    /// source (e.g., `nonReentrant` reduces reentrancy likelihood to `Unlikely`).
    ///
    /// Threats are deduplicated by name before returning to avoid redundant entries
    /// when primary and secondary types share similar threat patterns.
    fn generate_threats(
        &self,
        content: &str,
        contract_type: &ContractType,
        secondary_types: &[ContractType],
        attack_surface: &AttackSurface,
    ) -> Vec<Threat> {
        let mut threats = Vec::new();

        // --- Generic threats based on attack surface ---

        // Payable functions mean the contract holds ETH, which could be drained
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
                // ReentrancyGuard significantly reduces reentrancy likelihood
                likelihood: if content.contains("nonReentrant") { ThreatLikelihood::Unlikely } else { ThreatLikelihood::Likely },
                mitigations: vec!["ReentrancyGuard".to_string(), "CEI pattern".to_string(), "Access control".to_string()],
                affected_functions: vec!["withdraw".to_string(), "transfer".to_string()],
            });
        }

        // External calls introduce manipulation and callback risks
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

        // Oracle dependencies introduce price manipulation risks
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
                // TWAP oracles are resistant to single-block manipulation
                likelihood: if content.contains("TWAP") { ThreatLikelihood::Unlikely } else { ThreatLikelihood::Likely },
                mitigations: vec!["Use TWAP".to_string(), "Multiple oracles".to_string(), "Staleness check".to_string()],
                affected_functions: vec!["getPrice".to_string(), "calculate".to_string()],
            });
        }

        // Admin functions are at risk if admin keys are compromised
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

        // --- Type-specific threats for the primary contract type ---
        threats.extend(self.generate_type_specific_threats(content, contract_type));

        // --- Type-specific threats for each secondary type ---
        for secondary in secondary_types {
            threats.extend(self.generate_type_specific_threats(content, secondary));
        }

        // Deduplicate threats by name to avoid redundant entries when
        // primary and secondary types produce overlapping threats
        let mut seen_names = HashSet::new();
        threats.retain(|t| seen_names.insert(t.name.clone()));

        threats
    }

    /// Generate threats specific to a particular contract type.
    ///
    /// Each contract type has well-known attack patterns:
    /// - **ERC4626Vault**: First depositor inflation attack (share price manipulation)
    /// - **AMMPool**: Sandwich/MEV attacks on swaps
    /// - **LendingProtocol**: Bad debt accumulation from failed liquidations
    /// - **Bridge**: Cross-chain message replay attacks
    /// - **Governance**: Flash loan voting power manipulation
    /// - **Proxy**: Unauthorized implementation upgrade
    ///
    /// Likelihood is adjusted based on detected mitigations in the source code.
    fn generate_type_specific_threats(&self, content: &str, contract_type: &ContractType) -> Vec<Threat> {
        let mut threats = Vec::new();

        match contract_type {
            ContractType::ERC4626Vault => {
                // The inflation attack exploits empty/near-empty vaults where the
                // attacker donates assets to inflate the share price, causing
                // subsequent depositors to receive fewer shares than expected.
                threats.push(Threat {
                    category: ThreatCategory::FinancialLoss,
                    name: "First Depositor Inflation Attack".to_string(),
                    description: "Attacker can manipulate share price for subsequent depositors".to_string(),
                    attack_vectors: vec!["Donate assets before first deposit".to_string(), "Front-run first depositor".to_string()],
                    impact: ThreatImpact::Critical,
                    // Virtual shares/offsets are the standard mitigation for this attack
                    likelihood: if content.contains("virtual") && content.contains("shares") { ThreatLikelihood::Unlikely } else { ThreatLikelihood::Likely },
                    mitigations: vec!["Virtual shares offset".to_string(), "Minimum deposit".to_string(), "Dead shares".to_string()],
                    affected_functions: vec!["deposit".to_string(), "mint".to_string()],
                });
            }
            ContractType::AMMPool => {
                // Sandwich attacks are nearly inevitable for on-chain AMMs without
                // private mempools. Attackers front-run swaps to move the price,
                // then back-run to extract the difference.
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
                // Bad debt occurs when collateral value drops below debt value before
                // liquidation can occur, leaving the protocol with unrecoverable losses.
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
                // Cross-chain replay is critical for bridges: a message valid on one
                // chain could be replayed on another chain or after an upgrade.
                threats.push(Threat {
                    category: ThreatCategory::Replay,
                    name: "Cross-Chain Message Replay".to_string(),
                    description: "Messages could be replayed on different chains".to_string(),
                    attack_vectors: vec!["Replay on another chain".to_string(), "Replay after upgrade".to_string()],
                    impact: ThreatImpact::Critical,
                    // Including chainId in message hashes prevents cross-chain replay
                    likelihood: if content.contains("chainId") { ThreatLikelihood::Unlikely } else { ThreatLikelihood::Likely },
                    mitigations: vec!["Include chainId".to_string(), "Nonce tracking".to_string(), "Message hashing".to_string()],
                    affected_functions: vec!["sendMessage".to_string(), "receiveMessage".to_string()],
                });
            }
            ContractType::Governance => {
                // Flash loan governance attacks borrow tokens for a single block to
                // gain voting power, vote on a proposal, and repay in the same tx.
                threats.push(Threat {
                    category: ThreatCategory::GovernanceAttack,
                    name: "Flash Loan Governance Attack".to_string(),
                    description: "Attacker could use flash loan to gain voting power".to_string(),
                    attack_vectors: vec!["Borrow tokens via flash loan".to_string(), "Vote immediately".to_string(), "Repay in same transaction".to_string()],
                    impact: ThreatImpact::Critical,
                    // Checkpoint/snapshot-based voting prevents same-block vote manipulation
                    likelihood: if content.contains("checkpoint") || content.contains("getPastVotes") { ThreatLikelihood::Unlikely } else { ThreatLikelihood::Likely },
                    mitigations: vec!["Voting snapshots".to_string(), "Time-weighted voting".to_string(), "Voting delay".to_string()],
                    affected_functions: vec!["propose".to_string(), "vote".to_string()],
                });
            }
            ContractType::Proxy => {
                // Unauthorized upgrades are the most dangerous proxy attack: replacing
                // the implementation with a malicious contract gives full control.
                threats.push(Threat {
                    category: ThreatCategory::PrivilegeEscalation,
                    name: "Unauthorized Upgrade".to_string(),
                    description: "Attacker could upgrade implementation to malicious contract".to_string(),
                    attack_vectors: vec!["Admin key compromise".to_string(), "Selector collision".to_string(), "Uninitialized implementation".to_string()],
                    impact: ThreatImpact::Critical,
                    // onlyOwner guard on upgradeTo reduces but doesn't eliminate the risk
                    likelihood: if content.contains("onlyOwner") && content.contains("upgradeTo") { ThreatLikelihood::Unlikely } else { ThreatLikelihood::Possible },
                    mitigations: vec!["Timelock for upgrades".to_string(), "Multisig admin".to_string(), "Upgrade monitoring".to_string()],
                    affected_functions: vec!["upgradeTo".to_string(), "upgradeToAndCall".to_string()],
                });
            }
            _ => {}
        }

        threats
    }

    /// Calculate the overall risk summary from the list of identified threats.
    ///
    /// Counts threats by impact level (excluding "Unlikely" threats from critical/high
    /// counts since they are effectively mitigated). The overall risk level is set to
    /// the highest tier that has at least one qualifying threat. Generates prioritized
    /// recommendations including urgency flags for critical threats.
    fn calculate_risk_summary(&self, threats: &[Threat]) -> RiskSummary {
        // Count threats by severity, excluding unlikely ones from critical/high tallies
        // since mitigated threats should not inflate the overall risk assessment
        let critical = threats.iter().filter(|t| t.impact == ThreatImpact::Critical && t.likelihood != ThreatLikelihood::Unlikely).count();
        let high = threats.iter().filter(|t| t.impact == ThreatImpact::High && t.likelihood != ThreatLikelihood::Unlikely).count();
        let medium = threats.iter().filter(|t| t.impact == ThreatImpact::Medium).count();
        let low = threats.iter().filter(|t| t.impact == ThreatImpact::Low).count();

        // Overall risk is the highest tier with at least one qualifying threat
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

        // Add urgency-based recommendations
        if critical > 0 {
            recommendations.push("URGENT: Address critical threats before deployment".to_string());
        }
        if high > 0 {
            recommendations.push("Implement additional security controls for high-impact threats".to_string());
        }

        // Call out threats that are both critical AND very likely as top priority
        for threat in threats {
            if threat.impact == ThreatImpact::Critical && threat.likelihood == ThreatLikelihood::VeryLikely {
                recommendations.push(format!("Priority: Mitigate '{}' immediately", threat.name));
            }
        }

        // Standard recommendations that apply to all contracts
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

    /// Convert a threat model's threats into `Vulnerability` findings for unified reporting.
    ///
    /// This is a convenience wrapper that calls `to_vulnerabilities_with_content` with
    /// an empty content string, meaning all findings will default to line 1.
    pub fn to_vulnerabilities(&self, threat_model: &ThreatModel) -> Vec<Vulnerability> {
        self.to_vulnerabilities_with_content(threat_model, "")
    }

    /// Convert a threat model's threats into `Vulnerability` findings, using the
    /// original source content to resolve line numbers for affected functions.
    ///
    /// Filters out threats with `Unlikely` likelihood (already mitigated) and maps
    /// each remaining threat to a `Vulnerability` with:
    /// - Severity mapped from `ThreatImpact` to `VulnerabilitySeverity`
    /// - Category set to `LogicError` (threat model findings are architectural concerns)
    /// - Title prefixed with `[Threat Model]` for easy identification
    /// - Line number resolved by searching for `function <name>` in the source
    /// - Description includes attack vectors and affected function names
    /// - Recommendation includes the threat's suggested mitigations
    ///
    /// # Arguments
    /// * `threat_model` - The generated threat model to convert
    /// * `content` - The original Solidity source code (used for line number resolution)
    pub fn to_vulnerabilities_with_content(&self, threat_model: &ThreatModel, content: &str) -> Vec<Vulnerability> {
        let lines: Vec<&str> = content.lines().collect();

        threat_model.threats.iter()
            // Skip threats that are already mitigated (Unlikely likelihood)
            .filter(|t| t.likelihood != ThreatLikelihood::Unlikely)
            .map(|t| {
                // Map ThreatImpact to the scanner's VulnerabilitySeverity scale
                let severity = match t.impact {
                    ThreatImpact::Critical => VulnerabilitySeverity::Critical,
                    ThreatImpact::High => VulnerabilitySeverity::High,
                    ThreatImpact::Medium => VulnerabilitySeverity::Medium,
                    ThreatImpact::Low => VulnerabilitySeverity::Low,
                };

                // Resolve the line number by searching for the first affected function
                // in the source code. Falls back to line 1 if not found.
                let line_number = t.affected_functions.iter()
                    .find_map(|func_name| {
                        let pattern = format!("function {}", func_name);
                        lines.iter().enumerate().find_map(|(idx, line)| {
                            if line.contains(&pattern) { Some(idx + 1) } else { None }
                        })
                    })
                    .unwrap_or(1);

                Vulnerability::new(
                    severity,
                    VulnerabilityCategory::LogicError,
                    format!("[Threat Model] {}", t.name),
                    format!("{}\n\nAttack vectors: {}\nAffected functions: {}",
                           t.description,
                           t.attack_vectors.join(", "),
                           t.affected_functions.join(", ")),
                    line_number,
                    format!("Threat: {}", t.name),
                    format!("Mitigations: {}", t.mitigations.join(", ")),
                )
            })
            .collect()
    }
}
