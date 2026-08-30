//! Threat Model Generator
//!
//! Automatically generates STRIDE-based threat models for Solidity smart contracts.
//! This module performs the following analyses:
//!
//! 1. **Contract classification** - Identifies the contract type (ERC20, AMM, Lending, etc.)
//!    based on keyword/pattern heuristics to tailor threat analysis.
//! 2. **Attack surface analysis** - Counts payable/admin functions, oracle
//!    dependencies, and external calls to quantify exposure.
//! 3. **Threat generation** - Produces concrete threats with attack vectors, impact/
//!    likelihood ratings, and recommended mitigations, both generic (based on attack
//!    surface) and contract-type-specific.
//!
//! The generated `ThreatModel` can be converted into `Vulnerability` findings via
//! `to_vulnerabilities_with_content()` for unified reporting alongside pattern-based
//! detections.

use crate::vulnerabilities::{Vulnerability, VulnerabilityCategory, VulnerabilitySeverity};
use once_cell::sync::Lazy;
use regex::Regex;
use std::collections::HashSet;

/// Per-call-site regex cache. Each macro expansion creates its own `static Lazy<Regex>`,
/// so the pattern is compiled exactly once for the lifetime of the process — even when
/// the surrounding function runs once per scanned file in a 1,000-file sweep.
///
/// Use only with `'static` string literals. For dynamic patterns (e.g. `format!`-built),
/// fall back to `Regex::new(...)` directly.
macro_rules! re {
    ($pat:expr) => {{
        static RE: Lazy<Regex> = Lazy::new(|| Regex::new($pat).unwrap());
        &*RE
    }};
}

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

/// Represents a single identified threat with its full analysis.
///
/// Each threat includes concrete attack vectors, a risk assessment
/// (impact x likelihood), suggested mitigations, and the specific contract
/// functions that are affected.
#[derive(Debug, Clone)]
pub struct Threat {
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
    Critical, // Complete loss of funds
    High,     // Significant financial loss
}

/// Estimated probability of a threat being exploited.
///
/// Likelihood is adjusted downward when known mitigations (e.g., ReentrancyGuard,
/// TWAP oracles, voting snapshots) are detected in the contract source.
#[derive(Debug, Clone, PartialEq)]
pub enum ThreatLikelihood {
    VeryLikely, // Easy to exploit, requires minimal skill
    Likely,     // Moderate difficulty
    Possible,   // Requires specific conditions
    Unlikely,   // Requires significant effort/luck
}

/// The complete threat model output for a single contract.
///
/// Carries the identified threats. Contract classification and attack-surface metrics
/// are computed during `ThreatModelGenerator::generate()` purely as inputs to threat
/// generation and are not retained here.
#[derive(Debug)]
pub struct ThreatModel {
    /// All identified threats with risk assessments and mitigations
    pub threats: Vec<Threat>,
}

/// Quantified attack surface metrics for a contract.
///
/// These counts help assess the contract's overall exposure to external interaction.
/// Higher counts in any category generally indicate a larger attack surface.
#[derive(Debug)]
pub struct AttackSurface {
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

/// The main threat model generator that orchestrates all analysis phases.
///
/// Generates a `ThreatModel` from raw Solidity source code, running its analysis
/// phases in sequence: classification, attack surface, and threat generation.
pub struct ThreatModelGenerator;

impl ThreatModelGenerator {
    /// Create a new threat model generator.
    pub fn new() -> Self {
        Self
    }

    /// Generate a complete threat model for a Solidity contract.
    ///
    /// This is the main entry point. It runs all analysis phases in order:
    /// 1. Classify the contract type (ERC20, AMM, Lending, etc.)
    /// 2. Detect secondary types (e.g., an AMM with governance features)
    /// 3. Analyze the attack surface (payable, admin functions, external calls, etc.)
    /// 4. Generate threats (generic + type-specific) and deduplicate
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
        // Phase 4: Generate threats using both generic and type-specific rules
        let threats =
            self.generate_threats(content, &contract_type, &secondary_types, &attack_surface);

        ThreatModel { threats }
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
        if content.contains("ERC4626")
            || (content.contains("deposit")
                && content.contains("shares")
                && content.contains("assets"))
        {
            return ContractType::ERC4626Vault;
        }
        // Lending: requires borrow + collateral + liquidation keywords together
        if content.contains("borrow")
            && content.contains("collateral")
            && content.contains("liquidat")
        {
            return ContractType::LendingProtocol;
        }
        // AMM pool: swap+reserve combo or addLiquidity function
        if (content.contains("swap") && content.contains("reserve"))
            || content.contains("addLiquidity")
        {
            return ContractType::AMMPool;
        }
        // DEX router: "Router" name with swap or path routing
        if content.contains("Router") && (content.contains("swap") || content.contains("path")) {
            return ContractType::DEXRouter;
        }
        // Bridge: explicit bridge/crossChain keywords
        if content.contains("bridge")
            || content.contains("Bridge")
            || content.contains("crossChain")
        {
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
        if content.contains("ERC721")
            || (content.contains("tokenURI") && content.contains("ownerOf"))
        {
            return ContractType::ERC721NFT;
        }
        // ERC20: explicit interface or balanceOf+transfer+allowance triad
        if content.contains("ERC20")
            || (content.contains("balanceOf")
                && content.contains("transfer")
                && content.contains("allowance"))
        {
            return ContractType::ERC20Token;
        }
        // Multisig: explicit naming or confirmTransaction pattern
        if content.contains("multisig")
            || content.contains("Multisig")
            || content.contains("confirmTransaction")
        {
            return ContractType::Multisig;
        }
        // Oracle: explicit naming or getLatestPrice function
        if content.contains("oracle")
            || content.contains("Oracle")
            || content.contains("getLatestPrice")
        {
            return ContractType::Oracle;
        }
        // Factory: clone/create2 deployment or factory naming
        if content.contains("createClone")
            || content.contains("create2")
            || content.contains("factory")
        {
            return ContractType::Factory;
        }
        // Timelock: explicit naming or delay+queue combo
        if content.contains("timelock")
            || content.contains("Timelock")
            || content.contains("delay") && content.contains("queue")
        {
            return ContractType::Timelock;
        }
        // PaymentSplitter: explicit naming or shares+release combo
        if content.contains("PaymentSplitter")
            || content.contains("shares") && content.contains("release")
        {
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
        if primary != &ContractType::Governance
            && content.contains("vote")
            && content.contains("proposal")
        {
            types.push(ContractType::Governance);
        }

        // Check if a non-vault contract also implements vault-like deposit/withdraw/shares
        if primary != &ContractType::ERC4626Vault
            && content.contains("deposit")
            && content.contains("withdraw")
            && content.contains("shares")
        {
            types.push(ContractType::ERC4626Vault);
        }

        // Check if a non-proxy contract contains upgrade patterns
        if primary != &ContractType::Proxy
            && (content.contains("upgradeTo") || content.contains("_IMPLEMENTATION_SLOT"))
        {
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
    /// Counts payable functions, admin-like functions (by prefix heuristic), oracle
    /// dependencies, and low-level external calls. Also extracts the names of public
    /// entry point functions (up to 20).
    fn analyze_attack_surface(&self, content: &str) -> AttackSurface {
        // Match functions with `public` or `external` visibility
        let public_pattern = re!(r"function\s+\w+\s*\([^)]*\)\s*(?:public|external)");
        // Match functions with the `payable` modifier (accepts ETH)
        let payable_pattern = re!(r"function\s+\w+\s*\([^)]*\)[^{]*payable");
        // Match admin-like functions by common naming prefixes
        let admin_pattern = re!(
            r"function\s+(set|update|change|modify|withdraw|transfer|mint|burn|pause|upgrade)\w*"
        );

        let payable_count = payable_pattern.captures_iter(content).count();
        let admin_count = admin_pattern.captures_iter(content).count();

        // Count oracle dependencies by checking for common oracle-related keywords
        let oracle_patterns = [
            "latestRoundData",
            "getPrice",
            "oracle",
            "Oracle",
            "Chainlink",
        ];
        let oracle_count = oracle_patterns
            .iter()
            .filter(|p| content.contains(*p))
            .count();

        // Count low-level external calls that bypass Solidity's safety checks
        let external_call_pattern = re!(r"\.call\{|\.delegatecall\(|\.staticcall\(");
        let external_calls = external_call_pattern.captures_iter(content).count();

        // Extract function names that serve as public entry points.
        // Note: This currently re-captures from the start of content for each match,
        // so it may return the same name repeatedly. Limited to 20 entries.
        let entry_points: Vec<String> = public_pattern
            .captures_iter(content)
            .filter_map(|_| {
                let func_name_pattern = re!(r"function\s+(\w+)");
                func_name_pattern
                    .captures(content)
                    .and_then(|c| c.get(1))
                    .map(|m| m.as_str().to_string())
            })
            .take(20)
            .collect();

        AttackSurface {
            payable_functions: payable_count,
            admin_functions: admin_count,
            oracle_dependencies: oracle_count,
            external_calls,
            entry_points,
        }
    }

    /// Extract names of admin-restricted functions (those guarded by onlyOwner/onlyAdmin/onlyRole).
    /// Returns up to 10 function names.
    fn find_admin_functions(&self, content: &str) -> Vec<String> {
        let pattern = re!(r"function\s+(\w+)\s*\([^)]*\)[^{]*(onlyOwner|onlyAdmin|onlyRole)");
        pattern
            .captures_iter(content)
            .filter_map(|c| c.get(1).map(|m| m.as_str().to_string()))
            .take(10)
            .collect()
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
                name: "ETH Drainage".to_string(),
                description: "Contract holds ETH that could be drained through vulnerabilities"
                    .to_string(),
                attack_vectors: vec![
                    "Reentrancy attack".to_string(),
                    "Logic error in withdrawal".to_string(),
                    "Access control bypass".to_string(),
                ],
                impact: ThreatImpact::Critical,
                // ReentrancyGuard significantly reduces reentrancy likelihood
                likelihood: if content.contains("nonReentrant") {
                    ThreatLikelihood::Unlikely
                } else {
                    ThreatLikelihood::Likely
                },
                mitigations: vec![
                    "ReentrancyGuard".to_string(),
                    "CEI pattern".to_string(),
                    "Access control".to_string(),
                ],
                affected_functions: vec!["withdraw".to_string(), "transfer".to_string()],
            });
        }

        // External calls introduce manipulation and callback risks
        if attack_surface.external_calls > 0 {
            threats.push(Threat {
                name: "External Call Manipulation".to_string(),
                description: "External calls could be manipulated or fail unexpectedly".to_string(),
                attack_vectors: vec![
                    "Reentrancy via callback".to_string(),
                    "Return value not checked".to_string(),
                    "Gas griefing".to_string(),
                ],
                impact: ThreatImpact::High,
                likelihood: ThreatLikelihood::Possible,
                mitigations: vec![
                    "Check return values".to_string(),
                    "Use try/catch".to_string(),
                    "ReentrancyGuard".to_string(),
                ],
                affected_functions: attack_surface.entry_points.clone(),
            });
        }

        // Oracle dependencies introduce price manipulation risks
        if attack_surface.oracle_dependencies > 0 {
            threats.push(Threat {
                name: "Oracle Price Manipulation".to_string(),
                description: "Contract depends on external price data that could be manipulated"
                    .to_string(),
                attack_vectors: vec![
                    "Flash loan price manipulation".to_string(),
                    "Stale price data".to_string(),
                    "Oracle failure".to_string(),
                ],
                impact: ThreatImpact::Critical,
                // TWAP oracles are resistant to single-block manipulation
                likelihood: if content.contains("TWAP") {
                    ThreatLikelihood::Unlikely
                } else {
                    ThreatLikelihood::Likely
                },
                mitigations: vec![
                    "Use TWAP".to_string(),
                    "Multiple oracles".to_string(),
                    "Staleness check".to_string(),
                ],
                affected_functions: vec!["getPrice".to_string(), "calculate".to_string()],
            });
        }

        // Admin functions are at risk if admin keys are compromised
        if attack_surface.admin_functions > 0 {
            threats.push(Threat {
                name: "Admin Key Compromise".to_string(),
                description: "Compromised admin key could be used for malicious actions"
                    .to_string(),
                attack_vectors: vec![
                    "Private key theft".to_string(),
                    "Social engineering".to_string(),
                    "Insider threat".to_string(),
                ],
                impact: ThreatImpact::Critical,
                likelihood: ThreatLikelihood::Possible,
                mitigations: vec![
                    "Multisig".to_string(),
                    "Timelock".to_string(),
                    "Key rotation".to_string(),
                ],
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
    fn generate_type_specific_threats(
        &self,
        content: &str,
        contract_type: &ContractType,
    ) -> Vec<Threat> {
        let mut threats = Vec::new();

        match contract_type {
            ContractType::ERC4626Vault => {
                // The inflation attack exploits empty/near-empty vaults where the
                // attacker donates assets to inflate the share price, causing
                // subsequent depositors to receive fewer shares than expected.
                threats.push(Threat {
                    name: "First Depositor Inflation Attack".to_string(),
                    description: "Attacker can manipulate share price for subsequent depositors"
                        .to_string(),
                    attack_vectors: vec![
                        "Donate assets before first deposit".to_string(),
                        "Front-run first depositor".to_string(),
                    ],
                    impact: ThreatImpact::Critical,
                    // Virtual shares/offsets are the standard mitigation for this attack
                    likelihood: if content.contains("virtual") && content.contains("shares") {
                        ThreatLikelihood::Unlikely
                    } else {
                        ThreatLikelihood::Likely
                    },
                    mitigations: vec![
                        "Virtual shares offset".to_string(),
                        "Minimum deposit".to_string(),
                        "Dead shares".to_string(),
                    ],
                    affected_functions: vec!["deposit".to_string(), "mint".to_string()],
                });
            }
            ContractType::AMMPool => {
                // Sandwich attacks are nearly inevitable for on-chain AMMs without
                // private mempools. Attackers front-run swaps to move the price,
                // then back-run to extract the difference.
                threats.push(Threat {
                    name: "Sandwich Attack".to_string(),
                    description: "Swaps can be sandwiched for MEV extraction".to_string(),
                    attack_vectors: vec![
                        "Front-run with large swap".to_string(),
                        "Back-run to extract value".to_string(),
                    ],
                    impact: ThreatImpact::High,
                    likelihood: ThreatLikelihood::VeryLikely,
                    mitigations: vec![
                        "Slippage protection".to_string(),
                        "Deadline parameter".to_string(),
                        "Private mempool".to_string(),
                    ],
                    affected_functions: vec!["swap".to_string(), "addLiquidity".to_string()],
                });
            }
            ContractType::LendingProtocol => {
                // Bad debt occurs when collateral value drops below debt value before
                // liquidation can occur, leaving the protocol with unrecoverable losses.
                threats.push(Threat {
                    name: "Bad Debt Accumulation".to_string(),
                    description: "Protocol could accumulate bad debt from failed liquidations"
                        .to_string(),
                    attack_vectors: vec![
                        "Price crash".to_string(),
                        "Liquidation frontrunning".to_string(),
                        "Oracle manipulation".to_string(),
                    ],
                    impact: ThreatImpact::Critical,
                    likelihood: ThreatLikelihood::Possible,
                    mitigations: vec![
                        "Insurance fund".to_string(),
                        "Liquidation incentives".to_string(),
                        "Position limits".to_string(),
                    ],
                    affected_functions: vec!["liquidate".to_string(), "borrow".to_string()],
                });
            }
            ContractType::Bridge => {
                // Cross-chain replay is critical for bridges: a message valid on one
                // chain could be replayed on another chain or after an upgrade.
                threats.push(Threat {
                    name: "Cross-Chain Message Replay".to_string(),
                    description: "Messages could be replayed on different chains".to_string(),
                    attack_vectors: vec![
                        "Replay on another chain".to_string(),
                        "Replay after upgrade".to_string(),
                    ],
                    impact: ThreatImpact::Critical,
                    // Including chainId in message hashes prevents cross-chain replay
                    likelihood: if content.contains("chainId") {
                        ThreatLikelihood::Unlikely
                    } else {
                        ThreatLikelihood::Likely
                    },
                    mitigations: vec![
                        "Include chainId".to_string(),
                        "Nonce tracking".to_string(),
                        "Message hashing".to_string(),
                    ],
                    affected_functions: vec![
                        "sendMessage".to_string(),
                        "receiveMessage".to_string(),
                    ],
                });
            }
            ContractType::Governance => {
                // Flash loan governance attacks borrow tokens for a single block to
                // gain voting power, vote on a proposal, and repay in the same tx.
                threats.push(Threat {
                    name: "Flash Loan Governance Attack".to_string(),
                    description: "Attacker could use flash loan to gain voting power".to_string(),
                    attack_vectors: vec![
                        "Borrow tokens via flash loan".to_string(),
                        "Vote immediately".to_string(),
                        "Repay in same transaction".to_string(),
                    ],
                    impact: ThreatImpact::Critical,
                    // Checkpoint/snapshot-based voting prevents same-block vote manipulation
                    likelihood: if content.contains("checkpoint")
                        || content.contains("getPastVotes")
                    {
                        ThreatLikelihood::Unlikely
                    } else {
                        ThreatLikelihood::Likely
                    },
                    mitigations: vec![
                        "Voting snapshots".to_string(),
                        "Time-weighted voting".to_string(),
                        "Voting delay".to_string(),
                    ],
                    affected_functions: vec!["propose".to_string(), "vote".to_string()],
                });
            }
            ContractType::Proxy => {
                // Unauthorized upgrades are the most dangerous proxy attack: replacing
                // the implementation with a malicious contract gives full control.
                threats.push(Threat {
                    name: "Unauthorized Upgrade".to_string(),
                    description: "Attacker could upgrade implementation to malicious contract"
                        .to_string(),
                    attack_vectors: vec![
                        "Admin key compromise".to_string(),
                        "Selector collision".to_string(),
                        "Uninitialized implementation".to_string(),
                    ],
                    impact: ThreatImpact::Critical,
                    // onlyOwner guard on upgradeTo reduces but doesn't eliminate the risk
                    likelihood: if content.contains("onlyOwner") && content.contains("upgradeTo") {
                        ThreatLikelihood::Unlikely
                    } else {
                        ThreatLikelihood::Possible
                    },
                    mitigations: vec![
                        "Timelock for upgrades".to_string(),
                        "Multisig admin".to_string(),
                        "Upgrade monitoring".to_string(),
                    ],
                    affected_functions: vec![
                        "upgradeTo".to_string(),
                        "upgradeToAndCall".to_string(),
                    ],
                });
            }
            _ => {}
        }

        threats
    }

    /// Convert a threat model's threats into `Vulnerability` findings, using the
    /// original source content to resolve line numbers for affected functions.
    ///
    /// Filters out threats with `Unlikely` likelihood (already mitigated) and maps
    /// each remaining threat to a `Vulnerability` with:
    /// - Severity mapped from `ThreatImpact` to `VulnerabilitySeverity` (capped at Medium)
    /// - Category set to `LogicError` (threat model findings are architectural concerns)
    /// - Title prefixed with `[Threat Model]` for easy identification
    /// - Line number resolved by searching for `function <name>` in the source
    /// - Description includes attack vectors and affected function names
    /// - Recommendation includes the threat's suggested mitigations
    ///
    /// # Arguments
    /// * `threat_model` - The generated threat model to convert
    /// * `content` - The original Solidity source code (used for line number resolution)
    pub fn to_vulnerabilities_with_content(
        &self,
        threat_model: &ThreatModel,
        content: &str,
    ) -> Vec<Vulnerability> {
        let lines: Vec<&str> = content.lines().collect();

        threat_model
            .threats
            .iter()
            // Skip threats that are already mitigated (Unlikely likelihood)
            .filter(|t| t.likelihood != ThreatLikelihood::Unlikely)
            .map(|t| {
                // Map ThreatImpact to VulnerabilitySeverity, capped at Medium.
                // Threat model findings are theoretical (STRIDE-based), not confirmed
                // vulnerabilities, so they should never be Critical/High to avoid
                // inflating false positive counts.
                let severity = match t.impact {
                    ThreatImpact::Critical | ThreatImpact::High => VulnerabilitySeverity::Medium,
                };

                // Resolve the line number by searching for the first affected function
                // in the source code. Falls back to line 1 if not found.
                let line_number = t
                    .affected_functions
                    .iter()
                    .find_map(|func_name| {
                        let pattern = format!("function {}", func_name);
                        lines.iter().enumerate().find_map(|(idx, line)| {
                            if line.contains(&pattern) {
                                Some(idx + 1)
                            } else {
                                None
                            }
                        })
                    })
                    .unwrap_or(1);

                Vulnerability::new(
                    severity,
                    VulnerabilityCategory::LogicError,
                    format!("[Threat Model] {}", t.name),
                    format!(
                        "{}\n\nAttack vectors: {}\nAffected functions: {}",
                        t.description,
                        t.attack_vectors.join(", "),
                        t.affected_functions.join(", ")
                    ),
                    line_number,
                    format!("Threat: {}", t.name),
                    format!("Mitigations: {}", t.mitigations.join(", ")),
                )
            })
            .collect()
    }
}
