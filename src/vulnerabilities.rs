//! Vulnerability rules and type definitions for the 41Swara Solidity smart contract scanner.
//!
//! This module defines:
//! - Core data types for representing detected vulnerabilities (`Vulnerability`, `VulnerabilitySeverity`, etc.)
//! - The `VulnerabilityCategory` enum covering 80+ vulnerability classes from SWC Registry,
//!   OWASP Smart Contract Top 10, rekt.news exploit patterns, and academic research.
//! - `VulnerabilityRule` -- a regex-based pattern matcher tied to a category and severity.
//! - `create_vulnerability_rules()` -- the main rule set applied to all contracts.
//! - `create_version_specific_rules()` -- additional rules that depend on the Solidity compiler version.
//!
//! Rules are organized into thematic groups (reentrancy, access control, DeFi exploits, etc.)
//! and each rule carries a title, description, and remediation recommendation. Detected
//! vulnerabilities are further refined by the false-positive filter and reachability analyzer
//! in downstream pipeline stages.

use crate::parser::CompilerVersion;
use regex::Regex;
use serde::{Deserialize, Serialize};

/// SWC (Smart Contract Weakness) Registry ID with optional CWE (Common Weakness Enumeration) mapping.
///
/// Standard SWC IDs follow the format "SWC-NNN" (e.g., "SWC-107" for Reentrancy).
/// Custom 41Swara-specific IDs use the format "41S-NNN" for DeFi and modern exploit patterns
/// not yet covered by the SWC registry.
///
/// Reference: <https://swcregistry.io/>
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SwcId {
    /// The SWC or 41Swara weakness identifier (e.g., "SWC-107" or "41S-001").
    pub id: String,
    /// Human-readable title of the weakness (e.g., "Reentrancy").
    pub title: String,
    /// Optional corresponding CWE identifier (e.g., "CWE-841").
    pub cwe_id: Option<String>,
}

impl SwcId {
    /// Construct a new `SwcId` from string slices. Clones into owned `String` values.
    pub fn new(id: &str, title: &str, cwe_id: Option<&str>) -> Self {
        Self {
            id: id.to_string(),
            title: title.to_string(),
            cwe_id: cwe_id.map(|s| s.to_string()),
        }
    }
}

/// A single detected vulnerability finding in a Solidity source file.
///
/// Created by the scanner when a `VulnerabilityRule` pattern matches, then enriched
/// with context lines, confidence scoring, and optional fix suggestions before being
/// passed through the false-positive filter and reachability analyzer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vulnerability {
    /// How severe the finding is (Critical, High, Medium, Low, Info).
    pub severity: VulnerabilitySeverity,
    /// The vulnerability class this finding belongs to.
    pub category: VulnerabilityCategory,
    /// Short human-readable title shown in scan output.
    pub title: String,
    /// Longer explanation of why this pattern is dangerous.
    pub description: String,
    /// 1-based line number where the vulnerability was detected.
    pub line_number: usize,
    /// Optional end line for multi-line vulnerability spans.
    pub end_line_number: Option<usize>,
    /// The source code snippet that matched the detection rule.
    pub code_snippet: String,
    /// Source lines immediately before the finding for reviewer context.
    pub context_before: Option<String>,
    /// Source lines immediately after the finding for reviewer context.
    pub context_after: Option<String>,
    /// Actionable remediation advice.
    pub recommendation: String,
    /// Qualitative confidence level (High / Medium / Low).
    pub confidence: VulnerabilityConfidence,
    /// Confidence expressed as a 0--100 percentage.
    pub confidence_percent: u8,
    /// SWC Registry ID and CWE mapping, if applicable.
    pub swc_id: Option<SwcId>,
    /// Optional inline code fix suggestion.
    pub fix_suggestion: Option<String>,
    /// CVSS 3.1 base score (0.0 - 10.0).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cvss_score: Option<f64>,
    /// CVSS 3.1 vector string (e.g., "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:H/A:H").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cvss_vector: Option<String>,
    /// Real-world exploit references (e.g., "Cetus DEX ($223M, 2025)").
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub exploit_references: Vec<String>,
    /// Attack path narrative describing how this vulnerability could be exploited.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attack_path: Option<String>,
}

/// Qualitative confidence that a detected finding is a true positive.
///
/// Mapped from a numeric percentage via `from_percent()` and back via `to_percent()`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum VulnerabilityConfidence {
    /// Very likely a real vulnerability (80--100%).
    High,
    /// Likely a vulnerability but needs manual review (50--79%).
    Medium,
    /// Possible vulnerability; may be a false positive (0--49%).
    Low, // Low confidence
}

impl VulnerabilityConfidence {
    /// Convert a percentage (0-100) to a confidence level
    /// Used by external tools and the with_confidence_percent builder
    pub fn from_percent(percent: u8) -> Self {
        if percent >= 80 {
            VulnerabilityConfidence::High
        } else if percent >= 50 {
            VulnerabilityConfidence::Medium
        } else {
            VulnerabilityConfidence::Low
        }
    }

    /// Convert confidence level to a representative percentage
    pub fn to_percent(&self) -> u8 {
        match self {
            VulnerabilityConfidence::High => 90,
            VulnerabilityConfidence::Medium => 65,
            VulnerabilityConfidence::Low => 30,
        }
    }
}

impl Vulnerability {
    /// Create a new vulnerability with default values for optional fields
    pub fn new(
        severity: VulnerabilitySeverity,
        category: VulnerabilityCategory,
        title: String,
        description: String,
        line_number: usize,
        code_snippet: String,
        recommendation: String,
    ) -> Self {
        let swc_id = category.get_swc_id();
        Self {
            severity,
            category,
            title,
            description,
            line_number,
            end_line_number: None,
            code_snippet,
            context_before: None,
            context_after: None,
            recommendation,
            confidence: VulnerabilityConfidence::Medium,
            confidence_percent: 65,
            swc_id,
            fix_suggestion: None,
            cvss_score: None,
            cvss_vector: None,
            exploit_references: Vec::new(),
            attack_path: None,
        }
    }

    /// Create a vulnerability with high confidence (definitely a real issue)
    pub fn high_confidence(
        severity: VulnerabilitySeverity,
        category: VulnerabilityCategory,
        title: String,
        description: String,
        line_number: usize,
        code_snippet: String,
        recommendation: String,
    ) -> Self {
        let mut vuln = Self::new(
            severity,
            category,
            title,
            description,
            line_number,
            code_snippet,
            recommendation,
        );
        vuln.confidence = VulnerabilityConfidence::High;
        vuln.confidence_percent = 90;
        vuln
    }

    /// Create a vulnerability with a specific confidence percentage
    /// Public API for external tools building custom vulnerabilities
    pub fn with_confidence_percent(mut self, percent: u8) -> Self {
        self.confidence_percent = percent.min(100);
        self.confidence = VulnerabilityConfidence::from_percent(self.confidence_percent);
        self
    }

    /// Add a fix suggestion to the vulnerability
    /// Public API for external tools adding remediation suggestions
    pub fn with_fix(mut self, fix: String) -> Self {
        self.fix_suggestion = Some(fix);
        self
    }

    /// Get the SWC ID string if available
    /// Public API for reporters and formatters
    pub fn get_swc_id_str(&self) -> Option<&str> {
        self.swc_id.as_ref().map(|s| s.id.as_str())
    }

    /// Get the CWE ID string if available
    /// Public API for compliance tooling
    pub fn get_cwe_id(&self) -> Option<&str> {
        self.swc_id.as_ref().and_then(|s| s.cwe_id.as_deref())
    }

    /// Add context lines around the vulnerability
    pub fn with_context(mut self, before: Option<String>, after: Option<String>) -> Self {
        self.context_before = before;
        self.context_after = after;
        self
    }

    /// Set end line for multi-line vulnerabilities
    pub fn with_end_line(mut self, end_line: usize) -> Self {
        self.end_line_number = Some(end_line);
        self
    }

    /// Composite risk score on a 0..=10 scale, used to rank findings by exploitability
    /// rather than by raw severity label.
    ///
    /// Combines CVSS base, confidence, and known-exploit history:
    ///   `risk = CVSS * (0.5 + 0.5 * confidence/100) * exploit_multiplier`
    ///
    /// Where:
    /// - confidence acts as a half-weight scaler — a 100%-confident bug retains its full
    ///   CVSS, a 50%-confident bug counts at 75% — so noisy heuristics never outrank
    ///   high-confidence findings of the same nominal severity.
    /// - `exploit_multiplier` is 1.20 when `exploit_references` is non-empty, capping at 10.0.
    ///   Patterns with documented real-world exploits (Cetus, Balancer, etc.) get a small
    ///   boost over equivalent-CVSS findings without precedent.
    ///
    /// Findings with no CVSS score fall back to a coarse mapping from severity.
    pub fn risk_score(&self) -> f64 {
        let base = self.cvss_score.unwrap_or(match self.severity {
            VulnerabilitySeverity::Critical => 9.0,
            VulnerabilitySeverity::High => 7.0,
            VulnerabilitySeverity::Medium => 4.5,
            VulnerabilitySeverity::Low => 2.0,
            VulnerabilitySeverity::Info => 0.5,
        });
        let conf = (self.confidence_percent as f64 / 100.0).clamp(0.0, 1.0);
        let conf_factor = 0.5 + 0.5 * conf;
        let exploit_mult = if self.exploit_references.is_empty() {
            1.0
        } else {
            1.20
        };
        (base * conf_factor * exploit_mult).min(10.0)
    }

    /// Bucketed remediation priority derived from `risk_score()`.
    ///
    /// - `P1 - Immediate`: risk >= 7.0 (must fix before deploy / launch)
    /// - `P2 - Short-term`: risk >= 4.0 (fix in next sprint)
    /// - `P3 - Backlog`: everything else
    pub fn priority_label(&self) -> &'static str {
        let r = self.risk_score();
        if r >= 7.0 {
            "P1 - Immediate"
        } else if r >= 4.0 {
            "P2 - Short-term"
        } else {
            "P3 - Backlog"
        }
    }

    /// Extract context from content given a line number
    pub fn extract_context(
        content: &str,
        line_number: usize,
        context_lines: usize,
    ) -> (Option<String>, Option<String>) {
        let lines: Vec<&str> = content.lines().collect();

        let before = if line_number > 1 {
            let start = if line_number > context_lines {
                line_number - context_lines - 1
            } else {
                0
            };
            let end = line_number - 1;
            if start < end && end <= lines.len() {
                Some(lines[start..end].join("\n"))
            } else {
                None
            }
        } else {
            None
        };

        let after = if line_number < lines.len() {
            let start = line_number;
            let end = (line_number + context_lines).min(lines.len());
            if start < end {
                Some(lines[start..end].join("\n"))
            } else {
                None
            }
        } else {
            None
        };

        (before, after)
    }
}

/// Severity rating for a vulnerability finding, modeled after common audit report scales.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum VulnerabilitySeverity {
    /// Immediate risk of fund loss or contract takeover.
    Critical,
    /// Significant risk that should be fixed before deployment.
    High,
    /// Moderate risk or a pattern that becomes dangerous under certain conditions.
    Medium,
    /// Minor issue with limited impact.
    Low,
    /// Informational observation or gas optimization suggestion.
    Info,
}

/// All recognized vulnerability categories.
///
/// Categories are organized into several groups:
///
/// 1. **Core SWC categories** -- standard Smart Contract Weakness classifications.
/// 2. **Rekt.news real-world exploit patterns** -- derived from documented DeFi hacks.
/// 3. **ABI-level vulnerabilities** -- detected from contract ABI analysis.
/// 4. **OWASP Smart Contract Top 10 (2025)** -- the most impactful recent exploit classes.
/// 5. **Modern DeFi / L2 patterns (2024-2025)** -- ERC-4626, Permit2, LayerZero, etc.
/// 6. **Academic research patterns** -- from "Security Analysis of DeFi" (arXiv:2205.09524v1).
///
/// Each variant maps to an optional `SwcId` via `get_swc_id()`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum VulnerabilityCategory {
    // --- Core SWC Registry Categories ---
    /// SWC-107: State-changing external calls before state updates.
    Reentrancy,
    /// SWC-105: Missing or insufficient access control on sensitive functions.
    AccessControl,
    /// SWC-105 (specialized): Role-based access control misconfigurations.
    RoleBasedAccessControl,
    /// SWC-101: Integer overflow / underflow (primarily pre-0.8.0).
    ArithmeticIssues,
    /// SWC-104: Uncaught exceptions from external calls.
    UnhandledExceptions,
    /// Gas-related inefficiencies (informational).
    GasOptimization,
    /// SWC-103: Floating or outdated pragma declarations.
    PragmaIssues,
    /// SWC-120: Use of predictable on-chain values for randomness.
    RandomnessVulnerabilities,
    /// SWC-114: Transaction ordering dependence / front-running.
    FrontRunning,
    /// SWC-116: Reliance on `block.timestamp` for critical logic.
    TimeManipulation,
    /// SWC-128: Denial-of-service via gas limits or unbounded loops.
    DoSAttacks,
    /// Dead or unreachable code that may indicate logic errors.
    UnusedCode,
    /// Use of unexplained literal values in calculations.
    MagicNumbers,
    /// Typos, misleading names, or convention violations.
    NamingConventions,
    /// Issues with state variable declarations or storage layout.
    StateVariable,
    /// External calls without proper safety checks.
    UnsafeExternalCalls,
    /// SWC-112: Dangerous delegatecall usage.
    DelegateCalls,
    /// Unbounded storage growth that can cause DoS.
    StorageDoSAttacks,
    /// Loss of precision in financial calculations due to integer division.
    PrecisionLoss,
    /// SWC-102: Known compiler bugs for the detected Solidity version.
    CompilerBug,
    /// SWC-120: Bad pseudo-random number generation using block properties.
    BadPRNG,
    /// SWC-116: Direct `block.timestamp` dependency in comparisons.
    BlockTimestamp,
    /// SWC-104: Low-level `.call` / `.delegatecall` / `.staticcall` without return checks.
    LowLevelCalls,
    /// State-changing functions that do not emit events for off-chain tracking.
    MissingEvents,
    /// SWC-104: External call return values silently ignored.
    UncheckedReturnValues,
    /// SWC-109: Variables used before being explicitly initialized.
    UninitializedVariables,
    /// Function return values discarded by the caller.
    UnusedReturnValues,
    /// State variables that could be declared `immutable` or `constant`.
    ImmutabilityIssues,
    /// SWC-119: Local variables or parameters shadowing state variable names.
    ShadowingIssues,
    /// SWC-115: Using `tx.origin` for authentication instead of `msg.sender`.
    TxOriginAuth,
    /// SWC-106: Inline assembly blocks that bypass Solidity safety checks.
    AssemblyUsage,
    /// SWC-111: Usage of deprecated Solidity built-ins (e.g., `sha3`, `suicide`).
    DeprecatedFunctions,
    /// Excessively complex functions (high cyclomatic complexity).
    ComplexityIssues,
    /// Public functions that are never called internally (could be `external`).
    ExternalFunction,
    /// SWC-132: Strict equality checks on Ether balances.
    IncorrectEquality,
    /// SWC-117: Signature malleability and related cryptographic weaknesses.
    SignatureVulnerabilities,
    /// 41S-001: Price oracle manipulation via spot reserves.
    OracleManipulation,

    // --- Rekt.news Real-World Exploit Patterns ---
    /// 41S-003: Proxy admin function exposure (e.g., Aevo $2.7M).
    ProxyAdminVulnerability,
    /// 41S-004: Reentrancy via ERC-721/1155 callback hooks (e.g., Omni $1.43M).
    CallbackReentrancy,
    /// 41S-005: Calls to user-controlled addresses ($21M across 18 incidents).
    ArbitraryExternalCall,
    /// SWC-121: Signature replay due to missing nonce or chain ID.
    SignatureReplay,
    /// 41S-006: Cross-chain replay of messages or signatures.
    CrossChainReplay,
    /// 41S-007: Insufficient input validation (34.6% of 2024 exploits).
    InputValidationFailure,
    /// 41S-008: Mixing 18-decimal and 8-decimal token arithmetic.
    DecimalPrecisionMismatch,
    /// 41S-009: Upgrade functions without access control on proxy contracts.
    UnprotectedProxyUpgrade,
    /// 41S-010: Functions exploitable by MEV searchers (sandwich attacks, liquidations).
    MEVExploitable,
    /// 41S-011: State changes after callback-triggering operations.
    CallbackInjection,

    // --- ABI-Specific Vulnerabilities ---
    /// Access control issues detected from ABI function signatures.
    ABIAccessControl,
    /// Visibility misconfigurations detected from ABI analysis.
    ABIFunctionVisibility,
    /// Missing parameter validation inferred from ABI.
    ABIParameterValidation,
    /// Event security concerns from ABI definitions.
    ABIEventSecurity,
    /// Upgradeability risks inferred from ABI (proxy patterns).
    ABIUpgradeability,
    /// Token standard compliance issues from ABI.
    ABITokenStandard,

    // --- Advanced ABI Vulnerabilities (Ethereum Foundation-level analysis) ---
    /// Function selector collision risk from ABI.
    ABISelectorCollision,
    /// Reentrancy indicators in ABI call patterns.
    ABIReentrancyIndicator,
    /// Flash loan risk inferred from ABI function signatures.
    ABIFlashLoanRisk,
    /// Oracle manipulation exposure from ABI.
    ABIOracleManipulation,
    /// DEX interaction risks from ABI.
    ABIDEXInteraction,
    /// Signature-related weaknesses from ABI.
    ABISignatureVulnerability,
    /// Permit function vulnerabilities from ABI.
    ABIPermitVulnerability,
    /// Governance risks from ABI.
    ABIGovernanceRisk,
    /// Timelock bypass risks from ABI.
    ABITimelockBypass,
    /// MEV exposure from ABI function signatures.
    ABIMEVExposure,
    /// Front-running risks from ABI.
    ABIFrontrunningRisk,
    /// Cross-contract interaction risks from ABI.
    ABICrossContractRisk,
    /// Callback injection risks from ABI.
    ABICallbackInjection,
    /// Storage collision risks from ABI.
    ABIStorageCollision,
    /// Initializer vulnerabilities from ABI.
    ABIInitializerVulnerability,
    /// Self-destruct exposure from ABI.
    ABISelfDestruct,
    /// Delegatecall risks from ABI.
    ABIDelegateCallRisk,
    /// Arbitrary call risks from ABI.
    ABIArbitraryCall,
    /// Price manipulation risks from ABI.
    ABIPriceManipulation,
    /// Bridge vulnerabilities from ABI.
    ABIBridgeVulnerability,
    /// Multisig bypass risks from ABI.
    ABIMultisigBypass,
    /// Emergency function bypass risks from ABI.
    ABIEmergencyBypass,

    // --- 2025 OWASP Smart Contract Top 10 & Recent Exploits ---
    /// OWASP #4: Flash loan attack vectors ($33.8M in 2024).
    FlashLoanAttack,
    /// OWASP #2: Logic errors in business logic ($63.8M in 2024).
    LogicError,
    /// KiloEx $7.4M: MinimalForwarder meta-transaction exploit.
    MetaTransactionVulnerability,
    /// Cetus $223M: Unchecked overflow in math operations.
    UncheckedMathOperation,
    /// Meta-transaction trusted forwarder trust bypass.
    TrustedForwarderBypass,
    /// Flash loan governance attacks (e.g., Beanstalk $182M).
    GovernanceAttack,
    /// LP token and liquidity pool manipulation.
    LiquidityManipulation,
    /// Cross-chain bridge exploits.
    BridgeVulnerability,

    // --- 2024-2025 Modern DeFi / L2 Patterns ---
    /// First depositor inflation attack on ERC-4626 vaults.
    ERC4626Inflation,
    /// Permit2 signature reuse or deadline bypass.
    Permit2SignatureReuse,
    /// LayerZero trusted remote manipulation.
    LayerZeroTrustedRemote,
    /// CREATE2 / CREATE3 address collision attacks.
    Create2Collision,
    /// EIP-1153 transient storage reentrancy vectors.
    TransientStorageReentrancy,
    /// PUSH0 opcode (EIP-3855) compatibility issues on L2s.
    Push0Compatibility,
    /// EIP-4844 blob data handling issues.
    BlobDataHandling,
    /// Uniswap V4 hook exploitation vectors.
    UniswapV4HookExploit,
    /// Cross-chain message replay attacks.
    CrossChainMessageReplay,
    /// L2 sequencer downtime / uptime feed issues.
    L2SequencerDowntime,
    /// L2 gas price oracle manipulation.
    L2GasOracle,
    /// Base chain bridge security patterns.
    BaseBridgeSecurity,

    // --- Research Paper Patterns (arXiv:2205.09524v1) ---
    /// 41S-040: `==` on balance checks, bypassable via `selfdestruct`.
    StrictBalanceEquality,
    /// 41S-041: Incorrect `storage` / `memory` data location usage.
    MisleadingDataLocation,
    /// 41S-042: Function declares return type but misses return on some paths.
    MissingReturnValue,
    /// 41S-043: Contract accepts ETH (payable) but has no withdrawal mechanism.
    GreedyContract,
    /// 41S-044: DeFi contract without circuit breaker / pause functionality.
    MissingEmergencyStop,
    /// 41S-045: ERC-777 `tokensReceived` callback reentrancy (dForce $24M).
    ERC777CallbackReentrancy,
    /// 41S-046: `depositFor()` callback reentrancy (Grim Finance $30M).
    DepositForReentrancy,
    /// 41S-047: LP token transfer-and-claim double claiming (Popsicle Finance $25M).
    DoubleClaiming,
    /// 41S-048: Incomplete signature verification (Wormhole $326M).
    SignatureVerificationBypass,

    // --- Security Hardening Categories (v0.6.0) ---
    /// 41S-050: Missing storage gap in upgradeable contract base.
    MissingStorageGap,
    /// 41S-051: Admin function without timelock delay.
    MissingTimelock,
    /// 41S-052: selfdestruct usage (deprecated by EIP-6780, restricted post-Dencun).
    SelfdestructDeprecation,
    /// 41S-053: Uninitialized proxy implementation contract.
    UninitializedImplementation,
    /// 41S-054: Unsafe integer downcast (e.g., uint256 → uint128 truncation).
    UnsafeDowncast,
    /// 41S-055: Missing ERC-165 supportsInterface implementation.
    MissingERC165,
    /// 41S-056: Missing deadline parameter in DEX swap functions.
    MissingSwapDeadline,
    /// 41S-057: Hardcoded gas value in external call.
    HardcodedGasAmount,
    /// 41S-058: Unsafe use of `address.transfer()` with hardcoded 2300 gas.
    UnsafeTransferGas,
    /// 41S-059: Double initialization risk in proxy pattern.
    DoubleInitialization,

    // --- 2025-2026 Exploit Patterns (v0.7.0) ---
    /// 41S-060: Multicall batch resets solvency flag (Abracadabra $14.7M).
    MulticallStateReset,
    /// 41S-061: totalSupply=0 without clearing cached balances (Yearn $9M).
    InconsistentStateReset,
    /// 41S-062: tx.origin==msg.sender broken post-Pectra EIP-7702.
    EIP7702TxOriginBypass,
    /// 41S-063: .transfer()/.send() no longer safe with TSTORE gas changes.
    TransientStorageGasReentrancy,
    /// 41S-064: View functions return stale state during reentrancy.
    ReadOnlyReentrancy,
    /// 41S-065: _msgSender() spoofable via multicall in ERC2771 (Thirdweb).
    ERC2771MulticallSpoofing,
    /// 41S-066: msg.value persists across delegatecall sub-calls.
    MulticallMsgValueReuse,
    /// 41S-067: Protocols assume transferFrom amount == received amount.
    FeeOnTransferAssumption,
    /// 41S-068: Admin sweep without timelock (zkSync $5M).
    UnprotectedAdminSweep,
    /// 41S-069: Cross-chain receive without source validation (Atlas $112M).
    UnvalidatedCrossChainReceiver,
    /// 41S-070: AVS slash without timelock (EigenLayer restaking).
    AVSSlashingRisk,
    /// 41S-071: Bit-shift overflow in liquidity math (Cetus $223M).
    CLMMMathOverflow,
    /// 41S-072: mulDown+divUp mismatch in same function (Balancer $128M).
    InconsistentRounding,
    /// 41S-073: balanceOf(address(this)) in share price without offset.
    DonationAttackVector,
    /// 41S-074: Swap/deposit without minOutput parameter.
    MissingSlippageProtection,
    /// 41S-075: User-supplied receiver callback before state update (GMX $42M).
    ArbitraryReceiverCallback,
    /// 41S-076: extcodesize/isContract unreliable post-EIP-7702.
    IsContractPostPectra,
    /// 41S-077: multicall with delegatecall without msg.value isolation.
    UnsafeMulticallDelegatecall,

    // --- 2026 Exploit Patterns (v0.9.0) ---
    /// 41S-078: ERC-4337 paymaster validation without context revoke / replay guard.
    ERC4337PaymasterAbuse,
    /// 41S-079: EIP-1271 isValidSignature without nonce / replay protection.
    EIP1271SignatureReplay,
    /// 41S-080: Permit2 used with type(uint).max allowance and no expiration.
    Permit2UnlimitedApproval,
    /// 41S-081: LRT/restaking re-hypothecation - same collateral counted twice.
    LRTRehypothecation,
    /// 41S-082: Storage layout collision risk from inheritance reorder in upgradeable proxy.
    StorageLayoutCollision,
    /// 41S-083: Governance vote-buying via flash loan without snapshot/checkpoint.
    GovernanceFlashloanVoting,
    /// 41S-084: Sandwich/MEV exposure on price-sensitive write without commit-reveal or TWAP.
    SandwichResistantMissing,

    // --- Mid-2026 Exploit Patterns (v0.10.0) ---
    /// 41S-085: Solidity 0.8.28-0.8.33 IR codegen bug - clearing a persistent and a
    /// transient variable of the same type can emit the wrong opcode (sstore/tstore swap).
    TransientStorageCompilerBug,
    /// 41S-086: EIP-7702 delegate implementation using raw slot-0 storage - collides
    /// with other delegates the same EOA has pointed at (no ERC-7201 namespacing).
    EIP7702DelegateStorageCollision,
    /// 41S-087: LayerZero V2 OApp secured by a single required DVN (Kelp DAO $293M).
    LayerZeroSingleDVN,
    /// 41S-088: ERC-7683 destination settler fill() without settler/origin validation.
    ERC7683UnvalidatedFill,
    /// 41S-089: Uniswap V4 flash-accounting hook takes funds to a caller-controlled
    /// recipient (ERC-6909 claim/raw-token accounting mismatch drain).
    ERC6909FlashAccountingDrain,

    // --- Late-2026 Smart-Account Execution Surface (v0.11.0) ---
    /// 41S-090: ERC-7579 modular smart account exposes installModule/uninstallModule
    /// without access control - an attacker installs a malicious validator/executor
    /// module and takes over the account.
    ERC7579UnprotectedModule,
    /// 41S-091: ERC-7821 batch executor execute(bytes32 mode, bytes executionData)
    /// callable by anyone (not restricted to the EntryPoint or the account itself) -
    /// arbitrary batched calls from the account's context.
    ERC7821UnprotectedExecute,
    /// 41S-092: ERC-7579 executeFromExecutor() reachable without an installed-executor
    /// gate - any caller dispatches arbitrary calls as the account.
    ERC7579UnrestrictedExecutor,
}

impl VulnerabilityCategory {
    /// Returns the SWC Registry ID and CWE mapping for this vulnerability category.
    ///
    /// Standard weaknesses use official SWC IDs (SWC-1xx); DeFi-specific and modern
    /// exploit categories use custom 41Swara IDs (41S-0xx). Informational/quality
    /// categories (e.g., `GasOptimization`, `UnusedCode`) return `None`.
    ///
    /// References:
    /// - SWC Registry: <https://swcregistry.io/>
    /// - MITRE CWE: <https://cwe.mitre.org/>
    pub fn get_swc_id(&self) -> Option<SwcId> {
        match self {
            // Core SWC Registry mappings
            VulnerabilityCategory::Reentrancy => {
                Some(SwcId::new("SWC-107", "Reentrancy", Some("CWE-841")))
            }
            VulnerabilityCategory::AccessControl => Some(SwcId::new(
                "SWC-105",
                "Unprotected Ether Withdrawal",
                Some("CWE-284"),
            )),
            VulnerabilityCategory::RoleBasedAccessControl => Some(SwcId::new(
                "SWC-105",
                "Unprotected Ether Withdrawal",
                Some("CWE-284"),
            )),
            VulnerabilityCategory::ArithmeticIssues => Some(SwcId::new(
                "SWC-101",
                "Integer Overflow and Underflow",
                Some("CWE-190"),
            )),
            VulnerabilityCategory::UnhandledExceptions => Some(SwcId::new(
                "SWC-104",
                "Unchecked Call Return Value",
                Some("CWE-252"),
            )),
            VulnerabilityCategory::PragmaIssues => {
                Some(SwcId::new("SWC-103", "Floating Pragma", Some("CWE-1104")))
            }
            VulnerabilityCategory::RandomnessVulnerabilities => Some(SwcId::new(
                "SWC-120",
                "Weak Sources of Randomness",
                Some("CWE-330"),
            )),
            VulnerabilityCategory::FrontRunning => Some(SwcId::new(
                "SWC-114",
                "Transaction Order Dependence",
                Some("CWE-362"),
            )),
            VulnerabilityCategory::TimeManipulation => Some(SwcId::new(
                "SWC-116",
                "Block Timestamp Dependence",
                Some("CWE-829"),
            )),
            VulnerabilityCategory::BlockTimestamp => Some(SwcId::new(
                "SWC-116",
                "Block Timestamp Dependence",
                Some("CWE-829"),
            )),
            VulnerabilityCategory::DoSAttacks => Some(SwcId::new(
                "SWC-128",
                "DoS With Block Gas Limit",
                Some("CWE-400"),
            )),
            VulnerabilityCategory::StorageDoSAttacks => Some(SwcId::new(
                "SWC-128",
                "DoS With Block Gas Limit",
                Some("CWE-400"),
            )),
            VulnerabilityCategory::UnsafeExternalCalls => {
                Some(SwcId::new("SWC-107", "Reentrancy", Some("CWE-841")))
            }
            VulnerabilityCategory::DelegateCalls => Some(SwcId::new(
                "SWC-112",
                "Delegatecall to Untrusted Callee",
                Some("CWE-829"),
            )),
            VulnerabilityCategory::TxOriginAuth => Some(SwcId::new(
                "SWC-115",
                "Authorization through tx.origin",
                Some("CWE-477"),
            )),
            VulnerabilityCategory::SignatureVulnerabilities => Some(SwcId::new(
                "SWC-117",
                "Signature Malleability",
                Some("CWE-347"),
            )),
            VulnerabilityCategory::SignatureReplay => Some(SwcId::new(
                "SWC-121",
                "Missing Protection against Signature Replay",
                Some("CWE-294"),
            )),
            VulnerabilityCategory::DeprecatedFunctions => Some(SwcId::new(
                "SWC-111",
                "Use of Deprecated Functions",
                Some("CWE-477"),
            )),
            VulnerabilityCategory::UncheckedReturnValues => Some(SwcId::new(
                "SWC-104",
                "Unchecked Call Return Value",
                Some("CWE-252"),
            )),
            VulnerabilityCategory::UnusedReturnValues => Some(SwcId::new(
                "SWC-104",
                "Unchecked Call Return Value",
                Some("CWE-252"),
            )),
            VulnerabilityCategory::LowLevelCalls => Some(SwcId::new(
                "SWC-104",
                "Unchecked Call Return Value",
                Some("CWE-252"),
            )),
            VulnerabilityCategory::AssemblyUsage => Some(SwcId::new(
                "SWC-106",
                "Unprotected SELFDESTRUCT Instruction",
                Some("CWE-749"),
            )),
            VulnerabilityCategory::ShadowingIssues => Some(SwcId::new(
                "SWC-119",
                "Shadowing State Variables",
                Some("CWE-710"),
            )),
            VulnerabilityCategory::UninitializedVariables => Some(SwcId::new(
                "SWC-109",
                "Uninitialized Storage Pointer",
                Some("CWE-824"),
            )),
            VulnerabilityCategory::CompilerBug => Some(SwcId::new(
                "SWC-102",
                "Outdated Compiler Version",
                Some("CWE-1104"),
            )),
            VulnerabilityCategory::BadPRNG => Some(SwcId::new(
                "SWC-120",
                "Weak Sources of Randomness",
                Some("CWE-330"),
            )),
            VulnerabilityCategory::IncorrectEquality => Some(SwcId::new(
                "SWC-132",
                "Unexpected Ether Balance",
                Some("CWE-670"),
            )),
            VulnerabilityCategory::PrecisionLoss => Some(SwcId::new(
                "SWC-101",
                "Integer Overflow and Underflow",
                Some("CWE-190"),
            )),

            // DeFi-specific (41Swara custom IDs)
            VulnerabilityCategory::OracleManipulation => Some(SwcId::new(
                "41S-001",
                "Oracle Manipulation",
                Some("CWE-807"),
            )),
            VulnerabilityCategory::FlashLoanAttack => Some(SwcId::new(
                "41S-002",
                "Flash Loan Attack Vector",
                Some("CWE-807"),
            )),
            VulnerabilityCategory::ProxyAdminVulnerability => Some(SwcId::new(
                "41S-003",
                "Proxy Admin Vulnerability",
                Some("CWE-284"),
            )),
            VulnerabilityCategory::CallbackReentrancy => Some(SwcId::new(
                "41S-004",
                "Callback Reentrancy",
                Some("CWE-841"),
            )),
            VulnerabilityCategory::ArbitraryExternalCall => Some(SwcId::new(
                "41S-005",
                "Arbitrary External Call",
                Some("CWE-749"),
            )),
            VulnerabilityCategory::CrossChainReplay => {
                Some(SwcId::new("41S-006", "Cross-Chain Replay", Some("CWE-294")))
            }
            VulnerabilityCategory::InputValidationFailure => Some(SwcId::new(
                "41S-007",
                "Input Validation Failure",
                Some("CWE-20"),
            )),
            VulnerabilityCategory::DecimalPrecisionMismatch => Some(SwcId::new(
                "41S-008",
                "Decimal Precision Mismatch",
                Some("CWE-190"),
            )),
            VulnerabilityCategory::UnprotectedProxyUpgrade => Some(SwcId::new(
                "41S-009",
                "Unprotected Proxy Upgrade",
                Some("CWE-284"),
            )),
            VulnerabilityCategory::MEVExploitable => {
                Some(SwcId::new("41S-010", "MEV Exploitable", Some("CWE-362")))
            }
            VulnerabilityCategory::CallbackInjection => {
                Some(SwcId::new("41S-011", "Callback Injection", Some("CWE-94")))
            }
            VulnerabilityCategory::GovernanceAttack => {
                Some(SwcId::new("41S-012", "Governance Attack", Some("CWE-284")))
            }
            VulnerabilityCategory::LiquidityManipulation => Some(SwcId::new(
                "41S-013",
                "Liquidity Manipulation",
                Some("CWE-807"),
            )),
            VulnerabilityCategory::BridgeVulnerability => Some(SwcId::new(
                "41S-014",
                "Bridge Vulnerability",
                Some("CWE-345"),
            )),
            VulnerabilityCategory::LogicError => {
                Some(SwcId::new("41S-015", "Logic Error", Some("CWE-840")))
            }
            VulnerabilityCategory::MetaTransactionVulnerability => Some(SwcId::new(
                "41S-016",
                "Meta-Transaction Vulnerability",
                Some("CWE-345"),
            )),
            VulnerabilityCategory::UncheckedMathOperation => Some(SwcId::new(
                "41S-017",
                "Unchecked Math Operation",
                Some("CWE-190"),
            )),
            VulnerabilityCategory::TrustedForwarderBypass => Some(SwcId::new(
                "41S-018",
                "Trusted Forwarder Bypass",
                Some("CWE-345"),
            )),

            // 2024-2025 Modern patterns
            VulnerabilityCategory::ERC4626Inflation => Some(SwcId::new(
                "41S-020",
                "ERC-4626 Inflation Attack",
                Some("CWE-682"),
            )),
            VulnerabilityCategory::Permit2SignatureReuse => Some(SwcId::new(
                "41S-021",
                "Permit2 Signature Reuse",
                Some("CWE-294"),
            )),
            VulnerabilityCategory::LayerZeroTrustedRemote => Some(SwcId::new(
                "41S-022",
                "LayerZero Trusted Remote",
                Some("CWE-284"),
            )),
            VulnerabilityCategory::Create2Collision => Some(SwcId::new(
                "41S-023",
                "Create2 Address Collision",
                Some("CWE-327"),
            )),
            VulnerabilityCategory::TransientStorageReentrancy => Some(SwcId::new(
                "41S-024",
                "Transient Storage Reentrancy",
                Some("CWE-841"),
            )),
            VulnerabilityCategory::Push0Compatibility => Some(SwcId::new(
                "41S-025",
                "PUSH0 Compatibility",
                Some("CWE-1104"),
            )),
            VulnerabilityCategory::BlobDataHandling => {
                Some(SwcId::new("41S-026", "Blob Data Handling", Some("CWE-20")))
            }
            VulnerabilityCategory::UniswapV4HookExploit => Some(SwcId::new(
                "41S-027",
                "Uniswap V4 Hook Exploit",
                Some("CWE-94"),
            )),
            VulnerabilityCategory::CrossChainMessageReplay => Some(SwcId::new(
                "41S-028",
                "Cross-Chain Message Replay",
                Some("CWE-294"),
            )),
            VulnerabilityCategory::L2SequencerDowntime => Some(SwcId::new(
                "41S-029",
                "L2 Sequencer Downtime",
                Some("CWE-703"),
            )),
            VulnerabilityCategory::L2GasOracle => Some(SwcId::new(
                "41S-030",
                "L2 Gas Oracle Manipulation",
                Some("CWE-807"),
            )),
            VulnerabilityCategory::BaseBridgeSecurity => Some(SwcId::new(
                "41S-031",
                "Base Bridge Security",
                Some("CWE-345"),
            )),

            // Research Paper: "Security Analysis of DeFi" (arXiv:2205.09524v1) patterns
            VulnerabilityCategory::StrictBalanceEquality => Some(SwcId::new(
                "SWC-132",
                "Unexpected Ether Balance",
                Some("CWE-670"),
            )),
            VulnerabilityCategory::MisleadingDataLocation => Some(SwcId::new(
                "SWC-109",
                "Uninitialized Storage Pointer",
                Some("CWE-824"),
            )),
            VulnerabilityCategory::MissingReturnValue => Some(SwcId::new(
                "41S-042",
                "Missing Return Value",
                Some("CWE-394"),
            )),
            VulnerabilityCategory::GreedyContract => {
                Some(SwcId::new("41S-043", "Greedy Contract", Some("CWE-404")))
            }
            VulnerabilityCategory::MissingEmergencyStop => Some(SwcId::new(
                "41S-044",
                "Missing Emergency Stop",
                Some("CWE-703"),
            )),
            VulnerabilityCategory::ERC777CallbackReentrancy => Some(SwcId::new(
                "41S-045",
                "ERC-777 Callback Reentrancy",
                Some("CWE-841"),
            )),
            VulnerabilityCategory::DepositForReentrancy => Some(SwcId::new(
                "41S-046",
                "DepositFor Reentrancy",
                Some("CWE-841"),
            )),
            VulnerabilityCategory::DoubleClaiming => Some(SwcId::new(
                "41S-047",
                "Double Claiming Attack",
                Some("CWE-672"),
            )),
            VulnerabilityCategory::SignatureVerificationBypass => Some(SwcId::new(
                "41S-048",
                "Signature Verification Bypass",
                Some("CWE-347"),
            )),

            // Security hardening categories (v0.6.0)
            VulnerabilityCategory::MissingStorageGap => Some(SwcId::new(
                "41S-050",
                "Missing Storage Gap",
                Some("CWE-665"),
            )),
            VulnerabilityCategory::MissingTimelock => {
                Some(SwcId::new("41S-051", "Missing Timelock", Some("CWE-284")))
            }
            VulnerabilityCategory::SelfdestructDeprecation => Some(SwcId::new(
                "41S-052",
                "Selfdestruct Deprecation",
                Some("CWE-749"),
            )),
            VulnerabilityCategory::UninitializedImplementation => Some(SwcId::new(
                "41S-053",
                "Uninitialized Implementation",
                Some("CWE-665"),
            )),
            VulnerabilityCategory::UnsafeDowncast => Some(SwcId::new(
                "41S-054",
                "Unsafe Integer Downcast",
                Some("CWE-681"),
            )),
            VulnerabilityCategory::MissingERC165 => {
                Some(SwcId::new("41S-055", "Missing ERC-165", Some("CWE-573")))
            }
            VulnerabilityCategory::MissingSwapDeadline => Some(SwcId::new(
                "41S-056",
                "Missing Swap Deadline",
                Some("CWE-362"),
            )),
            VulnerabilityCategory::HardcodedGasAmount => Some(SwcId::new(
                "41S-057",
                "Hardcoded Gas Amount",
                Some("CWE-1188"),
            )),
            VulnerabilityCategory::UnsafeTransferGas => Some(SwcId::new(
                "41S-058",
                "Unsafe Transfer Gas Limit",
                Some("CWE-1188"),
            )),
            VulnerabilityCategory::DoubleInitialization => Some(SwcId::new(
                "41S-059",
                "Double Initialization Risk",
                Some("CWE-665"),
            )),

            // 2025-2026 Exploit Patterns (v0.7.0)
            VulnerabilityCategory::MulticallStateReset => Some(SwcId::new(
                "41S-060",
                "Multicall State Reset",
                Some("CWE-841"),
            )),
            VulnerabilityCategory::InconsistentStateReset => Some(SwcId::new(
                "41S-061",
                "Inconsistent State Reset",
                Some("CWE-665"),
            )),
            VulnerabilityCategory::EIP7702TxOriginBypass => Some(SwcId::new(
                "41S-062",
                "EIP-7702 tx.origin Bypass",
                Some("CWE-477"),
            )),
            VulnerabilityCategory::TransientStorageGasReentrancy => Some(SwcId::new(
                "41S-063",
                "Transient Storage Gas Reentrancy",
                Some("CWE-841"),
            )),
            VulnerabilityCategory::ReadOnlyReentrancy => Some(SwcId::new(
                "41S-064",
                "Read-Only Reentrancy",
                Some("CWE-841"),
            )),
            VulnerabilityCategory::ERC2771MulticallSpoofing => Some(SwcId::new(
                "41S-065",
                "ERC2771 Multicall Spoofing",
                Some("CWE-290"),
            )),
            VulnerabilityCategory::MulticallMsgValueReuse => Some(SwcId::new(
                "41S-066",
                "Multicall msg.value Reuse",
                Some("CWE-841"),
            )),
            VulnerabilityCategory::FeeOnTransferAssumption => Some(SwcId::new(
                "41S-067",
                "Fee-on-Transfer Assumption",
                Some("CWE-682"),
            )),
            VulnerabilityCategory::UnprotectedAdminSweep => Some(SwcId::new(
                "41S-068",
                "Unprotected Admin Sweep",
                Some("CWE-284"),
            )),
            VulnerabilityCategory::UnvalidatedCrossChainReceiver => Some(SwcId::new(
                "41S-069",
                "Unvalidated Cross-Chain Receiver",
                Some("CWE-345"),
            )),
            VulnerabilityCategory::AVSSlashingRisk => {
                Some(SwcId::new("41S-070", "AVS Slashing Risk", Some("CWE-284")))
            }
            VulnerabilityCategory::CLMMMathOverflow => {
                Some(SwcId::new("41S-071", "CLMM Math Overflow", Some("CWE-190")))
            }
            VulnerabilityCategory::InconsistentRounding => Some(SwcId::new(
                "41S-072",
                "Inconsistent Rounding",
                Some("CWE-682"),
            )),
            VulnerabilityCategory::DonationAttackVector => Some(SwcId::new(
                "41S-073",
                "Donation Attack Vector",
                Some("CWE-682"),
            )),
            VulnerabilityCategory::MissingSlippageProtection => Some(SwcId::new(
                "41S-074",
                "Missing Slippage Protection",
                Some("CWE-20"),
            )),
            VulnerabilityCategory::ArbitraryReceiverCallback => Some(SwcId::new(
                "41S-075",
                "Arbitrary Receiver Callback",
                Some("CWE-841"),
            )),
            VulnerabilityCategory::IsContractPostPectra => Some(SwcId::new(
                "41S-076",
                "isContract Post-Pectra",
                Some("CWE-477"),
            )),
            VulnerabilityCategory::UnsafeMulticallDelegatecall => Some(SwcId::new(
                "41S-077",
                "Unsafe Multicall Delegatecall",
                Some("CWE-841"),
            )),

            // 2026 exploit patterns (v0.9.0)
            VulnerabilityCategory::ERC4337PaymasterAbuse => Some(SwcId::new(
                "41S-078",
                "ERC-4337 Paymaster Abuse",
                Some("CWE-345"),
            )),
            VulnerabilityCategory::EIP1271SignatureReplay => Some(SwcId::new(
                "41S-079",
                "EIP-1271 Signature Replay",
                Some("CWE-294"),
            )),
            VulnerabilityCategory::Permit2UnlimitedApproval => Some(SwcId::new(
                "41S-080",
                "Permit2 Unlimited Approval",
                Some("CWE-863"),
            )),
            VulnerabilityCategory::LRTRehypothecation => Some(SwcId::new(
                "41S-081",
                "LRT Re-Hypothecation",
                Some("CWE-682"),
            )),
            VulnerabilityCategory::StorageLayoutCollision => Some(SwcId::new(
                "41S-082",
                "Upgradeable Storage Layout Collision",
                Some("CWE-665"),
            )),
            VulnerabilityCategory::GovernanceFlashloanVoting => Some(SwcId::new(
                "41S-083",
                "Governance Flash-Loan Voting",
                Some("CWE-345"),
            )),
            VulnerabilityCategory::SandwichResistantMissing => Some(SwcId::new(
                "41S-084",
                "Missing Sandwich Resistance",
                Some("CWE-362"),
            )),
            VulnerabilityCategory::TransientStorageCompilerBug => Some(SwcId::new(
                "41S-085",
                "Transient Storage Compiler Bug (0.8.28-0.8.33)",
                Some("CWE-1038"),
            )),
            VulnerabilityCategory::EIP7702DelegateStorageCollision => Some(SwcId::new(
                "41S-086",
                "EIP-7702 Delegate Storage Collision",
                Some("CWE-665"),
            )),
            VulnerabilityCategory::LayerZeroSingleDVN => Some(SwcId::new(
                "41S-087",
                "LayerZero Single DVN Verification",
                Some("CWE-654"),
            )),
            VulnerabilityCategory::ERC7683UnvalidatedFill => Some(SwcId::new(
                "41S-088",
                "ERC-7683 Unvalidated Fill",
                Some("CWE-345"),
            )),
            VulnerabilityCategory::ERC6909FlashAccountingDrain => Some(SwcId::new(
                "41S-089",
                "ERC-6909 Flash Accounting Drain",
                Some("CWE-682"),
            )),
            VulnerabilityCategory::ERC7579UnprotectedModule => Some(SwcId::new(
                "41S-090",
                "ERC-7579 Unprotected Module Installation",
                Some("CWE-284"),
            )),
            VulnerabilityCategory::ERC7821UnprotectedExecute => Some(SwcId::new(
                "41S-091",
                "ERC-7821 Unprotected Batch Execute",
                Some("CWE-284"),
            )),
            VulnerabilityCategory::ERC7579UnrestrictedExecutor => Some(SwcId::new(
                "41S-092",
                "ERC-7579 Unrestricted Executor Dispatch",
                Some("CWE-284"),
            )),

            // Info/Quality categories (no standard SWC)
            VulnerabilityCategory::GasOptimization
            | VulnerabilityCategory::UnusedCode
            | VulnerabilityCategory::MagicNumbers
            | VulnerabilityCategory::NamingConventions
            | VulnerabilityCategory::StateVariable
            | VulnerabilityCategory::MissingEvents
            | VulnerabilityCategory::ImmutabilityIssues
            | VulnerabilityCategory::ComplexityIssues
            | VulnerabilityCategory::ExternalFunction => None,

            // ABI categories (custom IDs)
            _ => None,
        }
    }
}

/// A regex-based detection rule that matches a specific vulnerability pattern in Solidity source code.
///
/// Each rule carries its own category, severity, and human-readable metadata. The scanner
/// iterates over all rules, matching `pattern` against either individual lines (single-line
/// mode) or the full file content (multiline mode). Matched results are wrapped into
/// `Vulnerability` instances for further filtering.
///
/// `Clone` is cheap: `regex::Regex` is internally reference-counted, so cloning a rule
/// shares the compiled program instead of recompiling it.
#[derive(Clone)]
pub struct VulnerabilityRule {
    /// The vulnerability class this rule detects.
    pub category: VulnerabilityCategory,
    /// Severity rating assigned to matches of this rule.
    pub severity: VulnerabilitySeverity,
    /// Compiled regex pattern. When `multiline` is true, the `(?s)` flag is prepended
    /// so that `.` also matches newlines.
    pub pattern: Regex,
    /// Short title displayed in scan output for matches.
    pub title: String,
    /// Detailed explanation of why the matched pattern is dangerous.
    pub description: String,
    /// Remediation guidance shown to the user.
    pub recommendation: String,
    /// If `true`, the pattern is applied to the full file content (dotall mode).
    /// If `false`, the pattern is applied line-by-line.
    pub multiline: bool,
}

impl VulnerabilityRule {
    /// Create a new rule. When `multiline` is `true`, the pattern is automatically
    /// wrapped with `(?s)` (dotall mode) so `.` matches across newlines.
    ///
    /// Returns `Err` if the regex pattern is invalid.
    pub fn new(
        category: VulnerabilityCategory,
        severity: VulnerabilitySeverity,
        pattern: &str,
        title: String,
        description: String,
        recommendation: String,
        multiline: bool,
    ) -> Result<Self, regex::Error> {
        let pattern = if multiline {
            Regex::new(&format!("(?s){}", pattern))?
        } else {
            Regex::new(pattern)?
        };

        Ok(VulnerabilityRule {
            category,
            severity,
            pattern,
            title,
            description,
            recommendation,
            multiline,
        })
    }
}

/// Creates the main set of vulnerability detection rules applied to all Solidity contracts
/// regardless of compiler version.
///
/// Rules are grouped into thematic sections:
/// - Reentrancy & unsafe external calls
/// - Access control & role-based access control (RBAC)
/// - Pragma & compiler issues
/// - Randomness & PRNG weaknesses
/// - Denial-of-service (DoS) patterns
/// - Storage DoS attacks
/// - Precision loss in financial calculations
/// - Delegatecall patterns
/// - Naming conventions & documentation
/// - Slither-inspired detectors (PRNG, low-level calls, shadowing, etc.)
/// - ERC standard compliance
/// - Rekt.news real-world exploit patterns (proxy, callback, arbitrary calls, etc.)
/// - 2025 OWASP Smart Contract Top 10 (flash loans, logic errors, governance, etc.)
/// - Meta-transaction / trusted forwarder patterns
/// - Unchecked math operations (Cetus-style)
/// - Governance, liquidity manipulation, and bridge vulnerabilities
/// - Research paper patterns (strict equality, data location, emergency stop, etc.)
/// - False-negative coverage rules (msg.value in loops, isContract bypass, return bomb, etc.)
///
/// Each rule is a `VulnerabilityRule` with a compiled regex, metadata, and remediation advice.
/// Rules intentionally removed due to false-positive history are documented inline with
/// `// REMOVED:` comments explaining why.
pub fn create_vulnerability_rules() -> Vec<VulnerabilityRule> {
    vec![
        // --- Reentrancy Rules ---
        VulnerabilityRule::new(
            VulnerabilityCategory::Reentrancy,
            VulnerabilitySeverity::Critical,
            r#"\.call\{value:\s*\w+\}\(\s*""\s*\)"#,
            "Potential Reentrancy Attack".to_string(),
            "External call with value transfer found without reentrancy protection".to_string(),
            "Use ReentrancyGuard or follow checks-effects-interactions pattern".to_string(),
            false,
        )
        .unwrap(),

        // REMOVED: Too broad - .transfer() and .send() have 2300 gas limit (safe from reentrancy)
        // .call.value() is legacy syntax covered by the .call{value:} pattern above

        // Unchecked external calls - only match when return value is not captured
        VulnerabilityRule::new(
            VulnerabilityCategory::UnsafeExternalCalls,
            VulnerabilitySeverity::Medium,
            r"^\s*\w+\.call\([^)]*\)\s*;",
            "Unchecked External Call".to_string(),
            "External call return value not checked".to_string(),
            "Always check the return value of external calls".to_string(),
            false,
        )
        .unwrap(),

        // Access control issues - Missing modifier on state-changing functions
        VulnerabilityRule::new(
            VulnerabilityCategory::AccessControl,
            VulnerabilitySeverity::Critical,
            r"function\s+(set|update|change|modify|withdraw|transfer|mint|burn|pause|unpause|destroy|kill|upgrade|initialize)\w*\([^)]*\)\s+(external|public)",
            "Missing Access Control on State-Changing Function".to_string(),
            "Critical state-changing function without access control modifier".to_string(),
            "Add access control modifiers (onlyOwner, onlyRole, etc.) to protect critical functions".to_string(),
            false,
        ).unwrap(),

        // REMOVED: Too broad - was causing false positives on every public function
        // Access control is now better handled by specific critical function checks

        // Pragma issues
        VulnerabilityRule::new(
            VulnerabilityCategory::PragmaIssues,
            // Low, not Medium: floating pragma is an informational finding in every
            // professional tool (Slither: informational). Libraries intentionally float.
            VulnerabilitySeverity::Low,
            r"pragma\s+solidity\s*\^",
            "Floating Pragma".to_string(),
            "Contract uses floating pragma which can lead to compilation with different versions"
                .to_string(),
            "Use a fixed pragma version for consistent compilation".to_string(),
            false,
        )
        .unwrap(),

        // Weak randomness - only flag when block properties are used for randomness (modulo, hashing)
        VulnerabilityRule::new(
            VulnerabilityCategory::RandomnessVulnerabilities,
            VulnerabilitySeverity::High,
            r"(block\.(timestamp|difficulty|number|prevrandao|blockhash))\s*%|keccak256\(.*block\.(timestamp|difficulty|number|prevrandao)",
            "Weak Randomness Source".to_string(),
            "Using predictable block properties for randomness generation".to_string(),
            "Use a secure randomness source like Chainlink VRF or commit-reveal schemes".to_string(),
            false,
        ).unwrap(),

        // DoS through gas limit
        VulnerabilityRule::new(
            VulnerabilityCategory::DoSAttacks,
            VulnerabilitySeverity::High,
            // Generalised from a hardcoded `players.length`, which only ever matched
            // one contract's variable name. Any nested iteration over dynamic arrays is
            // O(n^2): the duplicate-check loop in Puppy Raffle's `enterRaffle` is the
            // canonical case, where each new entrant raises the gas cost for the next.
            r"for\s*\([^)]*\w+\.length[^)]*\)\s*\{[^}]*for\s*\([^)]*\w+\.length",
            "Quadratic Loop Over Dynamic Array (DoS)".to_string(),
            "Nested loops over a dynamic array cost O(n^2) gas. As the array grows, the \
             function eventually exceeds the block gas limit and becomes uncallable, and \
             early entrants pay far less gas than later ones."
                .to_string(),
            "Replace the nested scan with an O(1) lookup (e.g. a mapping of seen \
             addresses), or bound the array length."
                .to_string(),
            true,
        )
        .unwrap(),

        // REMOVED: Too broad - now handled by version-specific rules with proper context
        // This was flagging every arithmetic operation including safe ones

        // REMOVED: Magic numbers pattern was too broad - flagged every multiplication/division
        // by 2+ digit numbers including common patterns like * 100, / 1000, * 60, etc.
        // Magic number detection is better handled at the audit level, not automated scanning.

        // Unused functions
        VulnerabilityRule::new(
            VulnerabilityCategory::UnusedCode,
            VulnerabilitySeverity::Info,
            r"function\s+(_\w+)\s*\([^)]*\)\s+internal\s+view\s+returns\s*\([^)]*\)\s*\{[^}]*\}",
            "Potentially Unused Function".to_string(),
            "Internal function that may not be used anywhere".to_string(),
            "Remove unused functions to reduce contract size and complexity".to_string(),
            true,
        )
        .unwrap(),

        // REMOVED: Too broad - public state variables are common and usually intentional
        // Having public visibility is not itself a vulnerability

        // Time manipulation
        VulnerabilityRule::new(
            VulnerabilityCategory::TimeManipulation,
            VulnerabilitySeverity::Medium,
            r"block\.timestamp\s*[<>=!]+",
            "Time Dependency".to_string(),
            "Contract logic depends on block.timestamp which can be manipulated by miners"
                .to_string(),
            "Avoid time-dependent logic or use block.number instead where appropriate".to_string(),
            false,
        )
        .unwrap(),

        // REMOVED: Too broad and noisy - now handled by context-aware ImmutabilityIssues check
        // This was flagging every public uint256 regardless of whether it could be immutable

        // Typos in function/event names (common ones)
        VulnerabilityRule::new(
            VulnerabilityCategory::NamingConventions,
            VulnerabilitySeverity::Medium,
            r"raffleStarttime|kaccak256|prizeZPool|totalFEees|tokenIdRarity|SetNet|recieve|occured|transfered|Withdrawl|Deposite",
            "Potential Typo in Code".to_string(),
            "Suspected typo in variable, event, or function name that could indicate a bug".to_string(),
            "Review for typos and correct any spelling mistakes that could cause bugs".to_string(),
            false,
        ).unwrap(),

        // Sensitive data storage on-chain - more specific pattern
        VulnerabilityRule::new(
            VulnerabilityCategory::AccessControl,
            VulnerabilitySeverity::Critical,
            r"(string|bytes|bytes32)\s+(private|public|internal)?\s*s_(password|secret|privateKey|secretKey|seed|mnemonic)",
            "Sensitive Data Storage On-Chain".to_string(),
            "Storing sensitive data like passwords on blockchain - ALL data is publicly readable".to_string(),
            "NEVER store passwords, secrets, or private keys on-chain. Use off-chain storage or encryption".to_string(),
            false,
        ).unwrap(),

        // Documentation mismatch
        VulnerabilityRule::new(
            VulnerabilityCategory::NamingConventions,
            VulnerabilitySeverity::Low,
            // Bounded gap: the @param tag lives in the NatSpec block directly above the
            // function. Under the `(?s)` prefix a bare `.*` would run to the last
            // zero-arg function in the file and annotate the whole file.
            r"@param\s+\w+[\s\S]{0,300}?function\s+\w+\(\s*\)",
            "Documentation Parameter Mismatch".to_string(),
            "Function documentation mentions parameters but function has none".to_string(),
            "Fix documentation to match actual function signature".to_string(),
            true,
        )
        .unwrap(),

        // Missing owner check pattern
        VulnerabilityRule::new(
            VulnerabilityCategory::AccessControl,
            VulnerabilitySeverity::Critical,
            r"function\s+setPassword\s*\([^)]*\)\s*external\s*\{[^}]*s_password\s*=",
            "Critical: setPassword Missing Access Control".to_string(),
            "setPassword function allows ANYONE to change the password - critical security vulnerability".to_string(),
            "Add owner check: if (msg.sender != s_owner) revert(); at the beginning of the function".to_string(),
            true,
        ).unwrap(),

        // IMPROVED: Now only checks critical state-changing functions, not all external functions
        // Better handled by the "Missing Access Control on State-Changing Function" rule above
        // which specifically targets dangerous function names like set*, update*, withdraw*, etc.

        // Additional delegate call patterns in main rules
        VulnerabilityRule::new(
            VulnerabilityCategory::DelegateCalls,
            VulnerabilitySeverity::Critical,
            // Bounded: the delegatecall must be inside this function's body, not the
            // last delegatecall anywhere in the file (`(?s)` makes `.*` cross newlines).
            r"function\s+\w*proxy\w*\([^)]*\)[\s\S]{0,400}?delegatecall",
            "Proxy Function with Delegatecall".to_string(),
            "Proxy functions using delegatecall can be exploited if implementation is malicious"
                .to_string(),
            "Implement proper access controls and validate implementation contract addresses"
                .to_string(),
            true,
        )
        .unwrap(),

        // Delegatecall with external data
        VulnerabilityRule::new(
            VulnerabilityCategory::DelegateCalls,
            VulnerabilitySeverity::High,
            r"delegatecall\s*\([^)]*calldata",
            "Delegatecall with Calldata".to_string(),
            "Using raw calldata in delegatecall can lead to function selector manipulation"
                .to_string(),
            "Validate function selectors and implement proper input sanitization".to_string(),
            false,
        )
        .unwrap(),

        // Conditional delegatecall patterns
        VulnerabilityRule::new(
            VulnerabilityCategory::DelegateCalls,
            VulnerabilitySeverity::High,
            r"if\s*\([^)]*\)\s*\{[^}]*delegatecall",
            "Conditional Delegatecall".to_string(),
            "Conditional delegatecalls can lead to inconsistent contract behavior".to_string(),
            "Ensure all code paths are properly validated and tested".to_string(),
            true,
        )
        .unwrap(),

        // Delegatecall with storage variables
        VulnerabilityRule::new(
            VulnerabilityCategory::DelegateCalls,
            VulnerabilitySeverity::Critical,
            r"delegatecall\s*\([^)]*\w+Address",
            "Delegatecall with Stored Address".to_string(),
            "Using stored addresses in delegatecall without validation is dangerous".to_string(),
            "Implement address validation, whitelisting, and access controls".to_string(),
            false,
        )
        .unwrap(),

        // Role-based access control detection patterns

        // REMOVED: "OpenZeppelin AccessControl Detected" is informational noise.
        // Using OZ AccessControl is good practice, not a finding to report.

        // Functions without role-based modifiers
        VulnerabilityRule::new(
            VulnerabilityCategory::RoleBasedAccessControl,
            VulnerabilitySeverity::Critical,
            r"function\s+(grant|revoke|renounce)\w*Role\w*\([^)]*\)\s+(external|public)\s*\{",
            "Role Management Function Without Access Control".to_string(),
            "Role management functions lack proper access control modifiers".to_string(),
            "Add onlyRole(ADMIN_ROLE) or equivalent access control to role management functions"
                .to_string(),
            false,
        )
        .unwrap(),

        // Missing role checks on critical functions
        VulnerabilityRule::new(
            VulnerabilityCategory::RoleBasedAccessControl,
            VulnerabilitySeverity::Critical,
            r"function\s+(mint|burn|pause|unpause|setRole|grantRole|revokeRole)\w*\([^)]*\)\s+(external|public)\s*\{",
            "Critical Function Missing Role Check".to_string(),
            "Critical administrative function lacks role-based access control".to_string(),
            "Add onlyRole modifier with appropriate role (MINTER_ROLE, ADMIN_ROLE, etc.)".to_string(),
            false,
        ).unwrap(),

        // REMOVED: Inline require(hasRole(...)) is perfectly valid access control.
        // Flagging it as a vulnerability is misleading - it's a style preference.

        // REMOVED: "Role Definition Found" is purely informational - flagging every
        // bytes32 constant ROLE definition adds noise without security value.

        // Default admin role assignments
        VulnerabilityRule::new(
            VulnerabilityCategory::RoleBasedAccessControl,
            VulnerabilitySeverity::High,
            r"_grantRole\s*\(\s*DEFAULT_ADMIN_ROLE\s*,\s*msg\.sender\s*\)",
            "Default Admin Role Auto-Assignment".to_string(),
            "Automatically granting DEFAULT_ADMIN_ROLE to deployer may be insecure".to_string(),
            "Consider using a multi-sig or governance contract for admin role assignment"
                .to_string(),
            false,
        )
        .unwrap(),

        // Missing role admin configuration
        VulnerabilityRule::new(
            VulnerabilityCategory::RoleBasedAccessControl,
            VulnerabilitySeverity::Medium,
            r"bytes32.*ROLE.*keccak256\(",
            "Role Definition Without Admin Setup".to_string(),
            "Custom role defined but admin role relationship may not be configured".to_string(),
            "Use _setRoleAdmin() to properly configure role hierarchy".to_string(),
            false,
        )
        .unwrap(),

        // Dangerous role combinations
        VulnerabilityRule::new(
            VulnerabilityCategory::RoleBasedAccessControl,
            VulnerabilitySeverity::High,
            // A modifier follows the function name in Solidity, so the previous
            // `onlyRole(DEFAULT_ADMIN_ROLE).*function.*(mint|burn|transfer)` ordering
            // could only ever match ACROSS functions -- and with `(?s)` the greedy `.*`
            // ran to the end of the file. Match the real shape instead: a critical
            // token function whose own signature carries onlyRole(DEFAULT_ADMIN_ROLE).
            r"function\s+\w*(?:mint|burn|transfer)\w*\s*\([^)]*\)[^{;]*onlyRole\s*\(\s*DEFAULT_ADMIN_ROLE\s*\)",
            "Over-Privileged Admin Role".to_string(),
            "DEFAULT_ADMIN_ROLE has direct access to critical token functions".to_string(),
            "Separate admin role from operational roles (MINTER_ROLE, BURNER_ROLE)".to_string(),
            true,
        )
        .unwrap(),

        // REMOVED: Flagging every grantRole() call is too noisy. OpenZeppelin AccessControl
        // already includes renounceRole(). Custom role systems are caught by other rules.

        // Role-based reentrancy issues
        VulnerabilityRule::new(
            VulnerabilityCategory::RoleBasedAccessControl,
            VulnerabilitySeverity::High,
            // `external` precedes the modifier in a Solidity signature, so requiring
            // `onlyRole.*external` only matched across functions; with `(?s)` both `.*`
            // ran to the end of the file. Bound the gap to the guarded function body.
            r"onlyRole\s*\([^)]*\)[\s\S]{0,400}?\.call\{value:",
            "Role-Based Function with External Call".to_string(),
            "Role-protected function makes external calls - potential reentrancy risk".to_string(),
            "Add reentrancy guards to role-protected functions making external calls".to_string(),
            true,
        )
        .unwrap(),

        // Custom role system detection
        VulnerabilityRule::new(
            VulnerabilityCategory::RoleBasedAccessControl,
            VulnerabilitySeverity::Medium,
            r"mapping\s*\(\s*address\s*=>\s*bool\s*\)\s+(public\s+)?admins?|mapping\s*\(\s*address\s*=>\s*bool\s*\)\s+(public\s+)?operators?",
            "Custom Role System Detected".to_string(),
            "Custom role system using address => bool mapping".to_string(),
            "Consider using OpenZeppelin AccessControl for standardized role management".to_string(),
            false,
        ).unwrap(),

        // REMOVED: Role enumeration (getRoleMemberCount/getRoleMember) is standard
        // OpenZeppelin AccessControlEnumerable. Not a vulnerability.

        // Missing role validation in constructors
        VulnerabilityRule::new(
            VulnerabilityCategory::RoleBasedAccessControl,
            VulnerabilitySeverity::Medium,
            // `grantRole.*msg\.sender` with `(?s)` reached the last `msg.sender` in the
            // file; the grantee is an argument of the very same call.
            r"constructor\s*\([^)]*\)\s*\{[^}]*grantRole\s*\([^)]*msg\.sender",
            "Constructor Role Assignment to Deployer".to_string(),
            "Constructor automatically assigns roles to deployer without validation".to_string(),
            "Consider requiring explicit role setup or using parameter validation".to_string(),
            true,
        )
        .unwrap(),

        // Role-based function without proper validation
        VulnerabilityRule::new(
            VulnerabilityCategory::RoleBasedAccessControl,
            VulnerabilitySeverity::High,
            // onlyRole belongs to this function's signature (before the body brace) and
            // the grantRole call to its body -- both `.*` were unbounded under `(?s)`.
            r"function\s+\w+\([^)]*address\s+\w+[^)]*\)[^{;]*onlyRole[\s\S]{0,400}?grantRole\s*\([^,]*,\s*\w+\s*\)",
            "Role Assignment Without Address Validation".to_string(),
            "Function grants roles to addresses without proper validation".to_string(),
            "Add address validation (non-zero, not contract, etc.) before role assignment"
                .to_string(),
            true,
        )
        .unwrap(),

        // REMOVED: "Timelock Integration Detected" is informational noise.
        // Having a timelock is a GOOD security practice, not a finding.

        // Role inheritance issues
        VulnerabilityRule::new(
            VulnerabilityCategory::RoleBasedAccessControl,
            VulnerabilitySeverity::Medium,
            r"_setRoleAdmin\s*\([^,]*,\s*\w+_ROLE\s*\)",
            "Role Admin Hierarchy Setup".to_string(),
            "Role admin hierarchy being configured - verify proper permission structure"
                .to_string(),
            "Ensure role admin relationships follow principle of least privilege".to_string(),
            false,
        )
        .unwrap(),

        // ZorpAudit Report Vulnerabilities - Storage DoS Attacks

        // Unbounded mapping assignments - submitData pattern
        VulnerabilityRule::new(
            VulnerabilityCategory::StorageDoSAttacks,
            VulnerabilitySeverity::Critical,
            r"index_\w+\s*\[\s*\+\+\w+\s*\]\s*=\s*msg\.sender",
            "Storage DoS via Unbounded Mapping Assignment".to_string(),
            "Unbounded mapping assignments allowing repeated submissions can cause storage DoS"
                .to_string(),
            "Implement submission limits, participant validation, or emergency stop mechanisms"
                .to_string(),
            false,
        )
        .unwrap(),

        // General unbounded storage pattern
        VulnerabilityRule::new(
            VulnerabilityCategory::StorageDoSAttacks,
            VulnerabilitySeverity::High,
            r"mapping\s*\([^)]*\)\s+\w+.*\[\s*\+\+\w+\s*\]",
            "Potential Storage DoS via Incremental Mapping".to_string(),
            "Incremental mapping assignments without bounds checking can lead to storage DoS"
                .to_string(),
            "Add participation limits, time bounds, or maximum submission constraints".to_string(),
            false,
        )
        .unwrap(),

        // Unbounded array pushes
        VulnerabilityRule::new(
            VulnerabilityCategory::StorageDoSAttacks,
            VulnerabilitySeverity::High,
            r"\w+\.push\s*\([^)]*msg\.sender[^)]*\)",
            "Unbounded Array Push DoS".to_string(),
            "Unbounded array operations can cause gas limit DoS attacks".to_string(),
            "Implement array size limits and validate user input before storage operations"
                .to_string(),
            false,
        )
        .unwrap(),

        // Submission functions without proper limits
        VulnerabilityRule::new(
            VulnerabilityCategory::StorageDoSAttacks,
            VulnerabilitySeverity::Medium,
            // `.*\{` was greedy across the whole file under `(?s)`: it latched onto the
            // LAST `{` in the file. `[^{]*\{` pins it to this function's own body.
            r"function\s+submit\w*\([^)]*\)\s+external[^{]*\{[^}]*\+\+",
            "Submission Function Without Rate Limiting".to_string(),
            "Submission functions lack rate limiting or spam protection mechanisms".to_string(),
            "Add time-based limits, maximum submissions per user, or validation checks".to_string(),
            true,
        )
        .unwrap(),

        // Storage operations in loops
        VulnerabilityRule::new(
            VulnerabilityCategory::StorageDoSAttacks,
            VulnerabilitySeverity::Medium,
            // `mapping.*=` ran to the last `=` in the file under `(?s)`, stretching the
            // reported span over everything after the loop. Keep it on one statement.
            r"for\s*\([^)]*\)\s*\{[^}]*mapping[^;{}]*=",
            "Storage Operations in Loops".to_string(),
            "Storage operations within loops can cause excessive gas consumption".to_string(),
            "Consider batching operations or using different data structures".to_string(),
            true,
        )
        .unwrap(),

        // ZorpAudit Report Vulnerabilities - Precision Loss

        // Integer division without remainder handling - endStudy pattern
        VulnerabilityRule::new(
            VulnerabilityCategory::PrecisionLoss,
            VulnerabilitySeverity::Critical,
            r"participant_payout_amount\s*=\s*balance\s*/\s*valid_submissions",
            "Financial Division Without Remainder Handling".to_string(),
            "Division of funds without proper remainder handling causes precision loss and fund loss".to_string(),
            "Use modulus operator (%) to calculate and handle remainders properly".to_string(),
            false,
        ).unwrap(),

        // General balance division patterns
        VulnerabilityRule::new(
            VulnerabilityCategory::PrecisionLoss,
            VulnerabilitySeverity::High,
            r"balance\s*/\s*\w+\s*;",
            "Balance Division Without Remainder Check".to_string(),
            "Dividing contract balance without remainder consideration can lead to fund loss"
                .to_string(),
            "Calculate and handle remainders using modulus operator to prevent fund loss"
                .to_string(),
            false,
        )
        .unwrap(),

        // Payout calculations
        VulnerabilityRule::new(
            VulnerabilityCategory::PrecisionLoss,
            VulnerabilitySeverity::High,
            r"payout.*=.*address\(this\)\.balance\s*/",
            "Payout Calculation Precision Loss".to_string(),
            "Payout calculations using integer division can result in precision loss".to_string(),
            "Implement proper remainder handling and consider using fixed-point arithmetic"
                .to_string(),
            false,
        )
        .unwrap(),

        // REMOVED: Flagged ALL uint256 division operations (uint256 x = a / b).
        // Division is fundamental to Solidity - this generated massive false positives.
        // Precision-sensitive division is caught by the more specific rules above
        // (balance division, reward distribution, pricing calculations).

        // REMOVED: Pattern (reward|distribution|share)\w*\s*=.*\/ flagged ANY line containing
        // "reward", "distribution", or "share" with ANY division anywhere on the line.
        // This was far too broad - the specific patterns above catch real precision issues.

        // Missing remainder calculations
        VulnerabilityRule::new(
            VulnerabilityCategory::PrecisionLoss,
            VulnerabilitySeverity::Low,
            r"uint256\s+remainder\s*=\s*\w+\s*-\s*\(",
            "Manual Remainder Calculation".to_string(),
            "Manual remainder calculation detected - verify correctness".to_string(),
            "Consider using modulus operator (%) for more accurate remainder calculation"
                .to_string(),
            false,
        )
        .unwrap(),

        // Transfer remainder patterns that may be incorrect
        VulnerabilityRule::new(
            VulnerabilityCategory::PrecisionLoss,
            VulnerabilitySeverity::Medium,
            r"msg\.sender\.call\{\s*value:\s*remainder\s*\}",
            "Remainder Transfer to msg.sender".to_string(),
            "Transferring remainders to msg.sender instead of proper recipient".to_string(),
            "Transfer remainders to the appropriate party (owner/treasury) not msg.sender"
                .to_string(),
            false,
        )
        .unwrap(),

        // Additional advanced detectors inspired by Slither

        // Bad PRNG patterns
        VulnerabilityRule::new(
            VulnerabilityCategory::BadPRNG,
            VulnerabilitySeverity::High,
            r"uint\w*\s+\w+\s*=\s*uint\w*\s*\(.*block\.\w+.*\)\s*%",
            "Bad Pseudo-Random Number Generation".to_string(),
            "Using block properties for randomness is predictable and can be manipulated"
                .to_string(),
            "Use Chainlink VRF or commit-reveal schemes for secure randomness".to_string(),
            false,
        )
        .unwrap(),

        // Unchecked low-level calls
        VulnerabilityRule::new(
            VulnerabilityCategory::LowLevelCalls,
            VulnerabilitySeverity::Medium,
            r"\.(call|delegatecall|staticcall)\s*\([^)]*\)\s*;",
            "Unchecked Low-Level Call".to_string(),
            "Low-level call return value not checked - can lead to silent failures".to_string(),
            "Always check return value: (bool success,) = target.call(); require(success);"
                .to_string(),
            false,
        )
        .unwrap(),

        // REMOVED: "Missing Event Emission" flagged ALL transfer/approve/mint/burn function
        // declarations without checking if events are actually emitted in the function body.
        // This requires multi-line analysis and is better handled by the advanced analyzer.

        // REMOVED: Too broad - flags every variable declaration
        // Solidity auto-initializes variables to default values, this is usually intentional
        // Now handled by context-aware detection in scanner.rs

        // Unused return values - only match ERC20 transferFrom (2+ args), not payable.transfer()
        VulnerabilityRule::new(
            VulnerabilityCategory::UnusedReturnValues,
            VulnerabilitySeverity::Medium,
            r"\w+\.transferFrom\s*\(",
            "Unused Return Value from transferFrom".to_string(),
            "ERC20 transferFrom return value should be checked".to_string(),
            "Use SafeERC20.safeTransferFrom() or check: require(token.transferFrom(...));"
                .to_string(),
            false,
        )
        .unwrap(),

        // REMOVED: "Could be immutable" flagged every address state variable declaration
        // without checking if the variable is actually only set in the constructor.
        // This requires data-flow analysis that regex cannot provide.

        // Shadowing state variables
        VulnerabilityRule::new(
            VulnerabilityCategory::ShadowingIssues,
            VulnerabilitySeverity::Medium,
            r"function\s+\w+\([^)]*uint\w*\s+totalSupply[^)]*\)",
            "State Variable Shadowing".to_string(),
            "Function parameter shadows state variable name causing confusion".to_string(),
            "Use different names for function parameters to avoid shadowing".to_string(),
            false,
        )
        .unwrap(),

        // Incorrect equality comparisons
        VulnerabilityRule::new(
            VulnerabilityCategory::IncorrectEquality,
            VulnerabilitySeverity::High,
            r"address\(this\)\.balance\s*==\s*\d+",
            "Strict Equality on Balance".to_string(),
            "Strict equality on balance can be manipulated by force-sending ether".to_string(),
            "Use >= or <= instead of == for balance checks".to_string(),
            false,
        )
        .unwrap(),

        // Assembly usage detection
        VulnerabilityRule::new(
            VulnerabilityCategory::AssemblyUsage,
            VulnerabilitySeverity::High,
            r"assembly\s*\{",
            "Inline Assembly Usage".to_string(),
            "Assembly code bypasses Solidity safety checks and is error-prone".to_string(),
            "Avoid assembly unless absolutely necessary, audit thoroughly if used".to_string(),
            false,
        )
        .unwrap(),

        // Deprecated functions
        VulnerabilityRule::new(
            VulnerabilityCategory::DeprecatedFunctions,
            VulnerabilitySeverity::Medium,
            r"\.(callcode|sha3|suicide)\s*\(",
            "Deprecated Function Usage".to_string(),
            "Using deprecated Solidity functions that may be removed in future versions"
                .to_string(),
            "Replace callcode with delegatecall, sha3 with keccak256, suicide with selfdestruct"
                .to_string(),
            false,
        )
        .unwrap(),

        // High complexity detection
        VulnerabilityRule::new(
            VulnerabilityCategory::ComplexityIssues,
            VulnerabilitySeverity::Info,
            r"function\s+\w+\([^)]*\)[^{]*\{[^}]*if[^}]*if[^}]*if[^}]*if",
            "High Cyclomatic Complexity".to_string(),
            "Function has high complexity with multiple nested conditions".to_string(),
            "Refactor complex functions into smaller, more manageable pieces".to_string(),
            true,
        )
        .unwrap(),

        // REMOVED: "Public could be external" flagged every public view function.
        // This is a minor gas optimization, not a vulnerability, and requires
        // call-graph analysis to determine if the function is called internally.

        // Signature malleability
        VulnerabilityRule::new(
            VulnerabilityCategory::SignatureVulnerabilities,
            VulnerabilitySeverity::High,
            r"ecrecover\s*\([^,]*,[^,]*,[^,]*,[^,]*\)",
            "Signature Malleability Vulnerability".to_string(),
            "ecrecover is vulnerable to signature malleability attacks".to_string(),
            "Use OpenZeppelin's ECDSA library which prevents signature malleability".to_string(),
            false,
        )
        .unwrap(),

        // Oracle manipulation
        VulnerabilityRule::new(
            VulnerabilityCategory::OracleManipulation,
            VulnerabilitySeverity::Critical,
            r"(getReserves|getAmountsOut|getAmountOut)\s*\(",
            "DEX Price Oracle Manipulation Risk".to_string(),
            "Using DEX reserves directly as price oracle is vulnerable to flash loan attacks"
                .to_string(),
            "Use time-weighted average prices (TWAP) or Chainlink oracles instead".to_string(),
            false,
        )
        .unwrap(),

        // Cache array length optimization
        VulnerabilityRule::new(
            VulnerabilityCategory::GasOptimization,
            VulnerabilitySeverity::Info,
            r"for\s*\([^;]*;\s*\w+\s*<\s*\w+\.length\s*;",
            "Cache Array Length in Loops".to_string(),
            "Reading array.length in loop condition wastes gas".to_string(),
            "Cache array length before loop: uint256 len = arr.length; for(uint i; i < len; i++)"
                .to_string(),
            false,
        )
        .unwrap(),

        // REMOVED: "Void Constructor Pattern" flagged ANY function starting with uppercase.
        // This is only relevant for Solidity <0.4.22 and is handled by version-specific rules.

        // Missing zero address validation
        VulnerabilityRule::new(
            VulnerabilityCategory::AccessControl,
            VulnerabilitySeverity::Medium,
            r"function\s+\w*[Ss]et\w*\([^)]*address\s+\w+[^)]*\)",
            "Missing Zero Address Validation".to_string(),
            "Function accepting address parameter - verify zero address check".to_string(),
            "Add require(address != address(0), 'Zero address') validation".to_string(),
            false,
        )
        .unwrap(),

        // Encode packed collision
        VulnerabilityRule::new(
            VulnerabilityCategory::SignatureVulnerabilities,
            VulnerabilitySeverity::High,
            r"abi\.encodePacked\([^)]*\)[^)]*keccak256",
            "Hash Collision Risk with encodePacked".to_string(),
            "Using abi.encodePacked in hashing can cause collisions with dynamic types".to_string(),
            "Use abi.encode instead of abi.encodePacked for hash generation".to_string(),
            false,
        )
        .unwrap(),

        // Additional ERC Standard Compliance Checks

        // ERC-20 missing return values
        VulnerabilityRule::new(
            VulnerabilityCategory::ABITokenStandard,
            VulnerabilitySeverity::High,
            r"function\s+transfer\s*\([^)]*\)\s+(external|public)\s+returns\s*\(\s*\)",
            "ERC-20 Transfer Missing Return Value".to_string(),
            "ERC-20 transfer function should return bool, not void".to_string(),
            "Change return type to 'returns (bool)' and return true on success".to_string(),
            false,
        )
        .unwrap(),

        // Missing zero address checks in critical functions
        VulnerabilityRule::new(
            VulnerabilityCategory::AccessControl,
            VulnerabilitySeverity::High,
            r"function\s+(constructor|initialize)\s*\([^)]*address\s+[^)]*\)",
            "Constructor/Initialize With Address Parameter".to_string(),
            "Constructor/initialize function accepts address without zero-address check"
                .to_string(),
            "Add 'require(address != address(0))' check for all address parameters".to_string(),
            false,
        )
        .unwrap(),

        // Hardcoded gas values
        VulnerabilityRule::new(
            VulnerabilityCategory::GasOptimization,
            VulnerabilitySeverity::Medium,
            r"\.call\{gas:\s*\d+",
            "Hardcoded Gas Value".to_string(),
            "Hardcoded gas values can break with EVM changes".to_string(),
            "Avoid hardcoded gas values, use gasleft() or dynamic calculations".to_string(),
            false,
        )
        .unwrap(),

        // Unbounded array iteration - more specific
        VulnerabilityRule::new(
            VulnerabilityCategory::DoSAttacks,
            VulnerabilitySeverity::High,
            r"for\s*\([^)]*;\s*\w+\s*<\s*\w+\[\]\.length\s*;",
            "Unbounded Array Iteration Risk".to_string(),
            "Iterating over dynamic array without bounds can cause gas limit DoS".to_string(),
            "Implement pagination, maximum iteration limits, or use pull-over-push pattern"
                .to_string(),
            false,
        )
        .unwrap(),

        // Missing input validation on amounts
        VulnerabilityRule::new(
            VulnerabilityCategory::AccessControl,
            VulnerabilitySeverity::Medium,
            r"function\s+\w*(deposit|stake|lock|add)\w*\s*\([^)]*uint\w*\s+amount[^)]*\)\s+(external|public)\s*\{",
            "Missing Amount Validation".to_string(),
            "Function accepts amount parameter - verify zero-value protection".to_string(),
            "Consider adding 'require(amount > 0)' to prevent zero-value operations".to_string(),
            false,
        ).unwrap(),

        // Dangerous strict equality on ether balance
        VulnerabilityRule::new(
            VulnerabilityCategory::IncorrectEquality,
            VulnerabilitySeverity::Critical,
            r"(address\(this\)\.balance|this\.balance)\s*==\s*\d+",
            "Strict Equality on Contract Balance".to_string(),
            "Contract balance can be manipulated via selfdestruct, breaking == checks".to_string(),
            "Use >= or <= instead of == for balance checks".to_string(),
            false,
        )
        .unwrap(),

        // ============================================================================
        // REKT.NEWS REAL-WORLD EXPLOIT PATTERNS (2024-2025)
        // Based on $3.1B+ in actual losses - High-priority detection rules
        // ============================================================================

        // 1. PROXY ADMIN VULNERABILITIES (Aevo/Ribbon Finance - $2.7M Dec 2025)
        // Unprotected transferOwnership and setImplementation functions
        VulnerabilityRule::new(
            VulnerabilityCategory::ProxyAdminVulnerability,
            VulnerabilitySeverity::Critical,
            r"function\s+(transferOwnership|setImplementation)\s*\([^)]*\)\s+(external|public)\s*\{",
            "Unprotected Proxy Admin Function (Aevo Pattern)".to_string(),
            "CRITICAL: Proxy admin functions without access control - $2.7M Aevo exploit pattern".to_string(),
            "Add onlyOwner or role-based access control to all proxy admin functions".to_string(),
            false,
        ).unwrap(),

        // Unprotected proxy upgrade path (detected in advanced analyzer with proper checks)
        VulnerabilityRule::new(
            VulnerabilityCategory::UnprotectedProxyUpgrade,
            VulnerabilitySeverity::Critical,
            r"function\s+upgrade\w*\s*\([^)]*\)\s+(external|public)",
            "Proxy Upgrade Function Detected".to_string(),
            "Upgrade function found - verify it has proper access control".to_string(),
            "Ensure upgrade functions have onlyOwner/onlyRole and consider timelock".to_string(),
            false,
        )
        .unwrap(),

        // REMOVED: Too broad - matched ANY mention of upgradeTo/setImplementation including
        // OpenZeppelin imports, comments, and properly protected implementations.
        // Proxy upgrade detection is better handled by the specific function-signature rules above.

        // 2. CALLBACK REENTRANCY (ERC721/ERC1155 - Omni NFT $1.43M, Multiple 2024 incidents)
        // onERC721Received callback exploitation
        VulnerabilityRule::new(
            VulnerabilityCategory::CallbackReentrancy,
            VulnerabilitySeverity::Critical,
            r"safeTransferFrom\s*\([^)]*\)|_safeMint\s*\(",
            "ERC721 Callback Reentrancy Risk".to_string(),
            "safeTransferFrom/safeMint trigger onERC721Received callback - reentrancy vector ($1.43M Omni)".to_string(),
            "Use ReentrancyGuard or checks-effects-interactions pattern before safe transfers".to_string(),
            false,
        ).unwrap(),

        // onERC1155Received callback - all ERC1155 operations callback
        VulnerabilityRule::new(
            VulnerabilityCategory::CallbackReentrancy,
            VulnerabilitySeverity::Critical,
            r"_mint.*ERC1155|safeTransferFrom.*ERC1155|safeBatchTransferFrom",
            "ERC1155 Callback Reentrancy Risk".to_string(),
            "ALL ERC1155 operations call receiving contract - critical reentrancy surface"
                .to_string(),
            "Mandatory ReentrancyGuard for all ERC1155 operations that change state".to_string(),
            false,
        )
        .unwrap(),

        // REMOVED: "State Change After Callback Operation". In dotall mode
        // `(safeTransferFrom|...).*\n.*=` matched from any callback NAME (including standard
        // interface implementations and function declarations) to any `=` later in the file.
        // Real callback reentrancy is covered by the CEI detector and CFG reentrancy analysis.

        // 3. ARBITRARY EXTERNAL CALLS ($21M across 18 incidents in 2024)
        // User-controlled call targets
        VulnerabilityRule::new(
            VulnerabilityCategory::ArbitraryExternalCall,
            VulnerabilitySeverity::Critical,
            // The former `|\.delegatecall\(` alternative flagged EVERY delegatecall in
            // the file (dotall mode); delegatecall risks are covered by DelegateCalls rules.
            r"function\s+\w+\([^)]*address\s+target[^)]*\)[^}]*\.(call|delegatecall)\s*\(",
            "Arbitrary External Call to User Address".to_string(),
            "Function allows external calls to user-controlled addresses ($21M in 2024)"
                .to_string(),
            "Implement address whitelist and validate all external call targets".to_string(),
            true,
        )
        .unwrap(),

        // Arbitrary calldata execution
        VulnerabilityRule::new(
            VulnerabilityCategory::ArbitraryExternalCall,
            VulnerabilitySeverity::Critical,
            r"\.call\s*\(\s*\w+\s*\)|\.call\{[^}]*\}\s*\(\s*calldata",
            "Arbitrary Calldata Execution".to_string(),
            "Contract executes arbitrary calldata without validation - critical exploit vector"
                .to_string(),
            "Validate function selectors and implement strict calldata verification".to_string(),
            false,
        )
        .unwrap(),

        // REMOVED: "Array Parameter Detected" — flagged every external/public function with
        // an array parameter as High. detect_input_validation_patterns() in
        // advanced_analysis.rs handles the dangerous case (function loops over the array
        // without a length bound) with proper context checking.

        // Address parameters - validated in advanced analyzer for zero-address checks
        // Removed negative lookahead - handled by context-aware analysis

        // REMOVED: "Calldata Parameter Detected" - flagged every function with a calldata param
        // as Critical. Calldata is a standard Solidity parameter location, not a vulnerability.
        // The advanced_analysis.rs detect_input_validation_patterns() handles the dangerous case
        // (bytes calldata without validation) with proper context checking.

        // 5. DECIMAL/PRECISION MISMATCH (Aevo/Ribbon - precision mismatch exploited)
        // Mixing different decimal precisions
        VulnerabilityRule::new(
            VulnerabilityCategory::DecimalPrecisionMismatch,
            VulnerabilitySeverity::Critical,
            // The second group's parentheses were escaped, turning the whole pattern into
            // a top-level alternation: `(...)…\+…\(1e18` OR `1e8` OR `10**18` OR `10**8)`.
            // Any line merely containing `1e8` was reported as a Critical mismatch.
            r"(?:1e18|1e8|10\*\*18|10\*\*8).*\+.*(?:1e18|1e8|10\*\*18|10\*\*8)",
            "Decimal Precision Mismatch Risk".to_string(),
            "Mixing different decimal precisions (18 vs 8) - Aevo $2.7M exploit pattern"
                .to_string(),
            "Normalize all values to same precision before arithmetic operations".to_string(),
            false,
        )
        .unwrap(),

        // REMOVED: Flagging all .decimals() usage is counterproductive - using decimals()
        // is the correct way to handle token precision. The decimal mismatch rule above
        // already catches the real vulnerability (mixing different precisions).

        // 6. SIGNATURE REPLAY ATTACKS (Multiple cross-chain incidents 2024-2025)
        // Signature verification patterns - detailed checks in advanced analyzer
        // (ecrecover usage triggers advanced analysis for nonce and chainId)

        // Missing deadline in permit/meta-transactions
        VulnerabilityRule::new(
            VulnerabilityCategory::SignatureReplay,
            VulnerabilitySeverity::High,
            r"permit\s*\(|executeMetaTransaction",
            "Missing Signature Deadline".to_string(),
            "Permit/meta-transaction without deadline allows indefinite signature validity"
                .to_string(),
            "Add deadline parameter and verify block.timestamp <= deadline".to_string(),
            false,
        )
        .unwrap(),

        // 7. MEV FRONT-RUNNING (19% YoY increase, $675M MEV profits 2025)
        // Swap functions - detailed MEV check in advanced analyzer
        // (checks for both slippage AND deadline)

        // Public liquidation without priority
        VulnerabilityRule::new(
            VulnerabilityCategory::MEVExploitable,
            VulnerabilitySeverity::Medium,
            r"function\s+liquidate\w*\([^)]*\)\s+(external|public)",
            "MEV Front-Running: Public Liquidation".to_string(),
            "Public liquidation functions are MEV targets - consider private relayers".to_string(),
            "Implement MEV protection: private mempool, Flashbots, or commit-reveal".to_string(),
            false,
        )
        .unwrap(),

        // Oracle and callback patterns - detailed checks in advanced analyzer
        // (These require context analysis to avoid false positives)

        // 9. PRECISION LOSS IN CRITICAL CALCULATIONS (Multiple incidents)
        // Division before multiplication in pricing
        VulnerabilityRule::new(
            VulnerabilityCategory::PrecisionLoss,
            VulnerabilitySeverity::Critical,
            r"(price|Price|value|Value|amount|Amount)\w*\s*=\s*\w+\s*/\s*\w+\s*\*",
            "Precision Loss in Pricing Calculation".to_string(),
            "Division before multiplication in price calculations loses precision".to_string(),
            "Multiply before division: (a * b) / c instead of (a / c) * b".to_string(),
            false,
        )
        .unwrap(),

        // Integer division without remainder handling in distributions
        VulnerabilityRule::new(
            VulnerabilityCategory::PrecisionLoss,
            VulnerabilitySeverity::High,
            r"(reward|distribution|payout|share)\w*\s*=.*totalSupply\s*/",
            "Precision Loss in Token Distribution".to_string(),
            "Integer division in distribution without remainder tracking loses funds".to_string(),
            "Track remainders: uint256 remainder = totalAmount % totalRecipients".to_string(),
            false,
        )
        .unwrap(),

        // ============================================================================
        // 2025 SECURITY PATTERNS - Additional critical vulnerabilities
        // ============================================================================

        // EIP-4337 Account Abstraction - validateUserOp without proper validation
        VulnerabilityRule::new(
            VulnerabilityCategory::AccessControl,
            VulnerabilitySeverity::Critical,
            r"function\s+validateUserOp\s*\([^)]*\)\s+(external|public)",
            "EIP-4337 validateUserOp Exposure".to_string(),
            "Account abstraction entry point must validate signatures and prevent replay"
                .to_string(),
            "Verify signature, check nonce, validate gas limits, and ensure proper return value"
                .to_string(),
            false,
        )
        .unwrap(),

        // CREATE2 with attacker-controlled salt
        VulnerabilityRule::new(
            VulnerabilityCategory::ArbitraryExternalCall,
            VulnerabilitySeverity::High,
            r"create2\s*\([^,]*,\s*\w+\s*,",
            "CREATE2 Predictable Address Attack".to_string(),
            "CREATE2 with user-controlled salt enables address prediction attacks".to_string(),
            "Use msg.sender in salt computation to prevent address hijacking".to_string(),
            false,
        )
        .unwrap(),

        // ERC-2612 permit without deadline validation
        VulnerabilityRule::new(
            VulnerabilityCategory::SignatureReplay,
            VulnerabilitySeverity::High,
            r"function\s+permit\s*\([^)]*deadline[^)]*\)",
            "ERC-2612 Permit Implementation".to_string(),
            "Permit function requires deadline validation before processing".to_string(),
            "Add require(block.timestamp <= deadline, 'Permit expired') at function start"
                .to_string(),
            false,
        )
        .unwrap(),

        // Fee-on-transfer token handling
        VulnerabilityRule::new(
            VulnerabilityCategory::InputValidationFailure,
            VulnerabilitySeverity::High,
            r"transferFrom\s*\([^)]*amount[^)]*\).*=.*amount",
            "Fee-on-Transfer Token Vulnerability".to_string(),
            "Assuming received amount equals transferred amount fails with fee tokens".to_string(),
            "Check actual received: uint256 received = balanceAfter - balanceBefore".to_string(),
            false,
        )
        .unwrap(),

        // REMOVED: "Rebasing Token Balance Tracking" flagged ALL balance increments (balance += x).
        // This is standard accounting code. Rebasing token issues require semantic analysis
        // of token types, not pattern matching on balance updates.

        // Self-destruct in proxy implementation
        VulnerabilityRule::new(
            VulnerabilityCategory::UnprotectedProxyUpgrade,
            VulnerabilitySeverity::Critical,
            r"selfdestruct\s*\(|suicide\s*\(",
            "Self-Destruct in Implementation Contract".to_string(),
            "Self-destruct in proxy implementation destroys the logic contract permanently"
                .to_string(),
            "Remove selfdestruct or protect with onlyOwner AND verify not called via delegatecall"
                .to_string(),
            false,
        )
        .unwrap(),

        // REMOVED: Flagging ALL IERC20/721/1155 casts is too noisy. Interface casting is
        // standard Solidity practice. ERC-165 checks are only needed for unknown addresses,
        // not for trusted contract references.

        // Unchecked block.number usage for randomness
        VulnerabilityRule::new(
            VulnerabilityCategory::BadPRNG,
            VulnerabilitySeverity::High,
            r"block\.number\s*%|block\.number\s*\^|keccak256.*block\.number",
            "Block Number Based Randomness".to_string(),
            "Block number is predictable and manipulable by miners/validators".to_string(),
            "Use Chainlink VRF, commit-reveal, or other secure randomness sources".to_string(),
            false,
        )
        .unwrap(),

        // Cross-chain message verification
        VulnerabilityRule::new(
            VulnerabilityCategory::CrossChainReplay,
            VulnerabilitySeverity::Critical,
            r"function\s+(receiveMessage|processMessage|onMessage)\w*\s*\([^)]*\)\s+(external|public)",
            "Cross-Chain Message Handler".to_string(),
            "Cross-chain message handlers must verify source chain and sender".to_string(),
            "Verify srcChainId, trustedRemote sender, and implement replay protection".to_string(),
            false,
        ).unwrap(),

        // REMOVED: INCORRECT RULE - keccak256(abi.encode(...)) is actually the SAFE pattern.
        // abi.encode pads arguments to 32 bytes preventing collisions.
        // abi.encodePacked is the one with collision risk (already detected above).

        // Unprotected callback functions
        VulnerabilityRule::new(
            VulnerabilityCategory::CallbackReentrancy,
            VulnerabilitySeverity::High,
            r"function\s+(onERC721Received|onERC1155Received|tokensReceived)\s*\(",
            "Callback Function Exposure".to_string(),
            "Token callback functions can be exploited for reentrancy attacks".to_string(),
            "Add ReentrancyGuard and validate the callback source (operator/from)".to_string(),
            false,
        )
        .unwrap(),

        // REMOVED: Duplicate of "Hardcoded Gas Value" rule at line ~1101

        // Incorrect use of address(0) checks
        VulnerabilityRule::new(
            VulnerabilityCategory::InputValidationFailure,
            VulnerabilitySeverity::Medium,
            r"require\s*\([^)]*==\s*address\(0\)",
            "Inverted Zero Address Check".to_string(),
            "Requiring address equals zero may be inverted logic (should be !=)".to_string(),
            "Verify the check is intentional - most cases should be != address(0)".to_string(),
            false,
        )
        .unwrap(),

        // Unsafe downcasting without checks.
        // Categorised as UnsafeDowncast, not ArithmeticIssues: truncation is a distinct
        // bug from overflow, and filing it under the math group made deduplication
        // collapse it together with genuine overflow findings on the same line.
        VulnerabilityRule::new(
            VulnerabilityCategory::UnsafeDowncast,
            VulnerabilitySeverity::High,
            r"uint8\s*\(\w+\)|uint16\s*\(\w+\)|uint32\s*\(\w+\)|uint64\s*\(\w+\)|uint128\s*\(\w+\)",
            "Unsafe Integer Downcast".to_string(),
            "Downcasting without bounds check can silently truncate values".to_string(),
            "Use SafeCast library or add require(value <= type(uintX).max) before casting"
                .to_string(),
            false,
        )
        .unwrap(),

        // Note: Missing receive/fallback detection requires AST analysis
        // and is handled in advanced_analysis.rs for contracts receiving ETH

        // ============================================================================
        // 2025 OWASP SMART CONTRACT TOP 10 & RECENT EXPLOIT PATTERNS
        // Based on $1.42B in losses documented in 2024
        // ============================================================================

        // ===========================================
        // FLASH LOAN ATTACK PATTERNS (OWASP #4 - $33.8M)
        // ===========================================

        // Flash loan callback without validation
        VulnerabilityRule::new(
            VulnerabilityCategory::FlashLoanAttack,
            VulnerabilitySeverity::Critical,
            r"function\s+(executeOperation|onFlashLoan|uniswapV2Call|uniswapV3FlashCallback|pancakeCall)\s*\(",
            "Flash Loan Callback Function".to_string(),
            "Flash loan callback detected - verify proper validation of loan initiator and amount".to_string(),
            "Verify msg.sender is the lending pool, validate initiator == address(this), check amounts match".to_string(),
            false,
        ).unwrap(),

        // Flash loan amount not validated - match within a single function (limit search window)
        VulnerabilityRule::new(
            VulnerabilityCategory::FlashLoanAttack,
            VulnerabilitySeverity::Critical,
            r"function\s+\w*(flashLoan|executeOperation|onFlashLoan)\w*\s*\([^)]*uint\w*\s+(amount|loanAmount)",
            "Flash Loan Amount Manipulation Risk".to_string(),
            "Flash loan amount passed to critical logic without validation enables price manipulation".to_string(),
            "Validate flash loan amounts against protocol limits and check price impact".to_string(),
            false,
        ).unwrap(),

        // Price calculation using spot reserves (vulnerable to flash loans)
        VulnerabilityRule::new(
            VulnerabilityCategory::FlashLoanAttack,
            VulnerabilitySeverity::Critical,
            r"getReserves\(\).*price|reserve\d\s*/\s*reserve\d|token\d+\.balanceOf.*price",
            "Flash Loan Price Manipulation Vector".to_string(),
            "Using spot reserves/balances for pricing is manipulable via flash loans (Abracadabra $13M)".to_string(),
            "Use TWAP oracles, Chainlink feeds, or implement flash loan guards".to_string(),
            false,
        ).unwrap(),

        // Missing flash loan protection in governance
        VulnerabilityRule::new(
            VulnerabilityCategory::GovernanceAttack,
            VulnerabilitySeverity::Critical,
            r"function\s+(propose|vote|castVote)\w*\([^)]*\)\s+(?:external|public)",
            "Flash Loan Governance Attack Vector (Beanstalk $182M)".to_string(),
            "Governance function without flash loan protection - Beanstalk style attack possible"
                .to_string(),
            "Implement voting power snapshots, time-locks, or flash loan guards".to_string(),
            false,
        )
        .unwrap(),

        // ===========================================
        // LOGIC ERROR PATTERNS (OWASP #2 - $63.8M)
        // ===========================================

        // Incorrect reward calculation (common DeFi bug)
        VulnerabilityRule::new(
            VulnerabilityCategory::LogicError,
            VulnerabilitySeverity::High,
            r"reward\w*\s*=\s*\w+\s*\*\s*\w+\s*/\s*\w+\s*\*",
            "Potential Reward Calculation Logic Error".to_string(),
            "Complex reward calculation with multiple operations - verify order of operations"
                .to_string(),
            "Use explicit parentheses and add unit tests for edge cases (0, max values)"
                .to_string(),
            false,
        )
        .unwrap(),

        // Missing check for zero shares/supply (division by zero in DeFi)
        VulnerabilityRule::new(
            VulnerabilityCategory::LogicError,
            VulnerabilitySeverity::Critical,
            r"assets?\s*\*\s*totalSupply\s*/|shares?\s*\*\s*totalAssets\s*/",
            "ERC-4626 Vault Logic - Zero Supply Risk".to_string(),
            "Vault share calculation without zero supply check leads to first depositor attack"
                .to_string(),
            "Add require(totalSupply > 0) or use virtual shares (INITIAL_SHARES offset)"
                .to_string(),
            false,
        )
        .unwrap(),

        // Incorrect withdrawal logic
        VulnerabilityRule::new(
            VulnerabilityCategory::LogicError,
            VulnerabilitySeverity::High,
            // Both branches shared the same prefix, and `withdraw.*\{` was greedy across the
            // file under `(?s)` -- it paired a `withdraw` function with a `balance -=` in a
            // completely different function. Factor the alternation and pin the brace.
            r"function\s+withdraw[^{]*\{[^}]*balance\s*(?:-=|=\s*balance\s*-)",
            "Withdrawal Balance Update Logic".to_string(),
            "Withdrawal function modifies balance - verify it happens BEFORE external transfer".to_string(),
            "Follow CEI: update balance, then transfer. Add reentrancy guard.".to_string(),
            true,
        ).unwrap(),

        // REMOVED: Flagging every approve() call as a logic error is too broad.
        // approve() is standard ERC20 - the front-running issue is well-known and
        // OpenZeppelin's implementation handles it. This generated massive noise.

        // ===========================================
        // META-TRANSACTION / TRUSTED FORWARDER (KiloEx $7.4M)
        // ===========================================

        // MinimalForwarder pattern (KiloEx exploit)
        VulnerabilityRule::new(
            VulnerabilityCategory::MetaTransactionVulnerability,
            VulnerabilitySeverity::Critical,
            r"MinimalForwarder|MinimalForwarderUpgradeable|TrustedForwarder",
            "CRITICAL: MinimalForwarder Pattern (KiloEx $7.4M)".to_string(),
            "MinimalForwarder detected - exact pattern from KiloEx $7.4M exploit".to_string(),
            "Verify execute() validates signatures against provided data, check trustedForwarder list".to_string(),
            false,
        ).unwrap(),

        // Trusted forwarder without signature validation
        VulnerabilityRule::new(
            VulnerabilityCategory::TrustedForwarderBypass,
            VulnerabilitySeverity::Critical,
            r"function\s+execute\s*\([^)]*ForwardRequest[^)]*\)",
            "Meta-Transaction Execute Function".to_string(),
            "Meta-transaction execute function must properly validate signatures against request data".to_string(),
            "Verify signature matches (from, to, value, gas, nonce, data) and increment nonce".to_string(),
            false,
        ).unwrap(),

        // REMOVED: _msgSender()/_msgData() are standard OpenZeppelin Context functions used
        // by virtually every OZ-based contract. Flagging every occurrence floods results.
        // Meta-tx risks are better caught by the MinimalForwarder and ERC2771Context rules.

        // REMOVED: ERC2771Context and isTrustedForwarder are standard OZ implementations.
        // Flagging their presence is noise - the MinimalForwarder rule catches real issues.

        // ===========================================
        // UNCHECKED MATH OPERATIONS (Cetus $223M style)
        // ===========================================

        // Custom overflow check implementation
        VulnerabilityRule::new(
            VulnerabilityCategory::UncheckedMathOperation,
            VulnerabilitySeverity::Critical,
            r"function\s+\w*(checked|safe)\w*(Mul|Add|Sub|Div|Shl|Shr)\w*\(",
            "Custom Safe Math Implementation (Cetus Pattern)".to_string(),
            "Custom overflow checks detected - Cetus $223M exploit used flawed checked_shlw".to_string(),
            "Prefer OpenZeppelin SafeMath or Solidity 0.8+ built-in checks over custom implementations".to_string(),
            false,
        ).unwrap(),

        // Bit shift operations with variable shift amount (potential overflow)
        // Only flag variable-amount shifts; constant shifts like << 1 are safe and common
        VulnerabilityRule::new(
            VulnerabilityCategory::UncheckedMathOperation,
            VulnerabilitySeverity::High,
            r"<<\s*[a-zA-Z_]\w*|>>\s*[a-zA-Z_]\w*",
            "Variable Bit Shift Operation (Cetus Pattern)".to_string(),
            "Bit shifts with variable amounts don't revert on overflow in Solidity".to_string(),
            "Validate shift amount < 256, check for overflow BEFORE shift operation".to_string(),
            false,
        )
        .unwrap(),

        // Unchecked block with complex calculations
        VulnerabilityRule::new(
            VulnerabilityCategory::UncheckedMathOperation,
            VulnerabilitySeverity::Critical,
            r"unchecked\s*\{[^}]*((<<|>>)\s*[a-zA-Z_]|\*\*|\bsqrt\s*\(|\bexp\s*\()",
            "Unchecked Complex Math Operation".to_string(),
            "Complex math in unchecked block - bit shifts and exponents don't revert on overflow"
                .to_string(),
            "Move complex operations outside unchecked block or add explicit overflow checks"
                .to_string(),
            true,
        )
        .unwrap(),

        // Liquidity calculation patterns (AMM vulnerability)
        VulnerabilityRule::new(
            VulnerabilityCategory::UncheckedMathOperation,
            VulnerabilitySeverity::Critical,
            r"liquidity\s*=.*sqrt|deltaLiquidity|getLiquidity.*<<",
            "AMM Liquidity Calculation (Cetus Pattern)".to_string(),
            "Liquidity calculation with sqrt/shifts - exact pattern from Cetus $223M exploit".to_string(),
            "Validate inputs before calculation, add bounds checking, use well-audited math libraries".to_string(),
            false,
        ).unwrap(),

        // ===========================================
        // GOVERNANCE ATTACK PATTERNS
        // ===========================================

        // Voting without timelock
        VulnerabilityRule::new(
            VulnerabilityCategory::GovernanceAttack,
            VulnerabilitySeverity::High,
            r"function\s+execute\w*\([^)]*proposalId[^)]*\).*external",
            "Governance Execution Without Timelock".to_string(),
            "Governance execution should have timelock delay for community review".to_string(),
            "Add TimelockController with minimum delay (e.g., 24-48 hours)".to_string(),
            false,
        )
        .unwrap(),

        // Emergency functions bypassing governance
        VulnerabilityRule::new(
            VulnerabilityCategory::GovernanceAttack,
            VulnerabilitySeverity::High,
            r"function\s+emergency\w*\([^)]*\)\s+(external|public)",
            "Emergency Function Bypassing Governance".to_string(),
            "Emergency functions can bypass normal governance - ensure proper access control"
                .to_string(),
            "Require multi-sig or DAO vote for emergency actions, add cooldown period".to_string(),
            false,
        )
        .unwrap(),

        // Quorum not checked
        VulnerabilityRule::new(
            VulnerabilityCategory::GovernanceAttack,
            VulnerabilitySeverity::Medium,
            r"function\s+execute.*proposal|function\s+queue.*proposal",
            "Governance Proposal Execution".to_string(),
            "Proposal execution detected - verify quorum and vote threshold are checked"
                .to_string(),
            "Add require(quorumReached(proposalId) && voteSucceeded(proposalId))".to_string(),
            false,
        )
        .unwrap(),

        // ===========================================
        // LIQUIDITY MANIPULATION PATTERNS
        // ===========================================

        // Unprotected addLiquidity
        VulnerabilityRule::new(
            VulnerabilityCategory::LiquidityManipulation,
            VulnerabilitySeverity::High,
            r"function\s+addLiquidity\w*\([^)]*\)\s+(external|public)\s*\{",
            "Unprotected Add Liquidity Function".to_string(),
            "Add liquidity function without minimum output check enables sandwich attacks"
                .to_string(),
            "Add minLiquidity parameter and deadline, verify price hasn't moved significantly"
                .to_string(),
            false,
        )
        .unwrap(),

        // REMOVED: "LP Token Manipulation in Single Transaction" (mint.*burn dotall regex).
        // In multiline mode this matched any FILE containing both words "mint" and "burn"
        // anywhere — including comments and standard token/bridge contracts that legitimately
        // mint and burn (24 Critical false positives on OpenZeppelin bridges/wrappers).
        // Flash-LP attacks are covered by the first-depositor and flash-loan rules.

        // First depositor/LP attack vector
        VulnerabilityRule::new(
            VulnerabilityCategory::LiquidityManipulation,
            VulnerabilitySeverity::Critical,
            // `|` binds looser than concatenation, so the second branch stood alone and
            // fired Critical on EVERY `if (totalSupply == 0)` -- including vaults that
            // are correctly mitigated with a virtual-shares offset. Keep only the first
            // branch's intent (a zero-supply special case that mints) and bound the gap
            // (`.*` crossed newlines to the last `mint` in the file under `(?s)`).
            r"totalSupply\s*==\s*0[\s\S]{0,400}?\b_?mint\s*\(",
            "First Depositor Attack Vector".to_string(),
            "First deposit special case can be exploited to steal subsequent deposits".to_string(),
            "Mint initial shares to address(0) or use virtual shares offset (e.g., 1e3)"
                .to_string(),
            true,
        )
        .unwrap(),

        // ===========================================
        // BRIDGE VULNERABILITY PATTERNS
        // ===========================================

        // Cross-chain message without source verification
        VulnerabilityRule::new(
            VulnerabilityCategory::BridgeVulnerability,
            VulnerabilitySeverity::Critical,
            r"function\s+(receive|handle|process)\w*Message\w*\([^)]*\)\s+(external|public)",
            "Cross-Chain Message Handler (Bridge Vulnerability)".to_string(),
            "Bridge message handler must verify source chain, sender, and message integrity"
                .to_string(),
            "Verify srcChainId matches expected, validate trustedRemote[srcChain] == srcAddress"
                .to_string(),
            false,
        )
        .unwrap(),

        // Bridge withdraw without proof verification
        VulnerabilityRule::new(
            VulnerabilityCategory::BridgeVulnerability,
            VulnerabilitySeverity::Critical,
            r"function\s+\w*(claim|withdraw|redeem)\w*\([^)]*bytes\s+(calldata\s+)?proof[^)]*\)",
            "Bridge Proof Verification".to_string(),
            "Bridge claim function with proof parameter - verify Merkle/signature proof thoroughly".to_string(),
            "Use well-audited proof verification, check for replay (mark claimed), validate amounts".to_string(),
            false,
        ).unwrap(),

        // LayerZero/Wormhole/Axelar integration
        VulnerabilityRule::new(
            VulnerabilityCategory::BridgeVulnerability,
            VulnerabilitySeverity::High,
            r"lzReceive|_nonblockingLzReceive|receiveWormholeMessages|_execute.*axelar",
            "Cross-Chain Protocol Integration".to_string(),
            "Cross-chain protocol integration detected - verify proper source validation"
                .to_string(),
            "Validate srcChainId, srcAddress against trusted remotes, implement replay protection"
                .to_string(),
            false,
        )
        .unwrap(),

        // Bridge relayer trust
        VulnerabilityRule::new(
            VulnerabilityCategory::BridgeVulnerability,
            VulnerabilitySeverity::High,
            r"mapping.*relayer|onlyRelayer|trustedRelayer",
            "Bridge Relayer Trust Pattern".to_string(),
            "Trusted relayer pattern - single relayer compromise breaks bridge security"
                .to_string(),
            "Implement multi-relayer consensus, fraud proofs, or optimistic verification"
                .to_string(),
            false,
        )
        .unwrap(),

        // ===========================================
        // ENHANCED ACCESS CONTROL (OWASP #1 - $953M)
        // ===========================================

        // Function selector collision risk
        VulnerabilityRule::new(
            VulnerabilityCategory::AccessControl,
            VulnerabilitySeverity::High,
            // Bounded: the delegatecall belongs to the fallback body. `.*` under `(?s)`
            // reached the last delegatecall in the file.
            r"fallback\s*\(\s*\)\s*external[\s\S]{0,400}?delegatecall",
            "Fallback Delegatecall - Selector Collision Risk".to_string(),
            "Fallback with delegatecall allows calling any function via selector collision"
                .to_string(),
            "Use explicit function routing, avoid fallback delegatecall pattern".to_string(),
            true,
        )
        .unwrap(),

        // Unprotected initializer (proxy pattern)
        VulnerabilityRule::new(
            VulnerabilityCategory::AccessControl,
            VulnerabilitySeverity::Critical,
            r"function\s+initialize\s*\([^)]*\)\s+(external|public)\s*\{",
            "Unprotected Initialize Function".to_string(),
            "Initialize function without initializer modifier can be called multiple times"
                .to_string(),
            "Add initializer modifier from OpenZeppelin Initializable contract".to_string(),
            false,
        )
        .unwrap(),

        // tx.origin for authentication
        VulnerabilityRule::new(
            VulnerabilityCategory::AccessControl,
            VulnerabilitySeverity::Critical,
            r"require\s*\(\s*tx\.origin\s*==|if\s*\(\s*tx\.origin\s*==",
            "tx.origin Authentication (Phishing Risk)".to_string(),
            "Using tx.origin for authentication enables phishing attacks".to_string(),
            "Use msg.sender instead of tx.origin for all authentication checks".to_string(),
            false,
        )
        .unwrap(),

        // Missing two-step ownership transfer
        VulnerabilityRule::new(
            VulnerabilityCategory::AccessControl,
            VulnerabilitySeverity::Medium,
            r"function\s+transferOwnership\s*\([^)]*address\s+newOwner[^)]*\)",
            "Single-Step Ownership Transfer".to_string(),
            "Single-step ownership transfer can lock contract if wrong address is used".to_string(),
            "Implement two-step transfer: propose owner, then new owner accepts".to_string(),
            false,
        )
        .unwrap(),

        // ===========================================
        // RESEARCH PAPER VULNERABILITIES
        // From: "Security Analysis of DeFi" (arXiv:2205.09524v1)
        // ===========================================

        // Strict Balance Equality (SWC-132) - Table I from paper
        // Can be bypassed via selfdestruct forcing ETH into contract
        VulnerabilityRule::new(
            VulnerabilityCategory::StrictBalanceEquality,
            VulnerabilitySeverity::Medium,
            // Top-level `|` made the second branch stand alone, matching any
            // `.balance == x` anywhere and rendering the first branch dead. Also
            // `[^)]*` could not reach past the `)` of `address(this).balance`.
            r"(?:require|assert|if|while)\s*\([^;{}]*\.balance\s*==\s*\w+",
            "Strict Balance Equality Check (SWC-132)".to_string(),
            "Using strict equality (==) for balance checks can be bypassed via selfdestruct"
                .to_string(),
            "Use >= or <= instead of == for balance comparisons to prevent bypass".to_string(),
            false,
        )
        .unwrap(),

        // Misleading Data Location - Table I from paper
        // Incorrect storage/memory type can lead to data corruption
        VulnerabilityRule::new(
            VulnerabilityCategory::MisleadingDataLocation,
            VulnerabilitySeverity::High,
            r"function\s+\w+\([^)]*\w+\[\]\s+storage\s+\w+[^)]*\)\s+(external|public)",
            "Storage Parameter in External Function".to_string(),
            "External/public functions cannot use storage parameters - data location mismatch"
                .to_string(),
            "Use memory or calldata for external function array parameters".to_string(),
            false,
        )
        .unwrap(),

        VulnerabilityRule::new(
            VulnerabilityCategory::MisleadingDataLocation,
            VulnerabilitySeverity::Medium,
            r"\w+\[\]\s+memory\s+\w+\s*=\s*\w+\s*;",
            "Potential Storage to Memory Copy".to_string(),
            "Copying storage array to memory creates independent copy - modifications won't persist".to_string(),
            "Use storage reference if you need to modify the original array".to_string(),
            false,
        ).unwrap(),

        // REMOVED: "Conditional Without Return in All Paths" (MissingReturnValue).
        // Determining whether all code paths return requires control-flow analysis; a regex
        // with [^}]* cannot handle nested braces and matched nearly every function containing
        // an if-block (76 false positives on OpenZeppelin alone, ~0 true positives).

        // REMOVED: "Payable Receive/Fallback" flagged every receive()/fallback() as a greedy
        // contract risk. Checking if a withdraw mechanism exists requires cross-function analysis
        // that single-line regex cannot do. This generated noise for all payable contracts.

        // REMOVED: "DeFi Function Without Pause Check" regex rule.
        // Duplicated the detect_missing_emergency_stop() in advanced_analysis.rs which
        // already reports once per contract (with break) and checks for Pausable pattern.
        // The regex version fired per-function, generating 15+ findings on a single contract.

        // ERC-777 Callback Reentrancy (dForce $24M attack) - Section IV.3 of paper
        // tokensReceived/tokensToSend hooks enable reentrancy
        VulnerabilityRule::new(
            VulnerabilityCategory::ERC777CallbackReentrancy,
            VulnerabilitySeverity::Critical,
            r"IERC777|ERC777|tokensReceived|tokensToSend|ERC777TokensSender|ERC777TokensRecipient",
            "ERC-777 Token Integration (dForce Attack Pattern)".to_string(),
            "ERC-777 tokens have callback hooks that can enable reentrancy attacks ($24M dForce exploit)".to_string(),
            "Use ReentrancyGuard on all ERC-777 interactions, follow checks-effects-interactions".to_string(),
            false,
        ).unwrap(),

        // DepositFor Reentrancy (Grim Finance $30M attack) - Section IV.3 of paper
        // depositFor pattern with callbacks before state update
        VulnerabilityRule::new(
            VulnerabilityCategory::DepositForReentrancy,
            VulnerabilitySeverity::Critical,
            r"function\s+depositFor\s*\([^)]*address\s+\w+[^)]*\)\s+(external|public)",
            "DepositFor Pattern (Grim Finance Attack)".to_string(),
            "depositFor functions can be exploited via callback reentrancy ($30M Grim Finance exploit)".to_string(),
            "Add ReentrancyGuard, validate input address, update state before external calls".to_string(),
            false,
        ).unwrap(),

        VulnerabilityRule::new(
            VulnerabilityCategory::DepositForReentrancy,
            VulnerabilitySeverity::High,
            r"function\s+deposit\s*\([^)]*address\s+(to|recipient|receiver|beneficiary)\w*[^)]*\)",
            "Deposit Function with Recipient Address".to_string(),
            "Deposit function with external recipient can be exploited via callback if recipient is contract".to_string(),
            "Add nonReentrant modifier and validate recipient address".to_string(),
            false,
        ).unwrap(),

        // Double Claiming Attack (Popsicle Finance $25M) - Section IV.5 of paper
        // Only flag external/public claim functions (not internal helpers)
        VulnerabilityRule::new(
            VulnerabilityCategory::DoubleClaiming,
            VulnerabilitySeverity::High,
            r"function\s+\w*(claim|harvest|getReward|collectFees)\w*\s*\([^)]*\)\s+(external|public)",
            "Reward Claiming Function (Popsicle Finance Pattern)".to_string(),
            "Reward claiming without transfer lockout can enable double-claiming attacks ($25M Popsicle Finance)".to_string(),
            "Track claimed amounts per address, use claimable mapping that resets on transfer".to_string(),
            false,
        ).unwrap(),

        VulnerabilityRule::new(
            VulnerabilityCategory::DoubleClaiming,
            VulnerabilitySeverity::High,
            r"balanceOf\s*\(\s*msg\.sender\s*\)\s*\*\s*\w*(reward|fee)|reward\w*\s*\*\s*balanceOf",
            "Reward Calculation Based on Balance".to_string(),
            "Calculating rewards based on current balance without tracking is vulnerable to transfer-and-claim".to_string(),
            "Use rewardDebt pattern: track claimed amounts and subtract from total rewards".to_string(),
            false,
        ).unwrap(),

        // Signature Verification Bypass (Wormhole $326M) - Section IV.5 of paper
        // Incomplete signature verification allows message forgery
        VulnerabilityRule::new(
            VulnerabilityCategory::SignatureVerificationBypass,
            VulnerabilitySeverity::Critical,
            r"function\s+verify\w*[Ss]ignature\w*\s*\([^)]*\)\s+(external|public|internal)",
            "Custom Signature Verification Function (Wormhole Pattern)".to_string(),
            "Custom signature verification may be bypassable ($326M Wormhole exploit)".to_string(),
            "Use well-audited libraries (OpenZeppelin ECDSA), verify signer address, check replay protection".to_string(),
            false,
        ).unwrap(),

        // Note: ecrecover/ECDSA.recover validation is handled by advanced_analysis.rs
        // with context-aware checking for require() statements
        VulnerabilityRule::new(
            VulnerabilityCategory::SignatureVerificationBypass,
            VulnerabilitySeverity::Medium,
            r"ecrecover\s*\([^)]*\)\s*;",
            "ecrecover Usage Detected".to_string(),
            "ecrecover returns address(0) for invalid signatures - must be validated".to_string(),
            "Always check: require(recovered != address(0) && recovered == expected)".to_string(),
            false,
        )
        .unwrap(),

        VulnerabilityRule::new(
            VulnerabilityCategory::SignatureVerificationBypass,
            VulnerabilitySeverity::Medium,
            r"ECDSA\.recover\s*\([^)]*\)\s*;",
            "ECDSA.recover Usage Detected".to_string(),
            "ECDSA.recover result must be compared to expected signer".to_string(),
            "Verify: require(ECDSA.recover(hash, signature) == expectedSigner)".to_string(),
            false,
        )
        .unwrap(),

        // FN-1: msg.value used in a loop (CRITICAL) - Logic bug, not arithmetic
        VulnerabilityRule::new(
            VulnerabilityCategory::LogicError,
            VulnerabilitySeverity::Critical,
            // [^}]* keeps the match inside the loop's own block: a `msg.value` that appears
            // after any closing brace (i.e. outside the loop or in a later function) no
            // longer matches. Conservative for nested blocks, but eliminates cross-function FPs.
            r"(for|while)\s*\([^)]*\)\s*\{[^}]*msg\.value",
            "msg.value Reused in Loop".to_string(),
            "msg.value is constant across loop iterations - each iteration uses the full value, not a fraction".to_string(),
            "Track total sent and decrement from msg.value, or use a separate amount per iteration".to_string(),
            true,
        ).unwrap(),

        // FN-2: isContract/extcodesize bypass during construction.
        //
        // Scoped to the *caller*. A code-size check only carries this weakness when it
        // gates access ("EOAs only"), which means it tests `msg.sender`/`tx.origin`:
        // an attacker bypasses it by acting from a constructor. The same check applied to
        // a parameter is almost always asking a different question -- "does this token
        // exist?", "should I invoke the receiver hook?" -- and is not a bug. Matching any
        // `.code.length` produced 11 findings across OpenZeppelin, all of them the benign
        // parameter form.
        VulnerabilityRule::new(
            VulnerabilityCategory::InputValidationFailure,
            VulnerabilitySeverity::High,
            r"isContract\s*\(\s*(?:msg\.sender|tx\.origin)\s*\)|(?:msg\.sender|tx\.origin)\.code\.length\s*(==|>)\s*0|extcodesize\s*\(\s*(?:caller\(\)|msg\.sender|tx\.origin)\s*\)",
            "Contract Check Bypassable During Construction".to_string(),
            "isContract()/extcodesize returns 0 during constructor execution - attacker contracts can bypass this check".to_string(),
            "Do not rely on isContract() for security. Use msg.sender == tx.origin for EOA checks or implement whitelisting".to_string(),
            false,
        ).unwrap(),

        // FN-3: Return bomb attack - unbounded return data capture
        VulnerabilityRule::new(
            VulnerabilityCategory::LowLevelCalls,
            VulnerabilitySeverity::Medium,
            r"\(bool\s+\w+,\s*bytes\s+memory\s+\w+\)\s*=\s*\w+\.(call|delegatecall|staticcall)",
            "Return Bomb Risk - Unbounded Return Data".to_string(),
            "Capturing full return data from external calls allows callee to return enormous data, consuming all gas in memory expansion".to_string(),
            "Use assembly to limit return data size, or use `(bool success, ) = addr.call(...)` if return data is not needed".to_string(),
            false,
        ).unwrap(),

        // FN-4: Unchecked ERC20 transfer (2 args = token transfer, not payable)
        // Match both `token.transfer(to, amount)` and `IERC20(token).transfer(to, amount)`
        VulnerabilityRule::new(
            VulnerabilityCategory::UnusedReturnValues,
            VulnerabilitySeverity::Medium,
            r"^\s*(?:\w+|\w+\([^)]*\))\.transfer\s*\(\s*\w+\s*,\s*\w+",
            "Unchecked ERC20 transfer Return Value".to_string(),
            "ERC20 transfer() returns bool but some tokens don't revert on failure".to_string(),
            "Use SafeERC20.safeTransfer() or check: require(token.transfer(to, amount))"
                .to_string(),
            false,
        )
        .unwrap(),

        // ====================================================================
        // Security Hardening Rules (v0.6.0) - New Detections
        // ====================================================================

        // REMOVED: 41S-050 regex variant of "Missing Storage Gap". It fired on every
        // `contract X is ...Upgradeable...` line without ever checking whether __gap (or
        // ERC-7201 namespaced storage) is present. detect_storage_collision_proxy() in
        // advanced_analysis.rs performs the same detection with the __gap check.

        // 41S-052: selfdestruct deprecation (EIP-6780)
        // Post-Dencun, selfdestruct only sends ETH without destroying the contract
        // except during the same transaction as creation. Using it is misleading.
        VulnerabilityRule::new(
            VulnerabilityCategory::SelfdestructDeprecation,
            VulnerabilitySeverity::High,
            r"\bselfdestruct\s*\(|\.selfdestruct\s*\(",
            "Deprecated selfdestruct Usage (EIP-6780)".to_string(),
            "selfdestruct is deprecated and restricted post-Dencun (EIP-6780). It no longer destroys contract code/storage except during the same creation transaction.".to_string(),
            "Remove selfdestruct. Use withdraw patterns for fund recovery. For upgradeable contracts, use the proxy upgrade pattern instead.".to_string(),
            false,
        ).unwrap(),

        // 41S-053: Uninitialized implementation contract
        // If a proxy's implementation contract isn't initialized, an attacker can
        // call initialize() on the implementation directly and potentially take control.
        VulnerabilityRule::new(
            VulnerabilityCategory::UninitializedImplementation,
            VulnerabilitySeverity::Critical,
            r"function\s+initialize\s*\([^)]*\)\s*(?:external|public)\s+initializer",
            "Potentially Uninitialized Implementation".to_string(),
            "Implementation contracts behind proxies must be initialized in the constructor to prevent attackers from calling initialize() directly.".to_string(),
            "Add `_disableInitializers()` in the constructor, or use `/// @custom:oz-upgrades-unsafe-allow constructor` with a constructor that calls `_disableInitializers()`.".to_string(),
            false,
        ).unwrap(),

        // 41S-054: Unsafe integer downcast
        // Casting uint256 to a smaller type silently truncates in Solidity < 0.8.0.
        // Even in 0.8+, explicit casts like uint128(x) silently truncate.
        VulnerabilityRule::new(
            VulnerabilityCategory::UnsafeDowncast,
            VulnerabilitySeverity::Medium,
            r"\b(?:uint(?:8|16|24|32|48|64|96|128|160|192|224)|int(?:8|16|24|32|48|64|96|128|160|192|224))\s*\(\s*\w+\s*\)",
            "Unsafe Integer Downcast".to_string(),
            "Casting to a smaller integer type silently truncates the value, potentially causing incorrect calculations or loss of funds.".to_string(),
            "Use OpenZeppelin's SafeCast library (e.g., toUint128()) which reverts on overflow, or add explicit range validation.".to_string(),
            false,
        ).unwrap(),

        // 41S-056: Missing deadline in swap functions
        // DEX swap functions without a deadline parameter are vulnerable to
        // transaction sitting in the mempool and being executed at an unfavorable time.
        // Note: Context filtering in scanner.rs checks for deadline in function body.
        VulnerabilityRule::new(
            VulnerabilityCategory::MissingSwapDeadline,
            VulnerabilitySeverity::Medium,
            r"function\s+\w*(?:swap|Swap)\w*\s*\([^)]*\)\s*(?:external|public)",
            "Missing Deadline Parameter in Swap Function".to_string(),
            "Swap functions without a deadline parameter allow transactions to sit in the mempool indefinitely and be executed at an unfavorable time.".to_string(),
            "Add a `uint256 deadline` parameter and validate with `require(block.timestamp <= deadline)`.".to_string(),
            false,
        ).unwrap(),

        // 41S-057: Hardcoded gas amount in external calls
        // Hardcoded gas values break when EVM gas costs change (e.g., Istanbul, Berlin).
        VulnerabilityRule::new(
            VulnerabilityCategory::HardcodedGasAmount,
            VulnerabilitySeverity::Medium,
            r"\.call\{[^}]*gas\s*:\s*\d+",
            "Hardcoded Gas Amount in External Call".to_string(),
            "Hardcoded gas values may break after EVM upgrades that change opcode gas costs (e.g., EIP-1884 in Istanbul, EIP-2929 in Berlin).".to_string(),
            "Avoid hardcoding gas amounts. Forward all available gas or use a configurable gas parameter.".to_string(),
            false,
        ).unwrap(),

        // 41S-058: address.transfer() with 2300 gas stipend
        // .transfer() and .send() only forward 2300 gas which may not be enough
        // if the recipient is a contract with a receive/fallback function.
        VulnerabilityRule::new(
            VulnerabilityCategory::UnsafeTransferGas,
            VulnerabilitySeverity::Low,
            r"\.\s*transfer\s*\(\s*[^,)]+\s*\)\s*;",
            "Low Gas Stipend with .transfer()".to_string(),
            "address.transfer() forwards only 2300 gas, which can cause failures if the recipient is a contract with logic in receive/fallback (especially after EIP-1884 gas cost changes).".to_string(),
            "Use `.call{value: amount}(\"\")` with proper return value checking instead of `.transfer()`.".to_string(),
            false,
        ).unwrap(),

        // 41S-059: Double initialization risk
        // Contracts with initialize() that don't use the initializer modifier
        // or Initializable pattern can be initialized multiple times.
        VulnerabilityRule::new(
            VulnerabilityCategory::DoubleInitialization,
            VulnerabilitySeverity::Critical,
            r"function\s+initialize\s*\([^)]*\)\s+(?:external|public)\s*(?:\{|returns)",
            "Missing Initializer Modifier".to_string(),
            "The initialize() function lacks the `initializer` modifier, allowing it to be called multiple times which can reset critical state.".to_string(),
            "Add OpenZeppelin's `initializer` modifier: `function initialize(...) external initializer { ... }`".to_string(),
            false,
        ).unwrap(),

        // Missing events on critical state changes (detected per-line, filtered by context in scanner)
        VulnerabilityRule::new(
            VulnerabilityCategory::MissingEvents,
            VulnerabilitySeverity::Low,
            r"function\s+(set|update|change|modify)\w+\s*\([^)]*\)\s+(?:external|public)",
            "Missing Event Emission on State Change".to_string(),
            "State-changing function may not emit an event, making off-chain monitoring and auditing difficult.".to_string(),
            "Emit an event at the end of every state-changing function for transparency and monitoring.".to_string(),
            false,
        ).unwrap(),

        // ====================================================================
        // 2026 Exploit Patterns (v0.9.0) - 41S-078..084
        // ====================================================================

        // 41S-078: ERC-4337 paymaster validation accepts any user op without nonce/replay guard
        // Multiline because solc style commonly wraps `external` modifier onto its own line.
        VulnerabilityRule::new(
            VulnerabilityCategory::ERC4337PaymasterAbuse,
            VulnerabilitySeverity::High,
            r"function\s+validatePaymasterUserOp\s*\([^)]*\)[^{;]*(?:external|public)",
            "ERC-4337 Paymaster Validation".to_string(),
            "Paymaster validatePaymasterUserOp must enforce sender allowlist, signature freshness, and gas budget caps. Misconfigured paymasters have been drained by adversarial bundlers.".to_string(),
            "Validate userOpHash against signed nonce, enforce per-sender daily budget, and revert on stale signatures (deadline). Pin verifying signer in storage.".to_string(),
            true,
        ).unwrap(),

        // 41S-079: EIP-1271 isValidSignature without replay/nonce
        VulnerabilityRule::new(
            VulnerabilityCategory::EIP1271SignatureReplay,
            VulnerabilitySeverity::High,
            r"function\s+isValidSignature\s*\([^)]*bytes(?:32)?[^)]*,\s*bytes[^)]*\)\s+(?:external|public)\s+view",
            "EIP-1271 Signature Without Nonce Tracking".to_string(),
            "Smart-wallet isValidSignature returning MAGICVALUE without nonce or used-hash tracking allows the same signature to authorize repeat actions across protocols.".to_string(),
            "Track consumed signature hashes (mapping(bytes32 => bool)) and require deadlines. Bind sigs to chainId+verifyingContract via EIP-712.".to_string(),
            false,
        ).unwrap(),

        // 41S-080: Permit2 with unlimited (type(uint).max / max uint160) approval
        // Use a wider span; the call site may include nested address(this), commas, etc.
        VulnerabilityRule::new(
            VulnerabilityCategory::Permit2UnlimitedApproval,
            VulnerabilitySeverity::Medium,
            r"(?i)permit2?\s*\.\s*approve\s*\([^;]*?type\s*\(\s*uint(?:160|256)?\s*\)\s*\.\s*max",
            "Permit2 Unlimited Allowance".to_string(),
            "Granting Permit2 a type(uint).max allowance bypasses the per-spender expiration model and converts a UX optimisation into a permanent drain primitive if any approved spender is compromised.".to_string(),
            "Set finite amount with explicit expiration (uint48). Re-approve per-session rather than persisting infinite approval.".to_string(),
            true,
        ).unwrap(),

        // 41S-081: LRT re-hypothecation pattern - asset accounted twice
        VulnerabilityRule::new(
            VulnerabilityCategory::LRTRehypothecation,
            VulnerabilitySeverity::High,
            r"(?i)function\s+\w*(?:restake|delegate|deposit)\w*\s*\([^)]*\)\s+(?:external|public)[^{]*\{[^}]*(?:totalAssets|totalSupply|totalShares)\s*\+=",
            "Possible LRT Re-Hypothecation".to_string(),
            "Liquid restaking deposits that increment totalAssets/totalShares without a withdrawal queue or per-operator cap allow the same collateral to back multiple AVS commitments. EigenLayer-style accounting must net out outstanding obligations.".to_string(),
            "Track delegated-amount per operator separately, require withdrawal queue with delay, and validate (totalAssets - delegated) >= pendingRedemptions.".to_string(),
            true,
        ).unwrap(),

        // 41S-082: Storage layout collision in upgradeable contracts (inheritance reorder)
        VulnerabilityRule::new(
            VulnerabilityCategory::StorageLayoutCollision,
            VulnerabilitySeverity::High,
            r"contract\s+\w+\s+is\s+[A-Za-z_][A-Za-z0-9_]*(?:\s*,\s*[A-Za-z_][A-Za-z0-9_]*){2,}[^{]*Upgradeable",
            "Upgradeable Storage Layout Risk".to_string(),
            "Multi-inheritance upgradeable contracts must keep the inheritance order stable across upgrades. Inserting or reordering parents shifts storage slots and corrupts state.".to_string(),
            "Pin inheritance order, add per-base __gap[50], and run `forge inspect storage-layout` diff in CI between versions.".to_string(),
            false,
        ).unwrap(),

        // 41S-083: Governance vote based on current balance (flash-loan vote-buying)
        VulnerabilityRule::new(
            VulnerabilityCategory::GovernanceFlashloanVoting,
            VulnerabilitySeverity::Critical,
            r"(?i)function\s+(?:vote|castVote)\w*\s*\([^)]*\)[^{]*\{[^}]*balanceOf\s*\(\s*msg\.sender\s*\)",
            "Governance Vote Uses Live balanceOf".to_string(),
            "Reading balanceOf(msg.sender) at vote time lets an attacker borrow tokens via flash loan, vote, then repay in the same tx. Governance must use checkpointed/snapshotted balances at proposal creation.".to_string(),
            "Use ERC20Votes (getPastVotes at proposal snapshot block) or Compound Bravo style checkpoints. Never read live balanceOf inside vote().".to_string(),
            true,
        ).unwrap(),

        // 41S-084: Price-sensitive write without commit-reveal / TWAP / minOut
        VulnerabilityRule::new(
            VulnerabilityCategory::SandwichResistantMissing,
            VulnerabilitySeverity::Medium,
            r"(?i)function\s+\w*(?:rebalance|harvest|compound|skim|rebase)\w*\s*\([^)]*\)\s+(?:external|public)",
            "MEV-Exposed Rebalance/Harvest".to_string(),
            "Public rebalance/harvest/compound entrypoints that touch AMM pools without a TWAP guard or commit-reveal can be sandwiched. Searchers extract value at LP expense each call.".to_string(),
            "Restrict to keeper role, or enforce a TWAP price band (Chainlink/Univ3 oracle deviation < N bps) before pool interaction. For public callers add minOut/maxIn slippage params.".to_string(),
            false,
        ).unwrap(),

        // ========================================================================
        // Mid-2026 Exploit Patterns (v0.10.0)
        // ========================================================================

        // 41S-085: Solidity 0.8.28-0.8.33 transient-storage clearing codegen bug.
        // When a contract clears both a persistent and a transient variable of the same
        // type via the IR pipeline, the shared Yul clearing helper collides and the
        // compiler emits the wrong opcode (sstore<->tstore swap). Solidity blog 2026-02-18.
        // Heuristic: affected pragma range + any `transient` state variable declaration.
        VulnerabilityRule::new(
            VulnerabilityCategory::TransientStorageCompilerBug,
            VulnerabilitySeverity::High,
            r"pragma\s+solidity\s*[^;]*0\.8\.(?:2[89]|3[0-3])\b[^;]*;[\s\S]*?\btransient\s+\w+\s*;",
            "Transient Storage Clearing Bug (solc 0.8.28-0.8.33)".to_string(),
            "Compilers 0.8.28-0.8.33 with the IR pipeline emit the wrong opcode (sstore instead of tstore, or vice versa) when a persistent and a transient variable of the same type are both cleared - the generated Yul clearing helpers share a name and one overwrites the other. State can silently corrupt or transient locks can persist.".to_string(),
            "Upgrade to solc >= 0.8.34 (fixed release), or avoid clearing persistent and transient variables of the same type in one contract. Verify with the Solidity 2026-02-18 security advisory.".to_string(),
            true,
        ).unwrap(),

        // 41S-086: EIP-7702 delegate implementation with raw (non-namespaced) storage.
        // A 7702 delegate runs in the EOA's storage context. If the user later re-delegates
        // to a different implementation, slot-0 variables collide and are reinterpreted.
        // Heuristic: the self-execution auth idiom (msg.sender == address(this)) that only
        // 7702/account-abstraction delegates use, in a contract declaring plain state vars.
        // The scanner-side context filter suppresses this when ERC-7201 namespaced storage
        // (@custom:storage-location) is present in the file.
        VulnerabilityRule::new(
            VulnerabilityCategory::EIP7702DelegateStorageCollision,
            VulnerabilitySeverity::High,
            // The two branches are DELIBERATELY asymmetric, and the grouping below makes
            // that explicit so the precedence is not misread as a bug:
            //   1. `require(msg.sender == address(this)` -- a complete self-execution guard.
            //      Self-sufficient: the idiom alone is the finding (see the description),
            //      and the ERC-7201 context filter in scanner.rs is what suppresses it.
            //   2. the bare comparison in any other spelling (`if (...)`, `assert(...)`),
            //      which needs a nearby `revert` to show it is an authorisation check.
            // Do NOT hoist the `revert` clause out onto branch 1: that silences 41S-086 on
            // the canonical delegate shape (test_contracts/test_2026_midyear_exploits.sol).
            r"(?:require\s*\(\s*msg\.sender\s*==\s*address\s*\(\s*this\s*\))|(?:msg\.sender\s*==\s*address\s*\(\s*this\s*\)\s*(?:,|\))[\s\S]{0,600}?revert)",
            "EIP-7702 Delegate Uses Raw Storage Slots".to_string(),
            "This contract authenticates via msg.sender == address(this), the EIP-7702 delegate self-execution idiom. Delegates execute in the EOA's own storage; when the EOA re-delegates to another implementation with a different layout, slot-0 state (owners, nonces, guards) is reinterpreted by the new code - a storage collision that can brick or hijack the account.".to_string(),
            "Use ERC-7201 namespaced storage (@custom:storage-location erc7201:...) for all delegate state so independent implementations cannot collide. Include a storage-version marker and validate it on initialization.".to_string(),
            true,
        ).unwrap(),

        // 41S-087: LayerZero V2 OApp secured by a single required DVN.
        // Kelp DAO lost $293M (April 2026) when its 1-of-1 verifier was isolated via DDoS
        // and fed forged cross-chain messages. Flag explicit single-DVN configurations.
        VulnerabilityRule::new(
            VulnerabilityCategory::LayerZeroSingleDVN,
            VulnerabilitySeverity::High,
            r"(?i)requiredDVNs?\s*=\s*new\s+address\[\]\(\s*1\s*\)|requiredDVNCount\s*=\s*1\b|confirmations?\s*:\s*1\s*,\s*requiredDVN",
            "LayerZero Single Required DVN".to_string(),
            "The OApp security stack requires only one DVN to verify cross-chain messages. A single verifier is a single point of failure: Kelp DAO's 1-of-1 DVN was isolated with DDoS and fed forged messages, authorizing a $293M mint (April 2026).".to_string(),
            "Require at least 2 independent DVNs (requiredDVNs) plus optional DVNs with a threshold. Prefer DVNs operated by unrelated infrastructure providers and monitor DVN liveness.".to_string(),
            false,
        ).unwrap(),

        // 41S-088: ERC-7683 destination settler that decodes originData in fill() without
        // validating the caller/settler. Anyone can invoke fill() with crafted originData
        // unless the settler restricts who may fill or verifies the order against the
        // origin settlement contract. Context filter suppresses when an auth check exists
        // inside the fill body.
        VulnerabilityRule::new(
            VulnerabilityCategory::ERC7683UnvalidatedFill,
            VulnerabilitySeverity::High,
            r"function\s+fill\s*\(\s*bytes32\s+\w+\s*,\s*bytes\s+calldata\s+originData[^)]*\)[^{]*\{[\s\S]{0,800}?abi\.decode\s*\(\s*originData",
            "ERC-7683 fill() Decodes originData Without Validation".to_string(),
            "The destination settler decodes caller-supplied originData directly. ERC-7683 delegates settlement security to the implementation: without validating the order hash against the origin settler, checking a filler allowlist, or replay-protecting the orderId, an attacker can craft originData that releases escrowed funds or double-fills an order.".to_string(),
            "Verify orderId == keccak256(originData) binding, track filled orderIds in a mapping, and restrict fill() to authorized fillers or verify the origin-chain settlement proof before releasing funds.".to_string(),
            true,
        ).unwrap(),

        // 41S-089: Uniswap V4 flash-accounting hook takes funds to a caller-controlled
        // recipient. Mismatched ERC-6909 claim vs raw ERC-20 accounting inside hooks lets
        // an attacker sync/settle/take to drain the pool's underlying currency.
        VulnerabilityRule::new(
            VulnerabilityCategory::ERC6909FlashAccountingDrain,
            VulnerabilitySeverity::High,
            r"(?i)poolManager\s*\.\s*take\s*\(\s*[^,]+,\s*(?:msg\.sender|\w*(?:recipient|receiver|_to)\w*)\s*,",
            "V4 Flash Accounting take() to Caller-Controlled Recipient".to_string(),
            "poolManager.take() sends real tokens against the transient delta. When the recipient is caller-controlled and the hook's ERC-6909 claim accounting does not exactly mirror raw ERC-20 balances, an attacker can sync, claim on behalf of the PoolManager, settle, and take - extracting the pool's underlying currency.".to_string(),
            "Take to address(this) and distribute after reconciling deltas, or require the final currencyDelta to be zero for every touched currency before unlock returns. Fuzz claim-vs-raw accounting for rounding drift.".to_string(),
            false,
        ).unwrap(),

        // ========================================================================
        // Late-2026 Smart-Account Execution Surface (v0.11.0)
        // ========================================================================

        // 41S-090: ERC-7579 modular smart account exposes installModule/uninstallModule
        // without access control. ERC-7579 accounts delegate all logic to installed
        // validator/executor/hook/fallback modules; whoever can install a module controls
        // the account. The scanner-side context filter suppresses this when the function
        // signature or its opening lines carry an auth modifier or msg.sender/self check.
        VulnerabilityRule::new(
            VulnerabilityCategory::ERC7579UnprotectedModule,
            VulnerabilitySeverity::High,
            r"function\s+(?:installModule|uninstallModule)\s*\(",
            "ERC-7579 Module (Un)Installation Without Access Control".to_string(),
            "This ERC-7579 modular account exposes installModule/uninstallModule with no visible caller restriction. Modules (validators, executors, hooks, fallbacks) are the account's authorization and execution logic - an attacker who installs a malicious validator can sign for the account, and a malicious executor can move all its assets, a full account takeover.".to_string(),
            "Restrict installModule/uninstallModule to the EntryPoint or the account itself (onlyEntryPointOrSelf / require(msg.sender == address(this))), validate moduleTypeId and the module address, and emit ModuleInstalled/Uninstalled events for monitoring.".to_string(),
            false,
        ).unwrap(),

        // 41S-091: ERC-7821 minimal batch executor. The standardized entrypoint is
        // execute(bytes32 mode, bytes calldata executionData) and is meant to run only
        // from the EntryPoint or the account itself. If unrestricted, anyone can execute
        // arbitrary batched calls from the account's context. Context filter suppresses
        // when an auth modifier / self check is present.
        VulnerabilityRule::new(
            VulnerabilityCategory::ERC7821UnprotectedExecute,
            VulnerabilitySeverity::High,
            r"function\s+execute\s*\(\s*bytes32\s+\w+\s*,\s*bytes\s+calldata\s+\w+\s*\)",
            "ERC-7821 Batch execute() Without Caller Restriction".to_string(),
            "This looks like the ERC-7821 batch-execution entrypoint execute(bytes32 mode, bytes executionData). It runs the decoded calls from the account's own context; without restricting the caller to the EntryPoint or the account itself, anyone can execute arbitrary calls - transferring tokens, approving spenders, or self-destructing the account.".to_string(),
            "Gate execute() with onlyEntryPointOrSelf (require msg.sender == entryPoint() || msg.sender == address(this)), or route third-party calls through a validated ERC-4337 UserOp so signatures are checked before execution.".to_string(),
            false,
        ).unwrap(),

        // 41S-092: ERC-7579 executeFromExecutor() is the entrypoint installed executor
        // modules call to dispatch actions as the account. It MUST verify the caller is a
        // currently-installed executor module; otherwise any address dispatches arbitrary
        // calls as the account. Context filter suppresses when a module/auth check exists.
        VulnerabilityRule::new(
            VulnerabilityCategory::ERC7579UnrestrictedExecutor,
            VulnerabilitySeverity::High,
            r"function\s+executeFromExecutor\s*\(",
            "ERC-7579 executeFromExecutor() Without Installed-Module Gate".to_string(),
            "executeFromExecutor() lets an executor module run calls in the account's context. If it does not verify that msg.sender is an installed executor module (e.g. onlyExecutorModule / isModuleInstalled(TYPE_EXECUTOR, msg.sender)), any caller can dispatch arbitrary calls as the account and drain it.".to_string(),
            "Guard executeFromExecutor() so it only accepts calls from installed executor modules: require(isModuleInstalled(MODULE_TYPE_EXECUTOR, msg.sender, \"\")) or an onlyExecutorModule modifier.".to_string(),
            false,
        ).unwrap(),
    ]
}

impl VulnerabilitySeverity {
    /// Return the severity level as an uppercase display string (e.g., "CRITICAL", "HIGH").
    pub fn as_str(&self) -> &str {
        match self {
            VulnerabilitySeverity::Critical => "CRITICAL",
            VulnerabilitySeverity::High => "HIGH",
            VulnerabilitySeverity::Medium => "MEDIUM",
            VulnerabilitySeverity::Low => "LOW",
            VulnerabilitySeverity::Info => "INFO",
        }
    }

    /// Return the terminal color associated with this severity for colored output.
    pub fn color(&self) -> colored::Color {
        match self {
            VulnerabilitySeverity::Critical => colored::Color::Red,
            VulnerabilitySeverity::High => colored::Color::Red,
            VulnerabilitySeverity::Medium => colored::Color::Yellow,
            VulnerabilitySeverity::Low => colored::Color::Blue,
            VulnerabilitySeverity::Info => colored::Color::Green,
        }
    }
}

impl VulnerabilityCategory {
    /// Return a human-readable display name for this vulnerability category.
    pub fn as_str(&self) -> &str {
        match self {
            VulnerabilityCategory::Reentrancy => "Reentrancy",
            VulnerabilityCategory::AccessControl => "Access Control",
            VulnerabilityCategory::RoleBasedAccessControl => "Role-Based Access Control",
            VulnerabilityCategory::ArithmeticIssues => "Arithmetic Issues",
            VulnerabilityCategory::UnhandledExceptions => "Unhandled Exceptions",
            VulnerabilityCategory::GasOptimization => "Gas Optimization",
            VulnerabilityCategory::PragmaIssues => "Pragma Issues",
            VulnerabilityCategory::RandomnessVulnerabilities => "Randomness Vulnerabilities",
            VulnerabilityCategory::FrontRunning => "Front Running",
            VulnerabilityCategory::TimeManipulation => "Time Manipulation",
            VulnerabilityCategory::DoSAttacks => "DoS Attacks",
            VulnerabilityCategory::UnusedCode => "Unused Code",
            VulnerabilityCategory::MagicNumbers => "Magic Numbers",
            VulnerabilityCategory::NamingConventions => "Naming Conventions",
            VulnerabilityCategory::StateVariable => "State Variable Issues",
            VulnerabilityCategory::UnsafeExternalCalls => "Unsafe External Calls",
            VulnerabilityCategory::DelegateCalls => "Delegate Call Vulnerabilities",
            VulnerabilityCategory::StorageDoSAttacks => "Storage DoS Attacks",
            VulnerabilityCategory::PrecisionLoss => "Precision Loss",
            VulnerabilityCategory::CompilerBug => "Compiler Bug",
            VulnerabilityCategory::BadPRNG => "Bad PRNG",
            VulnerabilityCategory::BlockTimestamp => "Block Timestamp Dependency",
            VulnerabilityCategory::LowLevelCalls => "Low Level Calls",
            VulnerabilityCategory::MissingEvents => "Missing Events",
            VulnerabilityCategory::UncheckedReturnValues => "Unchecked Return Values",
            VulnerabilityCategory::UninitializedVariables => "Uninitialized Variables",
            VulnerabilityCategory::UnusedReturnValues => "Unused Return Values",
            VulnerabilityCategory::ImmutabilityIssues => "Immutability Issues",
            VulnerabilityCategory::ShadowingIssues => "Shadowing Issues",
            VulnerabilityCategory::TxOriginAuth => "tx.origin Authentication",
            VulnerabilityCategory::AssemblyUsage => "Assembly Usage",
            VulnerabilityCategory::DeprecatedFunctions => "Deprecated Functions",
            VulnerabilityCategory::ComplexityIssues => "Complexity Issues",
            VulnerabilityCategory::ExternalFunction => "External Function Optimization",
            VulnerabilityCategory::IncorrectEquality => "Incorrect Equality",
            VulnerabilityCategory::SignatureVulnerabilities => "Signature Vulnerabilities",
            VulnerabilityCategory::OracleManipulation => "Oracle Manipulation",
            VulnerabilityCategory::ProxyAdminVulnerability => "Proxy Admin Vulnerability",
            VulnerabilityCategory::CallbackReentrancy => "Callback Reentrancy",
            VulnerabilityCategory::ArbitraryExternalCall => "Arbitrary External Call",
            VulnerabilityCategory::SignatureReplay => "Signature Replay Attack",
            VulnerabilityCategory::CrossChainReplay => "Cross-Chain Replay Attack",
            VulnerabilityCategory::InputValidationFailure => "Input Validation Failure",
            VulnerabilityCategory::DecimalPrecisionMismatch => "Decimal Precision Mismatch",
            VulnerabilityCategory::UnprotectedProxyUpgrade => "Unprotected Proxy Upgrade",
            VulnerabilityCategory::MEVExploitable => "MEV Exploitable",
            VulnerabilityCategory::CallbackInjection => "Callback Injection",
            VulnerabilityCategory::ABIAccessControl => "ABI Access Control",
            VulnerabilityCategory::ABIFunctionVisibility => "ABI Function Visibility",
            VulnerabilityCategory::ABIParameterValidation => "ABI Parameter Validation",
            VulnerabilityCategory::ABIEventSecurity => "ABI Event Security",
            VulnerabilityCategory::ABIUpgradeability => "ABI Upgradeability",
            VulnerabilityCategory::ABITokenStandard => "ABI Token Standard",
            // Advanced ABI categories
            VulnerabilityCategory::ABISelectorCollision => "ABI Selector Collision",
            VulnerabilityCategory::ABIReentrancyIndicator => "ABI Reentrancy Indicator",
            VulnerabilityCategory::ABIFlashLoanRisk => "ABI Flash Loan Risk",
            VulnerabilityCategory::ABIOracleManipulation => "ABI Oracle Manipulation",
            VulnerabilityCategory::ABIDEXInteraction => "ABI DEX Interaction Risk",
            VulnerabilityCategory::ABISignatureVulnerability => "ABI Signature Vulnerability",
            VulnerabilityCategory::ABIPermitVulnerability => "ABI Permit Vulnerability",
            VulnerabilityCategory::ABIGovernanceRisk => "ABI Governance Risk",
            VulnerabilityCategory::ABITimelockBypass => "ABI Timelock Bypass",
            VulnerabilityCategory::ABIMEVExposure => "ABI MEV Exposure",
            VulnerabilityCategory::ABIFrontrunningRisk => "ABI Frontrunning Risk",
            VulnerabilityCategory::ABICrossContractRisk => "ABI Cross-Contract Risk",
            VulnerabilityCategory::ABICallbackInjection => "ABI Callback Injection",
            VulnerabilityCategory::ABIStorageCollision => "ABI Storage Collision",
            VulnerabilityCategory::ABIInitializerVulnerability => "ABI Initializer Vulnerability",
            VulnerabilityCategory::ABISelfDestruct => "ABI Self-Destruct Risk",
            VulnerabilityCategory::ABIDelegateCallRisk => "ABI Delegate Call Risk",
            VulnerabilityCategory::ABIArbitraryCall => "ABI Arbitrary Call Risk",
            VulnerabilityCategory::ABIPriceManipulation => "ABI Price Manipulation Risk",
            VulnerabilityCategory::ABIBridgeVulnerability => "ABI Bridge Vulnerability",
            VulnerabilityCategory::ABIMultisigBypass => "ABI Multisig Bypass Risk",
            VulnerabilityCategory::ABIEmergencyBypass => "ABI Emergency Bypass Risk",
            // 2025 OWASP & Recent Exploits
            VulnerabilityCategory::FlashLoanAttack => "Flash Loan Attack Vector",
            VulnerabilityCategory::LogicError => "Logic Error",
            VulnerabilityCategory::MetaTransactionVulnerability => "Meta-Transaction Vulnerability",
            VulnerabilityCategory::UncheckedMathOperation => "Unchecked Math Operation",
            VulnerabilityCategory::TrustedForwarderBypass => "Trusted Forwarder Bypass",
            VulnerabilityCategory::GovernanceAttack => "Governance Attack Vector",
            VulnerabilityCategory::LiquidityManipulation => "Liquidity Manipulation Risk",
            VulnerabilityCategory::BridgeVulnerability => "Bridge Vulnerability",
            // 2024-2025 Modern DeFi/L2 patterns
            VulnerabilityCategory::ERC4626Inflation => "ERC-4626 First Depositor Attack",
            VulnerabilityCategory::Permit2SignatureReuse => "Permit2 Signature Reuse",
            VulnerabilityCategory::LayerZeroTrustedRemote => {
                "LayerZero Trusted Remote Manipulation"
            }
            VulnerabilityCategory::Create2Collision => "Create2/Create3 Address Collision",
            VulnerabilityCategory::TransientStorageReentrancy => "Transient Storage Reentrancy",
            VulnerabilityCategory::Push0Compatibility => "PUSH0 Opcode Compatibility",
            VulnerabilityCategory::BlobDataHandling => "EIP-4844 Blob Data Handling",
            VulnerabilityCategory::UniswapV4HookExploit => "Uniswap V4 Hook Exploitation",
            VulnerabilityCategory::CrossChainMessageReplay => "Cross-Chain Message Replay",
            VulnerabilityCategory::L2SequencerDowntime => "L2 Sequencer Downtime Risk",
            VulnerabilityCategory::L2GasOracle => "L2 Gas Oracle Manipulation",
            VulnerabilityCategory::BaseBridgeSecurity => "Base Chain Bridge Security",
            // Research Paper: "Security Analysis of DeFi" (arXiv:2205.09524v1) patterns
            VulnerabilityCategory::StrictBalanceEquality => "Strict Balance Equality",
            VulnerabilityCategory::MisleadingDataLocation => "Misleading Data Location",
            VulnerabilityCategory::MissingReturnValue => "Missing Return Value",
            VulnerabilityCategory::GreedyContract => "Greedy Contract",
            VulnerabilityCategory::MissingEmergencyStop => "Missing Emergency Stop",
            VulnerabilityCategory::ERC777CallbackReentrancy => "ERC-777 Callback Reentrancy",
            VulnerabilityCategory::DepositForReentrancy => "DepositFor Reentrancy",
            VulnerabilityCategory::DoubleClaiming => "Double Claiming Attack",
            VulnerabilityCategory::SignatureVerificationBypass => "Signature Verification Bypass",
            // Security hardening categories (v0.6.0)
            VulnerabilityCategory::MissingStorageGap => "Missing Storage Gap",
            VulnerabilityCategory::MissingTimelock => "Missing Timelock",
            VulnerabilityCategory::SelfdestructDeprecation => "Selfdestruct Deprecation",
            VulnerabilityCategory::UninitializedImplementation => "Uninitialized Implementation",
            VulnerabilityCategory::UnsafeDowncast => "Unsafe Integer Downcast",
            VulnerabilityCategory::MissingERC165 => "Missing ERC-165 Support",
            VulnerabilityCategory::MissingSwapDeadline => "Missing Swap Deadline",
            VulnerabilityCategory::HardcodedGasAmount => "Hardcoded Gas Amount",
            VulnerabilityCategory::UnsafeTransferGas => "Unsafe Transfer Gas Limit",
            VulnerabilityCategory::DoubleInitialization => "Double Initialization Risk",
            // 2025-2026 Exploit Patterns (v0.7.0)
            VulnerabilityCategory::MulticallStateReset => "Multicall State Reset",
            VulnerabilityCategory::InconsistentStateReset => "Inconsistent State Reset",
            VulnerabilityCategory::EIP7702TxOriginBypass => "EIP-7702 tx.origin Bypass",
            VulnerabilityCategory::TransientStorageGasReentrancy => {
                "Transient Storage Gas Reentrancy"
            }
            VulnerabilityCategory::ReadOnlyReentrancy => "Read-Only Reentrancy",
            VulnerabilityCategory::ERC2771MulticallSpoofing => "ERC2771 Multicall Spoofing",
            VulnerabilityCategory::MulticallMsgValueReuse => "Multicall msg.value Reuse",
            VulnerabilityCategory::FeeOnTransferAssumption => "Fee-on-Transfer Assumption",
            VulnerabilityCategory::UnprotectedAdminSweep => "Unprotected Admin Sweep",
            VulnerabilityCategory::UnvalidatedCrossChainReceiver => {
                "Unvalidated Cross-Chain Receiver"
            }
            VulnerabilityCategory::AVSSlashingRisk => "AVS Slashing Risk",
            VulnerabilityCategory::CLMMMathOverflow => "CLMM Math Overflow",
            VulnerabilityCategory::InconsistentRounding => "Inconsistent Rounding",
            VulnerabilityCategory::DonationAttackVector => "Donation Attack Vector",
            VulnerabilityCategory::MissingSlippageProtection => "Missing Slippage Protection",
            VulnerabilityCategory::ArbitraryReceiverCallback => "Arbitrary Receiver Callback",
            VulnerabilityCategory::IsContractPostPectra => "isContract Post-Pectra",
            VulnerabilityCategory::UnsafeMulticallDelegatecall => "Unsafe Multicall Delegatecall",
            // 2026 exploit patterns (v0.9.0)
            VulnerabilityCategory::ERC4337PaymasterAbuse => "ERC-4337 Paymaster Abuse",
            VulnerabilityCategory::EIP1271SignatureReplay => "EIP-1271 Signature Replay",
            VulnerabilityCategory::Permit2UnlimitedApproval => "Permit2 Unlimited Approval",
            VulnerabilityCategory::LRTRehypothecation => "LRT Re-Hypothecation",
            VulnerabilityCategory::StorageLayoutCollision => "Upgradeable Storage Layout Collision",
            VulnerabilityCategory::GovernanceFlashloanVoting => "Governance Flash-Loan Voting",
            VulnerabilityCategory::SandwichResistantMissing => "Missing Sandwich Resistance",
            VulnerabilityCategory::TransientStorageCompilerBug => {
                "Transient Storage Compiler Bug"
            }
            VulnerabilityCategory::EIP7702DelegateStorageCollision => {
                "EIP-7702 Delegate Storage Collision"
            }
            VulnerabilityCategory::LayerZeroSingleDVN => "LayerZero Single DVN Verification",
            VulnerabilityCategory::ERC7683UnvalidatedFill => "ERC-7683 Unvalidated Fill",
            VulnerabilityCategory::ERC6909FlashAccountingDrain => {
                "ERC-6909 Flash Accounting Drain"
            }
            VulnerabilityCategory::ERC7579UnprotectedModule => {
                "ERC-7579 Unprotected Module Installation"
            }
            VulnerabilityCategory::ERC7821UnprotectedExecute => {
                "ERC-7821 Unprotected Batch Execute"
            }
            VulnerabilityCategory::ERC7579UnrestrictedExecutor => {
                "ERC-7579 Unrestricted Executor Dispatch"
            }
        }
    }
}

/// Create additional vulnerability rules that depend on the detected Solidity compiler version.
/// Pre-0.8 contracts get arithmetic overflow/underflow rules, older versions get
/// additional known compiler bug checks, and cross-version attack patterns are added.
pub fn create_version_specific_rules(version: &CompilerVersion) -> Vec<VulnerabilityRule> {
    let mut rules = Vec::new();

    // Add compiler version warnings and known vulnerabilities
    add_compiler_vulnerabilities(&mut rules, version);

    match version {
        CompilerVersion::V04
        | CompilerVersion::V05
        | CompilerVersion::V06
        | CompilerVersion::V07 => {
            // Pre-0.8.0: No automatic overflow protection
            // More specific patterns for arithmetic operations in actual code contexts
            rules.push(VulnerabilityRule::new(
                VulnerabilityCategory::ArithmeticIssues,
                VulnerabilitySeverity::Critical,
                r"uint\d*\s+\w+\s*=\s*\w+\s*\+\s*\w+",
                "Integer Overflow Risk (Pre-0.8.0)".to_string(),
                "Addition without overflow check in Solidity < 0.8.0".to_string(),
                "Use SafeMath library or upgrade to Solidity 0.8.0+ for automatic overflow protection".to_string(),
                false,
            ).unwrap());

            rules.push(
                VulnerabilityRule::new(
                    VulnerabilityCategory::ArithmeticIssues,
                    VulnerabilitySeverity::Critical,
                    r"uint\d*\s+\w+\s*=\s*\w+\s*\*\s*\w+",
                    "Integer Multiplication Overflow Risk".to_string(),
                    "Multiplication without overflow check in Solidity < 0.8.0".to_string(),
                    "Use SafeMath.mul() or upgrade to Solidity 0.8.0+".to_string(),
                    false,
                )
                .unwrap(),
            );

            rules.push(
                VulnerabilityRule::new(
                    VulnerabilityCategory::ArithmeticIssues,
                    VulnerabilitySeverity::Critical,
                    r"uint\d*\s+\w+\s*=\s*\w+\s*-\s*\w+",
                    "Integer Underflow Risk (Pre-0.8.0)".to_string(),
                    "Subtraction without underflow check in Solidity < 0.8.0".to_string(),
                    "Use SafeMath.sub() or upgrade to Solidity 0.8.0+".to_string(),
                    false,
                )
                .unwrap(),
            );

            // Increment and decrement operations
            rules.push(
                VulnerabilityRule::new(
                    VulnerabilityCategory::ArithmeticIssues,
                    VulnerabilitySeverity::High,
                    r"\+\+\w+|\w+\+\+",
                    "Unchecked Increment (Pre-0.8.0)".to_string(),
                    "Increment operation without overflow check in Solidity < 0.8.0".to_string(),
                    "Use SafeMath or explicit checks for overflow".to_string(),
                    false,
                )
                .unwrap(),
            );

            rules.push(
                VulnerabilityRule::new(
                    VulnerabilityCategory::ArithmeticIssues,
                    VulnerabilitySeverity::High,
                    r"--\w+|\w+--",
                    "Unchecked Decrement (Pre-0.8.0)".to_string(),
                    "Decrement operation without underflow check in Solidity < 0.8.0".to_string(),
                    "Use SafeMath or explicit checks for underflow".to_string(),
                    false,
                )
                .unwrap(),
            );
        }
        CompilerVersion::V08 => {
            // Post-0.8.0: Check for unchecked blocks
            rules.push(VulnerabilityRule::new(
                VulnerabilityCategory::ArithmeticIssues,
                VulnerabilitySeverity::High,
                // `[\+\-\*]` also matched `unchecked { ++i; }` -- the standard 0.8+ loop
                // counter idiom, which cannot overflow. Require a real arithmetic
                // assignment so only genuinely wrappable math is reported.
                //
                // NOTE: this rule currently produces no output under the default
                // configuration -- `false_positive_filter::filter_arithmetic` drops every
                // `ArithmeticIssues` finding when the contract is Solidity 0.8+, which is
                // exactly when this rule is registered. See the report accompanying this
                // change for the filter-side fix (that file is owned elsewhere).
                r"unchecked\s*\{[^}]*(?:\+=|-=|\*=|\w+\s*=\s*\w+\s*[\+\-\*]\s*\w+)",
                "Unchecked Arithmetic in 0.8.0+".to_string(),
                "Using unchecked block disables overflow protection in Solidity 0.8.0+".to_string(),
                "Remove unchecked block unless gas optimization is critical and overflow is impossible".to_string(),
                true,
            ).unwrap());
        }
    }

    // Division by zero check (all versions) - more specific pattern
    rules.push(
        VulnerabilityRule::new(
            VulnerabilityCategory::ArithmeticIssues,
            VulnerabilitySeverity::High,
            r"uint\d*\s+\w+\s*=.*\w+\s*/\s*\w+",
            "Potential Division by Zero".to_string(),
            "Division without zero check can cause transaction revert".to_string(),
            "Add require(divisor != 0) check before division".to_string(),
            false,
        )
        .unwrap(),
    );

    // Precision loss in division
    rules.push(
        VulnerabilityRule::new(
            VulnerabilityCategory::ArithmeticIssues,
            VulnerabilitySeverity::Medium,
            r"(\w+)\s*/\s*(\d+)\s*\*\s*(\d+)",
            "Precision Loss in Division".to_string(),
            "Division before multiplication can cause precision loss".to_string(),
            "Perform multiplication before division to maintain precision".to_string(),
            false,
        )
        .unwrap(),
    );

    // Percentage calculation issues
    rules.push(
        VulnerabilityRule::new(
            VulnerabilityCategory::ArithmeticIssues,
            VulnerabilitySeverity::Medium,
            r"\*\s*(\d+)\s*/\s*100\b",
            "Percentage Calculation Precision Loss".to_string(),
            "Integer division in percentage calculation loses precision".to_string(),
            "Use basis points (10000) instead of percentages for better precision".to_string(),
            false,
        )
        .unwrap(),
    );

    // Version-specific constructor patterns
    if version == &CompilerVersion::V04 {
        rules.push(
            VulnerabilityRule::new(
                VulnerabilityCategory::NamingConventions,
                VulnerabilitySeverity::Critical,
                r"function\s+[A-Z]\w+\s*\([^)]*\)\s+public\s*\{",
                "Constructor as Function Name (0.4.x)".to_string(),
                "Using contract name as constructor is deprecated and error-prone".to_string(),
                "Use constructor() keyword instead (requires Solidity >= 0.4.22)".to_string(),
                false,
            )
            .unwrap(),
        );
    }

    // tx.origin authentication (all versions but especially problematic in older versions)
    rules.push(
        VulnerabilityRule::new(
            VulnerabilityCategory::AccessControl,
            VulnerabilitySeverity::High,
            r"require\s*\(\s*tx\.origin\s*==",
            "tx.origin Authentication".to_string(),
            "Using tx.origin for authentication is vulnerable to phishing attacks".to_string(),
            "Use msg.sender instead of tx.origin for authentication".to_string(),
            false,
        )
        .unwrap(),
    );

    // Selfdestruct issues (version-specific naming)
    match version {
        CompilerVersion::V04 | CompilerVersion::V05 => {
            rules.push(
                VulnerabilityRule::new(
                    VulnerabilityCategory::AccessControl,
                    VulnerabilitySeverity::Critical,
                    r"suicide\s*\(",
                    "Unprotected Suicide Function".to_string(),
                    "suicide() can destroy contract and send funds - ensure proper access control"
                        .to_string(),
                    "Add access control and consider if selfdestruct is necessary".to_string(),
                    false,
                )
                .unwrap(),
            );
        }
        _ => {
            rules.push(VulnerabilityRule::new(
                VulnerabilityCategory::AccessControl,
                VulnerabilitySeverity::Critical,
                r"selfdestruct\s*\(",
                "Unprotected Selfdestruct".to_string(),
                "selfdestruct can destroy contract and send funds - ensure proper access control".to_string(),
                "Add access control and consider if selfdestruct is necessary".to_string(),
                false,
            ).unwrap());
        }
    }

    // Single delegatecall detection (merged from 2 overlapping patterns)
    rules.push(VulnerabilityRule::new(
        VulnerabilityCategory::DelegateCalls,
        VulnerabilitySeverity::Critical,
        r"\.delegatecall\s*\(",
        "Delegatecall Usage Detected".to_string(),
        "Delegatecall preserves msg.sender/value and can modify storage - verify target is trusted".to_string(),
        "Ensure target address is trusted, validate input data, and implement access controls".to_string(),
        false,
    ).unwrap());

    // Delegatecall with user-controlled addresses
    rules.push(
        VulnerabilityRule::new(
            VulnerabilityCategory::DelegateCalls,
            VulnerabilitySeverity::Critical,
            r"\.delegatecall\s*\([^)]*\bmsg\.sender\b",
            "Delegatecall with User-Controlled Address".to_string(),
            "Allowing users to control delegatecall target enables arbitrary code execution"
                .to_string(),
            "Never allow user input to determine delegatecall target address".to_string(),
            false,
        )
        .unwrap(),
    );

    // Delegatecall in loops - dangerous pattern
    rules.push(
        VulnerabilityRule::new(
            VulnerabilityCategory::DelegateCalls,
            VulnerabilitySeverity::Critical,
            r"for\s*\([^)]*\)\s*\{[^}]*delegatecall",
            "Delegatecall in Loop".to_string(),
            "Multiple delegatecalls in loops can cause unpredictable state changes".to_string(),
            "Avoid delegatecalls in loops, batch operations instead".to_string(),
            true,
        )
        .unwrap(),
    );

    // REMOVED: Duplicate of "Unchecked Low-Level Call" rule in main rules which
    // already catches .delegatecall() with the pattern .(call|delegatecall|staticcall)\s*\(...\)\s*;

    // Delegatecall with dynamic data
    rules.push(
        VulnerabilityRule::new(
            VulnerabilityCategory::DelegateCalls,
            VulnerabilitySeverity::High,
            r"delegatecall\s*\([^)]*abi\.encode",
            "Delegatecall with Dynamic Data".to_string(),
            "Dynamic data in delegatecall can be manipulated to call unintended functions"
                .to_string(),
            "Validate and sanitize all data passed to delegatecall".to_string(),
            false,
        )
        .unwrap(),
    );

    // Assembly delegatecall
    rules.push(
        VulnerabilityRule::new(
            VulnerabilityCategory::DelegateCalls,
            VulnerabilitySeverity::Critical,
            r"assembly\s*\{[^}]*delegatecall",
            "Assembly Delegatecall".to_string(),
            "Assembly delegatecall bypasses Solidity safety checks completely".to_string(),
            "Extremely dangerous - thoroughly audit assembly code and consider alternatives"
                .to_string(),
            true,
        )
        .unwrap(),
    );

    // REMOVED: Duplicate of assembly rule in create_vulnerability_rules() (line ~1070)

    // Gas limit issues specific to versions
    match version {
        CompilerVersion::V04 | CompilerVersion::V05 | CompilerVersion::V06 => {
            rules.push(
                VulnerabilityRule::new(
                    VulnerabilityCategory::GasOptimization,
                    VulnerabilitySeverity::Medium,
                    r"\.transfer\s*\(",
                    "transfer() Gas Limitation".to_string(),
                    "transfer() only forwards 2300 gas which may not be enough for some operations"
                        .to_string(),
                    "Consider using call() with proper reentrancy protection".to_string(),
                    false,
                )
                .unwrap(),
            );
        }
        _ => {}
    }

    // Unsafe type conversions
    rules.push(
        VulnerabilityRule::new(
            VulnerabilityCategory::ArithmeticIssues,
            VulnerabilitySeverity::High,
            r"uint64\s*\([^)]*uint256",
            "Unsafe Type Downcast".to_string(),
            "Casting from uint256 to smaller type can cause data loss".to_string(),
            "Add bounds checking before downcasting or avoid downcasting".to_string(),
            false,
        )
        .unwrap(),
    );

    // Fee-on-transfer token issues
    rules.push(
        VulnerabilityRule::new(
            VulnerabilityCategory::ArithmeticIssues,
            VulnerabilitySeverity::Medium,
            r"balanceOf\(address\(this\)\)\s*\+\s*amount",
            "Fee-on-Transfer Token Vulnerability".to_string(),
            "Assuming balance increases by exact amount - fails with fee-on-transfer tokens"
                .to_string(),
            "Calculate actual received amount by checking balance before and after".to_string(),
            false,
        )
        .unwrap(),
    );

    // Rounding errors in calculations
    rules.push(
        VulnerabilityRule::new(
            VulnerabilityCategory::ArithmeticIssues,
            VulnerabilitySeverity::Medium,
            r"(\w+)\s*\*\s*(\w+)\s*/\s*(\w+)\s*\*\s*(\w+)",
            "Complex Division Chain".to_string(),
            "Multiple divisions can compound rounding errors".to_string(),
            "Minimize division operations and consider using fixed-point math libraries"
                .to_string(),
            false,
        )
        .unwrap(),
    );

    rules
}

/// Add rules for known compiler bugs specific to each Solidity version (0.4.x through 0.8.x).
/// Each version branch adds patterns for documented compiler vulnerabilities from the
/// Solidity changelog and security advisories.
fn add_compiler_vulnerabilities(rules: &mut Vec<VulnerabilityRule>, version: &CompilerVersion) {
    match version {
        CompilerVersion::V04 => {
            // Solidity 0.4.x - Multiple critical vulnerabilities
            rules.push(VulnerabilityRule::new(
                VulnerabilityCategory::PragmaIssues,
                VulnerabilitySeverity::Critical,
                r"pragma\s+solidity\s+.*0\.4\.",
                "Obsolete Compiler Version (0.4.x)".to_string(),
                "Solidity 0.4.x has numerous critical vulnerabilities and is no longer maintained".to_string(),
                "URGENT: Upgrade to Solidity 0.8.x or newer. Version 0.4.x is extremely vulnerable".to_string(),
                false,
            ).unwrap());

            // Function modifier order vulnerability (0.4.x)
            rules.push(VulnerabilityRule::new(
                VulnerabilityCategory::AccessControl,
                VulnerabilitySeverity::Critical,
                r"function\s+\w+\([^)]*\)\s+public\s+payable",
                "Function Modifier Order Vulnerability".to_string(),
                "In Solidity 0.4.x, function modifier order affects visibility and can cause security issues".to_string(),
                "Carefully check modifier order and upgrade to 0.8.x where order is enforced".to_string(),
                false,
            ).unwrap());

            // Constructor with contract name vulnerability
            rules.push(
                VulnerabilityRule::new(
                    VulnerabilityCategory::AccessControl,
                    VulnerabilitySeverity::Critical,
                    r"function\s+[A-Z]\w*\s*\([^)]*\)\s*(public|internal|private)?",
                    "Constructor Naming Vulnerability".to_string(),
                    "Using contract name as constructor can be exploited if contract is renamed"
                        .to_string(),
                    "Use constructor() keyword introduced in 0.4.22 to prevent this vulnerability"
                        .to_string(),
                    false,
                )
                .unwrap(),
            );

            // Uninitialized storage pointer (0.4.x)
            rules.push(
                VulnerabilityRule::new(
                    VulnerabilityCategory::StateVariable,
                    VulnerabilitySeverity::Critical,
                    r"struct\s+\w+\s+\w+;",
                    "Uninitialized Storage Pointer".to_string(),
                    "Uninitialized storage pointers in 0.4.x can overwrite arbitrary storage slots"
                        .to_string(),
                    "Always initialize storage pointers or upgrade to 0.5.0+ where this is fixed"
                        .to_string(),
                    false,
                )
                .unwrap(),
            );
        }

        CompilerVersion::V05 => {
            rules.push(VulnerabilityRule::new(
                VulnerabilityCategory::PragmaIssues,
                VulnerabilitySeverity::High,
                r"pragma\s+solidity\s+.*0\.5\.",
                "Legacy Compiler Version (0.5.x)".to_string(),
                "Solidity 0.5.x lacks modern safety features and has known vulnerabilities".to_string(),
                "Upgrade to Solidity 0.8.x for automatic overflow protection and better security".to_string(),
                false,
            ).unwrap());

            // ABI encoder v1 vulnerabilities
            rules.push(
                VulnerabilityRule::new(
                    VulnerabilityCategory::UnsafeExternalCalls,
                    VulnerabilitySeverity::High,
                    r"abi\.encode\(|abi\.encodePacked\(",
                    "ABI Encoder V1 Vulnerabilities".to_string(),
                    "Solidity 0.5.x uses ABI encoder v1 which has hash collision vulnerabilities"
                        .to_string(),
                    "Upgrade to 0.8.0+ which uses ABI encoder v2 by default".to_string(),
                    false,
                )
                .unwrap(),
            );
        }

        CompilerVersion::V06 => {
            rules.push(
                VulnerabilityRule::new(
                    VulnerabilityCategory::PragmaIssues,
                    VulnerabilitySeverity::High,
                    r"pragma\s+solidity\s+.*0\.6\.",
                    "Vulnerable Compiler Version (0.6.x)".to_string(),
                    "Solidity 0.6.x has security issues and lacks overflow protection".to_string(),
                    "Upgrade to Solidity 0.8.x for built-in overflow protection and security fixes"
                        .to_string(),
                    false,
                )
                .unwrap(),
            );

            // Array bounds check bypass (0.6.x)
            rules.push(
                VulnerabilityRule::new(
                    VulnerabilityCategory::ArithmeticIssues,
                    VulnerabilitySeverity::Critical,
                    r"\[\s*\w+\s*\]",
                    "Array Bounds Check Bypass (0.6.x)".to_string(),
                    "Solidity 0.6.x has vulnerabilities in array bounds checking".to_string(),
                    "Upgrade to 0.8.0+ and always validate array indices manually".to_string(),
                    false,
                )
                .unwrap(),
            );

            // Try-catch with dangerous external calls
            rules.push(
                VulnerabilityRule::new(
                    VulnerabilityCategory::UnsafeExternalCalls,
                    VulnerabilitySeverity::High,
                    r"try\s+\w+\.",
                    "Try-Catch External Call Risk".to_string(),
                    "try-catch in 0.6.x can mask failures and create security vulnerabilities"
                        .to_string(),
                    "Carefully handle try-catch exceptions and validate all external call results"
                        .to_string(),
                    false,
                )
                .unwrap(),
            );
        }

        CompilerVersion::V07 => {
            rules.push(
                VulnerabilityRule::new(
                    VulnerabilityCategory::PragmaIssues,
                    VulnerabilitySeverity::Medium,
                    r"pragma\s+solidity\s+.*0\.7\.",
                    "Pre-Overflow Protection Version (0.7.x)".to_string(),
                    "Solidity 0.7.x lacks automatic overflow protection introduced in 0.8.0"
                        .to_string(),
                    "Consider upgrading to 0.8.x for automatic overflow protection or use SafeMath"
                        .to_string(),
                    false,
                )
                .unwrap(),
            );

            // Inline assembly return data size bug (0.7.x)
            rules.push(
                VulnerabilityRule::new(
                    VulnerabilityCategory::UnsafeExternalCalls,
                    VulnerabilitySeverity::High,
                    r"assembly\s*\{[^}]*returndatasize",
                    "Inline Assembly Return Data Bug".to_string(),
                    "Solidity 0.7.x has bugs with returndatasize in inline assembly".to_string(),
                    "Avoid using returndatasize in assembly or upgrade to 0.8.4+".to_string(),
                    true,
                )
                .unwrap(),
            );

            // Free memory pointer corruption (0.7.x)
            rules.push(
                VulnerabilityRule::new(
                    VulnerabilityCategory::UnsafeExternalCalls,
                    VulnerabilitySeverity::Critical,
                    r"assembly\s*\{[^}]*mstore\s*\(\s*0x40",
                    "Free Memory Pointer Corruption".to_string(),
                    "Modifying free memory pointer (0x40) can cause memory corruption in 0.7.x"
                        .to_string(),
                    "Avoid manual memory management or upgrade to 0.8.x with better memory safety"
                        .to_string(),
                    true,
                )
                .unwrap(),
            );
        }

        CompilerVersion::V08 => {
            // Version 0.8.x specific vulnerabilities
            rules.push(
                VulnerabilityRule::new(
                    VulnerabilityCategory::PragmaIssues,
                    VulnerabilitySeverity::Info,
                    r"pragma\s+solidity\s+0\.8\.[0-6]\b",
                    "Early 0.8.x Version Vulnerabilities".to_string(),
                    "Early Solidity 0.8.x versions (0.8.0-0.8.6) have known bugs".to_string(),
                    "Upgrade to Solidity 0.8.19+ for the most stable and secure version"
                        .to_string(),
                    false,
                )
                .unwrap(),
            );

            // Optimizer bug in 0.8.13-0.8.16
            rules.push(
                VulnerabilityRule::new(
                    VulnerabilityCategory::PragmaIssues,
                    VulnerabilitySeverity::High,
                    r"pragma\s+solidity\s+0\.8\.1[3-6]\b",
                    "Optimizer Bug (0.8.13-0.8.16)".to_string(),
                    "Solidity 0.8.13-0.8.16 have optimizer bugs affecting certain code patterns"
                        .to_string(),
                    "Upgrade to 0.8.17+ or disable optimizer if stuck on these versions"
                        .to_string(),
                    false,
                )
                .unwrap(),
            );

            // ABI encoder v2 struct bug (0.8.0-0.8.6)
            rules.push(
                VulnerabilityRule::new(
                    VulnerabilityCategory::UnsafeExternalCalls,
                    VulnerabilitySeverity::Critical,
                    // `.*struct` under `(?s)` fired on ANY 0.8.0-0.8.6 file containing
                    // the word `struct` and spanned pragma -> last `struct` in the file,
                    // i.e. a whole-file Critical annotation in SARIF. The bug only bites
                    // when a struct crosses an ABI boundary, so require the evidence the
                    // recommendation already names: an external/public function taking a
                    // user-defined (capitalised) type in calldata/memory. Only structs
                    // and struct arrays can carry a data location, so this is precise.
                    r"pragma\s+solidity\s+0\.8\.[0-6]\b[\s\S]{0,4000}?\bfunction\s+\w+\s*\([^)]*\b[A-Z]\w*(?:\[\])?\s+(?:calldata|memory)\b[^)]*\)[^;{]*\b(?:external|public)\b",
                    "ABI Encoder Struct Bug (0.8.0-0.8.6)".to_string(),
                    "Solidity 0.8.0-0.8.6 have critical bugs in ABI encoding of structs"
                        .to_string(),
                    "URGENT: Upgrade to 0.8.7+ if using structs in external interfaces".to_string(),
                    true,
                )
                .unwrap(),
            );
        }
    }

    // Cross-version vulnerabilities and attacks
    add_cross_version_attacks(rules, version);
}

/// Add rules for attack patterns that span multiple Solidity versions
/// (e.g., abi.encodePacked hash collisions, constructor confusion in 0.4.x).
fn add_cross_version_attacks(rules: &mut Vec<VulnerabilityRule>, version: &CompilerVersion) {
    // Hash collision attacks (all versions with abi.encodePacked)
    rules.push(
        VulnerabilityRule::new(
            VulnerabilityCategory::UnsafeExternalCalls,
            VulnerabilitySeverity::Medium,
            r"(keccak256|sha256)\s*\(\s*abi\.encodePacked\s*\([^)]*,\s*[^)]*\)",
            "Hash Collision Attack Risk".to_string(),
            "abi.encodePacked with multiple dynamic types can cause hash collisions when hashed".to_string(),
            "Use abi.encode() instead of abi.encodePacked() or add fixed separators".to_string(),
            false,
        )
        .unwrap(),
    );

    // REMOVED: Duplicate and too broad - catches ANY mention of CREATE2 including
    // comments and imports. The specific create2 rule in main rules handles real issues.

    // Front-running attacks
    rules.push(
        VulnerabilityRule::new(
            VulnerabilityCategory::FrontRunning,
            VulnerabilitySeverity::High,
            r"block\.timestamp.*==.*now|now.*==.*block\.timestamp",
            "Front-running Attack Vulnerability".to_string(),
            "Exact timestamp comparisons enable front-running attacks".to_string(),
            "Use time ranges instead of exact timestamp matches".to_string(),
            false,
        )
        .unwrap(),
    );

    // MEV attacks
    rules.push(
        VulnerabilityRule::new(
            VulnerabilityCategory::FrontRunning,
            VulnerabilitySeverity::High,
            r"function\s+\w*swap\w*\([^)]*\)\s+(external|public)",
            "MEV Attack Surface".to_string(),
            "Public swap functions are vulnerable to MEV (sandwich attacks)".to_string(),
            "Implement MEV protection like commit-reveal or use private mempools".to_string(),
            false,
        )
        .unwrap(),
    );

    // Storage collision attacks in upgradeable contracts
    rules.push(
        VulnerabilityRule::new(
            VulnerabilityCategory::StateVariable,
            VulnerabilitySeverity::Critical,
            r"contract\s+\w+.*is.*Initializable",
            "Storage Collision in Upgradeable Contracts".to_string(),
            "Upgradeable contracts are vulnerable to storage collision attacks".to_string(),
            "Use storage gaps and careful variable ordering in upgradeable contracts".to_string(),
            false,
        )
        .unwrap(),
    );

    // Flash loan attack patterns
    rules.push(
        VulnerabilityRule::new(
            VulnerabilityCategory::UnsafeExternalCalls,
            VulnerabilitySeverity::Critical,
            r"function\s+\w*(flash|Flash)\w*\([^)]*\).*external",
            "Flash Loan Attack Surface".to_string(),
            "Flash loan functions can be exploited for price manipulation attacks".to_string(),
            "Implement proper oracle validation and reentrancy protection".to_string(),
            false,
        )
        .unwrap(),
    );

    // Oracle manipulation attacks
    rules.push(
        VulnerabilityRule::new(
            VulnerabilityCategory::UnsafeExternalCalls,
            VulnerabilitySeverity::Critical,
            r"\.latestRoundData\(\)|\.latestAnswer\(\)",
            "Oracle Manipulation Attack Risk".to_string(),
            "Single oracle calls are vulnerable to price manipulation attacks".to_string(),
            "Use multiple oracles, time-weighted averages, and validate price changes".to_string(),
            false,
        )
        .unwrap(),
    );

    match version {
        CompilerVersion::V04
        | CompilerVersion::V05
        | CompilerVersion::V06
        | CompilerVersion::V07 => {
            // Additional attacks for pre-0.8.0
            rules.push(
                VulnerabilityRule::new(
                    VulnerabilityCategory::ArithmeticIssues,
                    VulnerabilitySeverity::Critical,
                    r"balanceOf\(.*\)\s*\+\s*amount",
                    "Token Balance Manipulation".to_string(),
                    "Pre-0.8.0 token balance calculations vulnerable to overflow attacks"
                        .to_string(),
                    "Use SafeMath for all token calculations or upgrade to 0.8.0+".to_string(),
                    false,
                )
                .unwrap(),
            );
        }
        _ => {}
    }

    // REMOVED: Duplicate of loop-based DoS rules in create_vulnerability_rules()
    // and the gas optimization cache-array-length rule

    // REMOVED: Duplicate of ecrecover rules in create_vulnerability_rules()
    // (SignatureVulnerabilities and SignatureVerificationBypass categories)

    // REMOVED: Duplicate and too broad - catches ANY tx.origin reference including
    // safe reads. The specific require(tx.origin ==) rules handle real auth issues.
}
