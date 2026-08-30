//! Core scanning orchestration engine.
//!
//! `ContractScanner` coordinates the full analysis pipeline:
//! 1. Parse the Solidity source file
//! 2. Apply regex-based vulnerability rules (single-line and multiline)
//! 3. Run advanced analyzers (DeFi, NFT, exploit patterns, OWASP, L2)
//! 4. Run logic analysis for business logic bugs
//! 5. Run dependency/import analysis for known CVEs
//! 6. Generate threat model findings
//! 7. Filter unreachable code paths via reachability analysis
//! 8. Run EIP-specific compliance checks
//! 9. Apply false positive filtering to reduce noise
//!
//! Each phase can be independently toggled via `ScannerConfig`.

use crate::advanced_analysis::AdvancedAnalyzer;
use crate::dependency_analyzer::DependencyAnalyzer;
use crate::eip_analyzer::EIPAnalyzer;
use crate::false_positive_filter::{FalsePositiveFilter, FilterConfig};
use crate::inheritance::{ProjectIndex, ResolvedFile};
use crate::logic_analyzer::LogicAnalyzer;
use crate::parser::CompilerVersion;
use crate::parser::{CompilerInfo, SolidityParser};
use crate::reachability_analyzer::ReachabilityAnalyzer;
use crate::threat_model::ThreatModelGenerator;
use crate::unused_declarations::UnusedDeclarationAnalyzer;
use crate::vulnerabilities::{
    create_version_specific_rules, create_vulnerability_rules, Vulnerability, VulnerabilityRule,
};
use once_cell::sync::Lazy;
use regex::Regex;
use std::collections::HashMap;
use std::io;
use std::path::Path;
use std::sync::{Arc, Mutex};

type ParsedLine<'a> = (usize, &'a str);

/// Where in the source a rule matched, bundled so the context-aware filter takes one
/// positional argument instead of five. All fields are borrowed, so this is `Copy`.
#[derive(Clone, Copy)]
struct MatchSite<'a, 'src> {
    /// The text the rule actually matched against (comment-stripped for single-line rules).
    line: &'a str,
    /// The whole file, unmodified.
    full_content: &'a str,
    /// Every parsed line of the file, as `(line_number, text)`.
    lines: &'a [ParsedLine<'src>],
    /// Zero-based index of `line` within `lines`.
    line_idx: usize,
    /// Per-file facts (SafeMath, guards, compiler version, ...) computed once.
    scan_context: &'a ScanContext,
}

#[cfg(test)]
mod review_regression_tests {
    use super::*;
    use std::path::PathBuf;

    fn fixture(name: &str, source: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "41swara-scanner-review-tests-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).expect("create scanner test directory");
        let path = dir.join(name);
        std::fs::write(&path, source).expect("write scanner test fixture");
        path
    }

    #[test]
    fn oversized_file_is_an_error_not_a_clean_scan() {
        let path = fixture("oversized.sol", "contract Oversized {}");
        let scanner = ContractScanner::with_config(
            false,
            ScannerConfig {
                max_file_size_bytes: 1,
                ..ScannerConfig::default()
            },
        );

        let error = scanner
            .scan_file(&path)
            .expect_err("oversized input must fail");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn unrelated_contract_layouts_are_not_proxy_collisions() {
        let path = fixture(
            "unrelated-layouts.sol",
            r#"pragma solidity ^0.8.20;
contract NamedProxyButNotAProxy { address public owner; }
contract Treasury { uint256 public balance; }
"#,
        );
        let result = ContractScanner::new(false)
            .scan_file(&path)
            .expect("scan succeeds");

        assert!(
            result
                .vulnerabilities
                .iter()
                .all(|v| !v.title.starts_with("Storage Slot Collision:")),
            "unrelated contracts must not be treated as proxy/implementation layouts"
        );
    }

    #[test]
    fn delegatecall_plus_a_proxy_name_does_not_collide_unrelated_contracts() {
        // A file can contain a delegatecall and something named `*Proxy` while still holding
        // contracts that have nothing to do with each other. Before the stem check these drew
        // a High "Storage Slot Collision" against every other storage-bearing contract.
        let path = fixture(
            "unrelated-with-delegatecall.sol",
            r#"pragma solidity ^0.8.20;
contract Alpha { uint256 public totalSupply; }
contract SomeProxy {
    address public implementation;
    fallback() external payable {
        (bool ok,) = implementation.delegatecall(msg.data);
        require(ok);
    }
}
"#,
        );
        let result = ContractScanner::new(false)
            .scan_file(&path)
            .expect("scan succeeds");

        assert!(
            result
                .vulnerabilities
                .iter()
                .all(|v| !v.title.starts_with("Storage Slot Collision:")),
            "contracts with unrelated name stems must not be paired as proxy/implementation"
        );
    }

    #[test]
    fn contract_name_stems_identify_proxy_implementation_pairs() {
        assert!(proxy_implementation_pair(
            "VaultProxy",
            "VaultImplementation"
        ));
        assert!(proxy_implementation_pair("TokenProxy", "TokenLogicV2"));
        assert!(!proxy_implementation_pair("SomeProxy", "Alpha"));
        assert!(
            !proxy_implementation_pair("Vault", "VaultImplementation"),
            "neither side is proxy-like, so there is no delegatecall relationship to assume"
        );
    }

    #[test]
    fn delegatecall_proxy_layout_collision_is_retained() {
        let path = fixture(
            "proxy-layouts.sol",
            r#"pragma solidity ^0.8.20;
contract VaultProxy {
    address public implementation;
    fallback() external payable {
        (bool ok,) = implementation.delegatecall(msg.data);
        require(ok);
    }
}
contract VaultImplementation { uint256 public totalSupply; }
"#,
        );
        let result = ContractScanner::new(false)
            .scan_file(&path)
            .expect("scan succeeds");

        assert!(result
            .vulnerabilities
            .iter()
            .any(|v| v.title.starts_with("Storage Slot Collision:")));
    }
}

/// Strip the affixes that distinguish a proxy from the implementation it delegates into,
/// leaving the shared stem. `VaultProxy` and `VaultImplementationV2` both reduce to `vault`.
fn contract_name_stem(name: &str) -> String {
    let mut stem = name.to_ascii_lowercase();
    for affix in [
        "upgradeable",
        "implementation",
        "transparent",
        "beacon",
        "proxy",
        "impl",
        "logic",
    ] {
        stem = stem.replace(affix, "");
    }
    // Drop trailing version markers (`v2`, `_v2`, `2`) and separators left behind.
    let trimmed = stem.trim_matches(|c: char| c == '_' || c == '-' || c.is_ascii_digit());
    let trimmed = trimmed.strip_suffix('v').unwrap_or(trimmed);
    trimmed
        .trim_matches(|c: char| c == '_' || c == '-')
        .to_string()
}

/// Two contracts are a candidate proxy/implementation pair when one is named like a proxy
/// and both reduce to the same stem.
///
/// The stem check is what keeps unrelated contracts apart: a file that merely *contains* a
/// `delegatecall` and happens to declare something named `*Proxy` would otherwise report a
/// high-severity storage collision against every other contract in the file. Proving the real
/// call target is outside this scanner's model, so a shared name stem stands in for the
/// relationship. It errs towards silence, which is the right direction for a High finding.
fn proxy_implementation_pair(left: &str, right: &str) -> bool {
    let (l, r) = (left.to_ascii_lowercase(), right.to_ascii_lowercase());
    if !l.contains("proxy") && !r.contains("proxy") {
        return false;
    }
    let (ls, rs) = (contract_name_stem(left), contract_name_stem(right));
    !ls.is_empty() && ls == rs
}

/// The result of scanning a single Solidity file.
/// Bundles detected vulnerabilities together with compiler version information
/// so callers get both analysis results and contract metadata in one return value.
#[derive(Debug, Clone)]
pub struct ScanResult {
    /// All detected vulnerabilities (sorted by line number).
    pub vulnerabilities: Vec<Vulnerability>,
    /// Compiler version information extracted from the pragma statement.
    /// `None` if no `pragma solidity` line was found.
    pub compiler_info: Option<CompilerInfo>,
}

#[derive(Clone, Copy, Default)]
struct LineState {
    is_comment: bool,
    is_in_block_comment: bool,
    is_signature_only: bool,
}

struct ScanContext {
    has_safemath: bool,
    has_safe_erc20: bool,
    has_reentrancy_guard: bool,
    uses_openzeppelin: bool,
    uses_solidity_0_8_plus: bool,
    uses_safe_signature_library: bool,
    known_modifiers: Vec<String>,
    /// Cross-file inheritance facts for this file. `None` when the scan came from
    /// `scan_content` (no path to resolve against), in which case the single-file
    /// heuristics apply unchanged.
    inherited: Option<std::sync::Arc<ResolvedFile>>,
    line_states: Vec<LineState>,
}

// =============================================================================
// Pre-compiled regex patterns (compiled once, reused across all scans)
// Prevents ReDoS risk from repeated compilation and improves performance.
// =============================================================================

/// The master rule set, compiled once per process. `create_vulnerability_rules`
/// compiles ~300 regexes (~200ms); every `ContractScanner` after the first gets
/// a cheap clone (`regex::Regex` is internally reference-counted). This matters
/// most for the test suite, which constructs dozens of scanners in one process.
static MASTER_RULES: Lazy<Vec<VulnerabilityRule>> = Lazy::new(create_vulnerability_rules);

/// Matches a contract that inherits a recognised test base contract. Word-boundaried
/// so `is Testable` / `is TestHelper` do not count as a test harness.
static TEST_BASE_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\bcontract\s+\w+\s+is\s+[^{;]*\b(?:Test|DSTest|StdCheats|StdAssertions|Script)\b")
        .unwrap()
});

static RE_INTERFACE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^\s*interface\s+\w+").expect("invalid interface regex"));
static RE_CONTRACT: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^\s*(contract|abstract\s+contract|library)\s+\w+").expect("invalid contract regex")
});
static RE_LIBRARY: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^\s*library\s+\w+").expect("invalid library regex"));
static RE_CONTRACT_ONLY: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^\s*(abstract\s+)?contract\s+\w+").expect("invalid contract-only regex")
});
static RE_SOLIDITY_08: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"pragma\s+solidity\s*[\^>=<]*\s*0\.([89]|[1-9]\d+)\.")
        .expect("invalid version regex")
});
static RE_MODIFIER: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"modifier\s+(\w+)").expect("invalid modifier regex"));
static RE_STATE_MOD: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(\w+\s*=\s*[^=]|\w+\[[^\]]*\]\s*=|\+\+|--|\.\s*push\s*\(|delete\s+)")
        .expect("invalid state mod regex")
});
static RE_NAMED_RETURN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"returns\s*\([^)]*\b\w+\s+\w+[^)]*\)").expect("invalid named return regex")
});

static RE_BOUNDED_SHIFT: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(<<|>>)\s*uint8\s*\(").expect("invalid bounded shift regex"));

static RE_DOWNCAST_ARG: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b(?:uint|int)(?:8|16|24|32|48|64|96|128|160|192|224)\s*\(\s*(\w+)\s*\)")
        .expect("invalid downcast arg regex")
});

/// Maximum file size (in bytes) the scanner will process.
/// Files larger than this are skipped to prevent DoS from excessively large inputs.
const MAX_FILE_SIZE_BYTES: u64 = 10 * 1024 * 1024; // 10 MB

/// Scanner configuration for analysis features
/// All advanced features are enabled by default for maximum accuracy
#[derive(Clone)]
pub struct ScannerConfig {
    pub enable_logic_analysis: bool,
    pub enable_reachability_analysis: bool,
    pub enable_dependency_analysis: bool,
    pub enable_threat_model: bool,
    /// Enable DeFi-specific analyzers and protocol heuristics
    pub enable_defi_analysis: bool,
    /// Enable modern Phase 6 detectors (ERC4626, Permit2, LayerZero, EIP-4337, etc.)
    pub enable_phase6_analysis: bool,
    /// Enable EIP-specific vulnerability detection
    pub enable_eip_analysis: bool,
    /// Enable enhanced false positive filtering
    pub enable_strict_filter: bool,
    /// Maximum file size to scan, in bytes. Files above this are skipped (DoS guard).
    /// Populated from `--max-file-size`; defaults to [`MAX_FILE_SIZE_BYTES`].
    pub max_file_size_bytes: u64,
}

impl Default for ScannerConfig {
    fn default() -> Self {
        Self {
            // All advanced features enabled by default
            enable_logic_analysis: true,
            enable_reachability_analysis: true,
            enable_dependency_analysis: true,
            enable_threat_model: true,
            enable_defi_analysis: true,
            enable_phase6_analysis: true,
            enable_eip_analysis: true,  // EIP analysis enabled by default
            enable_strict_filter: true, // Strict filtering enabled by default
            max_file_size_bytes: MAX_FILE_SIZE_BYTES,
        }
    }
}

/// The main scanner that orchestrates all analysis phases.
/// Holds references to all sub-analyzers and the vulnerability rule set.
pub struct ContractScanner {
    parser: SolidityParser,                            // Solidity source parser
    rules: Vec<VulnerabilityRule>,                     // Regex-based vulnerability detection rules
    verbose: bool,                                     // Enable detailed progress output
    advanced_analyzer: AdvancedAnalyzer, // DeFi/NFT/exploit/OWASP/L2 pattern detection
    logic_analyzer: LogicAnalyzer,       // Business logic vulnerability detection
    unused_declarations: UnusedDeclarationAnalyzer, // Declared-but-never-enforced analysis
    reachability_analyzer: ReachabilityAnalyzer, // Dead code / unreachable path filtering
    dependency_analyzer: DependencyAnalyzer, // Import/dependency CVE detection
    threat_model_generator: ThreatModelGenerator, // Automatic threat model generation
    eip_analyzer: EIPAnalyzer,           // ERC standard compliance checks
    false_positive_filter: FalsePositiveFilter, // Multi-pass false positive reduction
    ast_bridge: crate::ast::bridge::ASTAnalysisBridge, // AST/CFG/taint structural analysis
    defi_analyzer: crate::defi::DeFiAnalyzer, // AMM/lending/oracle/MEV protocol analysis
    config: ScannerConfig,               // Feature toggle configuration
    /// Memoized version-specific rule sets. `create_version_specific_rules` compiles
    /// ~44 regexes; without this it ran once per scanned file. Keyed by the 5-variant
    /// `CompilerVersion` enum, so at most 5 compilations happen per process. Shared
    /// across rayon worker threads via `Mutex` (contention is negligible: a cache miss
    /// only occurs the first time each version is seen).
    version_rules_cache: Mutex<HashMap<CompilerVersion, Arc<Vec<VulnerabilityRule>>>>,
    /// One `ProjectIndex` per scan root, shared across files and rayon workers.
    /// `DashMap` because `scan_file` is called concurrently by the parallel walker.
    inheritance_indexes: dashmap::DashMap<std::path::PathBuf, Arc<ProjectIndex>>,
}

// =============================================================================
// Context Detection Helpers
// These methods inspect the contract source for safe patterns (libraries,
// guards, modifiers, pragma versions) to suppress false positive findings.
// =============================================================================
impl ContractScanner {
    /// Check if SafeMath library is imported or used (pre-0.8 overflow protection).
    fn has_safemath(&self, content: &str) -> bool {
        content.contains("using SafeMath for")
            || content.contains("SafeMath.")
            || content.contains("import") && content.contains("SafeMath")
    }

    /// Check if SafeERC20 wrapper is used (handles unchecked return values).
    fn has_safe_erc20(&self, content: &str) -> bool {
        content.contains("using SafeERC20 for")
            || content.contains("SafeERC20.")
            || content.contains("import") && content.contains("SafeERC20")
    }

    /// Replace comment text with spaces while preserving byte offsets and newlines,
    /// so regex matches on the result map to the same line numbers as the original.
    /// String literals are left intact (a `//` inside a string, e.g. a URL, is not a comment).
    fn strip_comments(content: &str) -> String {
        crate::parser::strip_comments(content)
    }

    /// Check if the given line index is a single-line comment (// or * or /*).
    fn is_in_comment(&self, lines: &[ParsedLine<'_>], line_idx: usize) -> bool {
        if line_idx >= lines.len() {
            return false;
        }
        let line = lines[line_idx].1;
        line.trim().starts_with("//")
            || line.trim().starts_with("*")
            || line.trim().starts_with("/*")
    }

    /// Check if the contract uses a reentrancy guard (OZ ReentrancyGuard or custom lock).
    fn has_reentrancy_guard(&self, content: &str) -> bool {
        content.contains("ReentrancyGuard")
            || content.contains("nonReentrant")
            || content.contains("_nonReentrantBefore")
            || content.contains("reentrancy_lock")
    }

    /// Check if this file contains only interface definitions (no contract/library bodies).
    /// Interface-only files are skipped since they have no implementation to analyze.
    fn is_interface_contract(&self, content: &str) -> bool {
        let has_interface = content.lines().any(|line| RE_INTERFACE.is_match(line));
        let has_contract = content.lines().any(|line| RE_CONTRACT.is_match(line));

        // Only skip if file has interfaces but NO contracts
        has_interface && !has_contract
    }

    /// Check if the file contains ONLY Solidity `library` code (stateless utility code).
    /// A helper library bundled alongside contracts must not disable analysis of those
    /// contracts, so files that also declare a contract are NOT treated as libraries.
    fn is_library(&self, content: &str) -> bool {
        let has_library = content.lines().any(|line| RE_LIBRARY.is_match(line));
        let has_contract = content.lines().any(|line| RE_CONTRACT_ONLY.is_match(line));
        has_library && !has_contract
    }

    /// Check if this is a test or mock contract (Foundry/Hardhat test patterns).
    /// Test contracts get relaxed checks for some vulnerability categories.
    /// Decide whether this *file* is a test harness, which relaxes ~18 analysis passes.
    ///
    /// This must stay narrow. The previous implementation matched the bare substrings
    /// `"contract Mock"` and `"is Test"` anywhere in the file, which made it trivially
    /// exploitable: appending `contract MockToken {}` to a vulnerable production file
    /// disabled the entire pipeline and took the finding count to zero. It also matched
    /// `is Testable` / `is TestHelper` by accident.
    ///
    /// Evidence now required is specific to a real test harness: an import that only
    /// appears in tests, or a contract that actually inherits a test base contract. A
    /// mock or helper *declared alongside* production code no longer disables scanning —
    /// findings inside such a contract are suppressed per-contract by the false-positive
    /// filter instead, which is where that decision belongs.
    fn is_test_contract(&self, content: &str) -> bool {
        // Imports that exist only in test/script harnesses.
        if content.contains("forge-std/Test.sol")
            || content.contains("forge-std/Script.sol")
            || content.contains("hardhat/console.sol")
            || content.contains("ds-test/test.sol")
            || content.contains("truffle/Assert.sol")
        {
            return true;
        }

        // A contract inheriting a recognised test base. Word-boundaried so that
        // `is Testable` and `is TestHelper` do not match.
        TEST_BASE_RE.is_match(content)
    }

    /// Check if OpenZeppelin libraries are imported (well-audited, trusted patterns).
    fn uses_openzeppelin(&self, content: &str) -> bool {
        content.contains("@openzeppelin")
            || content.contains("openzeppelin-contracts")
            || content.contains("Ownable")
            || content.contains("AccessControl")
            || content.contains("Pausable")
    }

    /// Check if the contract targets Solidity 0.8+ (built-in overflow/underflow protection).
    fn uses_solidity_0_8_plus(&self, content: &str) -> bool {
        RE_SOLIDITY_08.is_match(content)
    }

    /// Extract all custom modifier names defined in the contract.
    fn extract_modifiers(&self, content: &str) -> Vec<String> {
        RE_MODIFIER
            .captures_iter(content)
            .filter_map(|cap| cap.get(1).map(|m| m.as_str().to_string()))
            .collect()
    }

    /// Get the full function signature spanning multiple lines (from `function` keyword to `{`).
    /// Solidity function signatures can span many lines with parameters and modifiers.
    fn get_full_function_signature(
        &self,
        lines: &[ParsedLine<'_>],
        func_line_idx: usize,
    ) -> String {
        let mut sig = String::new();
        for parsed in lines.iter().skip(func_line_idx).take(15) {
            sig.push_str(parsed.1);
            sig.push(' ');
            if parsed.1.contains('{') {
                break;
            }
        }
        sig
    }

    /// Resolve well-known modifiers from inherited contracts.
    /// Maps common base contracts to the modifiers they provide.
    fn resolve_known_modifiers(
        &self,
        content: &str,
        inherited: Option<&ResolvedFile>,
    ) -> Vec<String> {
        let mut modifiers = Vec::new();
        // Cross-file truth first: every modifier the resolved inheritance chain provides.
        // The string heuristics below remain as the fallback for files whose bases could
        // not be resolved (dependency not vendored, no project root, etc.).
        if let Some(r) = inherited {
            modifiers.extend_from_slice(r.modifier_names());
        }
        // OpenZeppelin Ownable → onlyOwner
        if content.contains("Ownable") || content.contains("is Ownable") {
            modifiers.push("onlyOwner".to_string());
        }
        // ReentrancyGuard → nonReentrant
        if content.contains("ReentrancyGuard") {
            modifiers.push("nonReentrant".to_string());
        }
        // Pausable → whenNotPaused, whenPaused
        if content.contains("Pausable") || content.contains("is Pausable") {
            modifiers.push("whenNotPaused".to_string());
            modifiers.push("whenPaused".to_string());
        }
        // AccessControl → onlyRole
        if content.contains("AccessControl") {
            modifiers.push("onlyRole".to_string());
        }
        // AccessManaged (OZ v5) → restricted
        if content.contains("AccessManaged") {
            modifiers.push("restricted".to_string());
        }
        // Initializable → initializer, reinitializer
        if content.contains("Initializable") {
            modifiers.push("initializer".to_string());
            modifiers.push("reinitializer".to_string());
        }
        // Also include contract-defined modifiers
        modifiers.extend(self.extract_modifiers(content));
        modifiers
    }

    /// Check if a function declaration line contains access control modifiers
    /// (standard keywords like onlyOwner, or custom modifiers from the contract).
    fn has_access_control_modifier(
        &self,
        function_line: &str,
        modifiers: &[String],
        inherited: Option<&ResolvedFile>,
    ) -> bool {
        // Authoritative: a modifier on this signature that the resolved inheritance chain
        // classifies as caller-restricting. This is what makes `contract Vault is Ownable`
        // with `onlyOwner` stop being reported as missing access control when `Ownable`
        // lives in another file. Binary search over a sorted slice; no allocation.
        if let Some(r) = inherited {
            for token in function_line.split(|c: char| !(c.is_alphanumeric() || c == '_')) {
                if !token.is_empty() && r.has_access_control_modifier(token) {
                    return true;
                }
            }
        }
        // Check for common access control and protection modifiers
        let access_control_keywords = vec![
            "onlyOwner",
            "onlyAdmin",
            "onlyRole",
            "onlyMinter",
            "onlyGovernance",
            "authorized",
            "onlyController",
            "onlyOperator",
            "onlyProxy",
            "onlyDelegateCall",
            "onlyEntryPoint",
            "onlySelf",
            "restricted",
            "private",
            "internal",
            "whenNotPaused",
            "whenPaused",
            "initializer",
            "reinitializer",
            "nonReentrant",
        ];

        for keyword in &access_control_keywords {
            if function_line.contains(keyword) {
                return true;
            }
        }

        // Check custom modifiers
        for modifier in modifiers {
            if function_line.contains(modifier) {
                return true;
            }
        }

        false
    }

    /// Check if the function body contains inline access control checks
    /// (require(msg.sender==...), if(_msgSender()!=...), _checkOwner(), etc.).
    fn has_access_control_check(
        &self,
        content: &str,
        function_start: usize,
        function_end: usize,
    ) -> bool {
        let lines: Vec<&str> = content.lines().collect();
        if function_start >= lines.len() {
            return false;
        }

        let check_patterns = vec![
            "require(msg.sender ==",
            "require(msg.sender!=",
            "require(_msgSender() ==",
            "require(owner ==",
            "require(hasRole",
            "require(_owner ==",
            "if (msg.sender !=",
            "if(msg.sender!=",
            "if (_msgSender() !=",
            "revert Unauthorized",
            "revert OwnableUnauthorizedAccount",
            "revert AccessControlUnauthorizedAccount",
            "_checkOwner()",
            "_checkRole(",
            "_checkCanCall(",
            // tx.origin-based guards ARE authorization attempts (unsafe ones). The
            // dedicated TxOriginAuth detector reports the real defect, so treat this
            // as "has a check" here to avoid a redundant missing-access-control finding.
            "tx.origin ==",
            "tx.origin!=",
            "tx.origin !=",
        ];

        for line in lines
            .iter()
            .take(function_end.min(lines.len()))
            .skip(function_start)
        {
            for pattern in &check_patterns {
                if line.contains(pattern) {
                    return true;
                }
            }
            // OZ v5 style: `address caller = _msgSender(); if (caller != ...) revert XxxUnauthorized(...)`
            if line.contains("revert") && line.contains("Unauthorized") {
                return true;
            }
            if (line.contains("caller !=")
                || line.contains("caller ==")
                || line.contains("msg.sender !=")
                || line.contains("msg.sender =="))
                && (line.contains("require") || line.contains("if") || line.contains("revert"))
            {
                return true;
            }
        }

        false
    }

    /// Check if a function is view/pure (read-only, no state modifications possible).
    fn is_view_or_pure_function(&self, function_line: &str) -> bool {
        function_line.contains(" view ")
            || function_line.contains(" pure ")
            || function_line.contains(" view)")
            || function_line.contains(" pure)")
    }

    /// Check if a function is internal/private (not externally callable).
    fn is_internal_or_private(&self, function_line: &str) -> bool {
        function_line.contains(" internal ")
            || function_line.contains(" private ")
            || function_line.contains(" internal)")
            || function_line.contains(" private)")
    }

    /// Check if a function declaration has no implementation body.
    /// This covers interface and abstract signatures like `function foo() external;`.
    fn is_signature_only_declaration(&self, line: &str) -> bool {
        let trimmed = line.trim();
        trimmed.starts_with("function ")
            && trimmed.ends_with(';')
            && !trimmed.contains('{')
            && !trimmed.contains("= ")
    }

    /// Build the per-line state used by the single-line rule pass.
    ///
    /// `stripped_lines` must be the line-for-line comment-stripped view of `lines`
    /// produced by [`Self::strip_comments`], which is a proper state machine that
    /// understands string literals.
    ///
    /// The previous implementation derived comment state from `line.contains("/*")`,
    /// which was wrong in two directions and silently disabled detection for the rest
    /// of the file:
    ///   - `// see the block below /*` set `in_block_comment` forever, because the `/*`
    ///     inside a line comment was taken literally;
    ///   - `string constant U = "https://x/*";` did the same from inside a string.
    ///
    /// Both made every subsequent single-line rule skip. Deriving the state from the
    /// stripped view instead makes it string- and comment-aware by construction, and
    /// also stops treating a continuation line that begins with `*` (a multiplication
    /// split across lines) as a comment.
    fn build_scan_context(
        &self,
        content: &str,
        lines: &[ParsedLine<'_>],
        stripped_lines: &[&str],
        inherited: Option<std::sync::Arc<ResolvedFile>>,
    ) -> ScanContext {
        let mut line_states = Vec::with_capacity(lines.len());

        for (idx, (_, line)) in lines.iter().enumerate() {
            // A line is comment-only when it has content but nothing survives stripping.
            let stripped = stripped_lines.get(idx).copied().unwrap_or("");
            let raw_blank = line.trim().is_empty();
            let stripped_blank = stripped.trim().is_empty();
            let is_comment_only = !raw_blank && stripped_blank;

            let state = LineState {
                is_comment: is_comment_only,
                is_in_block_comment: is_comment_only,
                is_signature_only: self.is_signature_only_declaration(stripped),
            };
            line_states.push(state);
        }

        ScanContext {
            has_safemath: self.has_safemath(content),
            has_safe_erc20: self.has_safe_erc20(content),
            // A guard reachable only through an imported base contract counts.
            has_reentrancy_guard: self.has_reentrancy_guard(content)
                || inherited.as_ref().is_some_and(|r| r.has_reentrancy_guard()),
            uses_openzeppelin: self.uses_openzeppelin(content),
            uses_solidity_0_8_plus: self.uses_solidity_0_8_plus(content),
            uses_safe_signature_library: content.contains("ECDSA.recover")
                || content.contains("SignatureChecker"),
            known_modifiers: self.resolve_known_modifiers(content, inherited.as_deref()),
            inherited,
            line_states,
        }
    }
}

impl ContractScanner {
    /// Create a new scanner with default configuration (all analysis features enabled).
    pub fn new(verbose: bool) -> Self {
        // The two regex-heavy constructions (master rules: ~300 compiles; EIP +
        // DeFi analyzers: ~100) run concurrently the first time in a process.
        let (rules, (eip_analyzer, defi_analyzer)) = rayon::join(
            || MASTER_RULES.clone(),
            || (EIPAnalyzer::new(verbose), crate::defi::DeFiAnalyzer::new()),
        );
        Self {
            parser: SolidityParser::new(),
            rules,
            verbose,
            advanced_analyzer: AdvancedAnalyzer::new(),
            logic_analyzer: LogicAnalyzer::new(),
            unused_declarations: UnusedDeclarationAnalyzer::new(),
            reachability_analyzer: ReachabilityAnalyzer::new(verbose),
            dependency_analyzer: DependencyAnalyzer::new(),
            threat_model_generator: ThreatModelGenerator::new(),
            eip_analyzer,
            false_positive_filter: FalsePositiveFilter::new(FilterConfig::default()),
            ast_bridge: crate::ast::bridge::ASTAnalysisBridge::new(),
            defi_analyzer,
            config: ScannerConfig::default(),
            version_rules_cache: Mutex::new(HashMap::new()),
            inheritance_indexes: dashmap::DashMap::new(),
        }
    }

    /// Create a scanner with custom configuration
    pub fn with_config(verbose: bool, config: ScannerConfig) -> Self {
        let filter_config = FilterConfig {
            strict_mode: config.enable_strict_filter,
            ..FilterConfig::default()
        };
        let (rules, (eip_analyzer, defi_analyzer)) = rayon::join(
            || MASTER_RULES.clone(),
            || (EIPAnalyzer::new(verbose), crate::defi::DeFiAnalyzer::new()),
        );
        Self {
            parser: SolidityParser::new(),
            rules,
            verbose,
            advanced_analyzer: AdvancedAnalyzer::new(),
            logic_analyzer: LogicAnalyzer::new(),
            unused_declarations: UnusedDeclarationAnalyzer::new(),
            reachability_analyzer: ReachabilityAnalyzer::new(verbose),
            dependency_analyzer: DependencyAnalyzer::new(),
            threat_model_generator: ThreatModelGenerator::new(),
            eip_analyzer,
            false_positive_filter: FalsePositiveFilter::new(filter_config),
            ast_bridge: crate::ast::bridge::ASTAnalysisBridge::new(),
            defi_analyzer,
            config,
            version_rules_cache: Mutex::new(HashMap::new()),
            inheritance_indexes: dashmap::DashMap::new(),
        }
    }

    /// Return the memoized version-specific rule set for `version`, compiling it on
    /// first use. See `version_rules_cache` for why this matters.
    fn version_rules(&self, version: &CompilerVersion) -> Arc<Vec<VulnerabilityRule>> {
        if let Ok(mut cache) = self.version_rules_cache.lock() {
            if let Some(rules) = cache.get(version) {
                return Arc::clone(rules);
            }
            let rules = Arc::new(create_version_specific_rules(version));
            cache.insert(version.clone(), Arc::clone(&rules));
            return rules;
        }
        // Lock poisoned (a worker panicked): fall back to a one-off compile.
        Arc::new(create_version_specific_rules(version))
    }

    /// Add custom rules from TOML config to the scanner's rule set.
    pub fn add_custom_rules(&mut self, rules: Vec<VulnerabilityRule>) {
        self.rules.extend(rules);
    }

    /// Apply rule overrides from TOML config (disable rules, change severity).
    pub fn apply_rule_overrides(&mut self, config: &crate::config::ScanConfig) {
        // Apply the `[settings]` block. Every one of these keys is documented in the
        // config schema but none of them reached the filter before: a user could set
        // `trust_openzeppelin = false` or `min_confidence = 80` in `.41swara.toml` and
        // the scanner would silently ignore it.
        let s = &config.settings;
        if s.min_confidence.is_some()
            || s.trust_openzeppelin.is_some()
            || s.trust_solmate.is_some()
            || s.trust_solady.is_some()
        {
            let mut filter_config = FilterConfig::default();
            if let Some(v) = s.min_confidence {
                filter_config.min_confidence = v;
            }
            if let Some(v) = s.trust_openzeppelin {
                filter_config.trust_openzeppelin = v;
            }
            if let Some(v) = s.trust_solmate {
                filter_config.trust_solmate = v;
            }
            if let Some(v) = s.trust_solady {
                filter_config.trust_solady = v;
            }
            self.false_positive_filter = FalsePositiveFilter::new(filter_config);
        }

        let disabled = config.disabled_rule_ids();

        // Remove disabled rules
        if !disabled.is_empty() {
            self.rules.retain(|rule| {
                // Check if rule title or SWC/41S ID matches a disabled ID
                !disabled.iter().any(|id| rule.title.contains(id))
            });
        }

        // Apply severity overrides
        for rule in &mut self.rules {
            for id in &["SWC-", "41S-"] {
                if rule.title.contains(id) {
                    // Extract the ID from the title
                    if let Some(start) = rule.title.find(id) {
                        let id_str: String = rule.title[start..]
                            .chars()
                            .take_while(|c| c.is_alphanumeric() || *c == '-')
                            .collect();
                        if let Some(new_severity) = config.severity_override(&id_str) {
                            rule.severity = new_severity;
                        }
                    }
                }
            }
        }
    }

    /// Enable all advanced analysis features
    pub fn with_advanced_mode(mut self) -> Self {
        self.config.enable_logic_analysis = true;
        self.config.enable_reachability_analysis = true;
        self.config.enable_dependency_analysis = true;
        self.config.enable_threat_model = true;
        self.config.enable_eip_analysis = true;
        self.config.enable_strict_filter = true;
        self
    }

    /// Scan a single Solidity file and return detected vulnerabilities plus compiler info.
    /// Reads the file, runs the full analysis pipeline, and returns sorted results.
    /// Files exceeding MAX_FILE_SIZE_BYTES are skipped to prevent DoS.
    pub fn scan_file<P: AsRef<Path>>(&self, file_path: P) -> io::Result<ScanResult> {
        // Security: enforce file size limit to prevent DoS from excessively large inputs.
        // The limit comes from `--max-file-size`; previously the flag was parsed and then
        // ignored in favour of the hard-coded constant.
        let metadata = std::fs::metadata(file_path.as_ref())?;
        if metadata.len() > self.config.max_file_size_bytes {
            // Always announce the skip. Staying silent unless --verbose meant an oversized
            // file was indistinguishable from a clean one in the report, which is exactly
            // the case where a missed finding matters most.
            eprintln!(
                "  ⚠️  Skipping {} ({}MB exceeds {}MB limit; raise with --max-file-size)",
                file_path.as_ref().display(),
                metadata.len() / (1024 * 1024),
                self.config.max_file_size_bytes / (1024 * 1024)
            );
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "{} exceeds the configured {} byte file-size limit",
                    file_path.as_ref().display(),
                    self.config.max_file_size_bytes
                ),
            ));
        }

        let content = self.parser.read_file(&file_path)?;
        let file_name = file_path
            .as_ref()
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown");

        if self.verbose {
            println!(
                "🔍 Analyzing {} ({} lines)",
                file_name,
                content.lines().count()
            );
        }

        let inherited = self.resolve_inheritance(file_path.as_ref());
        let result = self.scan_content_with(&content, inherited);

        if self.verbose {
            if let Some(ref info) = result.compiler_info {
                println!(
                    "  📋 Compiler: Solidity {} ({})",
                    info.version_string, info.constraint
                );
            }
            println!(
                "✅ Found {} potential issues in {}",
                result.vulnerabilities.len(),
                file_name
            );
        }

        Ok(result)
    }

    /// Run the full analysis pipeline on raw Solidity source code.
    /// This is the core method that coordinates all analysis phases:
    /// regex rules, advanced analyzers, logic/reachability/dependency analysis,
    /// threat modeling, EIP checks, and false positive filtering.
    /// Resolve a file's inheritance closure, reusing one `ProjectIndex` per scan root.
    ///
    /// Never fails: an unresolvable project degrades to `None` and the single-file
    /// heuristics stay in charge, so a missing `lib/` checkout can only cost precision,
    /// never a crash or a skipped scan.
    fn resolve_inheritance(&self, path: &Path) -> Option<Arc<ResolvedFile>> {
        let root = crate::inheritance::root_for(path);
        let index = self
            .inheritance_indexes
            .entry(root.clone())
            .or_insert_with(|| Arc::new(ProjectIndex::for_root(&root)))
            .clone();
        let resolved = index.resolve(path);
        (!resolved.is_empty()).then_some(resolved)
    }

    /// Detect proxy/implementation storage-slot collisions across the inheritance chain.
    ///
    /// This needs cross-file resolution to work at all: the proxy and the implementation
    /// almost always inherit their storage from bases in other files, so a single-file
    /// scanner cannot compute either layout and the whole bug class was invisible. Writing
    /// through one layout and reading through the other reinterprets the same bytes as a
    /// different type — the classic upgradeable-proxy footgun.
    ///
    /// Returns nothing when inheritance could not be resolved, when the file declares
    /// fewer than two storage-bearing contracts, or when the layouts agree.
    fn detect_proxy_storage_collisions(
        &self,
        scan_context: &ScanContext,
        stripped_content: &str,
    ) -> Vec<Vulnerability> {
        use crate::vulnerabilities::{VulnerabilityCategory, VulnerabilitySeverity};

        let mut findings = Vec::new();
        let Some(resolved) = scan_context.inherited.as_deref() else {
            return findings;
        };

        // A storage mismatch matters only when one layout is used through the other
        // via delegatecall. Comparing every pair of contracts in an ordinary source
        // file produces high-severity false positives for unrelated contracts.
        if !stripped_content.contains("delegatecall") {
            return findings;
        }

        // Only contracts that actually occupy storage can collide. Require one side
        // to be recognisably proxy-like as a conservative relationship check; a full
        // call-target proof is outside this regex-based scanner's current model.
        let storage_bearing: Vec<_> = resolved
            .contracts
            .iter()
            .filter(|c| c.kind.contributes_storage() && !c.storage.slots.is_empty())
            .collect();

        for (i, left) in storage_bearing.iter().enumerate() {
            for right in storage_bearing.iter().skip(i + 1) {
                if !proxy_implementation_pair(&left.name, &right.name) {
                    continue;
                }
                for collision in left.storage.collisions_with(&right.storage) {
                    findings.push(Vulnerability::new(
                        VulnerabilitySeverity::High,
                        VulnerabilityCategory::ProxyAdminVulnerability,
                        format!("Storage Slot Collision: {} vs {}", left.name, right.name),
                        format!(
                            "Slot {} (offset {}) holds `{}` in {} but `{}` in {}. {} \
                                 If one contract delegatecalls into the other, a write through \
                                 one layout is read back as a different type through the other, \
                                 silently corrupting state.",
                            collision.slot,
                            collision.offset,
                            collision.left,
                            left.name,
                            collision.right,
                            right.name,
                            collision.reason,
                        ),
                        1,
                        format!("slot {}", collision.slot),
                        "Align the storage layouts, or move to ERC-7201 namespaced \
                             storage so the two contracts cannot share slots."
                            .to_string(),
                    ));
                }
            }
        }
        findings
    }

    /// Scan source text with no file path, so no cross-file inheritance is available.
    pub fn scan_content(&self, content: &str) -> ScanResult {
        self.scan_content_with(content, None)
    }

    fn scan_content_with(&self, content: &str, inherited: Option<Arc<ResolvedFile>>) -> ScanResult {
        // Set SCAN_PROFILE=1 to print per-phase timings to stderr (perf diagnostics).
        let profile = std::env::var_os("SCAN_PROFILE").is_some();
        let mut phase_times: Vec<(&str, std::time::Duration)> = Vec::new();
        macro_rules! timed {
            ($name:expr, $e:expr) => {{
                let t = std::time::Instant::now();
                let r = $e;
                if profile {
                    phase_times.push(($name, t.elapsed()));
                }
                r
            }};
        }
        let mut vulnerabilities = Vec::new();
        let lines: Vec<ParsedLine<'_>> = content
            .lines()
            .enumerate()
            .map(|(idx, line)| (idx + 1, line))
            .collect();

        // Comment-stripped view of the source (line count and line numbers preserved).
        // Computed before the scan context because the context's per-line comment state
        // is derived from it — see `build_scan_context`.
        let stripped_content = timed!("strip_comments", Self::strip_comments(content));
        let stripped: &str = &stripped_content;
        let stripped_lines: Vec<&str> = stripped.lines().collect();
        debug_assert_eq!(
            lines.len(),
            stripped_lines.len(),
            "strip_comments must preserve line count"
        );

        let scan_context = timed!(
            "build_scan_context",
            self.build_scan_context(content, &lines, &stripped_lines, inherited)
        );

        // Extract compiler info early — used for version-aware analysis and returned in ScanResult
        let compiler_info = self.parser.extract_compiler_info(content);

        // Skip interface contracts - they define signatures only, no implementation vulnerabilities
        if self.is_interface_contract(content) {
            if self.verbose {
                println!("  ℹ️  Skipping interface contract (no implementation to analyze)");
            }
            return ScanResult {
                vulnerabilities,
                compiler_info,
            };
        }

        // Skip pure library contracts for many vulnerability types
        let is_library = self.is_library(content);

        // Note if this is a test contract (lower severity for some issues)
        let is_test = self.is_test_contract(content);
        if is_test && self.verbose {
            println!("  ℹ️  Test/mock contract detected - some checks relaxed");
        }

        // Run advanced analysis (skip some for libraries/tests)
        if !is_library {
            timed!(
                "analyze_control_flow",
                vulnerabilities.extend(self.advanced_analyzer.analyze_control_flow(stripped))
            );
        }

        // Availability and input-validation patterns. All three reason about a
        // contract's own state, so they are skipped for libraries (stateless) and
        // test contracts (deliberately unsafe by construction).
        if !is_test && !is_library {
            timed!(
                "push_payment_dos",
                vulnerabilities.extend(self.advanced_analyzer.detect_push_payment_dos(stripped))
            );
            timed!(
                "zero_address_check",
                vulnerabilities.extend(
                    self.advanced_analyzer
                        .detect_missing_zero_address_check(stripped)
                )
            );
            timed!(
                "sentinel_index",
                vulnerabilities.extend(
                    self.advanced_analyzer
                        .detect_ambiguous_sentinel_index(stripped)
                )
            );
        }
        timed!(
            "analyze_complexity",
            vulnerabilities.extend(self.advanced_analyzer.analyze_complexity(stripped))
        );

        if !is_test && !is_library {
            timed!(
                "analyze_access_control",
                vulnerabilities.extend(self.advanced_analyzer.analyze_access_control(stripped))
            );
        }
        timed!(
            "analyze_storage_layout",
            vulnerabilities.extend(self.advanced_analyzer.analyze_storage_layout(content))
        );
        timed!(
            "analyze_gas_optimization",
            vulnerabilities.extend(self.advanced_analyzer.analyze_gas_optimization(content))
        );

        // Run DeFi-specific analysis (skip for test contracts)
        if self.config.enable_defi_analysis && !is_test {
            timed!(
                "analyze_defi_vulnerabilities",
                vulnerabilities.extend(
                    self.advanced_analyzer
                        .analyze_defi_vulnerabilities(stripped)
                )
            );
        }

        // Run NFT-specific analysis
        if !is_test {
            timed!(
                "analyze_nft_vulnerabilities",
                vulnerabilities
                    .extend(self.advanced_analyzer.analyze_nft_vulnerabilities(stripped))
            );
        }

        // Run known exploit pattern detection
        timed!(
            "detect_known_exploits",
            vulnerabilities.extend(self.advanced_analyzer.detect_known_exploits(stripped))
        );

        // Run REKT.NEWS real-world exploit pattern detection (HIGH PRIORITY)
        // Based on $3.1B+ in actual losses from 2024-2025
        if !is_test {
            timed!(
                "analyze_rekt_news_patterns",
                vulnerabilities.extend(self.advanced_analyzer.analyze_rekt_news_patterns(stripped))
            );
        }

        // Run 2025 OWASP Smart Contract Top 10 analysis
        // Based on $1.42B in losses documented in 2024 incidents
        if !is_test {
            timed!(
                "analyze_owasp_2025_patterns",
                vulnerabilities
                    .extend(self.advanced_analyzer.analyze_owasp_2025_patterns(stripped))
            );
        }

        // Run Phase 6 modern detector suite (ERC4626, Permit2, LayerZero, EIP-4337, Merkle, etc.)
        if self.config.enable_phase6_analysis && !is_test {
            timed!(
                "analyze_phase6_patterns",
                vulnerabilities.extend(self.advanced_analyzer.analyze_phase6_patterns(stripped))
            );
        }

        // Run DeFi security research paper analysis (arXiv:2205.09524v1)
        // Covers dForce ($24M), Grim Finance ($30M), Popsicle Finance ($25M), Wormhole ($326M) patterns
        if !is_test {
            timed!(
                "analyze_defi_paper_vulnerabilities",
                vulnerabilities.extend(
                    self.advanced_analyzer
                        .analyze_defi_paper_vulnerabilities(stripped)
                )
            );
        }

        // Run L2/chain-specific analysis (PUSH0 compatibility, sequencer, etc.)
        if !is_test {
            timed!(
                "analyze_l2_patterns",
                vulnerabilities.extend(self.advanced_analyzer.analyze_l2_patterns(content))
            );
        }

        // Run security hardening analysis (storage gaps, timelocks, downcasts, etc.)
        if !is_test {
            timed!(
                "analyze_security_hardening",
                vulnerabilities.extend(self.advanced_analyzer.analyze_security_hardening(content))
            );
        }

        // Run 2025-2026 exploit pattern analysis (v0.7.0)
        // Covers $400M+ real-world exploits: Abracadabra, Yearn, Cetus, Balancer, GMX, Atlas, etc.
        if !is_test {
            timed!(
                "analyze_2025_exploit_patterns",
                vulnerabilities.extend(
                    self.advanced_analyzer
                        .analyze_2025_exploit_patterns(stripped)
                )
            );
        }

        // Run classic SWC-registry pattern analysis (tx.origin auth, push-payment DoS,
        // unlimited approvals). Timeless bugs that complement the modern detectors.
        if !is_test {
            timed!(
                "analyze_classic_patterns",
                vulnerabilities.extend(self.advanced_analyzer.analyze_classic_patterns(stripped))
            );
        }

        // Run DeFi-specific protocol analysis (AMM, Lending, Oracle, MEV)
        if self.config.enable_defi_analysis && !is_test && !is_library {
            let defi_findings = timed!("defi_analyzer", self.defi_analyzer.analyze(stripped));
            // Deduplicate: skip DeFi findings within 3 lines of same-category existing findings
            for df in defi_findings {
                let is_dup = vulnerabilities.iter().any(|existing| {
                    existing.category == df.category
                        && (existing.line_number as i64 - df.line_number as i64).abs() <= 3
                });
                if !is_dup {
                    vulnerabilities.push(df);
                }
            }
        }

        // Run AST-based structural analysis (CFG reentrancy + taint tracking)
        if !is_test && !is_library {
            let ast_findings = timed!("ast_bridge", self.ast_bridge.analyze(content));
            // Deduplicate AST findings against regex-based findings
            for af in ast_findings {
                let is_dup = vulnerabilities.iter().any(|existing| {
                    existing.category == af.category
                        && (existing.line_number as i64 - af.line_number as i64).abs() <= 3
                });
                if !is_dup {
                    vulnerabilities.push(af);
                }
            }
        }

        // Detect compiler version for version-specific checks
        let compiler_version = self.parser.get_compiler_version(content);

        // Check for detailed version vulnerabilities — consolidate into a single finding
        if let Some(detailed_version) = self.parser.get_detailed_version(content) {
            let version_vulns = self.parser.is_version_vulnerable(&detailed_version);
            if !version_vulns.is_empty() {
                // Determine highest severity across all CVEs
                let severity = if version_vulns.iter().any(|v| v.contains("CRITICAL")) {
                    crate::vulnerabilities::VulnerabilitySeverity::Critical
                } else if version_vulns
                    .iter()
                    .any(|v| v.contains("0.4.") || v.contains("0.5."))
                {
                    crate::vulnerabilities::VulnerabilitySeverity::High
                } else {
                    crate::vulnerabilities::VulnerabilitySeverity::Medium
                };

                // Build a single consolidated description
                let consolidated_desc = if version_vulns.len() == 1 {
                    version_vulns[0].clone()
                } else {
                    let mut desc = format!("{} known compiler issues:\n", version_vulns.len());
                    for (i, vuln_desc) in version_vulns.iter().enumerate() {
                        desc.push_str(&format!("  {}. {}\n", i + 1, vuln_desc));
                    }
                    desc
                };

                let pragma_str = self.parser.get_pragma_version(content).unwrap_or_default();
                let version_str = pragma_str
                    .trim()
                    .replace("pragma solidity ", "")
                    .replace(';', "");

                // Floating constraints (^0.8.20, >=0.6.2) compile with newer patch
                // releases in practice, so the floor version's known issues are
                // advisory, not a defect of the contract. Only exact pins keep the
                // computed severity.
                let is_floating = version_str.contains('^') || version_str.contains(">=");
                let severity = if is_floating
                    && !matches!(
                        severity,
                        crate::vulnerabilities::VulnerabilitySeverity::Critical
                    ) {
                    crate::vulnerabilities::VulnerabilitySeverity::Info
                } else {
                    severity
                };

                let title = format!(
                    "Compiler: {} Known Issue{} for {}",
                    version_vulns.len(),
                    if version_vulns.len() > 1 { "s" } else { "" },
                    if version_str.is_empty() {
                        "detected version".to_string()
                    } else {
                        version_str
                    }
                );

                vulnerabilities.push(Vulnerability::high_confidence(
                    severity,
                    crate::vulnerabilities::VulnerabilityCategory::CompilerBug,
                    title,
                    consolidated_desc,
                    1,
                    pragma_str,
                    "Upgrade to Solidity 0.8.28 or later for the latest security fixes".to_string(),
                ));
            }
        }

        // Scan with general rules (multiline rules use the comment-stripped view)
        let t_rules = std::time::Instant::now();
        for rule in &self.rules {
            if rule.multiline {
                vulnerabilities.extend(self.scan_multiline_pattern(
                    &stripped_content,
                    content,
                    &lines,
                    &scan_context,
                    rule,
                ));
            } else {
                vulnerabilities.extend(self.scan_line_patterns(
                    content,
                    &lines,
                    &stripped_lines,
                    &scan_context,
                    rule,
                ));
            }
        }
        if profile {
            phase_times.push(("general_rules", t_rules.elapsed()));
        }

        // Add version-specific vulnerability checks.
        // Skip them for open-ended constraints like `pragma solidity >=0.6.2;` (no upper
        // bound): such files compile with current compilers, so rules targeting the old
        // floor version (e.g. "0.6.x lacks overflow protection") do not apply.
        let pragma_text = self.parser.get_pragma_version(content).unwrap_or_default();
        let open_ended_pragma = pragma_text.contains(">=") && !pragma_text.contains('<');
        let t_vrules = std::time::Instant::now();
        if let Some(version) = compiler_version.filter(|_| !open_ended_pragma) {
            // Pre-0.8 compilers wrap on overflow. The regex rules below only catch
            // local declarations; storage accumulators need statement-level analysis.
            if matches!(
                version,
                CompilerVersion::V04
                    | CompilerVersion::V05
                    | CompilerVersion::V06
                    | CompilerVersion::V07
            ) {
                vulnerabilities.extend(
                    self.advanced_analyzer
                        .detect_legacy_unchecked_arithmetic(stripped),
                );
            }
            let version_rules = self.version_rules(&version);
            for rule in version_rules.iter() {
                if rule.multiline {
                    vulnerabilities.extend(self.scan_multiline_pattern(
                        &stripped_content,
                        content,
                        &lines,
                        &scan_context,
                        rule,
                    ));
                } else {
                    vulnerabilities.extend(self.scan_line_patterns(
                        content,
                        &lines,
                        &stripped_lines,
                        &scan_context,
                        rule,
                    ));
                }
            }
        }
        if profile {
            phase_times.push(("version_rules", t_vrules.elapsed()));
        }

        // ============================================================================
        // Phase 6: Advanced Analysis Engine
        // ============================================================================

        // Run logic vulnerability analysis (business logic bugs).
        // Libraries are skipped: they hold no state and take salts/params by design
        // (e.g. Clones.cloneDeterministic legitimately accepts a caller-chosen salt).
        if self.config.enable_logic_analysis && !is_test && !is_library {
            if self.verbose {
                println!("  🧠 Running logic vulnerability analysis...");
            }
            timed!(
                "logic_analyzer",
                vulnerabilities.extend(self.logic_analyzer.analyze(stripped))
            );
            // 41S-093 / 41S-094. Kept separate from LogicAnalyzer on purpose: its
            // extract_functions matches a signature and its opening brace on one
            // line, so it never sees the multi-line signatures both of these
            // findings live in.
            timed!(
                "unused_declarations",
                vulnerabilities.extend(self.unused_declarations.analyze(stripped))
            );
        }

        // Run dependency/import analysis
        if self.config.enable_dependency_analysis {
            if self.verbose {
                println!("  📦 Running dependency analysis...");
            }
            timed!(
                "dependency_analyzer",
                vulnerabilities.extend(self.dependency_analyzer.analyze(content))
            );
        }

        // Generate threat model vulnerabilities
        if self.config.enable_threat_model && !is_test {
            if self.verbose {
                println!("  🎯 Generating threat model...");
            }
            let threat_model = timed!(
                "threat_model",
                self.threat_model_generator.generate(content)
            );
            timed!(
                "threat_model_vulns",
                vulnerabilities.extend(
                    self.threat_model_generator
                        .to_vulnerabilities_with_content(&threat_model, content),
                )
            );
        }

        // Apply reachability analysis to filter unreachable vulnerabilities
        if self.config.enable_reachability_analysis {
            if self.verbose {
                println!("  🔗 Running reachability analysis...");
            }
            let t_reach = std::time::Instant::now();
            // Single-pass reachability: builds the call graph once and runs
            // unreachable filtering, confidence adjustment, and external call
            // chain detection against it.
            vulnerabilities = self.reachability_analyzer.process(vulnerabilities, content);
            if profile {
                phase_times.push(("reachability", t_reach.elapsed()));
            }
        }

        // ============================================================================
        // Phase 7: EIP Analysis & Enhanced False Positive Filtering
        // ============================================================================

        // Run EIP-specific vulnerability analysis
        if self.config.enable_eip_analysis && !is_test {
            if self.verbose {
                println!("  📋 Running EIP vulnerability analysis...");
            }
            timed!(
                "eip_analyzer",
                vulnerabilities.extend(self.eip_analyzer.analyze(content))
            );
        }

        // Apply enhanced false positive filtering
        if self.config.enable_strict_filter {
            if self.verbose {
                let original_count = vulnerabilities.len();
                vulnerabilities = self.false_positive_filter.filter(vulnerabilities, content);
                let filtered_count = vulnerabilities.len();
                println!(
                    "  🧹 {}",
                    self.false_positive_filter
                        .get_filter_stats(original_count, filtered_count)
                );
            } else {
                vulnerabilities = timed!(
                    "fp_filter",
                    self.false_positive_filter.filter(vulnerabilities, content)
                );
            }
        }

        // Enrich all findings with CVSS scores, exploit references, and attack paths
        timed!("enrichment", {
            vulnerabilities.extend(self.detect_proxy_storage_collisions(&scan_context, stripped));

            crate::cvss::enrich_with_cvss(&mut vulnerabilities);
            crate::exploit_db::enrich_with_exploits(&mut vulnerabilities);
            crate::attack_path::enrich_with_attack_paths(&mut vulnerabilities, content);
        });

        // Sort by composite risk score (highest first) so the most dangerous
        // findings surface at the top of every report, with line number as a
        // stable tiebreaker. Risk enrichment above (CVSS + exploit history) is
        // complete at this point, so risk_score() is fully resolved.
        vulnerabilities.sort_by(|a, b| {
            b.risk_score()
                .partial_cmp(&a.risk_score())
                .unwrap_or(std::cmp::Ordering::Equal)
                .then(a.line_number.cmp(&b.line_number))
        });

        if profile {
            let mut out = String::from("SCAN_PROFILE");
            for (name, dur) in &phase_times {
                out.push_str(&format!(" {}={}", name, dur.as_micros()));
            }
            eprintln!("{out}");
        }

        ScanResult {
            vulnerabilities,
            compiler_info,
        }
    }

    /// Apply a single-line regex rule against all lines in the file.
    /// Skips commented lines and applies context-aware filtering to reduce false positives.
    /// Apply a single-line rule to every line of the file.
    ///
    /// Rules are matched against `stripped_lines` — the comment-stripped, string-aware
    /// view — while the finding still reports the raw line as its snippet. Previously
    /// the match ran on the raw line, so `uint256 x = 1; // never use tx.origin here`
    /// tripped the tx.origin rules from inside a trailing comment. Multiline rules
    /// already ran on the stripped view; this makes the two paths symmetric.
    fn scan_line_patterns(
        &self,
        content: &str,
        lines: &[ParsedLine<'_>],
        stripped_lines: &[&str],
        scan_context: &ScanContext,
        rule: &VulnerabilityRule,
    ) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        for (idx, (line_number, line_content)) in lines.iter().enumerate() {
            // Skip if line is in a comment
            if self.is_in_comment(lines, idx) {
                continue;
            }

            // Interface and abstract signatures have no executable body to analyze.
            if scan_context.line_states[idx].is_signature_only {
                continue;
            }

            // Match on code only; report the raw line.
            let match_target = stripped_lines.get(idx).copied().unwrap_or(*line_content);

            if rule.pattern.is_match(match_target) {
                // Context-aware filtering to reduce false positives
                let should_report = self.should_report_vulnerability_with_title(
                    &rule.category,
                    Some(&rule.title),
                    MatchSite {
                        line: match_target,
                        full_content: content,
                        lines,
                        line_idx: idx,
                        scan_context,
                    },
                );

                if should_report {
                    // Extract context around the vulnerability
                    let (context_before, context_after) =
                        Vulnerability::extract_context(content, *line_number, 2);

                    let vulnerability = Vulnerability::new(
                        rule.severity.clone(),
                        rule.category.clone(),
                        rule.title.clone(),
                        rule.description.clone(),
                        *line_number,
                        line_content.trim().to_string(),
                        rule.recommendation.clone(),
                    )
                    .with_context(context_before, context_after);

                    vulnerabilities.push(vulnerability);
                }
            }
        }

        vulnerabilities
    }

    /// Context-aware false positive suppression per vulnerability category.
    /// Uses surrounding code context (SafeMath, ReentrancyGuard, modifiers, Solidity version,
    /// OZ patterns, etc.) to decide whether a regex match is a true positive.
    /// This is the first layer of filtering before `false_positive_filter.rs`.
    fn should_report_vulnerability_with_title(
        &self,
        category: &crate::vulnerabilities::VulnerabilityCategory,
        rule_title: Option<&str>,
        site: MatchSite<'_, '_>,
    ) -> bool {
        use crate::vulnerabilities::VulnerabilityCategory;

        let MatchSite {
            line,
            full_content,
            lines,
            line_idx,
            scan_context,
        } = site;

        // Global filter: Skip commented lines
        if scan_context
            .line_states
            .get(line_idx)
            .is_some_and(|state| state.is_comment || state.is_in_block_comment)
        {
            return false;
        }

        match category {
            VulnerabilityCategory::ArithmeticIssues => {
                // FP-5: Suppress "Division by Zero" in Solidity 0.8+ (auto-reverts)
                if let Some(title) = rule_title {
                    if title.contains("Division by Zero") && scan_context.uses_solidity_0_8_plus {
                        return false;
                    }
                }
                // Don't report if SafeMath is being used
                if scan_context.has_safemath {
                    return false;
                }
                // Don't report in Solidity 0.8+ (has built-in overflow protection)
                if scan_context.uses_solidity_0_8_plus {
                    return false;
                }
                // Don't report simple counter increments
                if line.contains("++")
                    && (line.contains("for") || line.contains("i++") || line.contains("++i"))
                {
                    return false;
                }
                // Don't report if it's inside unchecked block and we know it's intentional
                if line.contains("unchecked") {
                    return false;
                }
                true
            }

            VulnerabilityCategory::UnusedReturnValues => {
                // Don't report if using SafeERC20 which handles this
                if scan_context.has_safe_erc20 {
                    return false;
                }
                // Check if return value is actually being checked on the same or next line
                if line.contains("require(") || line.contains("assert(") || line.contains("if (") {
                    return false;
                }
                // Check if it's assigned to a variable
                if line.contains("= ")
                    && (line.contains("transfer") || line.contains("transferFrom"))
                {
                    return false;
                }
                // Check next line for require/assert
                if line_idx + 1 < lines.len() {
                    let next_line = &lines[line_idx + 1].1;
                    if next_line.contains("require(")
                        || next_line.contains("assert(")
                        || next_line.contains("if (")
                    {
                        return false;
                    }
                }
                true
            }

            VulnerabilityCategory::AccessControl
            | VulnerabilityCategory::RoleBasedAccessControl => {
                // FP-3: Suppress "Missing Zero Address Validation" if validation exists nearby
                if let Some(title) = rule_title {
                    if title.contains("Zero Address") {
                        let end = (line_idx + 16).min(lines.len());
                        let has_zero_check = lines[line_idx..end].iter().any(|(_, l)| {
                            l.contains("!= address(0)")
                                || l.contains("== address(0)")
                                || l.contains("address(0)")
                                    && (l.contains("require")
                                        || l.contains("if")
                                        || l.contains("revert"))
                                || l.contains("_checkNonZero")
                        });
                        if has_zero_check {
                            return false;
                        }
                    }
                }
                // Check if function already has modifiers or access control
                if line.contains("function") {
                    // Use multi-line signature to catch modifiers on continuation lines
                    let full_sig = self.get_full_function_signature(lines, line_idx);
                    if self.has_access_control_modifier(
                        &full_sig,
                        &scan_context.known_modifiers,
                        scan_context.inherited.as_deref(),
                    ) {
                        return false;
                    }
                    // Check if there's an inline access control check within the function
                    let mut func_end = line_idx + 20;
                    if func_end > lines.len() {
                        func_end = lines.len();
                    }
                    if self.has_access_control_check(full_content, line_idx, func_end) {
                        return false;
                    }
                }
                // Don't report view/pure functions as critical (read-only)
                if self.is_view_or_pure_function(line) {
                    return false;
                }
                // Don't report internal/private functions (can't be called externally)
                if self.is_internal_or_private(line) {
                    return false;
                }
                // Don't report if using OpenZeppelin access control with any only* modifier
                if scan_context.uses_openzeppelin && line.contains("function") {
                    let full_sig = self.get_full_function_signature(lines, line_idx);
                    if scan_context
                        .known_modifiers
                        .iter()
                        .any(|m| m.starts_with("only") && full_sig.contains(m.as_str()))
                    {
                        return false;
                    }
                }
                // Don't flag user-facing withdrawals that check msg.sender balance
                // (e.g., withdraw() with balances[msg.sender] is not an admin function)
                if line.contains("withdraw") || line.contains("transfer") {
                    let func_end = (line_idx + 15).min(lines.len());
                    let func_body: String = lines[line_idx..func_end]
                        .iter()
                        .map(|(_, l)| *l)
                        .collect::<Vec<_>>()
                        .join("\n");
                    if func_body.contains("msg.sender")
                        && (func_body.contains("balances[") || func_body.contains("balance["))
                    {
                        return false;
                    }
                }
                true
            }

            VulnerabilityCategory::Reentrancy => {
                // Don't report if ReentrancyGuard is being used
                if scan_context.has_reentrancy_guard {
                    return false;
                }
                // .transfer() and .send() use 2300 gas — safe from reentrancy
                if line.contains(".transfer(") || line.contains(".send(") {
                    return false;
                }
                // Use multi-line signature to check for nonReentrant or access control modifier
                // Find the enclosing function by scanning backwards
                let enclosing_func_idx = (0..=line_idx)
                    .rev()
                    .find(|&i| lines[i].1.contains("function "))
                    .unwrap_or(line_idx);
                let full_sig = self.get_full_function_signature(lines, enclosing_func_idx);
                if full_sig.contains("nonReentrant") {
                    return false;
                }
                // Don't report reentrancy inside onlyOwner functions (only owner can trigger)
                if self.has_access_control_modifier(
                    &full_sig,
                    &scan_context.known_modifiers,
                    scan_context.inherited.as_deref(),
                ) {
                    return false;
                }
                // Don't report for view/pure functions
                if self.is_view_or_pure_function(line)
                    || full_sig.contains(" view ")
                    || full_sig.contains(" pure ")
                {
                    return false;
                }
                true
            }

            VulnerabilityCategory::GasOptimization | VulnerabilityCategory::ImmutabilityIssues => {
                // These are informational - check if intentional
                // Don't report if variable is clearly being modified elsewhere
                if line.contains("address")
                    && full_content.contains(&format!(
                        "{} =",
                        line.split_whitespace().last().unwrap_or("")
                    ))
                {
                    return false;
                }
                // Don't report if it's a constant or immutable already
                if line.contains("constant") || line.contains("immutable") {
                    return false;
                }
                true
            }

            VulnerabilityCategory::UninitializedVariables => {
                // Only report if it's a critical state variable without initialization
                // Don't report function parameters or local variables
                if line.contains("function") || line.contains("(") && line.contains(")") {
                    return false;
                }
                // Don't report if it's an array or mapping (they auto-initialize)
                if line.contains("mapping") || line.contains("[]") {
                    return false;
                }
                // Don't report immutable variables (must be set in constructor)
                if line.contains("immutable") {
                    return false;
                }
                true
            }

            VulnerabilityCategory::MagicNumbers => {
                // Don't report common values like 0, 1, 2, 100, 1000
                if line.contains("* 0")
                    || line.contains("/ 1")
                    || line.contains("* 1 ")
                    || line.contains("* 2 ")
                    || line.contains("/ 2 ")
                {
                    return false;
                }
                // Don't report if it's in a constant definition
                if line.contains("constant") {
                    return false;
                }
                // Don't report common precision constants
                if line.contains("1e18")
                    || line.contains("1e6")
                    || line.contains("10**18")
                    || line.contains("100")
                    || line.contains("1000")
                    || line.contains("10000")
                {
                    return false;
                }
                true
            }

            VulnerabilityCategory::DelegateCalls => {
                // Only report if the target is user-controlled
                // Don't report if it's part of a proxy pattern with fixed implementation
                if full_content.contains("_IMPLEMENTATION_SLOT") || full_content.contains("ERC1967")
                {
                    return false;
                }
                true
            }

            VulnerabilityCategory::BlockTimestamp | VulnerabilityCategory::TimeManipulation => {
                // Don't report simple logging or non-critical timestamp usage
                if line.contains("emit") || line.contains("event") {
                    return false;
                }
                true
            }

            VulnerabilityCategory::PragmaIssues => {
                // Don't report floating pragma in test files
                if self.is_test_contract(full_content) {
                    return false;
                }
                // Interface-only files intentionally use open pragmas (>=x.y.z) so they
                // can be imported by consumers on any compatible compiler version.
                if self.is_interface_contract(full_content) {
                    return false;
                }
                true
            }

            VulnerabilityCategory::ArbitraryExternalCall => {
                // Governance executors (Governor/Timelock) make arbitrary calls BY
                // DESIGN — the protection is the proposal/vote/timelock flow, not a
                // target whitelist. Flagging every governor as Critical is noise.
                if (full_content.contains("proposal") || full_content.contains("Proposal"))
                    && (full_content.contains("Governor")
                        || full_content.contains("quorum")
                        || full_content.contains("timelock")
                        || full_content.contains("Timelock"))
                {
                    return false;
                }
                true
            }

            VulnerabilityCategory::UncheckedMathOperation => {
                // Shift amounts produced by a uint8 cast are bounded to 0-255 and cannot
                // exceed the 256-bit shift range (e.g. `1 << uint8(enumValue)`).
                if RE_BOUNDED_SHIFT.is_match(line) {
                    return false;
                }
                true
            }

            VulnerabilityCategory::UnsafeDowncast => {
                // Don't report if SafeCast is used
                if full_content.contains("SafeCast") || full_content.contains("safeCast") {
                    return false;
                }
                // Don't report in pure/view functions (less risky)
                if self.is_view_or_pure_function(line) {
                    return false;
                }
                // Don't report casts of constants/literals
                if line.contains("(0)") || line.contains("(1)") || line.contains("(2)") {
                    return false;
                }
                // Only flag downcasts of financial-looking values. Casting enums,
                // addresses (uint160(target)), packed validation words, selectors etc.
                // is deliberate bit manipulation, not a truncation-of-funds risk.
                let financial = [
                    "amount",
                    "balance",
                    "share",
                    "price",
                    "fee",
                    "supply",
                    "debt",
                    "reward",
                    "liquidity",
                    "total",
                    "wei",
                    "assets",
                ];
                if let Some(caps) = RE_DOWNCAST_ARG.captures(line) {
                    let var = caps.get(1).map_or("", |m| m.as_str()).to_lowercase();
                    if !financial.iter().any(|f| var.contains(f)) {
                        return false;
                    }
                }
                true
            }

            VulnerabilityCategory::AssemblyUsage => {
                // FP-2: Suppress assembly in libraries
                if self.is_library(full_content) {
                    return false;
                }
                // FP-2: Suppress known-safe proxy/ERC-1967 assembly patterns
                let safe_assembly_ops = [
                    "_IMPLEMENTATION_SLOT",
                    "_ADMIN_SLOT",
                    "slot :=",
                    "returndatasize",
                    "returndatacopy",
                    "chainid",
                ];
                // Check the next 10 lines for safe assembly body
                let end = (line_idx + 10).min(lines.len());
                let assembly_body: String = lines[line_idx..end]
                    .iter()
                    .map(|(_, l)| *l)
                    .collect::<Vec<_>>()
                    .join("\n");
                if safe_assembly_ops
                    .iter()
                    .any(|op| assembly_body.contains(op))
                {
                    return false;
                }
                true
            }

            VulnerabilityCategory::UnsafeExternalCalls => {
                // Don't report if return value is captured
                if line.contains("(bool") || line.contains("= ") || line.contains("require(") {
                    return false;
                }
                // Don't report in view/pure functions
                if self.is_view_or_pure_function(line) {
                    return false;
                }
                true
            }

            VulnerabilityCategory::CallbackReentrancy
            | VulnerabilityCategory::ERC777CallbackReentrancy
            | VulnerabilityCategory::DepositForReentrancy => {
                // Don't report if ReentrancyGuard is used
                if self.has_reentrancy_guard(full_content) {
                    return false;
                }
                // Don't report in view/pure functions
                if self.is_view_or_pure_function(line) {
                    return false;
                }
                // FP-1: Suppress if no state changes follow the callback-capable call
                let end = (line_idx + 11).min(lines.len());
                let has_state_change = lines[(line_idx + 1)..end].iter().any(|(_, l)| {
                    let trimmed = l.trim();
                    // Skip comments, closing braces, local var declarations
                    if trimmed.starts_with("//") || trimmed == "}" || trimmed.is_empty() {
                        return false;
                    }
                    if l.contains("memory") || l.contains("calldata") {
                        return false;
                    }
                    RE_STATE_MOD.is_match(l)
                });
                if !has_state_change {
                    return false;
                }
                true
            }

            VulnerabilityCategory::ProxyAdminVulnerability
            | VulnerabilityCategory::UnprotectedProxyUpgrade => {
                // Don't report if using OpenZeppelin UUPS/Transparent proxy properly
                if full_content.contains("_authorizeUpgrade") && full_content.contains("onlyOwner")
                {
                    return false;
                }
                if full_content.contains("UUPSUpgradeable")
                    || full_content.contains("TransparentUpgradeableProxy")
                {
                    return false;
                }
                // Don't report if function has access control
                if line.contains("function") {
                    let modifiers = self.extract_modifiers(full_content);
                    if self.has_access_control_modifier(
                        line,
                        &modifiers,
                        scan_context.inherited.as_deref(),
                    ) {
                        return false;
                    }
                }
                true
            }

            VulnerabilityCategory::MissingEmergencyStop => {
                // Don't report if contract uses Pausable
                if full_content.contains("Pausable") || full_content.contains("whenNotPaused") {
                    return false;
                }
                // Don't report if function has whenNotPaused modifier
                if line.contains("whenNotPaused") {
                    return false;
                }
                true
            }

            VulnerabilityCategory::SignatureReplay
            | VulnerabilityCategory::SignatureVulnerabilities => {
                // Don't report if using OpenZeppelin ECDSA
                if scan_context.uses_safe_signature_library {
                    return false;
                }
                true
            }

            VulnerabilityCategory::LowLevelCalls => {
                // Don't suppress return bomb findings (they specifically flag captured data)
                if let Some(title) = rule_title {
                    if title.contains("Return Bomb") {
                        return true;
                    }
                }
                // Don't report unchecked calls if the call result is captured/checked
                if line.contains("(bool") || line.contains("success") || line.contains("require(") {
                    return false;
                }
                true
            }

            VulnerabilityCategory::InputValidationFailure => {
                // `address(this).code.length == 0` inspects the contract's OWN code to
                // detect constructor-time execution (OZ Initializable) — an attacker
                // cannot bypass a self-check, so the construction-bypass rule is moot.
                if let Some(title) = rule_title {
                    if title.contains("Contract Check Bypassable") && line.contains("address(this)")
                    {
                        return false;
                    }
                }
                // Don't report if function is internal/private
                if self.is_internal_or_private(line) {
                    return false;
                }
                // Don't report if function is view/pure
                if self.is_view_or_pure_function(line) {
                    return false;
                }
                // FP-4: Suppress "Array Parameter" if length validation exists nearby
                if let Some(title) = rule_title {
                    if title.contains("Array Parameter") {
                        let end = (line_idx + 16).min(lines.len());
                        let has_length_check = lines[line_idx..end].iter().any(|(_, l)| {
                            l.contains(".length")
                                && (l.contains("require")
                                    || l.contains("if ")
                                    || l.contains(">")
                                    || l.contains("<")
                                    || l.contains("<="))
                        });
                        if has_length_check {
                            return false;
                        }
                    }
                }
                true
            }

            VulnerabilityCategory::MetaTransactionVulnerability
            | VulnerabilityCategory::TrustedForwarderBypass => {
                // Don't report if using OpenZeppelin's Context/ERC2771Context properly
                if scan_context.uses_openzeppelin && full_content.contains("ERC2771Context") {
                    return false;
                }
                true
            }

            VulnerabilityCategory::MissingStorageGap => {
                // Only report if contract doesn't already have __gap
                if full_content.contains("__gap")
                    || full_content.contains("uint256[") && full_content.contains("private")
                {
                    return false;
                }
                // Don't report for non-upgradeable contracts
                if !full_content.contains("Upgradeable") && !full_content.contains("Initializable")
                {
                    return false;
                }
                true
            }

            VulnerabilityCategory::UninitializedImplementation
            | VulnerabilityCategory::DoubleInitialization => {
                // Don't report if _disableInitializers() is in constructor
                if full_content.contains("_disableInitializers()") {
                    return false;
                }
                // Don't report if initializer modifier is present on the function
                if line.contains("initializer") {
                    // For DoubleInitialization, the modifier IS the fix
                    if matches!(category, VulnerabilityCategory::DoubleInitialization) {
                        return false;
                    }
                }
                true
            }

            VulnerabilityCategory::SelfdestructDeprecation => {
                // Don't report in test/mock contracts
                if self.is_test_contract(full_content) {
                    return false;
                }
                true
            }

            VulnerabilityCategory::MissingSwapDeadline => {
                // Don't report if function body contains deadline check
                let end = (line_idx + 20).min(lines.len());
                let has_deadline = lines[line_idx..end].iter().any(|(_, l)| {
                    l.contains("deadline")
                        || l.contains("Deadline")
                        || l.contains("block.timestamp")
                });
                if has_deadline {
                    return false;
                }
                true
            }

            VulnerabilityCategory::UnsafeTransferGas => {
                // Don't report in test/mock contracts
                if self.is_test_contract(full_content) {
                    return false;
                }
                // Don't report ERC20 .transfer(to, amount) - only ETH .transfer(amount)
                // ERC20 transfers have 2 args: .transfer(address, uint256)
                if line.contains(",") {
                    return false;
                }
                true
            }

            VulnerabilityCategory::HardcodedGasAmount => {
                // Don't report if gas amount is a variable
                if line.contains("gas: gasleft()") || line.contains("gas: _gas") {
                    return false;
                }
                true
            }

            VulnerabilityCategory::MissingEvents => {
                // Check if the function body contains an emit statement
                let end = (line_idx + 30).min(lines.len());
                let has_emit = lines[line_idx..end]
                    .iter()
                    .any(|(_, l)| l.trim().starts_with("emit ") || l.contains("emit "));
                if has_emit {
                    return false;
                }
                // Don't report view/pure functions
                if self.is_view_or_pure_function(line) {
                    return false;
                }
                // Don't report internal/private functions
                if self.is_internal_or_private(line) {
                    return false;
                }
                true
            }

            // --- v0.7.0 context-aware filtering for new categories ---
            VulnerabilityCategory::TransientStorageGasReentrancy => {
                // Only report if contract actually uses transient storage
                full_content.contains("tstore")
                    || full_content.contains("tload")
                    || full_content.contains("TSTORE")
                    || full_content.contains("TLOAD")
                    || full_content.contains("transient")
            }

            VulnerabilityCategory::EIP7702TxOriginBypass => {
                // Only report if contract uses tx.origin == msg.sender
                full_content.contains("tx.origin") && full_content.contains("msg.sender")
            }

            VulnerabilityCategory::ReadOnlyReentrancy => {
                // Skip if ReentrancyGuard is present
                if self.has_reentrancy_guard(full_content) {
                    return false;
                }
                true
            }

            VulnerabilityCategory::IsContractPostPectra => {
                // Skip if not used for access control (just a utility check)
                if !line.contains("require") && !line.contains("if") && !line.contains("revert") {
                    return false;
                }
                true
            }

            VulnerabilityCategory::RandomnessVulnerabilities => {
                // Suppress block.timestamp % N when used for time period calculations.
                // "block.timestamp % 7 days" is computing elapsed time in a week, not randomness.
                let time_units = ["days", "hours", "minutes", "seconds", "weeks"];
                if time_units.iter().any(|u| line.contains(u)) {
                    return false;
                }
                // Also suppress if the context shows time calculation patterns
                if line.contains("elapsed")
                    || line.contains("period")
                    || line.contains("duration")
                    || line.contains("interval")
                    || line.contains("revenue")
                    || line.contains("reward")
                {
                    return false;
                }
                true
            }

            VulnerabilityCategory::MissingReturnValue => {
                // Suppress "Conditional Without Return" for functions with named return variables.
                // Solidity auto-returns named return vars, so `returns (uint256 shares)` doesn't
                // need explicit `return` statements — the variable is returned automatically.
                // Check if the returns clause has named parameters (type + name, not just type).
                if RE_NAMED_RETURN.is_match(line) || RE_NAMED_RETURN.is_match(full_content) {
                    // Check within 5 lines of match start for named returns
                    let start = line_idx.saturating_sub(5);
                    let end = (line_idx + 5).min(lines.len());
                    let context: String = lines[start..end]
                        .iter()
                        .map(|(_, l)| *l)
                        .collect::<Vec<_>>()
                        .join("\n");
                    if RE_NAMED_RETURN.is_match(&context) {
                        return false;
                    }
                }
                true
            }

            // 41S-090 / 41S-091 / 41S-092: smart-account execution surface. These fire
            // on a function signature (installModule/execute/executeFromExecutor); the
            // vulnerability is the ABSENCE of a caller restriction. Suppress when the
            // signature line or the opening lines of the body carry an access-control
            // signal (modifier, self check, or an installed-module gate).
            VulnerabilityCategory::ERC7579UnprotectedModule
            | VulnerabilityCategory::ERC7821UnprotectedExecute
            | VulnerabilityCategory::ERC7579UnrestrictedExecutor => {
                // Signature + up to 8 following lines (modifiers may wrap; guards are
                // usually the first statements of the body). Skip comment lines so an
                // explanatory comment (e.g. "// only callable by entryPoint") cannot
                // masquerade as a real access-control guard.
                let end = (line_idx + 8).min(lines.len());
                let window: String = (line_idx..end)
                    .filter(|&i| {
                        !scan_context
                            .line_states
                            .get(i)
                            .is_some_and(|s| s.is_comment || s.is_in_block_comment)
                    })
                    .map(|i| lines[i].1)
                    .collect::<Vec<_>>()
                    .join("\n");
                let auth_signals = [
                    "onlyEntryPointOrSelf",
                    "onlyEntryPoint",
                    "_onlyEntryPointOrSelf",
                    "requireFromEntryPoint",
                    "onlyExecutorModule",
                    "onlyInstalledModule",
                    "onlyModule",
                    "isModuleInstalled",
                    "onlyOwner",
                    "onlyAuthorized",
                    "onlySelf",
                    "_checkAccess",
                    "_authorizeExecute",
                    "address(this)", // require(msg.sender == address(this)) / entryPoint idiom
                    "entryPoint()",
                    "_entryPoint",
                ];
                if auth_signals.iter().any(|sig| window.contains(sig)) {
                    return false;
                }
                true
            }

            // 41S-086 / 41S-088 are multiline rules; their whole-file context
            // guards live in `multiline_category_suppressed`, not here.
            _ => true, // Report all other categories by default
        }
    }

    /// Apply a multiline regex rule against the entire file content.
    /// Used for patterns that span multiple lines (e.g., state changes after external calls).
    /// Content-level suppression for multiline rules. The line-based
    /// `should_report_vulnerability_with_title` filter never sees multiline
    /// matches, so category guards that depend only on whole-file context live
    /// here. Returns `true` when the whole rule should be skipped for this file.
    fn multiline_category_suppressed(
        category: &crate::vulnerabilities::VulnerabilityCategory,
        content: &str,
    ) -> bool {
        use crate::vulnerabilities::VulnerabilityCategory;
        match category {
            // 41S-086: mitigated by ERC-7201 namespaced storage.
            VulnerabilityCategory::EIP7702DelegateStorageCollision => {
                content.contains("erc7201:") || content.contains("@custom:storage-location")
            }
            // 41S-088: mitigated by binding originData to a verified orderId or
            // tracking filled orders. These are precise idioms; a bare `require`
            // elsewhere in the file is not evidence the fill path is guarded.
            VulnerabilityCategory::ERC7683UnvalidatedFill => {
                content.contains("keccak256(originData")
                    || content.contains("keccak256(abi.encode(orderId")
                    || content.contains("filledOrders")
                    || content.contains("orderStatus")
                    || content.contains("usedOrders")
            }
            _ => false,
        }
    }

    /// Apply a multiline rule to the comment-stripped source.
    ///
    /// Multiline findings now go through the same context-aware layer-1 filter as
    /// single-line ones. Previously they bypassed it entirely and relied only on
    /// `multiline_category_suppressed`, which covers just two categories — so 30-odd
    /// multiline rules in categories the filter *does* suppress (ArithmeticIssues,
    /// AccessControl, DelegateCalls, RoleBasedAccessControl, UnsafeExternalCalls, …)
    /// never saw the SafeMath / Solidity-0.8 / `nonReentrant` / access-modifier
    /// suppressions that their single-line counterparts did.
    fn scan_multiline_pattern(
        &self,
        content: &str,
        raw_content: &str,
        lines: &[ParsedLine<'_>],
        scan_context: &ScanContext,
        rule: &VulnerabilityRule,
    ) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        // Suppression consults the raw (un-stripped) source so mitigations that
        // live in NatSpec annotations (e.g. @custom:storage-location) are visible.
        if Self::multiline_category_suppressed(&rule.category, raw_content) {
            return vulnerabilities;
        }

        for mat in rule.pattern.find_iter(content) {
            // Find the line number where this match starts
            let match_start = mat.start();
            let match_end = mat.end();
            let lines_before = content[..match_start].matches('\n').count();
            let line_number = lines_before + 1;

            // Calculate end line number for multi-line matches
            let lines_in_match = content[match_start..match_end].matches('\n').count();
            let end_line_number = line_number + lines_in_match;

            // Get the matched text and clean it up
            let matched_text = mat.as_str();
            let code_snippet = matched_text
                .lines()
                .next()
                .unwrap_or(matched_text)
                .trim()
                .to_string();

            // Same context-aware filtering the single-line path applies, anchored at
            // the line where the match begins.
            let idx = line_number.saturating_sub(1);
            if idx < lines.len()
                && !self.should_report_vulnerability_with_title(
                    &rule.category,
                    Some(&rule.title),
                    MatchSite {
                        line: &code_snippet,
                        full_content: content,
                        lines,
                        line_idx: idx,
                        scan_context,
                    },
                )
            {
                continue;
            }

            // Extract context
            let (context_before, context_after) =
                Vulnerability::extract_context(content, line_number, 2);

            let mut vulnerability = Vulnerability::new(
                rule.severity.clone(),
                rule.category.clone(),
                rule.title.clone(),
                rule.description.clone(),
                line_number,
                code_snippet,
                rule.recommendation.clone(),
            )
            .with_context(context_before, context_after);

            // Set end line if it spans multiple lines
            if end_line_number > line_number {
                vulnerability = vulnerability.with_end_line(end_line_number);
            }

            vulnerabilities.push(vulnerability);
        }

        vulnerabilities
    }
}
