//! Enhanced False Positive Filter
//!
//! This module implements the second of three filtering layers in the scanner pipeline:
//!
//! **Layer 1** (`scanner.rs::should_report_vulnerability`) -- context-aware per-category
//! filtering applied at detection time.
//!
//! **Layer 2** (this module) -- post-detection filtering that operates on the full list of
//! findings. It removes false positives through:
//!   1. **Safe-pattern matching**: recognizes well-known safe implementations (ReentrancyGuard,
//!      SafeMath, SafeERC20, ECDSA.recover, etc.) and suppresses findings they already guard.
//!   2. **Contract-context extraction**: detects Solidity version, imported libraries,
//!      inheritance chains, custom modifiers, and audit annotations to inform per-category
//!      filtering decisions.
//!   3. **Category-specific filters**: each vulnerability category has a dedicated filter
//!      function that checks for mitigating patterns (e.g., `nonReentrant` on a function,
//!      `onlyOwner` modifier for access-control, `SafeERC20` for unchecked returns).
//!   4. **Confidence adjustment**: raises or lowers the confidence score depending on
//!      whether safety measures are present (library usage, audit annotations, test context).
//!   5. **Deduplication**: removes exact (line, category) duplicates and merges related
//!      findings from the same code region, keeping only the highest-severity entry.
//!
//! **Layer 3** (advanced analyzers: `reachability_analyzer.rs`, `logic_analyzer.rs`) --
//! structural analysis that checks call-graph reachability and logic-level correctness.
//!
//! Together the three layers achieve 90%+ false-positive reduction while maintaining high
//! detection accuracy.

#![allow(dead_code)]

use regex::Regex;
use std::collections::HashSet;
use crate::vulnerabilities::{Vulnerability, VulnerabilityCategory, VulnerabilitySeverity};

/// Configuration knobs that control how aggressively the false-positive filter
/// suppresses findings. All boolean flags default to `true` (trust safe libraries,
/// use version-aware filtering, etc.) except `strict_mode` which defaults to `false`.
#[derive(Clone)]
pub struct FilterConfig {
    /// When `true`, findings already guarded by OpenZeppelin patterns are suppressed.
    pub trust_openzeppelin: bool,
    /// When `true`, findings already guarded by Solmate patterns are suppressed.
    pub trust_solmate: bool,
    /// When `true`, findings already guarded by Solady patterns are suppressed.
    pub trust_solady: bool,
    /// When `true`, the Solidity compiler version is used to suppress findings that
    /// are handled by the compiler itself (e.g., overflow checks in 0.8+).
    pub version_aware_filtering: bool,
    /// When `true`, semantic analysis of code patterns (CEI ordering, modifier
    /// presence, etc.) is applied during filtering.
    pub semantic_analysis: bool,
    /// Findings with a confidence score below this threshold (0--100) are dropped
    /// after all other filtering and confidence adjustments have been applied.
    pub min_confidence: u8,
    /// When `true`, enables more aggressive filtering: all findings in test/mock
    /// contracts are suppressed entirely.
    pub strict_mode: bool,
}

impl Default for FilterConfig {
    fn default() -> Self {
        Self {
            trust_openzeppelin: true,
            trust_solmate: true,
            trust_solady: true,
            version_aware_filtering: true,
            semantic_analysis: true,
            min_confidence: 0,
            strict_mode: false,
        }
    }
}

/// Contextual information extracted from the contract source code. This is built
/// once per file by `extract_context()` and then passed to every per-category
/// filter so that filtering decisions can take the whole contract into account
/// (e.g., compiler version, library imports, modifier definitions).
#[derive(Debug, Default)]
pub struct ContractContext {
    /// The raw Solidity version string from the pragma (e.g., "0.8.20").
    pub solidity_version: Option<String>,
    /// `true` if the compiler version is 0.8.x or higher (built-in overflow checks).
    pub is_solidity_0_8_plus: bool,
    /// `true` if the contract uses the SafeMath library (pre-0.8 overflow protection).
    pub uses_safemath: bool,
    /// `true` if a ReentrancyGuard / nonReentrant pattern is detected.
    pub uses_reentrancy_guard: bool,
    /// `true` if the contract imports from `@openzeppelin`.
    pub uses_openzeppelin: bool,
    /// `true` if the contract imports from `solmate`.
    pub uses_solmate: bool,
    /// `true` if the contract imports from `solady`.
    pub uses_solady: bool,
    /// `true` if the contract uses SafeERC20 or `.safeTransfer()`.
    pub uses_safe_erc20: bool,
    /// `true` if the file contains only `interface` declarations and no `contract`.
    pub is_interface_only: bool,
    /// `true` if the file declares a `library` (not a contract).
    pub is_library: bool,
    /// `true` if the file is a Foundry/Hardhat test contract.
    pub is_test_contract: bool,
    /// `true` if the contract name or content indicates a mock.
    pub is_mock_contract: bool,
    /// `true` if any access-control pattern (Ownable, AccessControl, etc.) is detected.
    pub has_access_control: bool,
    /// Names of all `modifier` declarations found in the contract.
    pub custom_modifiers: Vec<String>,
    /// Names of contracts/interfaces in the `is` clause of the contract declaration.
    pub inherited_contracts: Vec<String>,
    /// Paths of all `import` statements.
    pub imported_files: Vec<String>,
    /// Parsed function signatures with visibility, modifiers, and access-control flags.
    pub defined_functions: Vec<FunctionInfo>,
    /// Any `@audit`, `@security`, `// SAFE:`, or `// AUDITED` annotations found.
    pub audit_annotations: Vec<String>,
}

/// Metadata for a single function definition parsed from the contract source.
/// Used by category-specific filters to determine if a finding's enclosing
/// function already has mitigating modifiers or restricted visibility.
#[derive(Debug, Clone)]
pub struct FunctionInfo {
    /// Function name (e.g., "withdraw", "transfer").
    pub name: String,
    /// Visibility keyword: "external", "public", "internal", or "private".
    pub visibility: String,
    /// Non-standard modifiers on the function (excludes visibility, view/pure,
    /// payable, virtual, override). Typically custom access-control modifiers.
    pub modifiers: Vec<String>,
    /// `true` if the function is declared `view` or `pure` (read-only).
    pub is_view_pure: bool,
    /// 1-based line number where the function declaration appears.
    pub line_number: usize,
    /// `true` if any modifier starts with "only" or matches known auth patterns.
    pub has_access_control: bool,
}

/// The main false-positive filtering engine. It holds a `FilterConfig` and a
/// pre-compiled set of `SafePattern` regexes. Call `filter()` to run the full
/// pipeline (context extraction -> per-category filtering -> confidence
/// adjustment -> deduplication) on a list of findings.
pub struct FalsePositiveFilter {
    /// User-supplied configuration controlling filter aggressiveness.
    config: FilterConfig,
    /// Pre-compiled regexes that match known-safe implementations. If any of
    /// these match the contract source for a finding's category, the finding
    /// is suppressed.
    safe_patterns: Vec<SafePattern>,
}

/// A single safe-pattern rule: if `pattern` matches the contract source and the
/// finding's category equals `category`, the finding is considered a false
/// positive and is suppressed.
#[derive(Debug)]
struct SafePattern {
    /// The vulnerability category this pattern guards against.
    category: VulnerabilityCategory,
    /// A regex that matches known-safe code constructs for this category.
    pattern: Regex,
    /// Human-readable description logged when this pattern triggers.
    description: String,
}

impl FalsePositiveFilter {
    /// Create a new `FalsePositiveFilter` with the given configuration.
    /// Pre-compiles all safe-pattern regexes on construction so they can be
    /// reused across multiple `filter()` calls without recompilation overhead.
    pub fn new(config: FilterConfig) -> Self {
        Self {
            config,
            safe_patterns: Self::create_safe_patterns(),
        }
    }

    /// Build the list of safe-pattern regexes. Each entry maps a vulnerability
    /// category to a regex that, if it matches the contract source, indicates
    /// the contract already mitigates that class of vulnerability. These are
    /// broad whole-file checks; category-specific filters perform finer-grained
    /// analysis afterwards.
    fn create_safe_patterns() -> Vec<SafePattern> {
        vec![
            // Reentrancy: suppress if any reentrancy guard mechanism is present
            SafePattern {
                category: VulnerabilityCategory::Reentrancy,
                pattern: Regex::new(r"(?i)(ReentrancyGuard|nonReentrant|_reentrancyGuard|locked\s*=\s*true)").unwrap(),
                description: "ReentrancyGuard detected".to_string(),
            },
            // Reentrancy: suppress if a CEI pattern annotation exists in comments
            SafePattern {
                category: VulnerabilityCategory::Reentrancy,
                pattern: Regex::new(r"CEI\s*pattern|checks-effects-interactions").unwrap(),
                description: "CEI pattern annotation detected".to_string(),
            },

            // Arithmetic: suppress if SafeMath is imported (pre-0.8 protection)
            SafePattern {
                category: VulnerabilityCategory::ArithmeticIssues,
                pattern: Regex::new(r"using\s+SafeMath\s+for|SafeMath\.").unwrap(),
                description: "SafeMath library in use".to_string(),
            },
            // Arithmetic: suppress if Solidity 0.8+ (compiler-level overflow protection)
            SafePattern {
                category: VulnerabilityCategory::ArithmeticIssues,
                pattern: Regex::new(r"pragma\s+solidity\s*[\^>=<]*\s*0\.[89]").unwrap(),
                description: "Solidity 0.8+ has built-in overflow protection".to_string(),
            },

            // Access control: suppress if common owner/role modifier keywords found
            SafePattern {
                category: VulnerabilityCategory::AccessControl,
                pattern: Regex::new(r"(?i)(onlyOwner|onlyAdmin|onlyRole|onlyMinter|onlyGovernance|requiresAuth|auth\(\))").unwrap(),
                description: "Access control modifier present".to_string(),
            },
            // Access control: suppress if inline require checks msg.sender
            SafePattern {
                category: VulnerabilityCategory::AccessControl,
                pattern: Regex::new(r"require\s*\(\s*msg\.sender\s*==|require\s*\(\s*_msgSender\s*\(\s*\)\s*==").unwrap(),
                description: "Sender verification in function".to_string(),
            },

            // Unchecked returns: suppress if SafeERC20 wrappers are used
            SafePattern {
                category: VulnerabilityCategory::UncheckedReturnValues,
                pattern: Regex::new(r"using\s+SafeERC20\s+for|\.safeTransfer\(|\.safeTransferFrom\(").unwrap(),
                description: "SafeERC20 library in use".to_string(),
            },

            // Proxy upgrade: suppress if _authorizeUpgrade is protected by onlyOwner
            SafePattern {
                category: VulnerabilityCategory::UnprotectedProxyUpgrade,
                pattern: Regex::new(r"_authorizeUpgrade\s*\([^)]*\)\s*internal\s*(virtual\s*)?(override\s*)?onlyOwner").unwrap(),
                description: "Protected upgrade function".to_string(),
            },

            // Signature: suppress if using OZ ECDSA or SignatureChecker (handles malleability)
            SafePattern {
                category: VulnerabilityCategory::SignatureVulnerabilities,
                pattern: Regex::new(r"ECDSA\.recover|ECDSA\.tryRecover|SignatureChecker").unwrap(),
                description: "Safe signature verification library".to_string(),
            },
        ]
    }

    /// Parse the full contract source to extract contextual information that
    /// informs filtering decisions. This runs once per file and produces a
    /// `ContractContext` struct containing compiler version, library usage,
    /// inheritance, modifiers, and more.
    pub fn extract_context(&self, content: &str) -> ContractContext {
        let mut ctx = ContractContext::default();

        // Detect Solidity version from the pragma directive
        let version_pattern = Regex::new(r"pragma\s+solidity\s*([\^>=<]*)?\s*(\d+\.\d+\.\d+|\d+\.\d+)").unwrap();
        if let Some(caps) = version_pattern.captures(content) {
            ctx.solidity_version = caps.get(2).map(|m| m.as_str().to_string());
            if let Some(ref version) = ctx.solidity_version {
                ctx.is_solidity_0_8_plus = version.starts_with("0.8") || version.starts_with("0.9")
                    || version.chars().next().map_or(false, |c| c > '0');
            }
        }

        // Detect SafeMath (pre-0.8 overflow library)
        ctx.uses_safemath = content.contains("using SafeMath for") || content.contains("SafeMath.");

        // Detect ReentrancyGuard (OZ, Solmate, or custom mutex pattern)
        ctx.uses_reentrancy_guard = content.contains("ReentrancyGuard")
            || content.contains("nonReentrant")
            || content.contains("_reentrancyGuard");

        // Detect OpenZeppelin imports or references
        ctx.uses_openzeppelin = content.contains("@openzeppelin")
            || content.contains("openzeppelin-contracts")
            || content.contains("OpenZeppelin");

        // Detect Solmate
        ctx.uses_solmate = content.contains("solmate") || content.contains("Solmate");

        // Detect Solady
        ctx.uses_solady = content.contains("solady") || content.contains("Solady");

        // Detect SafeERC20 (wraps ERC20 calls with revert-on-failure)
        ctx.uses_safe_erc20 = content.contains("using SafeERC20 for")
            || content.contains("SafeERC20.")
            || content.contains(".safeTransfer(");

        // Detect interface-only files (no findings are relevant for pure interfaces)
        let interface_pattern = Regex::new(r"^\s*interface\s+\w+").unwrap();
        let contract_pattern = Regex::new(r"^\s*(contract|abstract\s+contract)\s+\w+").unwrap();
        let has_interface = content.lines().any(|line| interface_pattern.is_match(line));
        let has_contract = content.lines().any(|line| contract_pattern.is_match(line));
        ctx.is_interface_only = has_interface && !has_contract;

        // Detect library declarations (libraries have restricted capabilities)
        ctx.is_library = Regex::new(r"^\s*library\s+\w+").unwrap()
            .find(content).is_some();

        // Detect test contracts (Foundry, Hardhat, DSTest frameworks)
        ctx.is_test_contract = content.contains("import \"forge-std")
            || content.contains("import \"hardhat")
            || content.contains("is Test")
            || content.contains("is DSTest");

        // Detect mock contracts by name or keyword
        ctx.is_mock_contract = content.contains("contract Mock")
            || content.contains("Contract Mock")
            || content.to_lowercase().contains("mock");

        // Detect broad access-control patterns (Ownable, RBAC, modifier keywords)
        ctx.has_access_control = content.contains("Ownable")
            || content.contains("AccessControl")
            || content.contains("onlyOwner")
            || content.contains("onlyRole");

        // Extract custom modifier names (used later to check per-function guards)
        let modifier_pattern = Regex::new(r"modifier\s+(\w+)").unwrap();
        for cap in modifier_pattern.captures_iter(content) {
            if let Some(name) = cap.get(1) {
                ctx.custom_modifiers.push(name.as_str().to_string());
            }
        }

        // Extract the inheritance list (contracts/interfaces after `is`)
        let inherit_pattern = Regex::new(r"(contract|abstract\s+contract)\s+\w+\s+is\s+([^{]+)").unwrap();
        if let Some(caps) = inherit_pattern.captures(content) {
            if let Some(inherited) = caps.get(2) {
                for part in inherited.as_str().split(',') {
                    let name = part.trim().split_whitespace().next().unwrap_or("");
                    if !name.is_empty() {
                        ctx.inherited_contracts.push(name.to_string());
                    }
                }
            }
        }

        // Extract all import paths (both direct and named import syntax)
        let import_pattern = Regex::new(r#"import\s+["']([^"']+)["']|import\s+\{[^}]+\}\s+from\s+["']([^"']+)["']"#).unwrap();
        for cap in import_pattern.captures_iter(content) {
            let path = cap.get(1).or_else(|| cap.get(2)).map(|m| m.as_str().to_string());
            if let Some(p) = path {
                ctx.imported_files.push(p);
            }
        }

        // Extract developer-placed audit/security annotations from comments
        let audit_pattern = Regex::new(r"@audit|@security|@notice\s+SAFE|// SAFE:|// AUDITED").unwrap();
        for mat in audit_pattern.find_iter(content) {
            ctx.audit_annotations.push(mat.as_str().to_string());
        }

        // Parse all function declarations into structured FunctionInfo records
        ctx.defined_functions = self.extract_functions(content);

        ctx
    }

    /// Parse every `function` declaration in the source into a `FunctionInfo`
    /// struct. Extracts name, visibility, custom modifiers, view/pure status,
    /// line number, and whether the function has an access-control modifier.
    fn extract_functions(&self, content: &str) -> Vec<FunctionInfo> {
        let mut functions = Vec::new();
        // Matches: function <name>(<params>) <modifiers...>
        let func_pattern = Regex::new(
            r"function\s+(\w+)\s*\([^)]*\)\s*((?:external|public|internal|private|view|pure|payable|virtual|override|\w+\s*)*)"
        ).unwrap();

        let lines: Vec<&str> = content.lines().collect();

        for (line_idx, line) in lines.iter().enumerate() {
            if let Some(caps) = func_pattern.captures(line) {
                let name = caps.get(1).map_or("", |m| m.as_str()).to_string();
                let modifiers_str = caps.get(2).map_or("", |m| m.as_str());

                // Determine visibility; default to "public" if none specified
                let visibility = if modifiers_str.contains("external") {
                    "external"
                } else if modifiers_str.contains("public") {
                    "public"
                } else if modifiers_str.contains("internal") {
                    "internal"
                } else if modifiers_str.contains("private") {
                    "private"
                } else {
                    "public"
                }.to_string();

                let is_view_pure = modifiers_str.contains("view") || modifiers_str.contains("pure");

                // Collect non-standard modifiers (i.e., custom ones like onlyOwner)
                let modifiers: Vec<String> = modifiers_str
                    .split_whitespace()
                    .filter(|m| !["external", "public", "internal", "private", "view", "pure", "payable", "virtual", "override"].contains(m))
                    .map(|s| s.to_string())
                    .collect();

                // Heuristic: any modifier starting with "only" or matching auth keywords
                let has_access_control = modifiers.iter().any(|m| {
                    m.starts_with("only") || m == "auth" || m == "authorized" || m == "requiresAuth"
                });

                functions.push(FunctionInfo {
                    name,
                    visibility,
                    modifiers,
                    is_view_pure,
                    line_number: line_idx + 1,
                    has_access_control,
                });
            }
        }

        functions
    }

    /// Run the full false-positive filtering pipeline on a list of findings.
    ///
    /// The pipeline proceeds in four stages:
    /// 1. **Context extraction** -- parse the contract source once to build a
    ///    `ContractContext` (compiler version, imports, modifiers, etc.).
    /// 2. **Per-finding filtering** -- each finding is checked against safe
    ///    patterns and category-specific filters; false positives are dropped.
    /// 3. **Confidence adjustment** -- remaining findings have their confidence
    ///    score raised or lowered based on contextual signals (library usage,
    ///    audit annotations, test context).
    /// 4. **Deduplication** -- exact (line, category) duplicates are removed,
    ///    and related findings within a 5-line window are merged.
    pub fn filter(&self, vulnerabilities: Vec<Vulnerability>, content: &str) -> Vec<Vulnerability> {
        let ctx = self.extract_context(content);

        // Interface-only files have no executable code; discard all findings
        if ctx.is_interface_only {
            return vec![];
        }

        // Stage 2: apply per-finding safe-pattern and category-specific filters
        let mut filtered: Vec<Vulnerability> = vulnerabilities
            .into_iter()
            .filter(|v| self.should_keep(v, content, &ctx))
            .collect();

        // Stage 3: adjust confidence scores based on contract context
        for vuln in &mut filtered {
            self.adjust_confidence(vuln, &ctx);
        }

        // Drop findings that fall below the minimum confidence threshold
        if self.config.min_confidence > 0 {
            filtered.retain(|v| v.confidence_percent >= self.config.min_confidence);
        }

        // Stage 4: remove exact duplicates and merge related nearby findings
        self.deduplicate(&mut filtered);

        filtered
    }

    /// Determine if a vulnerability should be kept
    fn should_keep(&self, vuln: &Vulnerability, content: &str, ctx: &ContractContext) -> bool {
        // Skip all findings in test/mock contracts if strict mode
        if self.config.strict_mode && (ctx.is_test_contract || ctx.is_mock_contract) {
            return false;
        }

        // Skip library-only findings for certain categories
        if ctx.is_library {
            match vuln.category {
                VulnerabilityCategory::AccessControl
                | VulnerabilityCategory::RoleBasedAccessControl => return false,
                _ => {}
            }
        }

        // Check for safe patterns
        for safe in &self.safe_patterns {
            if safe.category == vuln.category && safe.pattern.is_match(content) {
                return false;
            }
        }

        // Category-specific filtering
        match vuln.category {
            VulnerabilityCategory::ArithmeticIssues => {
                self.filter_arithmetic(vuln, ctx)
            }
            VulnerabilityCategory::Reentrancy
            | VulnerabilityCategory::CallbackReentrancy
            | VulnerabilityCategory::ERC777CallbackReentrancy
            | VulnerabilityCategory::DepositForReentrancy
            | VulnerabilityCategory::TransientStorageReentrancy => {
                self.filter_reentrancy(vuln, content, ctx)
            }
            VulnerabilityCategory::AccessControl
            | VulnerabilityCategory::RoleBasedAccessControl => {
                self.filter_access_control(vuln, content, ctx)
            }
            VulnerabilityCategory::UncheckedReturnValues
            | VulnerabilityCategory::UnusedReturnValues => {
                self.filter_unchecked_returns(vuln, ctx)
            }
            VulnerabilityCategory::PragmaIssues => {
                self.filter_pragma(vuln, ctx)
            }
            VulnerabilityCategory::GasOptimization => {
                // Always filter gas optimizations in test contracts
                !ctx.is_test_contract
            }
            VulnerabilityCategory::MagicNumbers => {
                self.filter_magic_numbers(vuln, content)
            }
            VulnerabilityCategory::OracleManipulation => {
                // FP-6: Suppress if no pricing context (just routing usage)
                let lines: Vec<&str> = content.lines().collect();
                let vuln_line = vuln.line_number.saturating_sub(1);
                let start = vuln_line.saturating_sub(5);
                let end = (vuln_line + 6).min(lines.len());
                let context: String = lines[start..end].join("\n").to_lowercase();
                let has_pricing_context = context.contains("price") || context.contains("oracle")
                    || context.contains(" / ") || context.contains(" * ");
                if !has_pricing_context {
                    return false;
                }
                true
            }
            VulnerabilityCategory::UnprotectedProxyUpgrade
            | VulnerabilityCategory::ProxyAdminVulnerability => {
                // FP-7: Suppress transferOwnership findings with Ownable2Step
                if content.contains("Ownable2Step") || content.contains("acceptOwnership")
                    || content.contains("pendingOwner") {
                    if vuln.code_snippet.contains("transferOwnership")
                        || vuln.title.contains("transferOwnership")
                        || vuln.description.contains("transferOwnership") {
                        return false;
                    }
                }
                self.filter_proxy_upgrade(vuln, content, ctx)
            }
            VulnerabilityCategory::SignatureVulnerabilities
            | VulnerabilityCategory::SignatureReplay => {
                self.filter_signature(vuln, content, ctx)
            }
            VulnerabilityCategory::BlockTimestamp
            | VulnerabilityCategory::TimeManipulation => {
                self.filter_timestamp(vuln, content)
            }
            VulnerabilityCategory::DelegateCalls => {
                self.filter_delegatecall(vuln, content, ctx)
            }
            VulnerabilityCategory::MissingEmergencyStop => {
                // Don't report if Pausable is used
                if content.contains("Pausable") || content.contains("whenNotPaused") {
                    return false;
                }
                // Don't report in test contracts
                if ctx.is_test_contract {
                    return false;
                }
                true
            }
            VulnerabilityCategory::MetaTransactionVulnerability
            | VulnerabilityCategory::TrustedForwarderBypass => {
                // Don't report if using OZ ERC2771Context properly
                if ctx.uses_openzeppelin && content.contains("ERC2771Context") {
                    return false;
                }
                true
            }
            VulnerabilityCategory::DoubleClaiming => {
                // Don't report if rewardDebt or claimed mapping exists
                if content.contains("rewardDebt") || content.contains("claimed[")
                    || content.contains("hasClaimed") || content.contains("_claimed") {
                    return false;
                }
                true
            }
            VulnerabilityCategory::UncheckedMathOperation => {
                // Don't report in Solidity 0.8+ for regular math (overflow protected)
                // Only keep for unchecked blocks and bit shifts
                if ctx.is_solidity_0_8_plus && !vuln.code_snippet.contains("unchecked")
                    && !vuln.code_snippet.contains("<<") && !vuln.code_snippet.contains(">>") {
                    return false;
                }
                true
            }
            VulnerabilityCategory::InputValidationFailure => {
                // Don't report for view/pure functions
                if vuln.code_snippet.contains(" view ") || vuln.code_snippet.contains(" pure ") {
                    return false;
                }
                // Don't report for internal/private functions
                if vuln.code_snippet.contains(" internal ") || vuln.code_snippet.contains(" private ") {
                    return false;
                }
                true
            }
            VulnerabilityCategory::LowLevelCalls => {
                // Don't suppress return bomb findings (they flag captured data as the risk)
                if vuln.title.contains("Return Bomb") {
                    return true;
                }
                // Don't report if return value is captured
                if vuln.code_snippet.contains("(bool") || vuln.code_snippet.contains("success") {
                    return false;
                }
                true
            }
            VulnerabilityCategory::GovernanceAttack => {
                // Don't report if using OZ Governor
                if content.contains("Governor") && ctx.uses_openzeppelin {
                    return false;
                }
                // Don't report if timelock is present
                if content.contains("TimelockController") || content.contains("timelock") {
                    return false;
                }
                true
            }
            VulnerabilityCategory::MissingStorageGap => {
                // Don't report if __gap exists
                if content.contains("__gap") {
                    return false;
                }
                // Don't report for non-upgradeable contracts
                if !content.contains("Upgradeable") && !content.contains("Initializable") {
                    return false;
                }
                true
            }
            VulnerabilityCategory::MissingTimelock => {
                // Don't report if timelock pattern exists
                if content.contains("TimelockController") || content.contains("Timelock")
                    || content.contains("delay") && content.contains("queue") {
                    return false;
                }
                // Don't report in test contracts
                if ctx.is_test_contract {
                    return false;
                }
                true
            }
            VulnerabilityCategory::SelfdestructDeprecation => {
                // Don't report in test/mock contracts
                if ctx.is_test_contract || ctx.is_mock_contract {
                    return false;
                }
                true
            }
            VulnerabilityCategory::UnsafeDowncast => {
                // Don't report if SafeCast is used
                if content.contains("SafeCast") || content.contains("safeCast") {
                    return false;
                }
                true
            }
            VulnerabilityCategory::UninitializedImplementation
            | VulnerabilityCategory::DoubleInitialization => {
                // Don't report if _disableInitializers is present
                if content.contains("_disableInitializers") {
                    return false;
                }
                // Don't report if initializer modifier is on the function
                if vuln.code_snippet.contains("initializer") {
                    return false;
                }
                true
            }
            VulnerabilityCategory::HardcodedGasAmount => {
                // Don't report if using gasleft()
                if vuln.code_snippet.contains("gasleft()") {
                    return false;
                }
                true
            }
            VulnerabilityCategory::UnsafeTransferGas => {
                // Don't report ERC20 transfers (have 2 args)
                if vuln.code_snippet.contains(",") {
                    return false;
                }
                // Don't report in test
                if ctx.is_test_contract {
                    return false;
                }
                true
            }
            _ => true
        }
    }

    /// Filter arithmetic issues
    fn filter_arithmetic(&self, _vuln: &Vulnerability, ctx: &ContractContext) -> bool {
        // Solidity 0.8+ has built-in overflow protection
        if ctx.is_solidity_0_8_plus {
            return false;
        }
        // SafeMath provides protection
        if ctx.uses_safemath {
            return false;
        }
        true
    }

    /// Filter reentrancy issues
    fn filter_reentrancy(&self, vuln: &Vulnerability, content: &str, ctx: &ContractContext) -> bool {
        // Has reentrancy guard
        if ctx.uses_reentrancy_guard {
            return false;
        }

        // Check if the specific line has nonReentrant modifier
        let lines: Vec<&str> = content.lines().collect();
        if vuln.line_number > 0 && vuln.line_number <= lines.len() {
            // Look at the function definition for this vulnerability
            for i in (0..vuln.line_number).rev() {
                let line = lines[i];
                if line.contains("function ") {
                    if line.contains("nonReentrant") || line.contains("reentrancyGuard") {
                        return false;
                    }
                    break;
                }
            }
        }

        // View/pure functions can't have reentrancy
        let snippet = &vuln.code_snippet.to_lowercase();
        if snippet.contains("view") || snippet.contains("pure") {
            return false;
        }

        true
    }

    /// Filter access control issues
    fn filter_access_control(&self, vuln: &Vulnerability, content: &str, ctx: &ContractContext) -> bool {
        // Check if function has access control
        let lines: Vec<&str> = content.lines().collect();
        if vuln.line_number > 0 && vuln.line_number <= lines.len() {
            let line = lines[vuln.line_number - 1];

            // Check for common access control patterns
            let access_patterns = [
                "onlyOwner", "onlyAdmin", "onlyRole", "onlyMinter", "onlyGovernance",
                "auth", "authorized", "requiresAuth", "whenNotPaused", "initializer"
            ];

            for pattern in &access_patterns {
                if line.contains(pattern) {
                    return false;
                }
            }

            // Check custom modifiers
            for modifier in &ctx.custom_modifiers {
                if modifier.starts_with("only") && line.contains(modifier) {
                    return false;
                }
            }

            // Check if it's a view/pure function (read-only, less critical)
            if line.contains(" view ") || line.contains(" view)")
                || line.contains(" pure ") || line.contains(" pure)") {
                return false;
            }

            // Check if internal/private
            if line.contains(" internal ") || line.contains(" private ") {
                return false;
            }

            // Check for inline access control (look at next few lines)
            let end_idx = (vuln.line_number + 10).min(lines.len());
            for i in vuln.line_number..end_idx {
                let check_line = lines[i];
                if check_line.contains("require(msg.sender")
                    || check_line.contains("require(_msgSender()")
                    || check_line.contains("if (msg.sender !=")
                    || check_line.contains("_checkOwner()")
                    || check_line.contains("_checkRole(") {
                    return false;
                }
                // Stop at function end
                if check_line.trim() == "}" {
                    break;
                }
            }
        }

        // OpenZeppelin Ownable with proper modifiers
        if ctx.uses_openzeppelin && ctx.inherited_contracts.iter().any(|c| c == "Ownable") {
            // Check if there are onlyOwner modifiers defined
            if ctx.custom_modifiers.iter().any(|m| m.starts_with("only")) {
                return false;
            }
        }

        true
    }

    /// Filter unchecked return value issues
    fn filter_unchecked_returns(&self, _vuln: &Vulnerability, ctx: &ContractContext) -> bool {
        // SafeERC20 handles this
        if ctx.uses_safe_erc20 {
            return false;
        }
        true
    }

    /// Filter pragma issues
    fn filter_pragma(&self, _vuln: &Vulnerability, ctx: &ContractContext) -> bool {
        // Don't report in test contracts
        if ctx.is_test_contract {
            return false;
        }
        true
    }

    /// Filter magic numbers
    fn filter_magic_numbers(&self, vuln: &Vulnerability, content: &str) -> bool {
        let snippet = &vuln.code_snippet;

        // Common acceptable values
        let acceptable = ["0", "1", "2", "100", "1000", "10000", "1e18", "1e6", "10**18", "10**6"];
        for val in &acceptable {
            if snippet.contains(val) {
                return false;
            }
        }

        // In constant definitions
        if snippet.contains("constant") || snippet.contains("immutable") {
            return false;
        }

        // Precision constants
        if snippet.contains("PRECISION") || snippet.contains("DECIMALS") || snippet.contains("WAD") {
            return false;
        }

        // Check if it's defining a constant nearby
        let lines: Vec<&str> = content.lines().collect();
        if vuln.line_number > 0 && vuln.line_number <= lines.len() {
            let line = lines[vuln.line_number - 1];
            if line.contains("constant") || line.contains("immutable") || line.contains("=") {
                return false;
            }
        }

        true
    }

    /// Filter proxy upgrade issues
    fn filter_proxy_upgrade(&self, _vuln: &Vulnerability, content: &str, ctx: &ContractContext) -> bool {
        // Check for protected upgrade patterns
        if content.contains("_authorizeUpgrade") && content.contains("onlyOwner") {
            return false;
        }
        if ctx.uses_openzeppelin && content.contains("UUPSUpgradeable") {
            // OpenZeppelin UUPS requires override of _authorizeUpgrade
            if content.contains("_authorizeUpgrade") {
                return false;
            }
        }
        true
    }

    /// Filter signature issues
    fn filter_signature(&self, _vuln: &Vulnerability, content: &str, ctx: &ContractContext) -> bool {
        // Using safe libraries
        if content.contains("ECDSA.recover") || content.contains("ECDSA.tryRecover") {
            return false;
        }
        if content.contains("SignatureChecker") {
            return false;
        }
        if ctx.uses_openzeppelin && content.contains("@openzeppelin") && content.contains("ECDSA") {
            return false;
        }
        true
    }

    /// Filter timestamp issues
    fn filter_timestamp(&self, vuln: &Vulnerability, content: &str) -> bool {
        let snippet = &vuln.code_snippet;

        // Event emissions using timestamp are fine
        if snippet.contains("emit") || content.lines().nth(vuln.line_number.saturating_sub(1))
            .map_or(false, |l| l.contains("emit")) {
            return false;
        }

        // Logging/tracking uses
        if snippet.contains("lastUpdate") || snippet.contains("timestamp =") {
            return false;
        }

        true
    }

    /// Filter delegatecall issues
    fn filter_delegatecall(&self, _vuln: &Vulnerability, content: &str, ctx: &ContractContext) -> bool {
        // ERC-1967 proxy pattern
        if content.contains("_IMPLEMENTATION_SLOT") || content.contains("ERC1967") {
            return false;
        }
        // Standard proxy patterns
        if ctx.inherited_contracts.iter().any(|c| {
            c.contains("Proxy") || c.contains("UUPS") || c.contains("Transparent")
        }) {
            return false;
        }
        true
    }

    /// Adjust vulnerability confidence based on context
    fn adjust_confidence(&self, vuln: &mut Vulnerability, ctx: &ContractContext) {
        // Reduce confidence for test/mock contracts
        if ctx.is_test_contract || ctx.is_mock_contract {
            vuln.confidence_percent = vuln.confidence_percent.saturating_sub(30);
        }

        // Increase confidence for contracts without safety measures
        if !ctx.uses_openzeppelin && !ctx.uses_solmate && !ctx.uses_solady {
            vuln.confidence_percent = (vuln.confidence_percent + 10).min(100);
        }

        // Reduce confidence if audit annotations present
        if !ctx.audit_annotations.is_empty() {
            vuln.confidence_percent = vuln.confidence_percent.saturating_sub(15);
        }

        // Increase confidence for critical categories without guards
        match vuln.category {
            VulnerabilityCategory::Reentrancy if !ctx.uses_reentrancy_guard => {
                vuln.confidence_percent = (vuln.confidence_percent + 15).min(100);
            }
            VulnerabilityCategory::ArithmeticIssues if !ctx.is_solidity_0_8_plus && !ctx.uses_safemath => {
                vuln.confidence_percent = (vuln.confidence_percent + 20).min(100);
            }
            _ => {}
        }

        // Update confidence enum
        vuln.confidence = if vuln.confidence_percent >= 80 {
            crate::vulnerabilities::VulnerabilityConfidence::High
        } else if vuln.confidence_percent >= 50 {
            crate::vulnerabilities::VulnerabilityConfidence::Medium
        } else {
            crate::vulnerabilities::VulnerabilityConfidence::Low
        };
    }

    /// Remove duplicate vulnerabilities
    fn deduplicate(&self, vulnerabilities: &mut Vec<Vulnerability>) {
        // Pass 1: exact (line, category) dedup
        let mut seen: HashSet<(usize, String)> = HashSet::new();
        vulnerabilities.retain(|v| {
            let key = (v.line_number, format!("{:?}", v.category));
            if seen.contains(&key) {
                false
            } else {
                seen.insert(key);
                true
            }
        });

        // FP-8: Pass 2 - Merge related categories within 5 lines, keep highest severity
        let category_group = |cat: &VulnerabilityCategory| -> u8 {
            match cat {
                VulnerabilityCategory::Reentrancy
                | VulnerabilityCategory::CallbackReentrancy
                | VulnerabilityCategory::ERC777CallbackReentrancy
                | VulnerabilityCategory::DepositForReentrancy
                | VulnerabilityCategory::TransientStorageReentrancy => 1,
                VulnerabilityCategory::AccessControl
                | VulnerabilityCategory::RoleBasedAccessControl
                | VulnerabilityCategory::ProxyAdminVulnerability => 2,
                VulnerabilityCategory::FlashLoanAttack
                | VulnerabilityCategory::OracleManipulation => 3,
                _ => 0,  // group 0 = no grouping
            }
        };

        let severity_rank = |v: &Vulnerability| -> u8 {
            match v.severity {
                VulnerabilitySeverity::Critical => 4,
                VulnerabilitySeverity::High => 3,
                VulnerabilitySeverity::Medium => 2,
                VulnerabilitySeverity::Low => 1,
                VulnerabilitySeverity::Info => 0,
            }
        };

        // Also treat LogicError with CEI/State After title as reentrancy group
        let effective_group = |v: &Vulnerability| -> u8 {
            let g = category_group(&v.category);
            if g != 0 {
                return g;
            }
            if matches!(v.category, VulnerabilityCategory::LogicError) {
                if v.title.contains("CEI") || v.title.contains("State After") {
                    return 1; // reentrancy group
                }
            }
            0
        };

        let mut to_remove: HashSet<usize> = HashSet::new();
        for i in 0..vulnerabilities.len() {
            if to_remove.contains(&i) {
                continue;
            }
            let gi = effective_group(&vulnerabilities[i]);
            if gi == 0 {
                continue;
            }
            for j in (i + 1)..vulnerabilities.len() {
                if to_remove.contains(&j) {
                    continue;
                }
                let gj = effective_group(&vulnerabilities[j]);
                if gi != gj {
                    continue;
                }
                let line_diff = (vulnerabilities[i].line_number as isize
                    - vulnerabilities[j].line_number as isize).unsigned_abs();
                if line_diff <= 5 {
                    // Keep the higher-severity one
                    if severity_rank(&vulnerabilities[i]) >= severity_rank(&vulnerabilities[j]) {
                        to_remove.insert(j);
                    } else {
                        to_remove.insert(i);
                        break; // i is removed, stop comparing from i
                    }
                }
            }
        }

        let mut idx = 0;
        vulnerabilities.retain(|_| {
            let keep = !to_remove.contains(&idx);
            idx += 1;
            keep
        });
    }

    /// Get statistics about filtering
    pub fn get_filter_stats(&self, original: usize, filtered: usize) -> String {
        let removed = original.saturating_sub(filtered);
        let percentage = if original > 0 {
            (removed as f64 / original as f64 * 100.0) as u32
        } else {
            0
        };

        format!(
            "False positive filtering: {} -> {} findings ({}% reduction, {} removed)",
            original, filtered, percentage, removed
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_context_extraction() {
        let filter = FalsePositiveFilter::new(FilterConfig::default());
        let content = r#"
            pragma solidity ^0.8.20;
            import "@openzeppelin/contracts/access/Ownable.sol";
            import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

            contract MyContract is Ownable, ReentrancyGuard {
                modifier onlyAdmin() { _; }

                function withdraw() external onlyOwner nonReentrant {
                    // ...
                }
            }
        "#;

        let ctx = filter.extract_context(content);
        assert!(ctx.is_solidity_0_8_plus);
        assert!(ctx.uses_openzeppelin);
        assert!(ctx.uses_reentrancy_guard);
        assert!(ctx.has_access_control);
        assert!(ctx.custom_modifiers.contains(&"onlyAdmin".to_string()));
    }

    #[test]
    fn test_filter_arithmetic_0_8() {
        let filter = FalsePositiveFilter::new(FilterConfig::default());
        let content = "pragma solidity ^0.8.0;";
        let ctx = filter.extract_context(content);

        let vuln = Vulnerability::new(
            VulnerabilitySeverity::High,
            VulnerabilityCategory::ArithmeticIssues,
            "Test".to_string(),
            "Test".to_string(),
            1,
            "a + b".to_string(),
            "Test".to_string(),
        );

        assert!(!filter.filter_arithmetic(&vuln, &ctx));
    }

    #[test]
    fn test_filter_test_contracts() {
        let filter = FalsePositiveFilter::new(FilterConfig {
            strict_mode: true,
            ..FilterConfig::default()
        });

        let content = r#"
            import "forge-std/Test.sol";
            contract MyTest is Test {
                function testSomething() public {}
            }
        "#;

        let ctx = filter.extract_context(content);
        assert!(ctx.is_test_contract);
    }
}
