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


use crate::vulnerabilities::{Vulnerability, VulnerabilityCategory, VulnerabilitySeverity};
use once_cell::sync::Lazy;
use regex::Regex;
use std::collections::HashSet;

/// Per-call-site regex cache. See `advanced_analysis::re!` for rationale.
/// Each macro expansion creates its own `static Lazy<Regex>` so the pattern is
/// compiled exactly once for the lifetime of the process.
macro_rules! re {
    ($pat:expr) => {{
        static RE: Lazy<Regex> = Lazy::new(|| Regex::new($pat).unwrap());
        &*RE
    }};
}

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
    /// The source with all comments stripped, computed once per file. Whole-file
    /// "safe pattern" regexes match against this rather than the raw source so that
    /// prose in a comment cannot suppress a real finding.
    pub code_only: String,
    /// `true` if the file declares a `library` (not a contract).
    pub is_library: bool,
    /// `true` if the file is a Foundry/Hardhat test contract.
    pub is_test_contract: bool,
    /// `true` if the contract name or content indicates a mock.
    /// Line ranges (1-based, inclusive) of contracts that are themselves mocks or test
    /// helpers. Findings are checked against these per-line; see `mock_contract_spans`.
    pub mock_spans: Vec<(usize, usize)>,
    /// `true` if any access-control pattern (Ownable, AccessControl, etc.) is detected.
    pub has_access_control: bool,
    /// Names of all `modifier` declarations found in the contract.
    pub custom_modifiers: Vec<String>,
    /// Names of contracts/interfaces in the `is` clause of the contract declaration.
    pub inherited_contracts: Vec<String>,
    /// Paths of all `import` statements.
    pub imported_files: Vec<String>,
    /// Any `@audit`, `@security`, `// SAFE:`, or `// AUDITED` annotations found.
    pub audit_annotations: Vec<String>,
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
    /// `&'static Regex` because patterns come from the per-call-site `re!` cache —
    /// each is compiled exactly once at first use and lives for the process lifetime.
    pattern: &'static Regex,
}


/// Pull the backticked identifier out of a finding title, e.g.
/// ``Unchecked Arithmetic on State Variable `totalFees` `` -> `totalFees`.
///
/// Used by deduplication to avoid merging findings that are about different
/// variables. Titles without a backticked subject return `None`, which leaves the
/// existing merge behaviour untouched.
fn subject_identifier(title: &str) -> Option<&str> {
    let start = title.find('`')? + 1;
    let rest = &title[start..];
    let end = rest.find('`')?;
    let ident = &rest[..end];
    if ident.is_empty() {
        None
    } else {
        Some(ident)
    }
}


/// The declaration line of the function containing `line` (1-based).
///
/// Scans backwards to the nearest `function`/`constructor` declaration. Returns
/// `None` at contract level, where there is no enclosing function.
fn enclosing_function_signature(content: &str, line: usize) -> Option<String> {
    let lines: Vec<&str> = content.lines().collect();
    if line == 0 || line > lines.len() {
        return None;
    }
    let decl = re!(r"^\s*(function\s+\w+|constructor\s*\()");
    lines[..line]
        .iter()
        .rev()
        .find(|l| decl.is_match(l))
        .map(|l| format!(" {} ", l.trim()))
}

impl ContractContext {
    /// Does `line` fall inside a contract that is itself a mock or test helper?
    ///
    /// Per-line rather than per-file so that a mock declared alongside production code
    /// suppresses findings only within its own body.
    pub fn is_in_mock_contract(&self, line: usize) -> bool {
        self.mock_spans
            .iter()
            .any(|&(start, end)| line >= start && line <= end)
    }
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

    fn strip_comment_lines(content: &str) -> String {
        // Delegates to the shared, string-aware stripper. The local copy this replaced
        // used `line.split("//").next()`, which truncated any line holding a URL in a
        // string literal (`"https://..."` became `"https:`) before the regexes ran.
        crate::parser::strip_comments(content)
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
                pattern: re!(r"(?i)(ReentrancyGuard|nonReentrant|_reentrancyGuard|locked\s*=\s*true)"),
            },
            // Reentrancy: suppress if a CEI pattern annotation exists in comments
            SafePattern {
                category: VulnerabilityCategory::Reentrancy,
                pattern: re!(r"CEI\s*pattern|checks-effects-interactions"),
            },

            // Arithmetic: suppress if SafeMath is imported (pre-0.8 protection)
            SafePattern {
                category: VulnerabilityCategory::ArithmeticIssues,
                pattern: re!(r"using\s+SafeMath\s+for|SafeMath\."),
            },
            // Arithmetic: suppress if Solidity 0.8+ (compiler-level overflow protection)
            SafePattern {
                category: VulnerabilityCategory::ArithmeticIssues,
                pattern: re!(r"pragma\s+solidity\s*[\^>=<]*\s*0\.[89]"),
            },

            // Access control: suppress if common owner/role modifier keywords found
            SafePattern {
                category: VulnerabilityCategory::AccessControl,
                pattern: re!(r"(?i)(onlyOwner|onlyAdmin|onlyRole|onlyMinter|onlyGovernance|requiresAuth|auth\(\))"),
            },
            // Access control: suppress if inline require checks msg.sender
            SafePattern {
                category: VulnerabilityCategory::AccessControl,
                pattern: re!(r"require\s*\(\s*msg\.sender\s*==|require\s*\(\s*_msgSender\s*\(\s*\)\s*=="),
            },

            // Unchecked returns: suppress if SafeERC20 wrappers are used
            SafePattern {
                category: VulnerabilityCategory::UncheckedReturnValues,
                pattern: re!(r"using\s+SafeERC20\s+for|\.safeTransfer\(|\.safeTransferFrom\("),
            },

            // Proxy upgrade: suppress if _authorizeUpgrade is protected by onlyOwner
            SafePattern {
                category: VulnerabilityCategory::UnprotectedProxyUpgrade,
                pattern: re!(r"_authorizeUpgrade\s*\([^)]*\)\s*internal\s*(virtual\s*)?(override\s*)?onlyOwner"),
            },

            // Signature: suppress if using OZ ECDSA or SignatureChecker (handles malleability)
            SafePattern {
                category: VulnerabilityCategory::SignatureVulnerabilities,
                pattern: re!(r"ECDSA\.recover|ECDSA\.tryRecover|SignatureChecker"),
            },
        ]
    }

    /// Parse the full contract source to extract contextual information that
    /// informs filtering decisions. This runs once per file and produces a
    /// `ContractContext` struct containing compiler version, library usage,
    /// inheritance, modifiers, and more.
    pub fn extract_context(&self, content: &str) -> ContractContext {
        let mut ctx = ContractContext {
            code_only: Self::strip_comment_lines(content),
            ..Default::default()
        };

        // Detect Solidity version from the pragma directive
        let version_pattern =
            re!(r"pragma\s+solidity\s*([\^>=<]*)?\s*(\d+\.\d+\.\d+|\d+\.\d+)");
        if let Some(caps) = version_pattern.captures(content) {
            ctx.solidity_version = caps.get(2).map(|m| m.as_str().to_string());
            if let Some(ref version) = ctx.solidity_version {
                // Gated on `version_aware_filtering`: withholding it means not crediting
                // the compiler's built-in checks, which is exactly what the knob promises.
                ctx.is_solidity_0_8_plus = self.config.version_aware_filtering
                    && (version.starts_with("0.8")
                        || version.starts_with("0.9")
                        || version.chars().next().is_some_and(|c| c > '0'));
            }
        }

        // Detect SafeMath (pre-0.8 overflow library)
        ctx.uses_safemath = content.contains("using SafeMath for") || content.contains("SafeMath.");

        // Detect ReentrancyGuard (OZ, Solmate, or custom mutex pattern)
        ctx.uses_reentrancy_guard = content.contains("ReentrancyGuard")
            || content.contains("nonReentrant")
            || content.contains("_reentrancyGuard");

        // Detect OpenZeppelin imports or references.
        //
        // The `trust_*` flags are honoured here rather than at each use site: "trusting" a
        // library means crediting its guarantees when deciding whether a finding is a false
        // positive, so withholding trust is exactly equivalent to not detecting it. Gating
        // once keeps every downstream consumer of `ctx.uses_*` consistent by construction.
        ctx.uses_openzeppelin = self.config.trust_openzeppelin
            && (content.contains("@openzeppelin")
                || content.contains("openzeppelin-contracts")
                || content.contains("OpenZeppelin"));

        // Detect Solmate
        ctx.uses_solmate =
            self.config.trust_solmate && (content.contains("solmate") || content.contains("Solmate"));

        // Detect Solady
        ctx.uses_solady =
            self.config.trust_solady && (content.contains("solady") || content.contains("Solady"));

        // Detect SafeERC20 (wraps ERC20 calls with revert-on-failure)
        ctx.uses_safe_erc20 = content.contains("using SafeERC20 for")
            || content.contains("SafeERC20.")
            || content.contains(".safeTransfer(");

        // Detect interface-only files (no findings are relevant for pure interfaces)
        let interface_pattern = re!(r"^\s*interface\s+\w+");
        let contract_pattern = re!(r"^\s*(contract|abstract\s+contract)\s+\w+");
        let has_interface = content.lines().any(|line| interface_pattern.is_match(line));
        let has_contract = content.lines().any(|line| contract_pattern.is_match(line));
        ctx.is_interface_only = has_interface && !has_contract;

        // Detect library-ONLY files (libraries have restricted capabilities). Files that
        // bundle a helper library next to contracts keep full analysis of the contracts.
        // (?m) so ^ anchors per line, not just at the start of the file.
        ctx.is_library = re!(r"(?m)^\s*library\s+\w+").is_match(content) && !has_contract;

        // Detect test contracts (Foundry, Hardhat, DSTest frameworks)
        ctx.is_test_contract = content.contains("import \"forge-std")
            || content.contains("import \"hardhat")
            || content.contains("is Test")
            || content.contains("is DSTest");

        // Mock/test contracts, as LINE SPANS rather than a whole-file flag.
        //
        // This used to be `content.to_lowercase().contains("mock")` — the bare substring
        // anywhere in the file, including inside a comment. Combined with `strict_mode`
        // (on by default) dropping every finding in a "mock" file, appending
        // `contract MockToken {}` to a vulnerable contract silently suppressed the entire
        // report. Scoping to the declaring contract's own line range means a mock or test
        // helper sitting beside production code no longer hides bugs in its neighbour.
        ctx.mock_spans = Self::mock_contract_spans(content);

        // Detect broad access-control patterns (Ownable, RBAC, modifier keywords)
        ctx.has_access_control = content.contains("Ownable")
            || content.contains("AccessControl")
            || content.contains("onlyOwner")
            || content.contains("onlyRole");

        // Extract custom modifier names (used later to check per-function guards)
        let modifier_pattern = re!(r"modifier\s+(\w+)");
        for cap in modifier_pattern.captures_iter(content) {
            if let Some(name) = cap.get(1) {
                ctx.custom_modifiers.push(name.as_str().to_string());
            }
        }

        // Extract the inheritance list (contracts/interfaces after `is`)
        let inherit_pattern =
            re!(r"(contract|abstract\s+contract)\s+\w+\s+is\s+([^{]+)");
        if let Some(caps) = inherit_pattern.captures(content) {
            if let Some(inherited) = caps.get(2) {
                for part in inherited.as_str().split(',') {
                    let name = part.split_whitespace().next().unwrap_or("");
                    if !name.is_empty() {
                        ctx.inherited_contracts.push(name.to_string());
                    }
                }
            }
        }

        // Extract all import paths (both direct and named import syntax)
        let import_pattern =
            re!(r#"import\s+["']([^"']+)["']|import\s+\{[^}]+\}\s+from\s+["']([^"']+)["']"#);
        for cap in import_pattern.captures_iter(content) {
            let path = cap
                .get(1)
                .or_else(|| cap.get(2))
                .map(|m| m.as_str().to_string());
            if let Some(p) = path {
                ctx.imported_files.push(p);
            }
        }

        // Extract developer-placed audit/security annotations from comments
        let audit_pattern =
            re!(r"@audit|@security|@notice\s+SAFE|// SAFE:|// AUDITED");
        for mat in audit_pattern.find_iter(content) {
            ctx.audit_annotations.push(mat.as_str().to_string());
        }

        // Parse all function declarations into structured FunctionInfo records

        ctx
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
    ///    related findings within function scope are merged, and threat model
    ///    findings are suppressed when specific detections exist.
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
        self.deduplicate(&mut filtered, content);

        filtered
    }

    fn get_context_window(
        &self,
        content: &str,
        line_number: usize,
        before: usize,
        after: usize,
    ) -> String {
        let lines: Vec<&str> = content.lines().collect();
        if lines.is_empty() {
            return String::new();
        }

        let idx = line_number.saturating_sub(1);
        let start = idx.saturating_sub(before);
        let end = (idx + after + 1).min(lines.len());
        // A finding whose line number exceeds the file length would make `start > end`
        // and panic on the slice. Nothing should produce such a finding, but a scanner
        // must not be one bad base_line offset away from crashing on user input.
        let start = start.min(end);
        lines[start..end].join("\n")
    }

    fn has_guard_or_validation(&self, context: &str) -> bool {
        context.contains("require(")
            || context.contains("assert(")
            || context.contains("revert")
            || context.contains("if (")
            || context.contains("if(")
    }

    fn has_array_length_validation(&self, context: &str) -> bool {
        context.contains(".length") && self.has_guard_or_validation(context)
    }

    fn has_raw_bytes_validation(&self, context: &str) -> bool {
        context.contains("abi.decode")
            || context.contains("bytes4(")
            || context.contains("selector")
            || (context.contains(".length") && self.has_guard_or_validation(context))
    }

    fn has_fee_on_transfer_accounting(&self, context: &str) -> bool {
        (context.contains("balancebefore") && context.contains("balanceafter"))
            || (context.contains("beforebalance") && context.contains("afterbalance"))
            || (context.contains("received")
                && context.contains("balanceafter")
                && context.contains('-'))
            || (context.contains("balanceof(") && context.contains('-'))
    }

    fn has_access_control_guard(&self, context: &str) -> bool {
        context.contains("onlyowner")
            || context.contains("onlyadmin")
            || context.contains("onlyrole")
            || context.contains("requiresauth")
            || context.contains("authorized")
            || context.contains("governance")
            || context.contains("timelock")
            || context.contains("_checkowner()")
            || context.contains("_checkrole(")
            || context.contains("require(msg.sender")
            || context.contains("require(_msgsender()")
            || context.contains("if (msg.sender !=")
    }

    fn has_pause_guard(&self, content: &str, context: &str) -> bool {
        let content_lower = content.to_lowercase();
        let pause_keywords = [
            "pausable",
            "whennotpaused",
            "whenactive",
            "notpaused",
            "onlywhenactive",
            "onlywhenlive",
            "onlyoperational",
            "emergencyshutdown",
            "shutdown",
            "halted",
            "stopped",
            "circuitbreaker",
            "pauseguard",
        ];

        pause_keywords
            .iter()
            .any(|k| content_lower.contains(k) || context.contains(k))
            || context.contains("require(!paused")
            || context.contains("require(!ispaused")
            || context.contains("require(!emergencyshutdown")
            || context.contains("require(active")
            || context.contains("if (paused)")
            || context.contains("if (emergencyshutdown)")
            || context.contains("revert paused")
    }

    fn has_slippage_guard(&self, context: &str) -> bool {
        let slippage_keywords = [
            "amountoutmin",
            "minamountout",
            "minout",
            "minreturn",
            "minreceived",
            "minimumreceived",
            "minsharesout",
            "minshares",
            "minliquidity",
            "minamount",
            "mindy",
            "maxslippage",
            "slippagebps",
            "priceimpact",
        ];

        slippage_keywords.iter().any(|k| context.contains(k))
            && (self.has_guard_or_validation(context)
                || context.contains("quote(")
                || context.contains("preview")
                || context.contains("getamountsout")
                || context.contains("getamountout"))
    }

    fn has_deadline_guard(&self, context: &str) -> bool {
        let deadline_keywords = [
            "deadline",
            "expiry",
            "validuntil",
            "expiresat",
            "expiration",
        ];

        deadline_keywords.iter().any(|k| context.contains(k))
            && (context.contains("block.timestamp")
                || context.contains("<= ")
                || context.contains(" < ")
                || self.has_guard_or_validation(context))
    }

    fn has_signature_verification(&self, content: &str, context: &str) -> bool {
        let content_lower = content.to_lowercase();
        context.contains("_verify(")
            || context.contains("verify(")
            || context.contains("ecdsa.recover")
            || context.contains("signaturechecker")
            || context.contains("ecrecover")
            || context.contains("recover(")
            || content_lower.contains("erc20permit")
            || content_lower.contains("domain_separator")
    }

    fn has_nonce_management(&self, content: &str, context: &str) -> bool {
        let content_lower = content.to_lowercase();
        context.contains("_usenonce(")
            || context.contains("nonce++")
            || context.contains("++nonce")
            || context.contains("+= 1")
            || context.contains("nonce = nonce + 1")
            || context.contains("_nonces[")
            || context.contains("nonces[")
            || content_lower.contains("noncebitmap")
    }

    /// Line spans of contracts whose own name marks them as a mock or test helper.
    ///
    /// A span runs from the contract's declaration to the line before the next top-level
    /// declaration (or end of file), matching the boundary logic used by `deduplicate`.
    fn mock_contract_spans(content: &str) -> Vec<(usize, usize)> {
        let decl = re!(r"^\s*(?:abstract\s+)?(?:contract|library|interface)\s+(\w+)");
        let mut decls: Vec<(usize, bool)> = Vec::new();
        for (idx, line) in content.lines().enumerate() {
            if let Some(caps) = decl.captures(line) {
                let name = caps.get(1).map_or("", |m| m.as_str());
                let lower = name.to_lowercase();
                // Only genuine mock naming. A contract called `TestVulnerable` is
                // usually the fixture UNDER test, not a helper, so treating a `test`
                // prefix as a mock would suppress findings in exactly the contracts a
                // corpus exists to exercise. Real test harnesses are recognised
                // file-level instead, by their forge-std/ds-test imports.
                let is_mock = lower.contains("mock");
                decls.push((idx + 1, is_mock));
            }
        }
        let total = content.lines().count();
        let mut spans = Vec::new();
        for (i, &(start, is_mock)) in decls.iter().enumerate() {
            if is_mock {
                let end = decls.get(i + 1).map_or(total, |&(n, _)| n.saturating_sub(1));
                spans.push((start, end));
            }
        }
        spans
    }

    /// Determine if a vulnerability should be kept
    fn should_keep(&self, vuln: &Vulnerability, content: &str, ctx: &ContractContext) -> bool {
        // Skip all findings in test/mock contracts if strict mode
        if self.config.strict_mode
            && (ctx.is_test_contract || ctx.is_in_mock_contract(vuln.line_number))
        {
            return false;
        }

        // Skip library-only findings for certain categories.
        // Libraries have no state of their own — state change, reentrancy, CEI,
        // missing events, and access control findings are the caller's responsibility.
        if ctx.is_library {
            match vuln.category {
                VulnerabilityCategory::AccessControl
                | VulnerabilityCategory::RoleBasedAccessControl
                | VulnerabilityCategory::Reentrancy
                | VulnerabilityCategory::CallbackReentrancy
                | VulnerabilityCategory::ERC777CallbackReentrancy
                | VulnerabilityCategory::ReadOnlyReentrancy
                | VulnerabilityCategory::MissingEvents
                | VulnerabilityCategory::MissingEmergencyStop
                // Audited math libraries (OZ Math, solady) use unchecked/shift tricks
                // deliberately; the caller-facing contract is where math risk surfaces.
                | VulnerabilityCategory::UncheckedMathOperation
                | VulnerabilityCategory::IsContractPostPectra => return false,
                _ => {
                    // Also suppress CEI/state-after-call findings in libraries
                    if vuln.title.contains("State Change After") || vuln.title.contains("CEI") {
                        return false;
                    }
                }
            }
        }

        // "Unused" internal helpers in abstract contracts, libraries, and interfaces are
        // the extension points those types exist to provide -- OpenZeppelin's
        // `_requireOwned`, `_domainSeparatorV4`, `_reentrancyGuardEntered` and friends
        // are all called by inheritors, not by the base file. Only report dead code in
        // files that declare a concrete, deployable contract.
        if matches!(vuln.category, VulnerabilityCategory::UnusedCode)
            && vuln.title.contains("Unused Function")
            && !re!(r"(?m)^\s*contract\s+\w+").is_match(content)
        {
            return false;
        }

        // Check for safe patterns.
        //
        // These are broad, case-insensitive, whole-file regexes that suppress an entire
        // category when the contract appears to mitigate it. They must be matched against
        // CODE ONLY. Previously they ran on the raw source, so prose in a comment was
        // enough to silence a real finding: adding `// This contract follows
        // checks-effects-interactions` removed a genuine "State Change After External
        // Call" reentrancy finding, and `// no ReentrancyGuard here` did the same. A
        // comment is a claim, not a mitigation.
        // Gated on `semantic_analysis`: these whole-file patterns are the "semantic
        // analysis of code patterns (CEI ordering, modifier presence)" the knob documents.
        if self.config.semantic_analysis {
            for safe in &self.safe_patterns {
                if safe.category == vuln.category && safe.pattern.is_match(&ctx.code_only) {
                    return false;
                }
            }
        }

        // Category-specific filtering
        match vuln.category {
            VulnerabilityCategory::ArithmeticIssues => self.filter_arithmetic(vuln, ctx),
            VulnerabilityCategory::Reentrancy
            | VulnerabilityCategory::CallbackReentrancy
            | VulnerabilityCategory::ERC777CallbackReentrancy
            | VulnerabilityCategory::DepositForReentrancy
            | VulnerabilityCategory::TransientStorageReentrancy
            | VulnerabilityCategory::TransientStorageGasReentrancy => {
                self.filter_reentrancy(vuln, content, ctx)
            }
            VulnerabilityCategory::ReadOnlyReentrancy => {
                // ReadOnlyReentrancy IS about view functions — don't filter by view/pure
                if ctx.uses_reentrancy_guard {
                    return false;
                }
                if ctx.is_test_contract {
                    return false;
                }
                true
            }
            VulnerabilityCategory::AccessControl
            | VulnerabilityCategory::RoleBasedAccessControl => {
                self.filter_access_control(vuln, content, ctx)
            }
            VulnerabilityCategory::UncheckedReturnValues
            | VulnerabilityCategory::UnusedReturnValues => self.filter_unchecked_returns(vuln, ctx),
            VulnerabilityCategory::PragmaIssues => self.filter_pragma(vuln, ctx),
            VulnerabilityCategory::GasOptimization => {
                // Always filter gas optimizations in test contracts
                !ctx.is_test_contract
            }
            VulnerabilityCategory::MagicNumbers => self.filter_magic_numbers(vuln, content),
            VulnerabilityCategory::OracleManipulation => {
                // FP-6: Suppress if no pricing context (just routing usage)
                let lines: Vec<&str> = content.lines().collect();
                let vuln_line = vuln.line_number.saturating_sub(1);
                let start = vuln_line.saturating_sub(5);
                let end = (vuln_line + 6).min(lines.len());
                let context: String = lines[start..end].join("\n").to_lowercase();
                let has_pricing_context = context.contains("price")
                    || context.contains("oracle")
                    || context.contains(" / ")
                    || context.contains(" * ");
                if !has_pricing_context {
                    return false;
                }
                true
            }
            VulnerabilityCategory::UnprotectedProxyUpgrade
            | VulnerabilityCategory::ProxyAdminVulnerability => {
                // FP-7: Suppress transferOwnership findings with Ownable2Step
                if (content.contains("Ownable2Step")
                    || content.contains("acceptOwnership")
                    || content.contains("pendingOwner"))
                    && (vuln.code_snippet.contains("transferOwnership")
                        || vuln.title.contains("transferOwnership")
                        || vuln.description.contains("transferOwnership"))
                    {
                        return false;
                    }
                self.filter_proxy_upgrade(vuln, content, ctx)
            }
            VulnerabilityCategory::SignatureVulnerabilities
            | VulnerabilityCategory::SignatureReplay => self.filter_signature(vuln, content, ctx),
            VulnerabilityCategory::SignatureVerificationBypass => {
                self.filter_signature_bypass(vuln, content, ctx)
            }
            VulnerabilityCategory::BlockTimestamp | VulnerabilityCategory::TimeManipulation => {
                self.filter_timestamp(vuln, content)
            }
            VulnerabilityCategory::DelegateCalls => self.filter_delegatecall(vuln, content, ctx),
            VulnerabilityCategory::MissingEmergencyStop => {
                let context = self
                    .get_context_window(content, vuln.line_number, 3, 25)
                    .to_lowercase();
                // Don't report if any pause/circuit-breaker pattern is used
                if self.has_pause_guard(content, &context) {
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
                self.filter_meta_transaction(vuln, content, ctx)
            }
            VulnerabilityCategory::DoubleClaiming => {
                // Don't report if rewardDebt or claimed mapping exists
                if content.contains("rewardDebt")
                    || content.contains("claimed[")
                    || content.contains("hasClaimed")
                    || content.contains("_claimed")
                {
                    return false;
                }
                true
            }
            VulnerabilityCategory::UncheckedMathOperation => {
                // Don't report in Solidity 0.8+ for regular math (overflow protected)
                // Only keep for unchecked blocks and bit shifts
                if ctx.is_solidity_0_8_plus
                    && !vuln.code_snippet.contains("unchecked")
                    && !vuln.code_snippet.contains("<<")
                    && !vuln.code_snippet.contains(">>")
                {
                    return false;
                }
                true
            }
            VulnerabilityCategory::InputValidationFailure => {
                let title = vuln.title.to_lowercase();
                let snippet = vuln.code_snippet.to_lowercase();
                let context = self
                    .get_context_window(content, vuln.line_number, 3, 25)
                    .to_lowercase();
                let contract_check_auth_like = title.contains("contract check bypassable")
                    && [
                        "function onlyeoa",
                        "function onlyhuman",
                        "function onlyexternallyowned",
                        "function requireeoa",
                        "function allowedeoa",
                        "function authorizedcaller",
                        "function isauthorized",
                        "function isallowed",
                        "function validatecaller",
                        "function gate",
                        "modifier onlyeoa",
                    ]
                    .iter()
                    .any(|pattern| context.contains(pattern));

                // Visibility and mutability are properties of the *enclosing* function,
                // so they must be read from its declaration rather than from a window of
                // surrounding lines. The window version suppressed a finding whenever any
                // nearby function happened to be `internal view` -- in Puppy Raffle, a
                // missing zero-address check in `changeFeeAddress` was hidden by the
                // unrelated `_isActivePlayer() internal view` five lines below it.
                let enclosing = enclosing_function_signature(content, vuln.line_number)
                    .unwrap_or_default()
                    .to_lowercase();

                // Don't report for view/pure functions
                if !contract_check_auth_like
                    && (snippet.contains(" view ")
                        || snippet.contains(" pure ")
                        || enclosing.contains(" view ")
                        || enclosing.contains(" pure "))
                {
                    return false;
                }

                // Don't report for internal/private functions
                if snippet.contains(" internal ")
                    || snippet.contains(" private ")
                    || enclosing.contains(" internal ")
                    || enclosing.contains(" private ")
                {
                    return false;
                }

                if (title.contains("array parameter") || title.contains("array length validation"))
                    && self.has_array_length_validation(&context) {
                        return false;
                    }

                if title.contains("unchecked raw calldata")
                    && self.has_raw_bytes_validation(&context) {
                        return false;
                    }

                if title.contains("fee-on-transfer")
                    && self.has_fee_on_transfer_accounting(&context) {
                        return false;
                    }

                if title.contains("contract check bypassable") {
                    let helper_context = context.contains("function iscontract")
                        || context.contains("function _iscontract")
                        || snippet.trim_start().starts_with("return ")
                        || context.contains("returns (bool)")
                        || context.contains("returns(bool)");
                    let used_for_auth = context.contains("require(")
                        || context.contains("if (")
                        || context.contains("if(")
                        || context.contains("revert");
                    if helper_context && !contract_check_auth_like {
                        return false;
                    }
                    if !used_for_auth && !contract_check_auth_like {
                        return false;
                    }
                }

                if title.contains("layerzero missing payload validation")
                    && self.has_raw_bytes_validation(&context) {
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
                if content.contains("TimelockController")
                    || content.contains("Timelock")
                    || content.contains("delay") && content.contains("queue")
                {
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
                if ctx.is_test_contract || ctx.is_in_mock_contract(vuln.line_number) {
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

            // --- v0.7.0 new category filters ---
            VulnerabilityCategory::ERC2771MulticallSpoofing => {
                // Suppress if using OZ ERC2771Forwarder v4.9+ (fixed version)
                if content.contains("ERC2771Forwarder") {
                    return false;
                }
                // Suppress if multicall override strips suffix
                if content.contains("_msgData()") && content.contains("multicall") {
                    return false;
                }
                true
            }
            VulnerabilityCategory::FeeOnTransferAssumption => {
                // Suppress if balance diff pattern exists anywhere in the function
                if content.contains("balanceBefore")
                    || content.contains("balanceAfter")
                    || content.contains("received =")
                    || content.contains("_before") && content.contains("_after")
                {
                    return false;
                }
                // Suppress in test contracts
                if ctx.is_test_contract {
                    return false;
                }
                true
            }
            VulnerabilityCategory::IsContractPostPectra => {
                // Suppress if used only in non-access-control context (e.g. isContract utility)
                if vuln.code_snippet.contains("function isContract") {
                    return false;
                }
                // Suppress in test contracts
                if ctx.is_test_contract {
                    return false;
                }
                true
            }
            VulnerabilityCategory::UnprotectedAdminSweep => {
                // Suppress if timelock exists
                if content.contains("TimelockController")
                    || content.contains("Timelock")
                    || content.contains("delay") && content.contains("queue")
                {
                    return false;
                }
                if ctx.is_test_contract {
                    return false;
                }
                true
            }
            VulnerabilityCategory::MissingSlippageProtection => {
                self.filter_slippage_or_mev(vuln, content, ctx, true)
            }
            VulnerabilityCategory::FrontRunning
            | VulnerabilityCategory::MEVExploitable
            | VulnerabilityCategory::MissingSwapDeadline => {
                self.filter_slippage_or_mev(vuln, content, ctx, false)
            }
            VulnerabilityCategory::MulticallStateReset
            | VulnerabilityCategory::InconsistentStateReset
            | VulnerabilityCategory::MulticallMsgValueReuse
            | VulnerabilityCategory::EIP7702TxOriginBypass
            | VulnerabilityCategory::UnvalidatedCrossChainReceiver
            | VulnerabilityCategory::CLMMMathOverflow
            | VulnerabilityCategory::InconsistentRounding
            | VulnerabilityCategory::ArbitraryReceiverCallback
            | VulnerabilityCategory::UnsafeMulticallDelegatecall => {
                // Critical/High findings — suppress in test contracts only
                if ctx.is_test_contract {
                    return false;
                }
                true
            }
            VulnerabilityCategory::DonationAttackVector => {
                // Suppress if virtual offset pattern exists
                if content.contains("virtualAssets")
                    || content.contains("_decimalsOffset")
                    || content.contains("INITIAL_DEPOSIT")
                {
                    return false;
                }
                if ctx.is_test_contract {
                    return false;
                }
                true
            }
            VulnerabilityCategory::AVSSlashingRisk => {
                // Suppress only when code, not comments, implements a delay/dispute flow
                let code_only = Self::strip_comment_lines(content).to_lowercase();
                if code_only.contains("timelock")
                    || code_only.contains("dispute")
                    || code_only.contains("vetoable")
                    || code_only.contains("cooldown") && code_only.contains("queue")
                {
                    return false;
                }
                true
            }
            // Suppress SafeERC20 false positives in EIP-20 compliance checks
            _ => {
                if ctx.uses_safe_erc20 {
                    let snippet = &vuln.code_snippet;
                    if snippet.contains("safeTransfer")
                        || snippet.contains("SafeERC20")
                        || snippet.contains("safeApprove")
                        || snippet.contains("safeIncreaseAllowance")
                    {
                        return false;
                    }
                }
                true
            }
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
    fn filter_reentrancy(
        &self,
        vuln: &Vulnerability,
        content: &str,
        ctx: &ContractContext,
    ) -> bool {
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
    fn filter_access_control(
        &self,
        vuln: &Vulnerability,
        content: &str,
        ctx: &ContractContext,
    ) -> bool {
        let lines: Vec<&str> = content.lines().collect();
        if vuln.line_number > 0 && vuln.line_number <= lines.len() {
            // Read the full function signature (multi-line: from `function` to `{`)
            let full_sig = {
                let start = vuln.line_number.saturating_sub(1);
                let mut sig = String::new();
                for &sig_line in lines.iter().skip(start).take(10) {
                    sig.push_str(sig_line);
                    sig.push(' ');
                    if sig_line.contains('{') {
                        break;
                    }
                }
                sig
            };

            // Check for common access control patterns in the full signature
            let access_patterns = [
                "onlyOwner",
                "onlyAdmin",
                "onlyRole",
                "onlyMinter",
                "onlyGovernance",
                "auth",
                "authorized",
                "requiresAuth",
                "whenNotPaused",
                "initializer",
                "nonReentrant",
            ];

            for pattern in &access_patterns {
                if full_sig.contains(pattern) {
                    return false;
                }
            }

            // Check for any only* modifier pattern
            if re!(r"\bonly\w+").is_match(&full_sig) {
                return false;
            }

            // Check custom modifiers
            for modifier in &ctx.custom_modifiers {
                if full_sig.contains(modifier.as_str()) {
                    return false;
                }
            }

            // Check if it's a view/pure function (read-only, less critical)
            if full_sig.contains(" view ")
                || full_sig.contains(" view)")
                || full_sig.contains(" pure ")
                || full_sig.contains(" pure)")
            {
                return false;
            }

            // Check if internal/private
            if full_sig.contains(" internal ") || full_sig.contains(" private ") {
                return false;
            }

            // Check for inline access control (look at function body)
            let start = vuln.line_number;
            let end_idx = (start + 15).min(lines.len());
            for &check_line in &lines[start..end_idx] {
                if check_line.contains("require(msg.sender")
                    || check_line.contains("require(_msgSender()")
                    || check_line.contains("if (msg.sender !=")
                    || check_line.contains("_checkOwner()")
                    || check_line.contains("_checkRole(")
                {
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
        let acceptable = [
            "0", "1", "2", "100", "1000", "10000", "1e18", "1e6", "10**18", "10**6",
        ];
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
        if snippet.contains("PRECISION") || snippet.contains("DECIMALS") || snippet.contains("WAD")
        {
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
    fn filter_proxy_upgrade(
        &self,
        _vuln: &Vulnerability,
        content: &str,
        ctx: &ContractContext,
    ) -> bool {
        let context = self
            .get_context_window(content, _vuln.line_number, 2, 20)
            .to_lowercase();

        if self.has_access_control_guard(&context) {
            return false;
        }
        // Check for protected upgrade patterns
        if content.contains("_authorizeUpgrade") && content.contains("onlyOwner") {
            return false;
        }
        if content.contains("_authorizeUpgrade")
            && (content.contains("onlyRole")
                || content.contains("requiresAuth")
                || content.contains("auth")
                || content.contains("_checkOwner()")
                || content.contains("_checkRole("))
        {
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
    fn filter_signature(&self, vuln: &Vulnerability, content: &str, ctx: &ContractContext) -> bool {
        let title = vuln.title.to_lowercase();
        let context = self
            .get_context_window(content, vuln.line_number, 3, 30)
            .to_lowercase();

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
        if (title.contains("deadline") || title.contains("permit"))
            && self.has_deadline_guard(&context) {
                return false;
            }
        if (title.contains("replay") || title.contains("signature"))
            && self.has_signature_verification(content, &context)
            && self.has_nonce_management(content, &context)
                && (self.has_deadline_guard(&context)
                    || context.contains("domain_separator")
                    || context.contains("block.chainid")
                    || content.to_lowercase().contains("domain_separator"))
            {
                return false;
            }
        true
    }

    fn filter_signature_bypass(
        &self,
        vuln: &Vulnerability,
        content: &str,
        ctx: &ContractContext,
    ) -> bool {
        let context = self
            .get_context_window(content, vuln.line_number, 3, 20)
            .to_lowercase();

        if ctx.uses_openzeppelin && content.contains("ECDSA") {
            return false;
        }

        if context.contains("address(0)")
            && (context.contains("require(recovered !=")
                || context.contains("require(recovered!=")
                || context.contains("recovered == expected")
                || context.contains("recovered == owner")
                || context.contains("recovered == signer"))
        {
            return false;
        }

        true
    }

    fn filter_meta_transaction(
        &self,
        vuln: &Vulnerability,
        content: &str,
        ctx: &ContractContext,
    ) -> bool {
        let title = vuln.title.to_lowercase();
        let context = self
            .get_context_window(content, vuln.line_number, 3, 30)
            .to_lowercase();
        let content_lower = content.to_lowercase();

        if ctx.uses_openzeppelin && content.contains("ERC2771Context") {
            return false;
        }

        if title.contains("minimalforwarder pattern")
            || title.contains("kiloex-pattern forwarder exploit")
        {
            let has_safe_forwarder_flow = content_lower.contains("function execute")
                && self.has_signature_verification(content, &content_lower)
                && self.has_nonce_management(content, &content_lower);
            if has_safe_forwarder_flow {
                return false;
            }
        }

        if (title.contains("mutable trusted forwarder") || title.contains("trusted forwarder"))
            && (self.has_access_control_guard(&context)
                || context.contains("immutable")
                || context.contains("constructor("))
            {
                return false;
            }

        if self.has_signature_verification(content, &context)
            && self.has_nonce_management(content, &context)
        {
            return false;
        }

        if self.has_signature_verification(content, &context) && self.has_deadline_guard(&context) {
            return false;
        }

        true
    }

    fn filter_slippage_or_mev(
        &self,
        vuln: &Vulnerability,
        content: &str,
        ctx: &ContractContext,
        only_slippage: bool,
    ) -> bool {
        let snippet = vuln.code_snippet.to_lowercase();
        let context = self
            .get_context_window(content, vuln.line_number, 3, 35)
            .to_lowercase();

        if snippet.contains(" internal ")
            || snippet.contains(" private ")
            || context.contains(" internal ")
            || context.contains(" private ")
        {
            return false;
        }
        if ctx.is_test_contract {
            return false;
        }
        if self.has_slippage_guard(&context) {
            if only_slippage {
                return false;
            }
            if !vuln.title.to_lowercase().contains("deadline") {
                return false;
            }
        }
        if self.has_deadline_guard(&context) && vuln.title.to_lowercase().contains("deadline") {
            return false;
        }
        if self.has_pause_guard(content, &context)
            && vuln.category == VulnerabilityCategory::MissingEmergencyStop
        {
            return false;
        }
        true
    }

    /// Filter timestamp issues
    fn filter_timestamp(&self, vuln: &Vulnerability, content: &str) -> bool {
        let snippet = &vuln.code_snippet;

        // Event emissions using timestamp are fine
        if snippet.contains("emit")
            || content
                .lines()
                .nth(vuln.line_number.saturating_sub(1))
                .is_some_and(|l| l.contains("emit"))
        {
            return false;
        }

        // Logging/tracking uses
        if snippet.contains("lastUpdate") || snippet.contains("timestamp =") {
            return false;
        }

        true
    }

    /// Filter delegatecall issues
    fn filter_delegatecall(
        &self,
        _vuln: &Vulnerability,
        content: &str,
        ctx: &ContractContext,
    ) -> bool {
        // ERC-1967 proxy pattern
        if content.contains("_IMPLEMENTATION_SLOT") || content.contains("ERC1967") {
            return false;
        }
        // Standard proxy patterns
        if ctx
            .inherited_contracts
            .iter()
            .any(|c| c.contains("Proxy") || c.contains("UUPS") || c.contains("Transparent"))
        {
            return false;
        }
        true
    }

    /// Adjust vulnerability confidence based on context
    fn adjust_confidence(&self, vuln: &mut Vulnerability, ctx: &ContractContext) {
        // Reduce confidence for test/mock contracts
        if ctx.is_test_contract || ctx.is_in_mock_contract(vuln.line_number) {
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
            VulnerabilityCategory::ArithmeticIssues
                if !ctx.is_solidity_0_8_plus && !ctx.uses_safemath =>
            {
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

    /// Remove duplicate vulnerabilities using three passes:
    /// 1. Exact (line, category) dedup
    /// 2. Related-category merge within the same function (or 5-line fallback)
    /// 3. Threat model suppression when specific detections exist
    fn deduplicate(&self, vulnerabilities: &mut Vec<Vulnerability>, content: &str) {
        // Pass 1: exact (line, category, title) dedup.
        //
        // The title is part of the key on purpose. Keying on (line, category) alone
        // treated two DIFFERENT rules that happen to share a category and a line as
        // duplicates and dropped one at random — e.g. on a bridge `claim(bytes proof)`
        // line, "Bridge Proof Verification" and "Bridge Claim Replay Attack" are distinct
        // vulnerabilities, and whichever arrived second was silently discarded. Because
        // rule order is not stable under parallel scanning, which one survived also
        // varied between runs of the same binary on the same input.
        //
        // The same rule firing twice on one line is still collapsed, which is what this
        // pass is for. Findings that are genuinely redundant rather than merely co-located
        // are handled by the scope-merge pass below.
        let mut seen: HashSet<(usize, String, String)> = HashSet::new();
        vulnerabilities.retain(|v| {
            let key = (v.line_number, format!("{:?}", v.category), v.title.clone());
            if seen.contains(&key) {
                false
            } else {
                seen.insert(key);
                true
            }
        });

        // Build a map of contract/library boundaries (1-based line ranges) so that
        // findings in DIFFERENT contracts are never merged together, even when their
        // line numbers happen to fall within the merge window. Without this, e.g. a
        // finding at the end of contract A and one at the start of contract B could be
        // collapsed into one, silently dropping a real finding.
        let contract_boundaries: Vec<(usize, usize)> = {
            let mut spans = Vec::new();
            let decl = re!(r"^\s*(abstract\s+)?(contract|library|interface)\s+\w+");
            let mut starts: Vec<usize> = Vec::new();
            for (idx, line) in content.lines().enumerate() {
                if decl.is_match(line) {
                    starts.push(idx + 1);
                }
            }
            let total = content.lines().count();
            for (i, &s) in starts.iter().enumerate() {
                let end = starts.get(i + 1).map_or(total, |&n| n - 1);
                spans.push((s, end));
            }
            spans
        };
        // Two findings are "co-located" if they live in the same contract span (or if
        // we couldn't determine any spans, fall back to permitting the merge).
        let same_contract = |a: usize, b: usize| -> bool {
            if contract_boundaries.is_empty() {
                return true;
            }
            let span_of = |ln: usize| {
                contract_boundaries
                    .iter()
                    .position(|&(s, e)| ln >= s && ln <= e)
            };
            match (span_of(a), span_of(b)) {
                (Some(x), Some(y)) => x == y,
                // A finding at line 1 (file-level, e.g. compiler) has no contract span;
                // allow those to merge as before.
                _ => true,
            }
        };

        // Function-scope map retained for the merge-window heuristic below.
        let func_boundaries: Vec<(usize, usize)> = contract_boundaries.clone();

        // Pass 2: Merge related categories within the same function or 15-line window
        let category_group = |cat: &VulnerabilityCategory| -> u8 {
            match cat {
                // Group 1: Reentrancy variants
                VulnerabilityCategory::Reentrancy
                | VulnerabilityCategory::CallbackReentrancy
                | VulnerabilityCategory::ERC777CallbackReentrancy
                | VulnerabilityCategory::DepositForReentrancy
                | VulnerabilityCategory::TransientStorageReentrancy
                | VulnerabilityCategory::TransientStorageGasReentrancy
                | VulnerabilityCategory::ReadOnlyReentrancy
                | VulnerabilityCategory::UnsafeExternalCalls
                | VulnerabilityCategory::ArbitraryReceiverCallback => 1,

                // Group 2: Access control variants
                VulnerabilityCategory::AccessControl
                | VulnerabilityCategory::RoleBasedAccessControl
                | VulnerabilityCategory::ProxyAdminVulnerability
                | VulnerabilityCategory::UnprotectedProxyUpgrade
                | VulnerabilityCategory::UnprotectedAdminSweep => 2,

                // Group 3: Oracle / flash loan
                VulnerabilityCategory::FlashLoanAttack
                | VulnerabilityCategory::OracleManipulation
                | VulnerabilityCategory::LiquidityManipulation => 3,

                // Group 4: Compiler / pragma
                VulnerabilityCategory::CompilerBug
                | VulnerabilityCategory::PragmaIssues
                | VulnerabilityCategory::Push0Compatibility => 4,

                // Group 5: Signature
                VulnerabilityCategory::SignatureVulnerabilities
                | VulnerabilityCategory::SignatureReplay
                | VulnerabilityCategory::SignatureVerificationBypass => 5,

                // Group 6: Math / precision
                VulnerabilityCategory::ArithmeticIssues
                | VulnerabilityCategory::PrecisionLoss
                | VulnerabilityCategory::UncheckedMathOperation
                | VulnerabilityCategory::InconsistentRounding
                | VulnerabilityCategory::CLMMMathOverflow => 6,

                // Group 12: Truncating downcast. Deliberately NOT grouped with the
                // math group: a downcast that truncates and an addition that wraps are
                // different bugs with different fixes (widen the type vs. use checked
                // math), and they routinely sit on the same line -- Puppy Raffle's
                // `totalFees = totalFees + uint64(fee)` is both at once. Merging them
                // drops one real finding.
                VulnerabilityCategory::UnsafeDowncast => 12,

                // Group 7: ERC-4626 vault inflation / donation
                VulnerabilityCategory::ERC4626Inflation
                | VulnerabilityCategory::DonationAttackVector => 7,

                // Group 8: Cross-chain replay
                VulnerabilityCategory::CrossChainReplay
                | VulnerabilityCategory::CrossChainMessageReplay => 8,

                // Group 9: Approval race condition (reported by eip_analyzer as FrontRunning
                // and by advanced_analysis/logic_analyzer as LogicError)
                VulnerabilityCategory::FrontRunning => 9,

                _ => 0, // group 0 = no grouping
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

        let specificity_rank = |v: &Vulnerability| -> u8 {
            match v.category {
                VulnerabilityCategory::CLMMMathOverflow => 3,
                VulnerabilityCategory::DonationAttackVector => 3,
                VulnerabilityCategory::ERC4626Inflation => 3,
                VulnerabilityCategory::UncheckedMathOperation if v.title.contains("Cetus") => 2,
                VulnerabilityCategory::OracleManipulation if v.title.contains("Flash Loan") => 1,
                _ => 0,
            }
        };

        // Also treat LogicError with CEI/State After title as reentrancy group,
        // and LogicError with inflation-specific ERC-4626 titles as the same
        // group as the dedicated inflation detector. Keep other ERC-4626 logic
        // findings separate so distinct accounting bugs are not collapsed away.
        let is_erc4626_inflation_like_logic_error = |title: &str| -> bool {
            title.contains("First Depositor")
                || title.contains("Inflation")
                || title.contains("LP Inflation")
                || title.contains("Donation")
        };

        let effective_group = |v: &Vulnerability| -> u8 {
            if matches!(v.category, VulnerabilityCategory::SignatureVulnerabilities)
                && v.title.contains("Malleability")
            {
                return 10;
            }
            if matches!(v.category, VulnerabilityCategory::CLMMMathOverflow)
                || matches!(v.category, VulnerabilityCategory::UncheckedMathOperation)
                    && v.title.contains("Cetus")
            {
                return 11;
            }
            let g = category_group(&v.category);
            if g != 0 {
                return g;
            }
            if matches!(v.category, VulnerabilityCategory::LogicError) {
                if v.title.contains("CEI") || v.title.contains("State After") {
                    return 1; // reentrancy group
                }
                if is_erc4626_inflation_like_logic_error(&v.title) {
                    return 7; // ERC-4626 inflation group
                }
                if v.title.contains("Approve Race") {
                    return 9; // approval race group
                }
            }
            0
        };

        // Use function-scope merge: if both findings are in the same function
        // (approximated by checking if they're within 30 lines — typical function size),
        // merge them. Fall back to 15-line window for ungrouped or edge cases.
        let merge_window = if func_boundaries.is_empty() { 30 } else { 15 };

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
                // Never merge findings that live in different contracts/libraries.
                if !same_contract(
                    vulnerabilities[i].line_number,
                    vulnerabilities[j].line_number,
                ) {
                    continue;
                }
                // Findings that name different state variables are different bugs,
                // even inside one merge window: two unchecked accumulators in the same
                // function each need their own fix.
                if let (Some(a), Some(b)) = (
                    subject_identifier(&vulnerabilities[i].title),
                    subject_identifier(&vulnerabilities[j].title),
                ) {
                    if a != b {
                        continue;
                    }
                }
                let line_diff = (vulnerabilities[i].line_number as isize
                    - vulnerabilities[j].line_number as isize)
                    .unsigned_abs();
                if line_diff <= merge_window {
                    let keep_i = severity_rank(&vulnerabilities[i])
                        > severity_rank(&vulnerabilities[j])
                        || severity_rank(&vulnerabilities[i]) == severity_rank(&vulnerabilities[j])
                            && specificity_rank(&vulnerabilities[i])
                                >= specificity_rank(&vulnerabilities[j]);
                    if keep_i {
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

        // Pass 3: Suppress [Threat Model] findings when a specific detection
        // for the same category group already exists
        let has_specific_detection: HashSet<u8> = vulnerabilities
            .iter()
            .filter(|v| !v.title.starts_with("[Threat Model]"))
            .filter_map(|v| {
                let g = effective_group(v);
                if g != 0 {
                    Some(g)
                } else {
                    None
                }
            })
            .collect();

        if !has_specific_detection.is_empty() {
            vulnerabilities.retain(|v| {
                if v.title.starts_with("[Threat Model]") {
                    let g = effective_group(v);
                    // Keep if it's in a group that has no specific detection
                    g == 0 || !has_specific_detection.contains(&g)
                } else {
                    true
                }
            });
        }
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
    use super::{FalsePositiveFilter, FilterConfig};
    use crate::vulnerabilities::{Vulnerability, VulnerabilityCategory, VulnerabilitySeverity};

    #[test]
    fn keeps_distinct_erc4626_liability_drift_finding() {
        let filter = FalsePositiveFilter::new(FilterConfig::default());
        let content = r#"contract ERC4626Vault {
    function slash() external {}
    function convertToShares(uint256 assets) external view returns (uint256) {
        return assets;
    }
}"#;

        let findings = vec![
            Vulnerability::high_confidence(
                VulnerabilitySeverity::Critical,
                VulnerabilityCategory::LogicError,
                "ERC4626 Liability Drift After Slash".to_string(),
                "distinct vault accounting bug".to_string(),
                22,
                "function slash()".to_string(),
                "sync liabilities".to_string(),
            ),
            Vulnerability::high_confidence(
                VulnerabilitySeverity::Critical,
                VulnerabilityCategory::ERC4626Inflation,
                "[EIP-4626] ERC-4626 First Depositor Inflation Attack".to_string(),
                "inflation bug".to_string(),
                31,
                "function convertToShares(uint256 assets)".to_string(),
                "virtual shares".to_string(),
            ),
            Vulnerability::high_confidence(
                VulnerabilitySeverity::Critical,
                VulnerabilityCategory::LogicError,
                "ERC-4626 First Depositor Logic Bug".to_string(),
                "duplicate inflation-style logic warning".to_string(),
                32,
                "function convertToShares(uint256 assets)".to_string(),
                "virtual shares".to_string(),
            ),
        ];

        let filtered = filter.filter(findings, content);
        let titles: Vec<&str> = filtered.iter().map(|finding| finding.title.as_str()).collect();

        assert!(titles.contains(&"ERC4626 Liability Drift After Slash"));
        assert!(titles.contains(&"[EIP-4626] ERC-4626 First Depositor Inflation Attack"));
        assert_eq!(titles.len(), 2);
    }
}
