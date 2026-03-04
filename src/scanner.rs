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

use std::path::Path;
use std::io;
use once_cell::sync::Lazy;
use regex::Regex;
use crate::parser::{SolidityParser, CompilerInfo};
use crate::vulnerabilities::{Vulnerability, VulnerabilityRule, create_vulnerability_rules, create_version_specific_rules};
use crate::advanced_analysis::AdvancedAnalyzer;
use crate::logic_analyzer::LogicAnalyzer;
use crate::reachability_analyzer::ReachabilityAnalyzer;
use crate::dependency_analyzer::DependencyAnalyzer;
use crate::threat_model::ThreatModelGenerator;
use crate::eip_analyzer::EIPAnalyzer;
use crate::false_positive_filter::{FalsePositiveFilter, FilterConfig};

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

// =============================================================================
// Pre-compiled regex patterns (compiled once, reused across all scans)
// Prevents ReDoS risk from repeated compilation and improves performance.
// =============================================================================
static RE_INTERFACE: Lazy<Regex> = Lazy::new(|| Regex::new(r"^\s*interface\s+\w+").expect("invalid interface regex"));
static RE_CONTRACT: Lazy<Regex> = Lazy::new(|| Regex::new(r"^\s*(contract|abstract\s+contract|library)\s+\w+").expect("invalid contract regex"));
static RE_LIBRARY: Lazy<Regex> = Lazy::new(|| Regex::new(r"^\s*library\s+\w+").expect("invalid library regex"));
static RE_SOLIDITY_08: Lazy<Regex> = Lazy::new(|| Regex::new(r"pragma\s+solidity\s*[\^>=<]*\s*0\.([89]|[1-9]\d+)\.").expect("invalid version regex"));
static RE_MODIFIER: Lazy<Regex> = Lazy::new(|| Regex::new(r"modifier\s+(\w+)").expect("invalid modifier regex"));
static RE_STATE_MOD: Lazy<Regex> = Lazy::new(|| Regex::new(r"(\w+\s*=\s*[^=]|\w+\[[^\]]*\]\s*=|\+\+|--|\.\s*push\s*\(|delete\s+)").expect("invalid state mod regex"));

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
    /// Enable EIP-specific vulnerability detection
    pub enable_eip_analysis: bool,
    /// Enable enhanced false positive filtering
    pub enable_strict_filter: bool,
}

impl Default for ScannerConfig {
    fn default() -> Self {
        Self {
            // All advanced features enabled by default
            enable_logic_analysis: true,
            enable_reachability_analysis: true,
            enable_dependency_analysis: true,
            enable_threat_model: true,
            enable_eip_analysis: true,  // EIP analysis enabled by default
            enable_strict_filter: true, // Strict filtering enabled by default
        }
    }
}

/// The main scanner that orchestrates all analysis phases.
/// Holds references to all sub-analyzers and the vulnerability rule set.
pub struct ContractScanner {
    parser: SolidityParser,                       // Solidity source parser
    rules: Vec<VulnerabilityRule>,                 // Regex-based vulnerability detection rules
    verbose: bool,                                 // Enable detailed progress output
    advanced_analyzer: AdvancedAnalyzer,            // DeFi/NFT/exploit/OWASP/L2 pattern detection
    logic_analyzer: LogicAnalyzer,                 // Business logic vulnerability detection
    reachability_analyzer: ReachabilityAnalyzer,    // Dead code / unreachable path filtering
    dependency_analyzer: DependencyAnalyzer,        // Import/dependency CVE detection
    threat_model_generator: ThreatModelGenerator,   // Automatic threat model generation
    eip_analyzer: EIPAnalyzer,                     // ERC standard compliance checks
    false_positive_filter: FalsePositiveFilter,     // Multi-pass false positive reduction
    ast_bridge: crate::ast::bridge::ASTAnalysisBridge, // AST/CFG/taint structural analysis
    config: ScannerConfig,                         // Feature toggle configuration
}

// =============================================================================
// Context Detection Helpers
// These methods inspect the contract source for safe patterns (libraries,
// guards, modifiers, pragma versions) to suppress false positive findings.
// =============================================================================
impl ContractScanner {
    /// Check if SafeMath library is imported or used (pre-0.8 overflow protection).
    fn has_safemath(&self, content: &str) -> bool {
        content.contains("using SafeMath for") ||
        content.contains("SafeMath.") ||
        content.contains("import") && content.contains("SafeMath")
    }

    /// Check if SafeERC20 wrapper is used (handles unchecked return values).
    fn has_safe_erc20(&self, content: &str) -> bool {
        content.contains("using SafeERC20 for") ||
        content.contains("SafeERC20.") ||
        content.contains("import") && content.contains("SafeERC20")
    }

    /// Check if the given line index is a single-line comment (// or * or /*).
    fn is_in_comment(&self, lines: &[(usize, String)], line_idx: usize) -> bool {
        if line_idx >= lines.len() {
            return false;
        }
        let line = &lines[line_idx].1;
        line.trim().starts_with("//") || line.trim().starts_with("*") || line.trim().starts_with("/*")
    }

    /// Check if a line falls inside a multi-line /* ... */ comment block.
    /// Tracks block comment state by scanning from the start of the file.
    fn is_in_multiline_comment(&self, content: &str, line_idx: usize) -> bool {
        let lines: Vec<&str> = content.lines().collect();
        if line_idx >= lines.len() {
            return false;
        }

        let mut in_block = false;
        for (idx, line) in lines.iter().enumerate() {
            if line.contains("/*") && !line.contains("*/") {
                in_block = true;
            }
            if line.contains("*/") {
                in_block = false;
            }
            if idx == line_idx {
                return in_block || line.trim().starts_with("//") || line.trim().starts_with("*");
            }
        }
        false
    }

    /// Check if the contract uses a reentrancy guard (OZ ReentrancyGuard or custom lock).
    fn has_reentrancy_guard(&self, content: &str) -> bool {
        content.contains("ReentrancyGuard") ||
        content.contains("nonReentrant") ||
        content.contains("_nonReentrantBefore") ||
        content.contains("reentrancy_lock")
    }

    /// Check if this file contains only interface definitions (no contract/library bodies).
    /// Interface-only files are skipped since they have no implementation to analyze.
    fn is_interface_contract(&self, content: &str) -> bool {
        let has_interface = content.lines().any(|line| RE_INTERFACE.is_match(line));
        let has_contract = content.lines().any(|line| RE_CONTRACT.is_match(line));

        // Only skip if file has interfaces but NO contracts
        has_interface && !has_contract
    }

    /// Check if the file defines a Solidity `library` (stateless utility code).
    fn is_library(&self, content: &str) -> bool {
        content.lines().any(|line| RE_LIBRARY.is_match(line))
    }

    /// Check if this is a test or mock contract (Foundry/Hardhat test patterns).
    /// Test contracts get relaxed checks for some vulnerability categories.
    fn is_test_contract(&self, content: &str) -> bool {
        content.contains("contract Mock") ||
        content.contains("contract Test") ||
        content.contains("import \"forge-std") ||
        content.contains("import \"hardhat/console") ||
        content.contains("is Test") ||
        content.contains("is DSTest")
    }

    /// Check if OpenZeppelin libraries are imported (well-audited, trusted patterns).
    fn uses_openzeppelin(&self, content: &str) -> bool {
        content.contains("@openzeppelin") ||
        content.contains("openzeppelin-contracts") ||
        content.contains("Ownable") ||
        content.contains("AccessControl") ||
        content.contains("Pausable")
    }

    /// Check if the contract targets Solidity 0.8+ (built-in overflow/underflow protection).
    fn uses_solidity_0_8_plus(&self, content: &str) -> bool {
        RE_SOLIDITY_08.is_match(content)
    }

    /// Extract all custom modifier names defined in the contract.
    fn extract_modifiers(&self, content: &str) -> Vec<String> {
        RE_MODIFIER.captures_iter(content)
            .filter_map(|cap| cap.get(1).map(|m| m.as_str().to_string()))
            .collect()
    }

    /// Get the full function signature spanning multiple lines (from `function` keyword to `{`).
    /// Solidity function signatures can span many lines with parameters and modifiers.
    fn get_full_function_signature(&self, lines: &[(usize, String)], func_line_idx: usize) -> String {
        let mut sig = String::new();
        let max_lines = (func_line_idx + 15).min(lines.len());
        for i in func_line_idx..max_lines {
            sig.push_str(&lines[i].1);
            sig.push(' ');
            if lines[i].1.contains('{') {
                break;
            }
        }
        sig
    }

    /// Resolve well-known modifiers from inherited contracts.
    /// Maps common base contracts to the modifiers they provide.
    fn resolve_known_modifiers(&self, content: &str) -> Vec<String> {
        let mut modifiers = Vec::new();
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
    fn has_access_control_modifier(&self, function_line: &str, modifiers: &[String]) -> bool {
        // Check for common access control and protection modifiers
        let access_control_keywords = vec![
            "onlyOwner", "onlyAdmin", "onlyRole", "onlyMinter",
            "onlyGovernance", "authorized", "onlyController",
            "onlyOperator", "onlyProxy", "onlyDelegateCall",
            "private", "internal", "whenNotPaused", "whenPaused",
            "initializer", "reinitializer", "nonReentrant",
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
    fn has_access_control_check(&self, content: &str, function_start: usize, function_end: usize) -> bool {
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
        ];

        for line in lines.iter().take(function_end.min(lines.len())).skip(function_start) {
            for pattern in &check_patterns {
                if line.contains(pattern) {
                    return true;
                }
            }
        }

        false
    }

    /// Check if a function is view/pure (read-only, no state modifications possible).
    fn is_view_or_pure_function(&self, function_line: &str) -> bool {
        function_line.contains(" view ") || function_line.contains(" pure ") ||
        function_line.contains(" view)") || function_line.contains(" pure)")
    }

    /// Check if a function is internal/private (not externally callable).
    fn is_internal_or_private(&self, function_line: &str) -> bool {
        function_line.contains(" internal ") || function_line.contains(" private ") ||
        function_line.contains(" internal)") || function_line.contains(" private)")
    }
}

impl ContractScanner {
    /// Create a new scanner with default configuration (all analysis features enabled).
    pub fn new(verbose: bool) -> Self {
        Self {
            parser: SolidityParser::new(),
            rules: create_vulnerability_rules(),
            verbose,
            advanced_analyzer: AdvancedAnalyzer::new(verbose),
            logic_analyzer: LogicAnalyzer::new(verbose),
            reachability_analyzer: ReachabilityAnalyzer::new(verbose),
            dependency_analyzer: DependencyAnalyzer::new(verbose),
            threat_model_generator: ThreatModelGenerator::new(verbose),
            eip_analyzer: EIPAnalyzer::new(verbose),
            false_positive_filter: FalsePositiveFilter::new(FilterConfig::default()),
            ast_bridge: crate::ast::bridge::ASTAnalysisBridge::new(),
            config: ScannerConfig::default(),
        }
    }

    /// Create a scanner with custom configuration
    pub fn with_config(verbose: bool, config: ScannerConfig) -> Self {
        let filter_config = FilterConfig {
            strict_mode: config.enable_strict_filter,
            ..FilterConfig::default()
        };
        Self {
            parser: SolidityParser::new(),
            rules: create_vulnerability_rules(),
            verbose,
            advanced_analyzer: AdvancedAnalyzer::new(verbose),
            logic_analyzer: LogicAnalyzer::new(verbose),
            reachability_analyzer: ReachabilityAnalyzer::new(verbose),
            dependency_analyzer: DependencyAnalyzer::new(verbose),
            threat_model_generator: ThreatModelGenerator::new(verbose),
            eip_analyzer: EIPAnalyzer::new(verbose),
            false_positive_filter: FalsePositiveFilter::new(filter_config),
            ast_bridge: crate::ast::bridge::ASTAnalysisBridge::new(),
            config,
        }
    }

    /// Add custom rules from TOML config to the scanner's rule set.
    pub fn add_custom_rules(&mut self, rules: Vec<VulnerabilityRule>) {
        self.rules.extend(rules);
    }

    /// Apply rule overrides from TOML config (disable rules, change severity).
    pub fn apply_rule_overrides(&mut self, config: &crate::config::ScanConfig) {
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
    #[allow(dead_code)]
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
        // Security: enforce file size limit to prevent DoS from excessively large inputs
        let metadata = std::fs::metadata(file_path.as_ref())?;
        if metadata.len() > MAX_FILE_SIZE_BYTES {
            if self.verbose {
                eprintln!("  ⚠️  Skipping {} ({}MB exceeds {}MB limit)",
                    file_path.as_ref().display(),
                    metadata.len() / (1024 * 1024),
                    MAX_FILE_SIZE_BYTES / (1024 * 1024));
            }
            return Ok(ScanResult { vulnerabilities: Vec::new(), compiler_info: None });
        }

        let content = self.parser.read_file(&file_path)?;
        let file_name = file_path.as_ref().file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown");

        if self.verbose {
            println!("🔍 Analyzing {} ({} lines)", file_name, content.lines().count());
        }

        let result = self.scan_content(&content);

        if self.verbose {
            if let Some(ref info) = result.compiler_info {
                println!("  📋 Compiler: Solidity {} ({})", info.version_string, info.constraint);
            }
            println!("✅ Found {} potential issues in {}", result.vulnerabilities.len(), file_name);
        }

        Ok(result)
    }
    
    /// Run the full analysis pipeline on raw Solidity source code.
    /// This is the core method that coordinates all analysis phases:
    /// regex rules, advanced analyzers, logic/reachability/dependency analysis,
    /// threat modeling, EIP checks, and false positive filtering.
    pub fn scan_content(&self, content: &str) -> ScanResult {
        let mut vulnerabilities = Vec::new();
        let lines: Vec<(usize, String)> = self.parser.parse_lines(content);

        // Extract compiler info early — used for version-aware analysis and returned in ScanResult
        let compiler_info = self.parser.extract_compiler_info(content);

        // Skip interface contracts - they define signatures only, no implementation vulnerabilities
        if self.is_interface_contract(content) {
            if self.verbose {
                println!("  ℹ️  Skipping interface contract (no implementation to analyze)");
            }
            return ScanResult { vulnerabilities, compiler_info };
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
            vulnerabilities.extend(self.advanced_analyzer.analyze_control_flow(content));
        }
        vulnerabilities.extend(self.advanced_analyzer.analyze_complexity(content));

        if !is_test && !is_library {
            vulnerabilities.extend(self.advanced_analyzer.analyze_access_control(content));
        }
        vulnerabilities.extend(self.advanced_analyzer.analyze_storage_layout(content));
        vulnerabilities.extend(self.advanced_analyzer.analyze_gas_optimization(content));

        // Run DeFi-specific analysis (skip for test contracts)
        if !is_test {
            vulnerabilities.extend(self.advanced_analyzer.analyze_defi_vulnerabilities(content));
        }

        // Run NFT-specific analysis
        if !is_test {
            vulnerabilities.extend(self.advanced_analyzer.analyze_nft_vulnerabilities(content));
        }

        // Run known exploit pattern detection
        vulnerabilities.extend(self.advanced_analyzer.detect_known_exploits(content));

        // Run REKT.NEWS real-world exploit pattern detection (HIGH PRIORITY)
        // Based on $3.1B+ in actual losses from 2024-2025
        if !is_test {
            vulnerabilities.extend(self.advanced_analyzer.analyze_rekt_news_patterns(content));
        }

        // Run 2025 OWASP Smart Contract Top 10 analysis
        // Based on $1.42B in losses documented in 2024 incidents
        if !is_test {
            vulnerabilities.extend(self.advanced_analyzer.analyze_owasp_2025_patterns(content));
        }

        // Run DeFi security research paper analysis (arXiv:2205.09524v1)
        // Covers dForce ($24M), Grim Finance ($30M), Popsicle Finance ($25M), Wormhole ($326M) patterns
        if !is_test {
            vulnerabilities.extend(self.advanced_analyzer.analyze_defi_paper_vulnerabilities(content));
        }

        // Run L2/chain-specific analysis (PUSH0 compatibility, sequencer, etc.)
        if !is_test {
            vulnerabilities.extend(self.advanced_analyzer.analyze_l2_patterns(content));
        }

        // Run security hardening analysis (storage gaps, timelocks, downcasts, etc.)
        if !is_test {
            vulnerabilities.extend(self.advanced_analyzer.analyze_security_hardening(content));
        }

        // Run 2025-2026 exploit pattern analysis (v0.7.0)
        // Covers $400M+ real-world exploits: Abracadabra, Yearn, Cetus, Balancer, GMX, Atlas, etc.
        if !is_test {
            vulnerabilities.extend(self.advanced_analyzer.analyze_2025_exploit_patterns(content));
        }

        // Run DeFi-specific protocol analysis (AMM, Lending, Oracle, MEV)
        if !is_test && !is_library {
            let defi_analyzer = crate::defi::DeFiAnalyzer::new();
            let defi_findings = defi_analyzer.analyze(content);
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
            let ast_findings = self.ast_bridge.analyze(content);
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
                } else if version_vulns.iter().any(|v| v.contains("0.4.") || v.contains("0.5.")) {
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
                let version_str = pragma_str.trim().replace("pragma solidity ", "").replace(';', "");
                let title = format!("Compiler: {} Known Issue{} for {}",
                    version_vulns.len(),
                    if version_vulns.len() > 1 { "s" } else { "" },
                    if version_str.is_empty() { "detected version".to_string() } else { version_str }
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
        
        // Scan with general rules
        for rule in &self.rules {
            if rule.multiline {
                vulnerabilities.extend(self.scan_multiline_pattern(content, rule));
            } else {
                vulnerabilities.extend(self.scan_line_patterns(&lines, rule));
            }
        }
        
        // Add version-specific vulnerability checks
        if let Some(version) = compiler_version {
            let version_rules = create_version_specific_rules(&version);
            for rule in &version_rules {
                if rule.multiline {
                    vulnerabilities.extend(self.scan_multiline_pattern(content, rule));
                } else {
                    vulnerabilities.extend(self.scan_line_patterns(&lines, rule));
                }
            }
        }
        
        // ============================================================================
        // Phase 6: Advanced Analysis Engine
        // ============================================================================

        // Run logic vulnerability analysis (business logic bugs)
        if self.config.enable_logic_analysis && !is_test {
            if self.verbose {
                println!("  🧠 Running logic vulnerability analysis...");
            }
            vulnerabilities.extend(self.logic_analyzer.analyze(content));
        }

        // Run dependency/import analysis
        if self.config.enable_dependency_analysis {
            if self.verbose {
                println!("  📦 Running dependency analysis...");
            }
            vulnerabilities.extend(self.dependency_analyzer.analyze(content));
        }

        // Generate threat model vulnerabilities
        if self.config.enable_threat_model && !is_test {
            if self.verbose {
                println!("  🎯 Generating threat model...");
            }
            let threat_model = self.threat_model_generator.generate(content);
            vulnerabilities.extend(self.threat_model_generator.to_vulnerabilities_with_content(&threat_model, content));
        }

        // Apply reachability analysis to filter unreachable vulnerabilities
        if self.config.enable_reachability_analysis {
            if self.verbose {
                println!("  🔗 Running reachability analysis...");
            }
            vulnerabilities = self.reachability_analyzer.filter_unreachable_vulnerabilities(vulnerabilities, content);
            self.reachability_analyzer.adjust_confidence(&mut vulnerabilities, content);

            // Also check for external call chain vulnerabilities
            vulnerabilities.extend(self.reachability_analyzer.analyze_external_call_chains(content));
        }

        // ============================================================================
        // Phase 7: EIP Analysis & Enhanced False Positive Filtering
        // ============================================================================

        // Run EIP-specific vulnerability analysis
        if self.config.enable_eip_analysis && !is_test {
            if self.verbose {
                println!("  📋 Running EIP vulnerability analysis...");
            }
            vulnerabilities.extend(self.eip_analyzer.analyze(content));
        }

        // Apply enhanced false positive filtering
        if self.config.enable_strict_filter {
            if self.verbose {
                let original_count = vulnerabilities.len();
                vulnerabilities = self.false_positive_filter.filter(vulnerabilities, content);
                let filtered_count = vulnerabilities.len();
                println!("  🧹 {}", self.false_positive_filter.get_filter_stats(original_count, filtered_count));
            } else {
                vulnerabilities = self.false_positive_filter.filter(vulnerabilities, content);
            }
        }

        // Enrich all findings with CVSS scores, exploit references, and attack paths
        crate::cvss::enrich_with_cvss(&mut vulnerabilities);
        crate::exploit_db::enrich_with_exploits(&mut vulnerabilities);
        crate::attack_path::enrich_with_attack_paths(&mut vulnerabilities, content);

        // Sort vulnerabilities by line number
        vulnerabilities.sort_by(|a, b| a.line_number.cmp(&b.line_number));

        ScanResult { vulnerabilities, compiler_info }
    }

    /// Apply a single-line regex rule against all lines in the file.
    /// Skips commented lines and applies context-aware filtering to reduce false positives.
    fn scan_line_patterns(&self, lines: &[(usize, String)], rule: &VulnerabilityRule) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        let full_content: String = lines.iter().map(|(_, line)| line.as_str()).collect::<Vec<_>>().join("\n");

        for (idx, (line_number, line_content)) in lines.iter().enumerate() {
            // Skip if line is in a comment
            if self.is_in_comment(lines, idx) {
                continue;
            }

            if rule.pattern.is_match(line_content) {
                // Context-aware filtering to reduce false positives
                let should_report = self.should_report_vulnerability_with_title(
                    &rule.category,
                    Some(&rule.title),
                    line_content,
                    &full_content,
                    lines,
                    idx
                );

                if should_report {
                    // Extract context around the vulnerability
                    let (context_before, context_after) = Vulnerability::extract_context(&full_content, *line_number, 2);

                    let vulnerability = Vulnerability::new(
                        rule.severity.clone(),
                        rule.category.clone(),
                        rule.title.clone(),
                        rule.description.clone(),
                        *line_number,
                        line_content.trim().to_string(),
                        rule.recommendation.clone(),
                    ).with_context(context_before, context_after);

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
        _title: Option<&str>,
        line: &str,
        full_content: &str,
        lines: &[(usize, String)],
        line_idx: usize
    ) -> bool {
        use crate::vulnerabilities::VulnerabilityCategory;

        // Global filter: Skip commented lines
        if self.is_in_comment(lines, line_idx) {
            return false;
        }

        // Global filter: Skip if inside multiline comment
        if self.is_in_multiline_comment(full_content, line_idx) {
            return false;
        }

        match category {
            VulnerabilityCategory::ArithmeticIssues => {
                // FP-5: Suppress "Division by Zero" in Solidity 0.8+ (auto-reverts)
                if let Some(title) = _title {
                    if title.contains("Division by Zero") && self.uses_solidity_0_8_plus(full_content) {
                        return false;
                    }
                }
                // Don't report if SafeMath is being used
                if self.has_safemath(full_content) {
                    return false;
                }
                // Don't report in Solidity 0.8+ (has built-in overflow protection)
                if self.uses_solidity_0_8_plus(full_content) {
                    return false;
                }
                // Don't report simple counter increments
                if line.contains("++") && (line.contains("for") || line.contains("i++") || line.contains("++i")) {
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
                if self.has_safe_erc20(full_content) {
                    return false;
                }
                // Check if return value is actually being checked on the same or next line
                if line.contains("require(") || line.contains("assert(") || line.contains("if (") {
                    return false;
                }
                // Check if it's assigned to a variable
                if line.contains("= ") && (line.contains("transfer") || line.contains("transferFrom")) {
                    return false;
                }
                // Check next line for require/assert
                if line_idx + 1 < lines.len() {
                    let next_line = &lines[line_idx + 1].1;
                    if next_line.contains("require(") || next_line.contains("assert(") || next_line.contains("if (") {
                        return false;
                    }
                }
                true
            }

            VulnerabilityCategory::AccessControl | VulnerabilityCategory::RoleBasedAccessControl => {
                // FP-3: Suppress "Missing Zero Address Validation" if validation exists nearby
                if let Some(title) = _title {
                    if title.contains("Zero Address") {
                        let end = (line_idx + 16).min(lines.len());
                        let has_zero_check = lines[line_idx..end].iter().any(|(_, l)| {
                            l.contains("!= address(0)") || l.contains("== address(0)")
                                || l.contains("address(0)") && (l.contains("require") || l.contains("if") || l.contains("revert"))
                                || l.contains("_checkNonZero")
                        });
                        if has_zero_check {
                            return false;
                        }
                    }
                }
                // Check if function already has modifiers or access control
                if line.contains("function") {
                    let modifiers = self.resolve_known_modifiers(full_content);
                    // Use multi-line signature to catch modifiers on continuation lines
                    let full_sig = self.get_full_function_signature(lines, line_idx);
                    if self.has_access_control_modifier(&full_sig, &modifiers) {
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
                if self.uses_openzeppelin(full_content) && line.contains("function") {
                    let modifiers = self.resolve_known_modifiers(full_content);
                    let full_sig = self.get_full_function_signature(lines, line_idx);
                    if modifiers.iter().any(|m| m.starts_with("only") && full_sig.contains(m.as_str())) {
                        return false;
                    }
                }
                // Don't flag user-facing withdrawals that check msg.sender balance
                // (e.g., withdraw() with balances[msg.sender] is not an admin function)
                if line.contains("withdraw") || line.contains("transfer") {
                    let func_end = (line_idx + 15).min(lines.len());
                    let func_body: String = lines[line_idx..func_end].iter()
                        .map(|(_, l)| l.as_str())
                        .collect::<Vec<_>>()
                        .join("\n");
                    if func_body.contains("msg.sender") && (func_body.contains("balances[") || func_body.contains("balance[")) {
                        return false;
                    }
                }
                true
            }

            VulnerabilityCategory::Reentrancy => {
                // Don't report if ReentrancyGuard is being used
                if self.has_reentrancy_guard(full_content) {
                    return false;
                }
                // .transfer() and .send() use 2300 gas — safe from reentrancy
                if line.contains(".transfer(") || line.contains(".send(") {
                    return false;
                }
                // Use multi-line signature to check for nonReentrant or access control modifier
                // Find the enclosing function by scanning backwards
                let enclosing_func_idx = (0..=line_idx).rev()
                    .find(|&i| lines[i].1.contains("function "))
                    .unwrap_or(line_idx);
                let full_sig = self.get_full_function_signature(lines, enclosing_func_idx);
                if full_sig.contains("nonReentrant") {
                    return false;
                }
                // Don't report reentrancy inside onlyOwner functions (only owner can trigger)
                let modifiers = self.resolve_known_modifiers(full_content);
                if self.has_access_control_modifier(&full_sig, &modifiers) {
                    return false;
                }
                // Don't report for view/pure functions
                if self.is_view_or_pure_function(line) || full_sig.contains(" view ") || full_sig.contains(" pure ") {
                    return false;
                }
                true
            }

            VulnerabilityCategory::GasOptimization |
            VulnerabilityCategory::ImmutabilityIssues => {
                // These are informational - check if intentional
                // Don't report if variable is clearly being modified elsewhere
                if line.contains("address") && full_content.contains(&format!("{} =", line.split_whitespace().last().unwrap_or(""))) {
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
                if line.contains("* 0") || line.contains("/ 1") || line.contains("* 1 ") ||
                   line.contains("* 2 ") || line.contains("/ 2 ") {
                    return false;
                }
                // Don't report if it's in a constant definition
                if line.contains("constant") {
                    return false;
                }
                // Don't report common precision constants
                if line.contains("1e18") || line.contains("1e6") || line.contains("10**18") ||
                   line.contains("100") || line.contains("1000") || line.contains("10000") {
                    return false;
                }
                true
            }

            VulnerabilityCategory::DelegateCalls => {
                // Only report if the target is user-controlled
                // Don't report if it's part of a proxy pattern with fixed implementation
                if full_content.contains("_IMPLEMENTATION_SLOT") || full_content.contains("ERC1967") {
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
                true
            }

            VulnerabilityCategory::AssemblyUsage => {
                // FP-2: Suppress assembly in libraries
                if self.is_library(full_content) {
                    return false;
                }
                // FP-2: Suppress known-safe proxy/ERC-1967 assembly patterns
                let safe_assembly_ops = [
                    "_IMPLEMENTATION_SLOT", "_ADMIN_SLOT", "slot :=",
                    "returndatasize", "returndatacopy", "chainid",
                ];
                // Check the next 10 lines for safe assembly body
                let end = (line_idx + 10).min(lines.len());
                let assembly_body: String = lines[line_idx..end].iter()
                    .map(|(_, l)| l.as_str())
                    .collect::<Vec<_>>()
                    .join("\n");
                if safe_assembly_ops.iter().any(|op| assembly_body.contains(op)) {
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

            VulnerabilityCategory::CallbackReentrancy | VulnerabilityCategory::ERC777CallbackReentrancy
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

            VulnerabilityCategory::ProxyAdminVulnerability | VulnerabilityCategory::UnprotectedProxyUpgrade => {
                // Don't report if using OpenZeppelin UUPS/Transparent proxy properly
                if full_content.contains("_authorizeUpgrade") && full_content.contains("onlyOwner") {
                    return false;
                }
                if full_content.contains("UUPSUpgradeable") || full_content.contains("TransparentUpgradeableProxy") {
                    return false;
                }
                // Don't report if function has access control
                if line.contains("function") {
                    let modifiers = self.extract_modifiers(full_content);
                    if self.has_access_control_modifier(line, &modifiers) {
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

            VulnerabilityCategory::SignatureReplay | VulnerabilityCategory::SignatureVulnerabilities => {
                // Don't report if using OpenZeppelin ECDSA
                if full_content.contains("ECDSA.recover") || full_content.contains("SignatureChecker") {
                    return false;
                }
                true
            }

            VulnerabilityCategory::LowLevelCalls => {
                // Don't suppress return bomb findings (they specifically flag captured data)
                if let Some(title) = _title {
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
                // Don't report if function is internal/private
                if self.is_internal_or_private(line) {
                    return false;
                }
                // Don't report if function is view/pure
                if self.is_view_or_pure_function(line) {
                    return false;
                }
                // FP-4: Suppress "Array Parameter" if length validation exists nearby
                if let Some(title) = _title {
                    if title.contains("Array Parameter") {
                        let end = (line_idx + 16).min(lines.len());
                        let has_length_check = lines[line_idx..end].iter().any(|(_, l)| {
                            l.contains(".length") && (l.contains("require") || l.contains("if ")
                                || l.contains(">") || l.contains("<") || l.contains("<="))
                        });
                        if has_length_check {
                            return false;
                        }
                    }
                }
                true
            }

            VulnerabilityCategory::MetaTransactionVulnerability | VulnerabilityCategory::TrustedForwarderBypass => {
                // Don't report if using OpenZeppelin's Context/ERC2771Context properly
                if self.uses_openzeppelin(full_content) && full_content.contains("ERC2771Context") {
                    return false;
                }
                true
            }

            VulnerabilityCategory::MissingStorageGap => {
                // Only report if contract doesn't already have __gap
                if full_content.contains("__gap") || full_content.contains("uint256[") && full_content.contains("private") {
                    return false;
                }
                // Don't report for non-upgradeable contracts
                if !full_content.contains("Upgradeable") && !full_content.contains("Initializable") {
                    return false;
                }
                true
            }

            VulnerabilityCategory::UninitializedImplementation | VulnerabilityCategory::DoubleInitialization => {
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
                true
            }

            VulnerabilityCategory::MissingSwapDeadline => {
                // Don't report if function body contains deadline check
                let end = (line_idx + 20).min(lines.len());
                let has_deadline = lines[line_idx..end].iter().any(|(_, l)| {
                    l.contains("deadline") || l.contains("Deadline") || l.contains("block.timestamp")
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
                let has_emit = lines[line_idx..end].iter().any(|(_, l)| {
                    l.trim().starts_with("emit ") || l.contains("emit ")
                });
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
                full_content.contains("tstore") || full_content.contains("tload")
                    || full_content.contains("TSTORE") || full_content.contains("TLOAD")
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

            _ => true // Report all other categories by default
        }
    }

    /// Apply a multiline regex rule against the entire file content.
    /// Used for patterns that span multiple lines (e.g., state changes after external calls).
    fn scan_multiline_pattern(&self, content: &str, rule: &VulnerabilityRule) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

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

            // Extract context
            let (context_before, context_after) = Vulnerability::extract_context(content, line_number, 2);

            let mut vulnerability = Vulnerability::new(
                rule.severity.clone(),
                rule.category.clone(),
                rule.title.clone(),
                rule.description.clone(),
                line_number,
                code_snippet,
                rule.recommendation.clone(),
            ).with_context(context_before, context_after);

            // Set end line if it spans multiple lines
            if end_line_number > line_number {
                vulnerability = vulnerability.with_end_line(end_line_number);
            }

            vulnerabilities.push(vulnerability);
        }

        vulnerabilities
    }
    
}

#[cfg(test)]
mod tests {
    use super::*;
    #[allow(unused_imports)]
    use crate::vulnerabilities::VulnerabilitySeverity;
    
    #[test]
    fn test_scan_reentrancy() {
        let scanner = ContractScanner::new(false);
        let content = r#"
function withdraw() public {
    (bool success,) = msg.sender.call{value: balance}("");
    require(success, "Transfer failed");
    balance = 0;
}
"#;
        let result = scanner.scan_content(content);
        let reentrancy_vulns: Vec<_> = result.vulnerabilities
            .iter()
            .filter(|v| matches!(v.category, crate::vulnerabilities::VulnerabilityCategory::Reentrancy))
            .collect();
        assert!(!reentrancy_vulns.is_empty());
    }

    #[test]
    fn test_scan_floating_pragma() {
        // Use a scanner with strict filter disabled to test raw rule detection
        let config = ScannerConfig {
            enable_strict_filter: false,
            ..ScannerConfig::default()
        };
        let scanner = ContractScanner::with_config(false, config);
        let content = "pragma solidity ^0.8.0;";
        let result = scanner.scan_content(content);
        let pragma_vulns: Vec<_> = result.vulnerabilities
            .iter()
            .filter(|v| matches!(v.category, crate::vulnerabilities::VulnerabilityCategory::PragmaIssues))
            .collect();
        assert!(!pragma_vulns.is_empty());
    }

    #[test]
    fn test_scan_result_includes_compiler_info() {
        let scanner = ContractScanner::new(false);
        let content = "pragma solidity ^0.8.19;\ncontract Test {}";
        let result = scanner.scan_content(content);
        assert!(result.compiler_info.is_some());
        let info = result.compiler_info.unwrap();
        assert_eq!(info.version_string, "0.8.19");
        assert!(info.is_floating);
        assert!(info.evm_features.overflow_protection);
        assert!(info.evm_features.custom_errors);
        assert!(!info.evm_features.push0_opcode); // 0.8.19 < 0.8.20
    }

    #[test]
    fn test_scan_result_no_pragma() {
        let scanner = ContractScanner::new(false);
        let content = "contract Test { function foo() public {} }";
        let result = scanner.scan_content(content);
        assert!(result.compiler_info.is_none());
    }
}