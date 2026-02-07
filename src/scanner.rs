use std::path::Path;
use std::io;
use crate::parser::SolidityParser;
use crate::vulnerabilities::{Vulnerability, VulnerabilityRule, create_vulnerability_rules, create_version_specific_rules};
use crate::advanced_analysis::AdvancedAnalyzer;
use crate::logic_analyzer::LogicAnalyzer;
use crate::reachability_analyzer::ReachabilityAnalyzer;
use crate::dependency_analyzer::DependencyAnalyzer;
use crate::threat_model::ThreatModelGenerator;
use crate::eip_analyzer::EIPAnalyzer;
use crate::false_positive_filter::{FalsePositiveFilter, FilterConfig};

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

pub struct ContractScanner {
    parser: SolidityParser,
    rules: Vec<VulnerabilityRule>,
    verbose: bool,
    advanced_analyzer: AdvancedAnalyzer,
    logic_analyzer: LogicAnalyzer,
    reachability_analyzer: ReachabilityAnalyzer,
    dependency_analyzer: DependencyAnalyzer,
    threat_model_generator: ThreatModelGenerator,
    eip_analyzer: EIPAnalyzer,
    false_positive_filter: FalsePositiveFilter,
    config: ScannerConfig,
}

// Context detection helpers to reduce false positives
impl ContractScanner {
    // Check if SafeMath library is being used
    fn has_safemath(&self, content: &str) -> bool {
        content.contains("using SafeMath for") ||
        content.contains("SafeMath.") ||
        content.contains("import") && content.contains("SafeMath")
    }

    // Check if SafeERC20 is being used
    fn has_safe_erc20(&self, content: &str) -> bool {
        content.contains("using SafeERC20 for") ||
        content.contains("SafeERC20.") ||
        content.contains("import") && content.contains("SafeERC20")
    }

    // Check if a line is inside a comment
    fn is_in_comment(&self, lines: &[(usize, String)], line_idx: usize) -> bool {
        if line_idx >= lines.len() {
            return false;
        }
        let line = &lines[line_idx].1;
        line.trim().starts_with("//") || line.trim().starts_with("*") || line.trim().starts_with("/*")
    }

    // Check if inside a multi-line comment block
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

    // Check if ReentrancyGuard is being used
    fn has_reentrancy_guard(&self, content: &str) -> bool {
        content.contains("ReentrancyGuard") ||
        content.contains("nonReentrant") ||
        content.contains("_nonReentrantBefore") ||
        content.contains("reentrancy_lock")
    }

    // Check if this is a pure interface contract (should skip most vulnerability checks)
    // Only returns true if the file contains ONLY interface definitions, no contracts
    fn is_interface_contract(&self, content: &str) -> bool {
        let interface_pattern = regex::Regex::new(r"^\s*interface\s+\w+").unwrap();
        let contract_pattern = regex::Regex::new(r"^\s*(contract|abstract\s+contract|library)\s+\w+").unwrap();

        let has_interface = content.lines().any(|line| interface_pattern.is_match(line));
        let has_contract = content.lines().any(|line| contract_pattern.is_match(line));

        // Only skip if file has interfaces but NO contracts
        has_interface && !has_contract
    }

    // Check if this is a library
    fn is_library(&self, content: &str) -> bool {
        let library_pattern = regex::Regex::new(r"^\s*library\s+\w+").unwrap();
        for line in content.lines() {
            if library_pattern.is_match(line) {
                return true;
            }
        }
        false
    }

    // Check if this is likely a test/mock contract
    fn is_test_contract(&self, content: &str) -> bool {
        content.contains("contract Mock") ||
        content.contains("contract Test") ||
        content.contains("import \"forge-std") ||
        content.contains("import \"hardhat/console") ||
        content.contains("is Test") ||
        content.contains("is DSTest")
    }

    // Check if OpenZeppelin libraries are being used (generally well-audited)
    fn uses_openzeppelin(&self, content: &str) -> bool {
        content.contains("@openzeppelin") ||
        content.contains("openzeppelin-contracts") ||
        content.contains("Ownable") ||
        content.contains("AccessControl") ||
        content.contains("Pausable")
    }

    // Check if contract uses Solidity 0.8+ (has built-in overflow protection)
    fn uses_solidity_0_8_plus(&self, content: &str) -> bool {
        let version_pattern = regex::Regex::new(r"pragma\s+solidity\s*[\^>=<]*\s*0\.([89]|[1-9]\d+)\.").unwrap();
        version_pattern.is_match(content)
    }

    // Extract all modifiers defined in the contract
    fn extract_modifiers(&self, content: &str) -> Vec<String> {
        let modifier_regex = regex::Regex::new(r"modifier\s+(\w+)").unwrap();
        modifier_regex.captures_iter(content)
            .filter_map(|cap| cap.get(1).map(|m| m.as_str().to_string()))
            .collect()
    }

    // Check if a function has access control modifiers
    fn has_access_control_modifier(&self, function_line: &str, modifiers: &[String]) -> bool {
        // Check for common access control patterns
        let access_control_keywords = vec![
            "onlyOwner", "onlyAdmin", "onlyRole", "onlyMinter",
            "onlyGovernance", "authorized", "onlyController",
            "onlyOperator", "onlyProxy", "onlyDelegateCall",
            "private", "internal", "whenNotPaused", "whenPaused",
            "initializer", "reinitializer"
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

    // Check if there's a require statement checking msg.sender or access control
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

    // Check if a function is a view/pure function (read-only, safer)
    fn is_view_or_pure_function(&self, function_line: &str) -> bool {
        function_line.contains(" view ") || function_line.contains(" pure ") ||
        function_line.contains(" view)") || function_line.contains(" pure)")
    }

    // Check if a function is an internal or private function
    fn is_internal_or_private(&self, function_line: &str) -> bool {
        function_line.contains(" internal ") || function_line.contains(" private ") ||
        function_line.contains(" internal)") || function_line.contains(" private)")
    }
}

impl ContractScanner {
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
            config,
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
    
    pub fn scan_file<P: AsRef<Path>>(&self, file_path: P) -> io::Result<Vec<Vulnerability>> {
        let content = self.parser.read_file(&file_path)?;
        let file_name = file_path.as_ref().file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown");
        
        if self.verbose {
            println!("🔍 Analyzing {} ({} lines)", file_name, content.lines().count());
        }
        
        let vulnerabilities = self.scan_content(&content);
        
        if self.verbose {
            println!("✅ Found {} potential issues in {}", vulnerabilities.len(), file_name);
        }
        
        Ok(vulnerabilities)
    }
    
    pub fn scan_content(&self, content: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();
        let lines: Vec<(usize, String)> = self.parser.parse_lines(content);

        // Skip interface contracts - they define signatures only, no implementation vulnerabilities
        if self.is_interface_contract(content) {
            if self.verbose {
                println!("  ℹ️  Skipping interface contract (no implementation to analyze)");
            }
            return vulnerabilities;
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

        // Detect compiler version for version-specific checks
        let compiler_version = self.parser.get_compiler_version(content);
        
        // Check for detailed version vulnerabilities
        if let Some(detailed_version) = self.parser.get_detailed_version(content) {
            let version_vulns = self.parser.is_version_vulnerable(&detailed_version);
            for vuln_desc in version_vulns.iter() {
                let severity = if vuln_desc.contains("CRITICAL") {
                    crate::vulnerabilities::VulnerabilitySeverity::Critical
                } else if vuln_desc.contains("0.4.") || vuln_desc.contains("0.5.") {
                    crate::vulnerabilities::VulnerabilitySeverity::High
                } else {
                    crate::vulnerabilities::VulnerabilitySeverity::Medium
                };
                vulnerabilities.push(Vulnerability::high_confidence(
                    severity,
                    crate::vulnerabilities::VulnerabilityCategory::CompilerBug,
                    "Compiler Version Vulnerability".to_string(),
                    vuln_desc.clone(),
                    1, // Pragma is usually on line 1 or 2
                    self.parser.get_pragma_version(content).unwrap_or_default(),
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
            vulnerabilities.extend(self.threat_model_generator.to_vulnerabilities(&threat_model));
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

        // Sort vulnerabilities by line number
        vulnerabilities.sort_by(|a, b| a.line_number.cmp(&b.line_number));

        vulnerabilities
    }

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
                let should_report = self.should_report_vulnerability(
                    &rule.category,
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

    // Context-aware decision on whether to report a vulnerability
    fn should_report_vulnerability(
        &self,
        category: &crate::vulnerabilities::VulnerabilityCategory,
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
                // Check if function already has modifiers or access control
                if line.contains("function") {
                    let modifiers = self.extract_modifiers(full_content);
                    if self.has_access_control_modifier(line, &modifiers) {
                        return false;
                    }
                    // Check if there's an inline access control check within the function
                    // Look for the function body
                    let mut func_end = line_idx + 20; // Check next 20 lines
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
                // Don't report if using OpenZeppelin access control
                if self.uses_openzeppelin(full_content) && full_content.contains("Ownable") {
                    if line.contains("function") {
                        let modifiers = self.extract_modifiers(full_content);
                        if modifiers.iter().any(|m| m.starts_with("only")) {
                            return false;
                        }
                    }
                }
                true
            }

            VulnerabilityCategory::Reentrancy => {
                // Don't report if ReentrancyGuard is being used
                if self.has_reentrancy_guard(full_content) {
                    return false;
                }
                // Don't report for view/pure functions
                if self.is_view_or_pure_function(line) {
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
                // Don't report if it's using standard inline assembly patterns
                if line.contains("assembly") && (line.contains("memory") || line.contains("size") || line.contains("codecopy")) {
                    // This is often necessary for certain operations
                    return true; // Still report but these are often intentional
                }
                true
            }

            _ => true // Report all other categories by default
        }
    }
    
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
        let vulnerabilities = scanner.scan_content(content);
        let reentrancy_vulns: Vec<_> = vulnerabilities
            .iter()
            .filter(|v| matches!(v.category, crate::vulnerabilities::VulnerabilityCategory::Reentrancy))
            .collect();
        assert!(!reentrancy_vulns.is_empty());
    }
    
    #[test]
    fn test_scan_floating_pragma() {
        let scanner = ContractScanner::new(false);
        let content = "pragma solidity ^0.8.0;";
        let vulnerabilities = scanner.scan_content(content);
        let pragma_vulns: Vec<_> = vulnerabilities
            .iter()
            .filter(|v| matches!(v.category, crate::vulnerabilities::VulnerabilityCategory::PragmaIssues))
            .collect();
        assert!(!pragma_vulns.is_empty());
    }
}