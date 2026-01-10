use std::path::Path;
use std::io;
use crate::parser::SolidityParser;
use crate::vulnerabilities::{Vulnerability, VulnerabilityRule, create_vulnerability_rules, create_version_specific_rules};
use crate::advanced_analysis::AdvancedAnalyzer;

pub struct ContractScanner {
    parser: SolidityParser,
    rules: Vec<VulnerabilityRule>,
    verbose: bool,
    advanced_analyzer: AdvancedAnalyzer,
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

    // Check if ReentrancyGuard is being used
    fn has_reentrancy_guard(&self, content: &str) -> bool {
        content.contains("ReentrancyGuard") ||
        content.contains("nonReentrant")
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
            "private", "internal"
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
            "require(owner ==",
            "require(hasRole",
            "if (msg.sender !=",
            "if(msg.sender!=",
            "revert Unauthorized",
        ];

        for idx in function_start..function_end.min(lines.len()) {
            for pattern in &check_patterns {
                if lines[idx].contains(pattern) {
                    return true;
                }
            }
        }

        false
    }
}

impl ContractScanner {
    pub fn new(verbose: bool) -> Self {
        Self {
            parser: SolidityParser::new(),
            rules: create_vulnerability_rules(),
            verbose,
            advanced_analyzer: AdvancedAnalyzer::new(verbose),
        }
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

        // Run advanced analysis
        vulnerabilities.extend(self.advanced_analyzer.analyze_control_flow(content));
        vulnerabilities.extend(self.advanced_analyzer.analyze_complexity(content));
        vulnerabilities.extend(self.advanced_analyzer.analyze_access_control(content));
        vulnerabilities.extend(self.advanced_analyzer.analyze_storage_layout(content));
        vulnerabilities.extend(self.advanced_analyzer.analyze_gas_optimization(content));

        // Run DeFi-specific analysis
        vulnerabilities.extend(self.advanced_analyzer.analyze_defi_vulnerabilities(content));

        // Run NFT-specific analysis
        vulnerabilities.extend(self.advanced_analyzer.analyze_nft_vulnerabilities(content));

        // Run known exploit pattern detection
        vulnerabilities.extend(self.advanced_analyzer.detect_known_exploits(content));

        // Run REKT.NEWS real-world exploit pattern detection (HIGH PRIORITY)
        // Based on $3.1B+ in actual losses from 2024-2025
        vulnerabilities.extend(self.advanced_analyzer.analyze_rekt_news_patterns(content));
        
        // Detect compiler version for version-specific checks
        let compiler_version = self.parser.get_compiler_version(content);
        
        // Check for detailed version vulnerabilities
        if let Some(detailed_version) = self.parser.get_detailed_version(content) {
            let version_vulns = self.parser.is_version_vulnerable(&detailed_version);
            for (_idx, vuln_desc) in version_vulns.iter().enumerate() {
                vulnerabilities.push(Vulnerability {
                    severity: if vuln_desc.contains("CRITICAL") {
                        crate::vulnerabilities::VulnerabilitySeverity::Critical
                    } else if vuln_desc.contains("0.4.") || vuln_desc.contains("0.5.") {
                        crate::vulnerabilities::VulnerabilitySeverity::High
                    } else {
                        crate::vulnerabilities::VulnerabilitySeverity::Medium
                    },
                    category: crate::vulnerabilities::VulnerabilityCategory::CompilerBug,
                    title: format!("Compiler Version Vulnerability"),
                    description: vuln_desc.clone(),
                    line_number: 1, // Pragma is usually on line 1 or 2
                    code_snippet: self.parser.get_pragma_version(content).unwrap_or_default(),
                    recommendation: "Upgrade to Solidity 0.8.28 or later for the latest security fixes".to_string(),
                });
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
                    vulnerabilities.extend(self.scan_multiline_pattern(content, &rule));
                } else {
                    vulnerabilities.extend(self.scan_line_patterns(&lines, &rule));
                }
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
                    let vulnerability = Vulnerability {
                        severity: rule.severity.clone(),
                        category: rule.category.clone(),
                        title: rule.title.clone(),
                        description: rule.description.clone(),
                        line_number: *line_number,
                        code_snippet: line_content.trim().to_string(),
                        recommendation: rule.recommendation.clone(),
                    };

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

        match category {
            VulnerabilityCategory::ArithmeticIssues => {
                // Don't report if SafeMath is being used
                if self.has_safemath(full_content) {
                    return false;
                }
                // Don't report simple counter increments
                if line.contains("++") && (line.contains("for") || line.contains("i++") || line.contains("++i")) {
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
                if line.contains("require(") || line.contains("assert(") {
                    return false;
                }
                // Check next line for require/assert
                if line_idx + 1 < lines.len() {
                    let next_line = &lines[line_idx + 1].1;
                    if next_line.contains("require(") || next_line.contains("assert(") {
                        return false;
                    }
                }
                true
            }

            VulnerabilityCategory::AccessControl => {
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
                // Don't report view/pure functions as critical
                if line.contains("view") || line.contains("pure") {
                    return false;
                }
                true
            }

            VulnerabilityCategory::Reentrancy => {
                // Don't report if ReentrancyGuard is being used
                if self.has_reentrancy_guard(full_content) {
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
            let lines_before = content[..match_start].matches('\n').count();
            let line_number = lines_before + 1;
            
            // Get the matched text and clean it up
            let matched_text = mat.as_str();
            let code_snippet = matched_text
                .lines()
                .next()
                .unwrap_or(matched_text)
                .trim()
                .to_string();
            
            let vulnerability = Vulnerability {
                severity: rule.severity.clone(),
                category: rule.category.clone(),
                title: rule.title.clone(),
                description: rule.description.clone(),
                line_number,
                code_snippet,
                recommendation: rule.recommendation.clone(),
            };
            
            vulnerabilities.push(vulnerability);
        }
        
        vulnerabilities
    }
    
}

#[cfg(test)]
mod tests {
    use super::*;
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