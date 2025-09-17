use std::path::Path;
use std::io;
use crate::parser::SolidityParser;
use crate::vulnerabilities::{Vulnerability, VulnerabilityRule, create_vulnerability_rules, create_version_specific_rules};

pub struct ContractScanner {
    parser: SolidityParser,
    rules: Vec<VulnerabilityRule>,
    verbose: bool,
}

impl ContractScanner {
    pub fn new(verbose: bool) -> Self {
        Self {
            parser: SolidityParser::new(),
            rules: create_vulnerability_rules(),
            verbose,
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
        
        for (line_number, line_content) in lines {
            if rule.pattern.is_match(line_content) {
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
        
        vulnerabilities
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