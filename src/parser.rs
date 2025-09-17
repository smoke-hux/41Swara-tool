use std::fs;
use std::io::Result;
use std::path::Path;

#[derive(Debug, Clone, PartialEq)]
pub enum CompilerVersion {
    V04, // 0.4.x - Very old, many issues
    V05, // 0.5.x - Breaking changes from 0.4
    V06, // 0.6.x - Try-catch, array slices
    V07, // 0.7.x - Last version before overflow protection
    V08, // 0.8.x - Built-in overflow protection
}

#[derive(Debug, Clone, PartialEq)]
pub struct DetailedVersion {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
}

pub struct SolidityParser;

impl SolidityParser {
    pub fn new() -> Self {
        Self
    }
    
    pub fn read_file<P: AsRef<Path>>(&self, path: P) -> Result<String> {
        fs::read_to_string(path)
    }
    
    pub fn parse_lines(&self, content: &str) -> Vec<(usize, String)> {
        content
            .lines()
            .enumerate()
            .map(|(idx, line)| (idx + 1, line.to_string()))
            .collect()
    }
    
    #[allow(dead_code)]
    pub fn extract_functions(&self, content: &str) -> Vec<(usize, String)> {
        let mut functions = Vec::new();
        let lines = self.parse_lines(content);
        
        for (line_num, line) in lines {
            let trimmed = line.trim();
            if trimmed.starts_with("function ") {
                functions.push((line_num, line));
            }
        }
        
        functions
    }
    
    #[allow(dead_code)]
    pub fn extract_modifiers(&self, content: &str) -> Vec<(usize, String)> {
        let mut modifiers = Vec::new();
        let lines = self.parse_lines(content);
        
        for (line_num, line) in lines {
            let trimmed = line.trim();
            if trimmed.starts_with("modifier ") {
                modifiers.push((line_num, line));
            }
        }
        
        modifiers
    }
    
    #[allow(dead_code)]
    pub fn extract_state_variables(&self, content: &str) -> Vec<(usize, String)> {
        let mut variables = Vec::new();
        let lines = self.parse_lines(content);
        
        for (line_num, line) in lines {
            let trimmed = line.trim();
            // Basic detection of state variables
            if (trimmed.contains("uint") || trimmed.contains("int") || 
                trimmed.contains("bool") || trimmed.contains("address") ||
                trimmed.contains("string") || trimmed.contains("bytes")) &&
               !trimmed.starts_with("//") && !trimmed.starts_with("function") &&
               !trimmed.starts_with("event") && !trimmed.starts_with("modifier") {
                variables.push((line_num, line));
            }
        }
        
        variables
    }
    
    #[allow(dead_code)]
    pub fn get_contract_name(&self, content: &str) -> Option<String> {
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("contract ") {
                if let Some(name) = trimmed
                    .strip_prefix("contract ")
                    .and_then(|s| s.split_whitespace().next()) {
                    return Some(name.to_string());
                }
            }
        }
        None
    }
    
    pub fn get_pragma_version(&self, content: &str) -> Option<String> {
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("pragma solidity") {
                return Some(trimmed.to_string());
            }
        }
        None
    }
    
    pub fn get_compiler_version(&self, content: &str) -> Option<CompilerVersion> {
        if let Some(pragma) = self.get_pragma_version(content) {
            if pragma.contains("0.4.") {
                return Some(CompilerVersion::V04);
            } else if pragma.contains("0.5.") {
                return Some(CompilerVersion::V05);
            } else if pragma.contains("0.6.") {
                return Some(CompilerVersion::V06);
            } else if pragma.contains("0.7.") {
                return Some(CompilerVersion::V07);
            } else if pragma.contains("0.8.") {
                return Some(CompilerVersion::V08);
            }
        }
        None
    }
    
    pub fn get_detailed_version(&self, content: &str) -> Option<DetailedVersion> {
        if let Some(pragma) = self.get_pragma_version(content) {
            // Extract version number from pragma
            // Handles formats like: "^0.8.19", ">=0.8.0", "0.8.20", etc.
            let version_regex = regex::Regex::new(r"(\d+)\.(\d+)\.(\d+)").ok()?;
            
            if let Some(captures) = version_regex.captures(&pragma) {
                let major = captures.get(1)?.as_str().parse().ok()?;
                let minor = captures.get(2)?.as_str().parse().ok()?;
                let patch = captures.get(3)?.as_str().parse().ok()?;
                
                return Some(DetailedVersion { major, minor, patch });
            }
        }
        None
    }
    
    pub fn is_version_vulnerable(&self, version: &DetailedVersion) -> Vec<String> {
        let mut vulnerabilities = Vec::new();
        
        // Check for known vulnerabilities in specific versions
        match (version.major, version.minor, version.patch) {
            // Solidity 0.8.x specific vulnerabilities
            (0, 8, 0..=12) => {
                vulnerabilities.push("Version < 0.8.13: Vulnerable to optimizer bug with inline assembly".to_string());
            }
            (0, 8, 0..=14) => {
                vulnerabilities.push("Version < 0.8.15: ABI coder v2 issues with tuples".to_string());
            }
            (0, 8, 0..=16) => {
                vulnerabilities.push("Version < 0.8.17: Vulnerable to storage write reentrancy in libraries".to_string());
            }
            (0, 8, 0..=18) => {
                vulnerabilities.push("Version < 0.8.19: Optimizer bug affecting constant expressions".to_string());
            }
            (0, 8, 0..=19) => {
                vulnerabilities.push("Version < 0.8.20: Missing check in bytes.concat() with dynamic arrays".to_string());
            }
            (0, 8, 0..=20) => {
                vulnerabilities.push("Version < 0.8.21: Potential issues with using for directive and libraries".to_string());
            }
            (0, 8, 0..=21) => {
                vulnerabilities.push("Version < 0.8.22: Head overflow bug in calldata tuple decoder".to_string());
            }
            (0, 8, 22) => {
                vulnerabilities.push("Version 0.8.22: Contains unchecked loop increment overflow bug".to_string());
            }
            (0, 8, 0..=23) => {
                vulnerabilities.push("Version < 0.8.24: Missing check for extra data in CREATE2 deployments".to_string());
            }
            (0, 8, 0..=24) => {
                vulnerabilities.push("Version < 0.8.25: Optimizer bug with multiple memory copies".to_string());
            }
            (0, 8, 0..=25) => {
                vulnerabilities.push("Version < 0.8.26: Potential issues with transient storage (TSTORE/TLOAD)".to_string());
            }
            (0, 8, 27) => {
                vulnerabilities.push("Version 0.8.27: Known issue with constructor visibility (deprecated but still compilable)".to_string());
            }
            (0, 8, 0..=27) => {
                vulnerabilities.push("Version < 0.8.28: Vulnerable to specific edge cases in unchecked blocks".to_string());
            }
            (0, 8, 29) => {
                vulnerabilities.push("Version 0.8.29: Memory expansion cost miscalculation in specific scenarios".to_string());
            }
            (0, 8, 30) => {
                vulnerabilities.push("Version 0.8.30: Latest - Check Solidity blog for any recent security advisories".to_string());
            }
            
            // Solidity 0.7.x vulnerabilities
            (0, 7, _) => {
                vulnerabilities.push("Version 0.7.x: No automatic overflow/underflow protection - use SafeMath".to_string());
                if version.patch < 6 {
                    vulnerabilities.push("Version < 0.7.6: Vulnerable to shift operation bugs".to_string());
                }
            }
            
            // Solidity 0.6.x vulnerabilities
            (0, 6, _) => {
                vulnerabilities.push("Version 0.6.x: No automatic overflow/underflow protection".to_string());
                if version.patch < 12 {
                    vulnerabilities.push("Version < 0.6.12: Array slice bug can cause data corruption".to_string());
                }
            }
            
            // Solidity 0.5.x vulnerabilities
            (0, 5, _) => {
                vulnerabilities.push("Version 0.5.x: Outdated - many security improvements missing".to_string());
                if version.patch < 17 {
                    vulnerabilities.push("Version < 0.5.17: ABIEncoderV2 bugs present".to_string());
                }
            }
            
            // Solidity 0.4.x vulnerabilities
            (0, 4, _) => {
                vulnerabilities.push("Version 0.4.x: CRITICALLY OUTDATED - Multiple severe vulnerabilities".to_string());
                vulnerabilities.push("No constructor keyword - using contract name is deprecated".to_string());
                vulnerabilities.push("No automatic overflow protection".to_string());
                vulnerabilities.push("Delegatecall return value not properly checked".to_string());
            }
            
            _ => {}
        }
        
        vulnerabilities
    }
    
    #[allow(dead_code)]
    pub fn remove_comments(&self, content: &str) -> String {
        let mut result = String::new();
        let mut in_multiline_comment = false;
        
        for line in content.lines() {
            let mut cleaned_line = String::new();
            let mut chars = line.chars().peekable();
            
            while let Some(ch) = chars.next() {
                if in_multiline_comment {
                    if ch == '*' && chars.peek() == Some(&'/') {
                        chars.next(); // consume '/'
                        in_multiline_comment = false;
                    }
                } else {
                    if ch == '/' {
                        match chars.peek() {
                            Some('/') => break, // Single line comment, ignore rest of line
                            Some('*') => {
                                chars.next(); // consume '*'
                                in_multiline_comment = true;
                            }
                            _ => cleaned_line.push(ch),
                        }
                    } else {
                        cleaned_line.push(ch);
                    }
                }
            }
            
            if !in_multiline_comment {
                result.push_str(&cleaned_line);
                result.push('\n');
            }
        }
        
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_extract_functions() {
        let parser = SolidityParser::new();
        let content = r#"
contract Test {
    function test1() public {
        
    }
    
    function test2() private {
        
    }
}
"#;
        let functions = parser.extract_functions(content);
        assert_eq!(functions.len(), 2);
    }
    
    #[test]
    fn test_get_contract_name() {
        let parser = SolidityParser::new();
        let content = "contract MyContract is ERC20 {";
        let name = parser.get_contract_name(content);
        assert_eq!(name, Some("MyContract".to_string()));
    }
    
    #[test]
    fn test_remove_comments() {
        let parser = SolidityParser::new();
        let content = r#"
// This is a comment
contract Test { /* multiline comment */ }
uint256 public value; // inline comment
"#;
        let cleaned = parser.remove_comments(content);
        assert!(!cleaned.contains("This is a comment"));
        assert!(!cleaned.contains("multiline comment"));
        assert!(!cleaned.contains("inline comment"));
    }
}