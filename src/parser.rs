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