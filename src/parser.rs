use serde::{Deserialize, Serialize};
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

impl std::fmt::Display for DetailedVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

/// How the pragma constrains the compiler version.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum PragmaConstraint {
    /// `^0.8.19` — allows patches but not minor bumps
    Caret,
    /// `>=0.8.0` — allows any version at or above
    GreaterEqual,
    /// `>=0.8.0 <0.9.0` — bounded range
    Range,
    /// `0.8.19` — exact pinned version (no operator)
    Exact,
    /// `>0.8.0` — strictly greater
    Greater,
    /// Other or unparseable constraint
    Other,
}

impl std::fmt::Display for PragmaConstraint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PragmaConstraint::Caret => write!(f, "Floating (^)"),
            PragmaConstraint::GreaterEqual => write!(f, "Floating (>=)"),
            PragmaConstraint::Range => write!(f, "Range"),
            PragmaConstraint::Greater => write!(f, "Floating (>)"),
            PragmaConstraint::Exact => write!(f, "Pinned"),
            PragmaConstraint::Other => write!(f, "Unknown"),
        }
    }
}

/// How outdated the compiler version is.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum VersionAge {
    /// Latest stable (0.8.28+)
    Current,
    /// Recent but not latest (0.8.20-0.8.27)
    Recent,
    /// Getting old (0.8.0-0.8.19)
    Aging,
    /// Pre-0.8 without overflow protection (0.6-0.7)
    Outdated,
    /// Critically old (0.4-0.5)
    Critical,
}

impl std::fmt::Display for VersionAge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VersionAge::Current => write!(f, "Current"),
            VersionAge::Recent => write!(f, "Recent"),
            VersionAge::Aging => write!(f, "Aging"),
            VersionAge::Outdated => write!(f, "Outdated"),
            VersionAge::Critical => write!(f, "Critically Outdated"),
        }
    }
}

/// EVM features available at a given compiler version.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvmFeatures {
    /// Built-in overflow/underflow protection (0.8+)
    pub overflow_protection: bool,
    /// try/catch for external calls (0.6+)
    pub try_catch: bool,
    /// Custom errors with `error` keyword (0.8.4+)
    pub custom_errors: bool,
    /// User-defined value types (0.8.8+)
    pub user_defined_value_types: bool,
    /// PUSH0 opcode / Shanghai EVM target (0.8.20+)
    pub push0_opcode: bool,
    /// Transient storage TSTORE/TLOAD (0.8.24+)
    pub transient_storage: bool,
    /// Immutable variables (0.6.5+)
    pub immutable_vars: bool,
    /// ABI coder v2 by default (0.8.0+)
    pub abi_coder_v2_default: bool,
}

/// Comprehensive compiler version information extracted from a Solidity source file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompilerInfo {
    /// The raw pragma line (e.g., "pragma solidity ^0.8.19;")
    pub pragma_raw: String,
    /// Parsed version string (e.g., "0.8.19")
    pub version_string: String,
    /// Major.minor.patch components
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
    /// How the pragma constrains the version
    pub constraint: PragmaConstraint,
    /// Whether the pragma is floating (allows different versions to compile)
    pub is_floating: bool,
    /// How old this version is
    pub age: VersionAge,
    /// The latest recommended Solidity version
    pub latest_recommended: String,
    /// Whether an upgrade is recommended
    pub upgrade_recommended: bool,
    /// EVM features available at this version
    pub evm_features: EvmFeatures,
    /// Number of known compiler CVEs for this version
    pub known_cves: usize,
    /// Security recommendation based on version analysis
    pub security_note: String,
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
            if (trimmed.contains("uint")
                || trimmed.contains("int")
                || trimmed.contains("bool")
                || trimmed.contains("address")
                || trimmed.contains("string")
                || trimmed.contains("bytes"))
                && !trimmed.starts_with("//")
                && !trimmed.starts_with("function")
                && !trimmed.starts_with("event")
                && !trimmed.starts_with("modifier")
            {
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
                    .and_then(|s| s.split_whitespace().next())
                {
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

                return Some(DetailedVersion {
                    major,
                    minor,
                    patch,
                });
            }
        }
        None
    }

    /// Extract comprehensive compiler information from contract source.
    /// Returns None if no pragma solidity statement is found.
    pub fn extract_compiler_info(&self, content: &str) -> Option<CompilerInfo> {
        let pragma_raw = self.get_pragma_version(content)?;
        let detailed = self.get_detailed_version(content)?;

        let version_string = format!("{}.{}.{}", detailed.major, detailed.minor, detailed.patch);

        // Determine pragma constraint type
        let constraint = {
            let after_solidity = pragma_raw
                .trim()
                .strip_prefix("pragma solidity")
                .unwrap_or("")
                .trim();
            if after_solidity.contains(">=") && after_solidity.contains('<') {
                PragmaConstraint::Range
            } else if after_solidity.starts_with('^') || after_solidity.contains('^') {
                PragmaConstraint::Caret
            } else if after_solidity.starts_with(">=") || after_solidity.contains(">=") {
                PragmaConstraint::GreaterEqual
            } else if after_solidity.starts_with('>') || after_solidity.contains('>') {
                PragmaConstraint::Greater
            } else if after_solidity
                .chars()
                .next()
                .map_or(false, |c| c.is_ascii_digit())
            {
                PragmaConstraint::Exact
            } else {
                PragmaConstraint::Other
            }
        };

        let is_floating = matches!(
            constraint,
            PragmaConstraint::Caret | PragmaConstraint::GreaterEqual | PragmaConstraint::Greater
        );

        // Determine version age
        let age = match (detailed.major, detailed.minor) {
            (0, 4) | (0, 5) => VersionAge::Critical,
            (0, 6) | (0, 7) => VersionAge::Outdated,
            (0, 8) if detailed.patch < 20 => VersionAge::Aging,
            (0, 8) if detailed.patch < 28 => VersionAge::Recent,
            (0, 8) => VersionAge::Current,
            _ => VersionAge::Current,
        };

        let latest_recommended = "0.8.28".to_string();
        let upgrade_recommended =
            !(detailed.major == 0 && detailed.minor == 8 && detailed.patch >= 28);

        // Determine EVM features
        let evm_features = EvmFeatures {
            overflow_protection: detailed.minor >= 8 || detailed.major > 0,
            try_catch: (detailed.minor >= 6 || detailed.major > 0),
            custom_errors: (detailed.minor > 8 || (detailed.minor == 8 && detailed.patch >= 4))
                || detailed.major > 0,
            user_defined_value_types: (detailed.minor > 8
                || (detailed.minor == 8 && detailed.patch >= 8))
                || detailed.major > 0,
            push0_opcode: (detailed.minor > 8 || (detailed.minor == 8 && detailed.patch >= 20))
                || detailed.major > 0,
            transient_storage: (detailed.minor > 8
                || (detailed.minor == 8 && detailed.patch >= 24))
                || detailed.major > 0,
            immutable_vars: (detailed.minor > 6 || (detailed.minor == 6 && detailed.patch >= 5))
                || detailed.major > 0,
            abi_coder_v2_default: detailed.minor >= 8 || detailed.major > 0,
        };

        // Count known CVEs
        let cves = self.is_version_vulnerable(&detailed);
        let known_cves = cves.len();

        // Build security note
        let security_note = match &age {
            VersionAge::Critical => format!(
                "CRITICAL: Solidity {} is severely outdated with {} known issues. \
                 Missing overflow protection, modern error handling, and years of security fixes. \
                 Upgrade to {} immediately.",
                version_string, known_cves, latest_recommended
            ),
            VersionAge::Outdated => format!(
                "WARNING: Solidity {} lacks built-in overflow protection and has {} known issues. \
                 Requires SafeMath for arithmetic safety. Upgrade to {} strongly recommended.",
                version_string, known_cves, latest_recommended
            ),
            VersionAge::Aging => format!(
                "Solidity {} has {} known compiler issues. \
                 Consider upgrading to {} for latest security patches and gas optimizations.",
                version_string, known_cves, latest_recommended
            ),
            VersionAge::Recent if known_cves > 0 => format!(
                "Solidity {} has {} minor known issue{}. \
                 Upgrading to {} is recommended for the latest fixes.",
                version_string,
                known_cves,
                if known_cves > 1 { "s" } else { "" },
                latest_recommended
            ),
            VersionAge::Recent => format!(
                "Solidity {} is a recent version with no critical known issues.",
                version_string
            ),
            VersionAge::Current => format!(
                "Solidity {} is a current version. No upgrade needed.",
                version_string
            ),
        };

        Some(CompilerInfo {
            pragma_raw,
            version_string,
            major: detailed.major,
            minor: detailed.minor,
            patch: detailed.patch,
            constraint,
            is_floating,
            age,
            latest_recommended,
            upgrade_recommended,
            evm_features,
            known_cves,
            security_note,
        })
    }

    pub fn is_version_vulnerable(&self, version: &DetailedVersion) -> Vec<String> {
        let mut vulnerabilities = Vec::new();

        match (version.major, version.minor) {
            // Solidity 0.8.x: cumulative CVE checks (each fires independently)
            (0, 8) => {
                let patch = version.patch;
                if patch <= 12 {
                    vulnerabilities.push(
                        "Version < 0.8.13: Vulnerable to optimizer bug with inline assembly"
                            .to_string(),
                    );
                }
                if patch <= 14 {
                    vulnerabilities
                        .push("Version < 0.8.15: ABI coder v2 issues with tuples".to_string());
                }
                if patch <= 16 {
                    vulnerabilities.push(
                        "Version < 0.8.17: Vulnerable to storage write reentrancy in libraries"
                            .to_string(),
                    );
                }
                if patch <= 18 {
                    vulnerabilities.push(
                        "Version < 0.8.19: Optimizer bug affecting constant expressions"
                            .to_string(),
                    );
                }
                if patch <= 19 {
                    vulnerabilities.push(
                        "Version < 0.8.20: Missing check in bytes.concat() with dynamic arrays"
                            .to_string(),
                    );
                }
                if patch <= 20 {
                    vulnerabilities.push(
                        "Version < 0.8.21: Potential issues with using for directive and libraries"
                            .to_string(),
                    );
                }
                if patch <= 21 {
                    vulnerabilities.push(
                        "Version < 0.8.22: Head overflow bug in calldata tuple decoder".to_string(),
                    );
                }
                if patch == 22 {
                    vulnerabilities.push(
                        "Version 0.8.22: Contains unchecked loop increment overflow bug"
                            .to_string(),
                    );
                }
                if patch <= 23 {
                    vulnerabilities.push(
                        "Version < 0.8.24: Missing check for extra data in CREATE2 deployments"
                            .to_string(),
                    );
                }
                if patch <= 24 {
                    vulnerabilities.push(
                        "Version < 0.8.25: Optimizer bug with multiple memory copies".to_string(),
                    );
                }
                if patch <= 25 {
                    vulnerabilities.push(
                        "Version < 0.8.26: Potential issues with transient storage (TSTORE/TLOAD)"
                            .to_string(),
                    );
                }
                if patch == 27 {
                    vulnerabilities.push("Version 0.8.27: Known issue with constructor visibility (deprecated but still compilable)".to_string());
                }
                if patch <= 27 {
                    vulnerabilities.push(
                        "Version < 0.8.28: Vulnerable to specific edge cases in unchecked blocks"
                            .to_string(),
                    );
                }
                if patch == 29 {
                    vulnerabilities.push("Version 0.8.29: Memory expansion cost miscalculation in specific scenarios".to_string());
                }
                if patch == 30 {
                    vulnerabilities.push("Version 0.8.30: Latest - Check Solidity blog for any recent security advisories".to_string());
                }
            }

            // Solidity 0.7.x vulnerabilities
            (0, 7) => {
                vulnerabilities.push(
                    "Version 0.7.x: No automatic overflow/underflow protection - use SafeMath"
                        .to_string(),
                );
                if version.patch < 6 {
                    vulnerabilities
                        .push("Version < 0.7.6: Vulnerable to shift operation bugs".to_string());
                }
            }

            // Solidity 0.6.x vulnerabilities
            (0, 6) => {
                vulnerabilities
                    .push("Version 0.6.x: No automatic overflow/underflow protection".to_string());
                if version.patch < 12 {
                    vulnerabilities.push(
                        "Version < 0.6.12: Array slice bug can cause data corruption".to_string(),
                    );
                }
            }

            // Solidity 0.5.x vulnerabilities
            (0, 5) => {
                vulnerabilities.push(
                    "Version 0.5.x: Outdated - many security improvements missing".to_string(),
                );
                if version.patch < 17 {
                    vulnerabilities.push("Version < 0.5.17: ABIEncoderV2 bugs present".to_string());
                }
            }

            // Solidity 0.4.x vulnerabilities
            (0, 4) => {
                vulnerabilities.push(
                    "Version 0.4.x: CRITICALLY OUTDATED - Multiple severe vulnerabilities"
                        .to_string(),
                );
                vulnerabilities
                    .push("No constructor keyword - using contract name is deprecated".to_string());
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
            let mut in_string = false;
            let mut string_char = ' ';

            while let Some(ch) = chars.next() {
                if in_multiline_comment {
                    if ch == '*' && chars.peek() == Some(&'/') {
                        chars.next();
                        in_multiline_comment = false;
                    }
                } else if in_string {
                    cleaned_line.push(ch);
                    if ch == '\\' {
                        // Escaped character: consume next without checking
                        if let Some(escaped) = chars.next() {
                            cleaned_line.push(escaped);
                        }
                    } else if ch == string_char {
                        in_string = false;
                    }
                } else {
                    match ch {
                        '"' | '\'' => {
                            in_string = true;
                            string_char = ch;
                            cleaned_line.push(ch);
                        }
                        '/' => match chars.peek() {
                            Some('/') => break,
                            Some('*') => {
                                chars.next();
                                in_multiline_comment = true;
                            }
                            _ => cleaned_line.push(ch),
                        },
                        _ => cleaned_line.push(ch),
                    }
                }
            }

            if !in_multiline_comment || !cleaned_line.trim().is_empty() {
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

    #[test]
    fn test_remove_comments_preserves_strings() {
        let parser = SolidityParser::new();
        let content = r#"string url = "http://example.com"; // real comment"#;
        let cleaned = parser.remove_comments(content);
        assert!(
            cleaned.contains("http://example.com"),
            "URL inside string was incorrectly stripped"
        );
        assert!(
            !cleaned.contains("real comment"),
            "Comment after string was not stripped"
        );
    }

    #[test]
    fn test_version_vulnerable_cumulative() {
        let parser = SolidityParser::new();
        // Version 0.8.5 should fire ALL CVEs for patches <= 5
        let version = DetailedVersion {
            major: 0,
            minor: 8,
            patch: 5,
        };
        let vulns = parser.is_version_vulnerable(&version);
        assert!(
            vulns.len() >= 5,
            "Expected at least 5 CVEs for 0.8.5, got {}: {:?}",
            vulns.len(),
            vulns
        );
        assert!(
            vulns.iter().any(|v| v.contains("0.8.13")),
            "Missing optimizer bug CVE"
        );
        assert!(
            vulns.iter().any(|v| v.contains("0.8.15")),
            "Missing ABI coder CVE"
        );
        assert!(
            vulns.iter().any(|v| v.contains("0.8.17")),
            "Missing storage write CVE"
        );
    }

    #[test]
    fn test_version_vulnerable_latest_has_fewer() {
        let parser = SolidityParser::new();
        let old = DetailedVersion {
            major: 0,
            minor: 8,
            patch: 5,
        };
        let new = DetailedVersion {
            major: 0,
            minor: 8,
            patch: 26,
        };
        let old_vulns = parser.is_version_vulnerable(&old);
        let new_vulns = parser.is_version_vulnerable(&new);
        assert!(
            old_vulns.len() > new_vulns.len(),
            "0.8.5 should have more CVEs than 0.8.26: {} vs {}",
            old_vulns.len(),
            new_vulns.len()
        );
    }
}
