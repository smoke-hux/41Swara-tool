//! Dependency and Import Analyzer
//!
//! Analyzes imported contracts and dependencies for known vulnerabilities,
//! version mismatches, and supply chain security issues.

#![allow(dead_code)]

use std::collections::{HashMap, HashSet};
use regex::Regex;
use crate::vulnerabilities::{Vulnerability, VulnerabilitySeverity, VulnerabilityCategory};

/// Represents an imported dependency
#[derive(Debug, Clone)]
pub struct ImportedDependency {
    pub path: String,
    pub alias: Option<String>,
    pub symbols: Vec<String>,
    pub line: usize,
    pub is_openzeppelin: bool,
    pub is_local: bool,
    pub version: Option<String>,
}

/// Known vulnerable OpenZeppelin versions and their issues
#[derive(Debug, Clone)]
pub struct KnownVulnerability {
    pub package: String,
    pub affected_versions: Vec<String>,
    pub severity: VulnerabilitySeverity,
    pub description: String,
    pub recommendation: String,
    pub cve: Option<String>,
}

pub struct DependencyAnalyzer {
    verbose: bool,
    known_vulnerabilities: Vec<KnownVulnerability>,
}

impl DependencyAnalyzer {
    pub fn new(verbose: bool) -> Self {
        Self {
            verbose,
            known_vulnerabilities: Self::load_known_vulnerabilities(),
        }
    }

    /// Load database of known vulnerabilities in common dependencies
    fn load_known_vulnerabilities() -> Vec<KnownVulnerability> {
        vec![
            // OpenZeppelin known issues
            KnownVulnerability {
                package: "@openzeppelin/contracts".to_string(),
                affected_versions: vec!["4.0.0".to_string(), "4.1.0".to_string()],
                severity: VulnerabilitySeverity::Critical,
                description: "ERC1967Upgrade vulnerability allowing unauthorized upgrade".to_string(),
                recommendation: "Upgrade to OpenZeppelin 4.3.2 or later".to_string(),
                cve: Some("CVE-2021-41264".to_string()),
            },
            KnownVulnerability {
                package: "@openzeppelin/contracts".to_string(),
                affected_versions: vec!["4.4.0".to_string(), "4.4.1".to_string()],
                severity: VulnerabilitySeverity::High,
                description: "GovernorVotesQuorumFraction may cause division by zero".to_string(),
                recommendation: "Upgrade to OpenZeppelin 4.4.2 or later".to_string(),
                cve: Some("CVE-2022-21698".to_string()),
            },
            KnownVulnerability {
                package: "@openzeppelin/contracts".to_string(),
                affected_versions: vec!["4.7.0".to_string(), "4.7.1".to_string(), "4.7.2".to_string()],
                severity: VulnerabilitySeverity::High,
                description: "ERC165Checker may revert instead of returning false".to_string(),
                recommendation: "Upgrade to OpenZeppelin 4.7.3 or later".to_string(),
                cve: None,
            },
            KnownVulnerability {
                package: "@openzeppelin/contracts".to_string(),
                affected_versions: vec!["3.0.0".to_string(), "3.1.0".to_string(), "3.2.0".to_string(), "3.3.0".to_string(), "3.4.0".to_string()],
                severity: VulnerabilitySeverity::Critical,
                description: "Initializable contract can be re-initialized in some scenarios".to_string(),
                recommendation: "Upgrade to OpenZeppelin 4.x and use reinitializer".to_string(),
                cve: None,
            },
            // Chainlink known issues
            KnownVulnerability {
                package: "@chainlink/contracts".to_string(),
                affected_versions: vec!["0.1.0".to_string(), "0.2.0".to_string()],
                severity: VulnerabilitySeverity::High,
                description: "AggregatorV2V3Interface may return stale prices without validation".to_string(),
                recommendation: "Always check updatedAt and answeredInRound".to_string(),
                cve: None,
            },
            // Uniswap known patterns
            KnownVulnerability {
                package: "@uniswap/v2-periphery".to_string(),
                affected_versions: vec!["1.0.0".to_string()],
                severity: VulnerabilitySeverity::High,
                description: "Deadline check may be bypassed if not properly implemented".to_string(),
                recommendation: "Ensure deadline is validated against block.timestamp".to_string(),
                cve: None,
            },
            // Solmate known patterns
            KnownVulnerability {
                package: "solmate".to_string(),
                affected_versions: vec!["6.0.0".to_string(), "6.1.0".to_string()],
                severity: VulnerabilitySeverity::Medium,
                description: "ERC20 approve may have race condition without increaseAllowance".to_string(),
                recommendation: "Use SafeERC20 wrapper or implement approval checks".to_string(),
                cve: None,
            },
        ]
    }

    /// Analyze all imports in a contract
    pub fn analyze(&self, content: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();
        let imports = self.extract_imports(content);

        // Check for known vulnerable dependencies
        vulnerabilities.extend(self.check_known_vulnerabilities(&imports));

        // Check for version mismatches
        vulnerabilities.extend(self.check_version_mismatches(content, &imports));

        // Check for unsafe import patterns
        vulnerabilities.extend(self.check_unsafe_imports(&imports));

        // Check for circular dependency risks
        vulnerabilities.extend(self.check_circular_dependencies(&imports, content));

        // Check for outdated patterns
        vulnerabilities.extend(self.check_outdated_patterns(content, &imports));

        // Check for mixed import sources
        vulnerabilities.extend(self.check_mixed_sources(&imports));

        vulnerabilities
    }

    /// Extract all import statements
    fn extract_imports(&self, content: &str) -> Vec<ImportedDependency> {
        let mut imports = Vec::new();

        // Standard import pattern
        let import_pattern = Regex::new(
            r#"import\s*(?:\{([^}]+)\}\s*from\s*)?"([^"]+)"|import\s+"([^"]+)""#
        ).unwrap();

        // Aliased import pattern
        let alias_pattern = Regex::new(
            r#"import\s+"([^"]+)"\s+as\s+(\w+)"#
        ).unwrap();

        for (idx, line) in content.lines().enumerate() {
            if let Some(caps) = import_pattern.captures(line) {
                let symbols: Vec<String> = caps.get(1)
                    .map(|m| m.as_str().split(',').map(|s| s.trim().to_string()).collect())
                    .unwrap_or_default();

                let path = caps.get(2)
                    .or_else(|| caps.get(3))
                    .map(|m| m.as_str().to_string())
                    .unwrap_or_default();

                if !path.is_empty() {
                    let is_openzeppelin = path.contains("@openzeppelin") || path.contains("openzeppelin");
                    let is_local = path.starts_with("./") || path.starts_with("../");
                    let version = self.extract_version_from_path(&path);

                    imports.push(ImportedDependency {
                        path: path.clone(),
                        alias: None,
                        symbols,
                        line: idx + 1,
                        is_openzeppelin,
                        is_local,
                        version,
                    });
                }
            }

            // Check for aliased imports
            if let Some(caps) = alias_pattern.captures(line) {
                let path = caps.get(1).map(|m| m.as_str().to_string()).unwrap_or_default();
                let alias = caps.get(2).map(|m| m.as_str().to_string());

                if !path.is_empty() {
                    let is_openzeppelin = path.contains("@openzeppelin") || path.contains("openzeppelin");
                    let is_local = path.starts_with("./") || path.starts_with("../");
                    let version = self.extract_version_from_path(&path);

                    imports.push(ImportedDependency {
                        path,
                        alias,
                        symbols: vec![],
                        line: idx + 1,
                        is_openzeppelin,
                        is_local,
                        version,
                    });
                }
            }
        }

        imports
    }

    /// Extract version from import path if present
    fn extract_version_from_path(&self, path: &str) -> Option<String> {
        let version_pattern = Regex::new(r"@(\d+\.\d+\.\d+)").unwrap();
        version_pattern.captures(path)
            .and_then(|c| c.get(1))
            .map(|m| m.as_str().to_string())
    }

    /// Check for known vulnerabilities in dependencies
    fn check_known_vulnerabilities(&self, imports: &[ImportedDependency]) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        for import in imports {
            for known_vuln in &self.known_vulnerabilities {
                if import.path.contains(&known_vuln.package) {
                    if let Some(ref version) = import.version {
                        if known_vuln.affected_versions.contains(version) {
                            let mut vuln = Vulnerability::high_confidence(
                                known_vuln.severity.clone(),
                                VulnerabilityCategory::CompilerBug, // Using this as closest category
                                format!("Known Vulnerability in {}", known_vuln.package),
                                format!("{} {}", known_vuln.description,
                                       known_vuln.cve.as_ref().map(|c| format!("({})", c)).unwrap_or_default()),
                                import.line,
                                format!("import \"{}\"", import.path),
                                known_vuln.recommendation.clone(),
                            );

                            if let Some(ref cve) = known_vuln.cve {
                                vuln.description = format!("{} [{}]", vuln.description, cve);
                            }

                            vulnerabilities.push(vuln);
                        }
                    }
                }
            }
        }

        vulnerabilities
    }

    /// Check for version mismatches between dependencies
    fn check_version_mismatches(&self, content: &str, imports: &[ImportedDependency]) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        // Group imports by package
        let mut package_versions: HashMap<String, Vec<(&ImportedDependency, String)>> = HashMap::new();

        for import in imports {
            // Extract package name
            let package = if import.path.contains('@') {
                import.path.split('/').take(2).collect::<Vec<_>>().join("/")
            } else {
                import.path.split('/').next().unwrap_or("").to_string()
            };

            if let Some(ref version) = import.version {
                package_versions.entry(package)
                    .or_insert_with(Vec::new)
                    .push((import, version.clone()));
            }
        }

        // Check for mismatches
        for (package, versions) in package_versions {
            let unique_versions: HashSet<_> = versions.iter().map(|(_, v)| v.clone()).collect();

            if unique_versions.len() > 1 {
                let version_list: Vec<_> = unique_versions.into_iter().collect();
                vulnerabilities.push(Vulnerability::new(
                    VulnerabilitySeverity::Medium,
                    VulnerabilityCategory::CompilerBug,
                    format!("Version Mismatch in {}", package),
                    format!("Multiple versions detected: {} - may cause unexpected behavior", version_list.join(", ")),
                    versions[0].0.line,
                    format!("Package: {}", package),
                    "Use a single consistent version across all imports".to_string(),
                ));
            }
        }

        // Check Solidity pragma vs dependency compatibility
        let pragma_pattern = Regex::new(r"pragma\s+solidity\s*([^;]+)").unwrap();
        if let Some(caps) = pragma_pattern.captures(content) {
            let pragma_version = caps.get(1).map(|m| m.as_str()).unwrap_or("");

            // OpenZeppelin 5.x requires Solidity 0.8.20+
            let has_oz5 = imports.iter().any(|i| i.path.contains("@openzeppelin") && i.version.as_ref().map(|v| v.starts_with("5.")).unwrap_or(false));
            let has_old_pragma = pragma_version.contains("0.8.0") || pragma_version.contains("0.8.1") || pragma_version.contains("^0.8.0");

            if has_oz5 && has_old_pragma {
                vulnerabilities.push(Vulnerability::new(
                    VulnerabilitySeverity::High,
                    VulnerabilityCategory::CompilerBug,
                    "OpenZeppelin 5.x Incompatible with Solidity Version".to_string(),
                    "OpenZeppelin 5.x requires Solidity 0.8.20+ but pragma suggests older version".to_string(),
                    1,
                    format!("pragma solidity {}", pragma_version),
                    "Update to pragma solidity ^0.8.20 or downgrade OpenZeppelin".to_string(),
                ));
            }
        }

        vulnerabilities
    }

    /// Check for unsafe import patterns
    fn check_unsafe_imports(&self, imports: &[ImportedDependency]) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        for import in imports {
            // Check for wildcard imports (all symbols)
            if import.symbols.is_empty() && import.alias.is_none() && !import.path.ends_with(".sol") {
                if !import.path.contains("interface") && !import.path.contains("Interface") {
                    vulnerabilities.push(Vulnerability::new(
                        VulnerabilitySeverity::Low,
                        VulnerabilityCategory::CompilerBug,
                        "Wildcard Import".to_string(),
                        "Importing entire file without specifying symbols - may import unnecessary code".to_string(),
                        import.line,
                        format!("import \"{}\"", import.path),
                        "Use specific imports: import {Contract} from \"path\"".to_string(),
                    ));
                }
            }

            // Check for git/URL imports (supply chain risk)
            if import.path.contains("github.com") || import.path.contains("http://") || import.path.contains("https://") {
                vulnerabilities.push(Vulnerability::high_confidence(
                    VulnerabilitySeverity::Critical,
                    VulnerabilityCategory::CompilerBug,
                    "External URL Import - Supply Chain Risk".to_string(),
                    "Importing from external URL is dangerous - content may change".to_string(),
                    import.line,
                    format!("import \"{}\"", import.path),
                    "Use package manager (npm/yarn) with locked versions instead".to_string(),
                ));
            }

            // Check for deprecated import paths
            let deprecated_paths = vec![
                ("@openzeppelin/contracts/access/Ownable.sol", "Consider using OwnableUpgradeable for upgradeable contracts"),
                ("@openzeppelin/contracts/security/Pausable.sol", "Consider using PausableUpgradeable for upgradeable contracts"),
                ("@chainlink/contracts/src/v0.6/", "Upgrade to Chainlink v0.8 interfaces"),
            ];

            for (deprecated, suggestion) in deprecated_paths {
                if import.path.contains(deprecated) {
                    vulnerabilities.push(Vulnerability::new(
                        VulnerabilitySeverity::Low,
                        VulnerabilityCategory::DeprecatedFunctions,
                        "Potentially Outdated Import Path".to_string(),
                        suggestion.to_string(),
                        import.line,
                        format!("import \"{}\"", import.path),
                        "Review import and update if necessary".to_string(),
                    ));
                }
            }
        }

        vulnerabilities
    }

    /// Check for potential circular dependency issues
    fn check_circular_dependencies(&self, imports: &[ImportedDependency], content: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        // Get current contract name
        let contract_pattern = Regex::new(r"contract\s+(\w+)").unwrap();
        let current_contract = contract_pattern.captures(content)
            .and_then(|c| c.get(1))
            .map(|m| m.as_str().to_string());

        if let Some(ref contract_name) = current_contract {
            // Check if any imported file might import back
            for import in imports.iter().filter(|i| i.is_local) {
                // Local imports that might create cycles
                if import.path.contains(&contract_name.to_lowercase()) {
                    vulnerabilities.push(Vulnerability::new(
                        VulnerabilitySeverity::Medium,
                        VulnerabilityCategory::CompilerBug,
                        "Potential Circular Dependency".to_string(),
                        format!("Import path '{}' may create circular dependency with '{}'", import.path, contract_name),
                        import.line,
                        format!("import \"{}\"", import.path),
                        "Review import structure to avoid circular dependencies".to_string(),
                    ));
                }
            }
        }

        vulnerabilities
    }

    /// Check for outdated patterns in imports and usage
    fn check_outdated_patterns(&self, content: &str, imports: &[ImportedDependency]) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        // Check for SafeMath usage with Solidity 0.8+
        let uses_safemath = imports.iter().any(|i| i.path.contains("SafeMath") || i.symbols.iter().any(|s| s == "SafeMath"));
        let uses_solidity_8 = content.contains("pragma solidity") &&
                             (content.contains("0.8.") || content.contains("^0.8"));

        if uses_safemath && uses_solidity_8 {
            vulnerabilities.push(Vulnerability::new(
                VulnerabilitySeverity::Info,
                VulnerabilityCategory::GasOptimization,
                "Unnecessary SafeMath Import".to_string(),
                "SafeMath is not needed in Solidity 0.8+ - built-in overflow protection".to_string(),
                imports.iter().find(|i| i.path.contains("SafeMath")).map(|i| i.line).unwrap_or(1),
                "using SafeMath for uint256".to_string(),
                "Remove SafeMath import and usage to save gas".to_string(),
            ));
        }

        // Check for old Counters library
        let uses_counters = imports.iter().any(|i| i.path.contains("Counters"));
        if uses_counters {
            vulnerabilities.push(Vulnerability::new(
                VulnerabilitySeverity::Info,
                VulnerabilityCategory::GasOptimization,
                "Deprecated Counters Library".to_string(),
                "Counters library is deprecated in OpenZeppelin 5.x".to_string(),
                imports.iter().find(|i| i.path.contains("Counters")).map(|i| i.line).unwrap_or(1),
                "import \"@openzeppelin/contracts/utils/Counters.sol\"".to_string(),
                "Use plain uint256 with unchecked increment for gas savings".to_string(),
            ));
        }

        // Check for ERC20 without SafeERC20
        let uses_erc20 = imports.iter().any(|i| i.path.contains("ERC20") || i.path.contains("IERC20"));
        let uses_safe_erc20 = imports.iter().any(|i| i.path.contains("SafeERC20"));
        let has_transfer_calls = content.contains(".transfer(") || content.contains(".transferFrom(");

        if uses_erc20 && has_transfer_calls && !uses_safe_erc20 {
            vulnerabilities.push(Vulnerability::new(
                VulnerabilitySeverity::High,
                VulnerabilityCategory::UncheckedReturnValues,
                "ERC20 Without SafeERC20".to_string(),
                "Using ERC20 transfer without SafeERC20 wrapper - some tokens don't return bool".to_string(),
                imports.iter().find(|i| i.path.contains("ERC20")).map(|i| i.line).unwrap_or(1),
                ".transfer() / .transferFrom()".to_string(),
                "Import and use SafeERC20: safeTransfer(), safeTransferFrom()".to_string(),
            ));
        }

        vulnerabilities
    }

    /// Check for mixed dependency sources
    fn check_mixed_sources(&self, imports: &[ImportedDependency]) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        let has_openzeppelin = imports.iter().any(|i| i.is_openzeppelin);
        let has_solmate = imports.iter().any(|i| i.path.contains("solmate"));
        let has_solady = imports.iter().any(|i| i.path.contains("solady"));

        // Check for mixing OpenZeppelin with Solmate/Solady
        if has_openzeppelin && (has_solmate || has_solady) {
            let conflict_source = if has_solmate { "Solmate" } else { "Solady" };

            vulnerabilities.push(Vulnerability::new(
                VulnerabilitySeverity::Medium,
                VulnerabilityCategory::CompilerBug,
                format!("Mixed Dependencies: OpenZeppelin + {}", conflict_source),
                format!("Mixing OpenZeppelin with {} may cause interface conflicts", conflict_source),
                1,
                "Multiple dependency sources".to_string(),
                "Stick to one dependency library when possible for consistency".to_string(),
            ));
        }

        // Check for different ERC20 implementations
        let erc20_sources: HashSet<_> = imports.iter()
            .filter(|i| i.path.contains("ERC20"))
            .map(|i| {
                if i.path.contains("openzeppelin") { "OpenZeppelin" }
                else if i.path.contains("solmate") { "Solmate" }
                else if i.path.contains("solady") { "Solady" }
                else { "Other" }
            })
            .collect();

        if erc20_sources.len() > 1 {
            vulnerabilities.push(Vulnerability::new(
                VulnerabilitySeverity::High,
                VulnerabilityCategory::CompilerBug,
                "Multiple ERC20 Implementations".to_string(),
                format!("Multiple ERC20 sources detected: {:?} - may cause conflicts", erc20_sources),
                1,
                "Different ERC20 implementations".to_string(),
                "Use a single ERC20 implementation source".to_string(),
            ));
        }

        vulnerabilities
    }

    /// Get a summary of all imports
    pub fn get_import_summary(&self, content: &str) -> ImportSummary {
        let imports = self.extract_imports(content);

        let openzeppelin_count = imports.iter().filter(|i| i.is_openzeppelin).count();
        let local_count = imports.iter().filter(|i| i.is_local).count();
        let external_count = imports.len() - openzeppelin_count - local_count;

        let packages: HashSet<_> = imports.iter()
            .map(|i| {
                if i.path.contains('@') {
                    i.path.split('/').take(2).collect::<Vec<_>>().join("/")
                } else {
                    i.path.split('/').next().unwrap_or("").to_string()
                }
            })
            .filter(|p| !p.is_empty())
            .collect();

        ImportSummary {
            total_imports: imports.len(),
            openzeppelin_imports: openzeppelin_count,
            local_imports: local_count,
            external_imports: external_count,
            unique_packages: packages.into_iter().collect(),
            imports,
        }
    }
}

/// Summary of contract imports
#[derive(Debug)]
pub struct ImportSummary {
    pub total_imports: usize,
    pub openzeppelin_imports: usize,
    pub local_imports: usize,
    pub external_imports: usize,
    pub unique_packages: Vec<String>,
    pub imports: Vec<ImportedDependency>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_import_extraction() {
        let content = r#"
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import "./MyContract.sol";
"#;
        let analyzer = DependencyAnalyzer::new(false);
        let imports = analyzer.extract_imports(content);

        assert_eq!(imports.len(), 3);
        assert!(imports[0].is_openzeppelin);
        assert!(imports[2].is_local);
    }

    #[test]
    fn test_safemath_detection() {
        let content = r#"
pragma solidity ^0.8.0;
import "@openzeppelin/contracts/utils/math/SafeMath.sol";

contract Test {
    using SafeMath for uint256;
}
"#;
        let analyzer = DependencyAnalyzer::new(false);
        let vulns = analyzer.analyze(content);

        assert!(vulns.iter().any(|v| v.title.contains("SafeMath")));
    }
}
