use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use crate::vulnerabilities::{Vulnerability, VulnerabilitySeverity, VulnerabilityCategory};

/// SARIF 2.1.0 format support for CI/CD integration
/// Specification: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifReport {
    #[serde(rename = "$schema")]
    pub schema: String,
    pub version: String,
    pub runs: Vec<SarifRun>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifRun {
    pub tool: SarifTool,
    pub results: Vec<SarifResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifTool {
    pub driver: SarifDriver,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifDriver {
    pub name: String,
    pub version: String,
    #[serde(rename = "informationUri")]
    pub information_uri: String,
    pub rules: Vec<SarifRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifRule {
    pub id: String,
    pub name: String,
    #[serde(rename = "shortDescription")]
    pub short_description: SarifMessage,
    #[serde(rename = "fullDescription")]
    pub full_description: SarifMessage,
    #[serde(rename = "defaultConfiguration")]
    pub default_configuration: SarifConfiguration,
    pub help: SarifMessage,
    pub properties: SarifRuleProperties,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifConfiguration {
    pub level: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifRuleProperties {
    pub tags: Vec<String>,
    pub precision: String,
    #[serde(rename = "security-severity")]
    pub security_severity: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cwe: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub swc: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifResult {
    #[serde(rename = "ruleId")]
    pub rule_id: String,
    pub level: String,
    pub message: SarifMessage,
    pub locations: Vec<SarifLocation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifMessage {
    pub text: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifLocation {
    #[serde(rename = "physicalLocation")]
    pub physical_location: SarifPhysicalLocation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifPhysicalLocation {
    #[serde(rename = "artifactLocation")]
    pub artifact_location: SarifArtifactLocation,
    pub region: SarifRegion,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifArtifactLocation {
    pub uri: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifRegion {
    #[serde(rename = "startLine")]
    pub start_line: usize,
    pub snippet: SarifSnippet,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifSnippet {
    pub text: String,
}

impl SarifReport {
    pub fn new(
        results: Vec<(PathBuf, Vec<Vulnerability>)>,
        version: &str,
    ) -> Self {
        let mut sarif_results = Vec::new();
        let mut rules_map = std::collections::HashMap::new();

        // Convert vulnerabilities to SARIF results
        for (file_path, vulns) in results {
            let file_uri = file_path.to_string_lossy().to_string();

            for vuln in vulns {
                let rule_id = category_to_rule_id(&vuln.category);

                // Collect unique rules
                rules_map.entry(rule_id.clone()).or_insert_with(|| {
                    create_sarif_rule(&vuln.category, &vuln.severity, &vuln.title, &vuln.description, &vuln.recommendation)
                });

                sarif_results.push(SarifResult {
                    rule_id: rule_id.clone(),
                    level: severity_to_sarif_level(&vuln.severity),
                    message: SarifMessage {
                        text: vuln.description.clone(),
                    },
                    locations: vec![SarifLocation {
                        physical_location: SarifPhysicalLocation {
                            artifact_location: SarifArtifactLocation {
                                uri: file_uri.clone(),
                            },
                            region: SarifRegion {
                                start_line: vuln.line_number,
                                snippet: SarifSnippet {
                                    text: vuln.code_snippet.clone(),
                                },
                            },
                        },
                    }],
                });
            }
        }

        let rules: Vec<SarifRule> = rules_map.into_values().collect();

        SarifReport {
            schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json".to_string(),
            version: "2.1.0".to_string(),
            runs: vec![SarifRun {
                tool: SarifTool {
                    driver: SarifDriver {
                        name: "41Swara Smart Contract Scanner".to_string(),
                        version: version.to_string(),
                        information_uri: "https://github.com/41swara/smart-contract-scanner".to_string(),
                        rules,
                    },
                },
                results: sarif_results,
            }],
        }
    }
}

fn category_to_rule_id(category: &VulnerabilityCategory) -> String {
    match category {
        VulnerabilityCategory::Reentrancy => "SWC-107".to_string(),
        VulnerabilityCategory::AccessControl => "SWC-105".to_string(),
        VulnerabilityCategory::ArithmeticIssues => "SWC-101".to_string(),
        VulnerabilityCategory::UnhandledExceptions => "SWC-104".to_string(),
        VulnerabilityCategory::RandomnessVulnerabilities => "SWC-120".to_string(),
        VulnerabilityCategory::FrontRunning => "SWC-114".to_string(),
        VulnerabilityCategory::TimeManipulation => "SWC-116".to_string(),
        VulnerabilityCategory::DoSAttacks => "SWC-128".to_string(),
        VulnerabilityCategory::UnsafeExternalCalls => "SWC-107".to_string(),
        VulnerabilityCategory::DelegateCalls => "SWC-112".to_string(),
        VulnerabilityCategory::PragmaIssues => "SWC-103".to_string(),
        VulnerabilityCategory::TxOriginAuth => "SWC-115".to_string(),
        VulnerabilityCategory::SignatureVulnerabilities => "SWC-117".to_string(),
        VulnerabilityCategory::OracleManipulation => "SWC-201".to_string(),
        VulnerabilityCategory::ProxyAdminVulnerability => "41S-001".to_string(),
        VulnerabilityCategory::CallbackReentrancy => "41S-002".to_string(),
        VulnerabilityCategory::ArbitraryExternalCall => "41S-003".to_string(),
        VulnerabilityCategory::SignatureReplay => "41S-004".to_string(),
        VulnerabilityCategory::CrossChainReplay => "41S-005".to_string(),
        VulnerabilityCategory::InputValidationFailure => "41S-006".to_string(),
        VulnerabilityCategory::DecimalPrecisionMismatch => "41S-007".to_string(),
        VulnerabilityCategory::UnprotectedProxyUpgrade => "41S-008".to_string(),
        VulnerabilityCategory::MEVExploitable => "41S-009".to_string(),
        VulnerabilityCategory::CallbackInjection => "41S-010".to_string(),
        _ => format!("41S-{:03}", category_to_number(category)),
    }
}

fn category_to_number(category: &VulnerabilityCategory) -> usize {
    match category {
        VulnerabilityCategory::RoleBasedAccessControl => 100,
        VulnerabilityCategory::GasOptimization => 101,
        VulnerabilityCategory::UnusedCode => 102,
        VulnerabilityCategory::MagicNumbers => 103,
        VulnerabilityCategory::NamingConventions => 104,
        VulnerabilityCategory::StateVariable => 105,
        VulnerabilityCategory::StorageDoSAttacks => 106,
        VulnerabilityCategory::PrecisionLoss => 107,
        VulnerabilityCategory::CompilerBug => 108,
        VulnerabilityCategory::BadPRNG => 109,
        VulnerabilityCategory::BlockTimestamp => 110,
        VulnerabilityCategory::LowLevelCalls => 111,
        VulnerabilityCategory::MissingEvents => 112,
        VulnerabilityCategory::UncheckedReturnValues => 113,
        VulnerabilityCategory::UninitializedVariables => 114,
        VulnerabilityCategory::UnusedReturnValues => 115,
        VulnerabilityCategory::ImmutabilityIssues => 116,
        VulnerabilityCategory::ShadowingIssues => 117,
        VulnerabilityCategory::AssemblyUsage => 118,
        VulnerabilityCategory::DeprecatedFunctions => 119,
        VulnerabilityCategory::ComplexityIssues => 120,
        VulnerabilityCategory::ExternalFunction => 121,
        VulnerabilityCategory::IncorrectEquality => 122,
        VulnerabilityCategory::ABIAccessControl => 200,
        VulnerabilityCategory::ABIFunctionVisibility => 201,
        VulnerabilityCategory::ABIParameterValidation => 202,
        VulnerabilityCategory::ABIEventSecurity => 203,
        VulnerabilityCategory::ABIUpgradeability => 204,
        VulnerabilityCategory::ABITokenStandard => 205,
        _ => 999,
    }
}

fn severity_to_sarif_level(severity: &VulnerabilitySeverity) -> String {
    match severity {
        VulnerabilitySeverity::Critical | VulnerabilitySeverity::High => "error",
        VulnerabilitySeverity::Medium => "warning",
        VulnerabilitySeverity::Low | VulnerabilitySeverity::Info => "note",
    }
    .to_string()
}

fn severity_to_score(severity: &VulnerabilitySeverity) -> String {
    match severity {
        VulnerabilitySeverity::Critical => "9.0",
        VulnerabilitySeverity::High => "7.0",
        VulnerabilitySeverity::Medium => "5.0",
        VulnerabilitySeverity::Low => "3.0",
        VulnerabilitySeverity::Info => "1.0",
    }
    .to_string()
}

fn create_sarif_rule(
    category: &VulnerabilityCategory,
    severity: &VulnerabilitySeverity,
    title: &str,
    description: &str,
    recommendation: &str,
) -> SarifRule {
    let rule_id = category_to_rule_id(category);
    let level = severity_to_sarif_level(severity);
    let security_severity = severity_to_score(severity);

    // Get SWC/CWE IDs from the category
    let swc_id = category.get_swc_id();
    let (swc, cwe) = match swc_id {
        Some(ref id) => (Some(id.id.clone()), id.cwe_id.clone()),
        None => (None, None),
    };

    // Build tags with SWC/CWE
    let mut tags = vec![
        "security".to_string(),
        "smart-contract".to_string(),
        format!("{:?}", category).to_lowercase(),
    ];
    if let Some(ref swc_val) = swc {
        tags.push(swc_val.clone());
    }
    if let Some(ref cwe_val) = cwe {
        tags.push(cwe_val.clone());
    }

    SarifRule {
        id: rule_id.clone(),
        name: title.to_string(),
        short_description: SarifMessage {
            text: title.to_string(),
        },
        full_description: SarifMessage {
            text: description.to_string(),
        },
        default_configuration: SarifConfiguration {
            level: level.clone(),
        },
        help: SarifMessage {
            text: format!("{}\\n\\nRecommendation: {}", description, recommendation),
        },
        properties: SarifRuleProperties {
            tags,
            precision: "high".to_string(),
            security_severity,
            cwe,
            swc,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sarif_creation() {
        let vuln = Vulnerability::high_confidence(
            VulnerabilitySeverity::Critical,
            VulnerabilityCategory::Reentrancy,
            "Reentrancy Vulnerability".to_string(),
            "Potential reentrancy attack".to_string(),
            42,
            "msg.sender.call{value: amount}(\"\")".to_string(),
            "Use ReentrancyGuard".to_string(),
        );

        let results = vec![(PathBuf::from("test.sol"), vec![vuln])];
        let report = SarifReport::new(results, "0.4.0");

        assert_eq!(report.version, "2.1.0");
        assert_eq!(report.runs.len(), 1);
        assert_eq!(report.runs[0].results.len(), 1);
        assert_eq!(report.runs[0].results[0].rule_id, "SWC-107");
        assert_eq!(report.runs[0].results[0].level, "error");
    }
}
