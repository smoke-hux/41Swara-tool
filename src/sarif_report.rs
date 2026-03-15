use crate::vulnerabilities::{Vulnerability, VulnerabilityConfidence, VulnerabilitySeverity};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;

/// SARIF 2.1.0 report for CI/CD and code-scanning integrations.
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
    #[serde(rename = "endLine", skip_serializing_if = "Option::is_none")]
    pub end_line: Option<usize>,
    pub snippet: SarifSnippet,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifSnippet {
    pub text: String,
}

impl SarifReport {
    pub fn new(results: Vec<(PathBuf, Vec<Vulnerability>)>, scanner_version: &str) -> Self {
        let mut sarif_results = Vec::new();
        let mut rules = BTreeMap::new();

        for (file_path, vulnerabilities) in results {
            let file_uri = file_path.to_string_lossy().to_string();

            for vulnerability in vulnerabilities {
                let rule_id = vulnerability
                    .get_swc_id_str()
                    .map(ToOwned::to_owned)
                    .unwrap_or_else(|| format!("41S-{}", format!("{:?}", vulnerability.category)));
                let level = severity_to_sarif_level(&vulnerability.severity);

                rules
                    .entry(rule_id.clone())
                    .or_insert_with(|| create_sarif_rule(&rule_id, &vulnerability, &level));

                sarif_results.push(SarifResult {
                    rule_id,
                    level,
                    message: SarifMessage {
                        text: vulnerability.description.clone(),
                    },
                    locations: vec![SarifLocation {
                        physical_location: SarifPhysicalLocation {
                            artifact_location: SarifArtifactLocation {
                                uri: file_uri.clone(),
                            },
                            region: SarifRegion {
                                start_line: vulnerability.line_number,
                                end_line: vulnerability.end_line_number,
                                snippet: SarifSnippet {
                                    text: vulnerability.code_snippet.clone(),
                                },
                            },
                        },
                    }],
                });
            }
        }

        Self {
            schema: "https://docs.oasis-open.org/sarif/sarif/v2.1.0/csprd01/schemas/sarif-schema-2.1.0.json".to_string(),
            version: "2.1.0".to_string(),
            runs: vec![SarifRun {
                tool: SarifTool {
                    driver: SarifDriver {
                        name: "41Swara Smart Contract Scanner".to_string(),
                        version: scanner_version.to_string(),
                        information_uri: "https://github.com/41swara/smart-contract-scanner"
                            .to_string(),
                        rules: rules.into_values().collect(),
                    },
                },
                results: sarif_results,
            }],
        }
    }
}

fn create_sarif_rule(rule_id: &str, vulnerability: &Vulnerability, level: &str) -> SarifRule {
    let category = format!("{:?}", vulnerability.category).to_lowercase();

    SarifRule {
        id: rule_id.to_string(),
        name: vulnerability.title.clone(),
        short_description: SarifMessage {
            text: vulnerability.title.clone(),
        },
        full_description: SarifMessage {
            text: vulnerability.description.clone(),
        },
        default_configuration: SarifConfiguration {
            level: level.to_string(),
        },
        help: SarifMessage {
            text: format!(
                "{}\n\nRecommendation: {}",
                vulnerability.description, vulnerability.recommendation
            ),
        },
        properties: SarifRuleProperties {
            tags: vec![
                "security".to_string(),
                "smart-contract".to_string(),
                category,
            ],
            precision: confidence_to_precision(&vulnerability.confidence),
            security_severity: vulnerability
                .cvss_score
                .map(|score| format!("{score:.1}"))
                .unwrap_or_else(|| severity_to_score(&vulnerability.severity)),
        },
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

fn confidence_to_precision(confidence: &VulnerabilityConfidence) -> String {
    match confidence {
        VulnerabilityConfidence::High => "high",
        VulnerabilityConfidence::Medium => "medium",
        VulnerabilityConfidence::Low => "low",
    }
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vulnerabilities::{Vulnerability, VulnerabilityCategory, VulnerabilitySeverity};

    #[test]
    fn creates_valid_sarif_payload() {
        let vulnerability = Vulnerability::high_confidence(
            VulnerabilitySeverity::Critical,
            VulnerabilityCategory::Reentrancy,
            "Reentrancy Vulnerability".to_string(),
            "Potential reentrancy attack".to_string(),
            42,
            "msg.sender.call{value: amount}(\"\")".to_string(),
            "Use ReentrancyGuard".to_string(),
        );

        let report = SarifReport::new(
            vec![(PathBuf::from("test.sol"), vec![vulnerability])],
            "0.8.1",
        );

        assert_eq!(report.version, "2.1.0");
        assert_eq!(report.runs.len(), 1);
        assert_eq!(report.runs[0].results.len(), 1);
        assert_eq!(report.runs[0].results[0].rule_id, "SWC-107");
        assert_eq!(report.runs[0].results[0].level, "error");
    }
}
