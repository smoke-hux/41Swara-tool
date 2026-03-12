//! TOML Configuration Module
//!
//! Supports `.41swara.toml` configuration files for:
//! - Custom vulnerability detection rules (regex-based)
//! - Severity overrides for built-in rules
//! - Rule disabling
//! - Scan settings (confidence threshold, exclude patterns, library trust)

#![allow(dead_code)]

use regex::Regex;
use serde::Deserialize;
use std::path::{Path, PathBuf};

use crate::vulnerabilities::{VulnerabilityCategory, VulnerabilityRule, VulnerabilitySeverity};

/// A custom vulnerability detection rule loaded from TOML config.
#[derive(Debug, Clone, Deserialize)]
pub struct CustomRule {
    /// Unique identifier (e.g., "PROJ-001")
    pub id: String,
    /// Human-readable title
    pub title: String,
    /// Detailed description of the vulnerability
    pub description: String,
    /// Severity: "Critical", "High", "Medium", "Low", "Info"
    pub severity: String,
    /// Regex pattern to match
    pub pattern: String,
    /// Whether pattern spans multiple lines
    #[serde(default)]
    pub multiline: bool,
    /// Remediation advice
    pub recommendation: String,
    /// Optional SWC ID mapping
    pub swc_id: Option<String>,
    /// Whether this rule is enabled (default: true)
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Confidence percentage override (0-100)
    pub confidence: Option<u8>,
}

/// Severity override for a built-in rule.
#[derive(Debug, Clone, Deserialize)]
pub struct SeverityOverride {
    /// Rule ID to override (e.g., "SWC-107", "41S-050")
    pub rule_id: String,
    /// New severity: "Critical", "High", "Medium", "Low", "Info"
    pub severity: Option<String>,
    /// Disable the rule entirely
    pub enabled: Option<bool>,
}

/// Global scanner settings from config.
#[derive(Debug, Clone, Deserialize, Default)]
#[allow(dead_code)]
pub struct ScanSettings {
    /// Minimum confidence threshold (0-100)
    pub min_confidence: Option<u8>,
    /// Trust OpenZeppelin libraries
    pub trust_openzeppelin: Option<bool>,
    /// Trust Solmate libraries
    pub trust_solmate: Option<bool>,
    /// Trust Solady libraries
    pub trust_solady: Option<bool>,
    /// File patterns to always exclude
    #[serde(default)]
    pub exclude: Vec<String>,
}

/// Root configuration loaded from `.41swara.toml`.
#[derive(Debug, Deserialize, Default)]
#[allow(dead_code)]
pub struct ScanConfig {
    /// Custom detection rules
    #[serde(default)]
    pub rules: Vec<CustomRule>,
    /// Severity/enablement overrides for built-in rules
    #[serde(default)]
    pub overrides: Vec<SeverityOverride>,
    /// Global settings
    #[serde(default)]
    pub settings: ScanSettings,
}

impl ScanConfig {
    /// Load configuration from a TOML file.
    pub fn load_from_file(path: &Path) -> Result<Self, String> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("Failed to read config '{}': {}", path.display(), e))?;
        toml::from_str(&content)
            .map_err(|e| format!("Failed to parse config '{}': {}", path.display(), e))
    }

    /// Walk up from `start` directory looking for `.41swara.toml`.
    pub fn find_config(start: &Path) -> Option<PathBuf> {
        let mut dir = if start.is_file() {
            start.parent()?.to_path_buf()
        } else {
            start.to_path_buf()
        };
        loop {
            let candidate = dir.join(".41swara.toml");
            if candidate.exists() {
                return Some(candidate);
            }
            if !dir.pop() {
                return None;
            }
        }
    }

    /// Convert custom rules into VulnerabilityRule structs for the scanner.
    pub fn compile_custom_rules(&self) -> Vec<VulnerabilityRule> {
        self.rules
            .iter()
            .filter(|r| r.enabled)
            .filter_map(|r| match r.to_vulnerability_rule() {
                Ok(rule) => Some(rule),
                Err(e) => {
                    eprintln!("Warning: Skipping custom rule '{}': {}", r.id, e);
                    None
                }
            })
            .collect()
    }

    /// Get set of rule IDs that should be disabled.
    pub fn disabled_rule_ids(&self) -> std::collections::HashSet<String> {
        self.overrides
            .iter()
            .filter(|o| o.enabled == Some(false))
            .map(|o| o.rule_id.clone())
            .collect()
    }

    /// Get severity override for a rule ID (if any).
    pub fn severity_override(&self, rule_id: &str) -> Option<VulnerabilitySeverity> {
        self.overrides
            .iter()
            .find(|o| o.rule_id == rule_id)
            .and_then(|o| o.severity.as_ref())
            .and_then(|s| parse_severity(s))
    }
}

impl CustomRule {
    /// Convert this custom rule into a scanner VulnerabilityRule.
    pub fn to_vulnerability_rule(&self) -> Result<VulnerabilityRule, String> {
        let pattern_str = if self.multiline {
            format!("(?s){}", self.pattern)
        } else {
            self.pattern.clone()
        };

        let pattern = Regex::new(&pattern_str)
            .map_err(|e| format!("Invalid regex '{}': {}", self.pattern, e))?;

        let severity = parse_severity(&self.severity).unwrap_or(VulnerabilitySeverity::Medium);

        Ok(VulnerabilityRule {
            category: VulnerabilityCategory::LogicError,
            severity,
            pattern,
            title: self.title.clone(),
            description: self.description.clone(),
            recommendation: self.recommendation.clone(),
            multiline: self.multiline,
        })
    }
}

fn parse_severity(s: &str) -> Option<VulnerabilitySeverity> {
    match s {
        "Critical" => Some(VulnerabilitySeverity::Critical),
        "High" => Some(VulnerabilitySeverity::High),
        "Medium" => Some(VulnerabilitySeverity::Medium),
        "Low" => Some(VulnerabilitySeverity::Low),
        "Info" => Some(VulnerabilitySeverity::Info),
        _ => None,
    }
}

fn default_true() -> bool {
    true
}
