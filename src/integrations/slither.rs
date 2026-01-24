//! Slither Integration
//!
//! Provides integration with Trail of Bits' Slither analyzer:
//! - Parse Slither JSON output
//! - Correlate findings (both found = high confidence)
//! - Merge unique findings from each tool
//! - Unified report generation

#![allow(dead_code)]
#![allow(unused_imports)]

use serde::Deserialize;
use std::collections::HashSet;
use std::fs::File;
use std::io::BufReader;
use std::path::Path;

use crate::vulnerabilities::{Vulnerability, VulnerabilitySeverity, VulnerabilityCategory, VulnerabilityConfidence};

/// Slither JSON output structure
#[derive(Debug, Deserialize)]
pub struct SlitherOutput {
    pub success: bool,
    pub error: Option<String>,
    pub results: Option<SlitherResults>,
}

#[derive(Debug, Deserialize)]
pub struct SlitherResults {
    pub detectors: Vec<SlitherFinding>,
    pub printers: Option<Vec<serde_json::Value>>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SlitherFinding {
    pub check: String,
    pub impact: String,
    pub confidence: String,
    pub description: String,
    pub elements: Vec<SlitherElement>,
    pub first_markdown_element: Option<String>,
    pub id: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SlitherElement {
    #[serde(rename = "type")]
    pub element_type: String,
    pub name: String,
    pub source_mapping: Option<SourceMapping>,
    pub type_specific_fields: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SourceMapping {
    pub start: usize,
    pub length: usize,
    pub filename_relative: Option<String>,
    pub filename_absolute: Option<String>,
    pub lines: Option<Vec<usize>>,
}

/// Result of correlating 41Swara findings with Slither
#[derive(Debug)]
pub struct CorrelatedFinding {
    pub swara_finding: Option<Vulnerability>,
    pub slither_finding: Option<SlitherFinding>,
    pub correlation: CorrelationType,
    pub adjusted_confidence: f64,
    pub unified_severity: VulnerabilitySeverity,
}

#[derive(Debug, Clone, PartialEq)]
pub enum CorrelationType {
    /// Both tools found the same issue (highest confidence)
    BothFound,
    /// Only 41Swara found this issue
    SwaraOnly,
    /// Only Slither found this issue
    SlitherOnly,
    /// Similar but not identical findings
    Similar,
}

/// Slither integration handler
pub struct SlitherIntegration {
    slither_findings: Vec<SlitherFinding>,
}

impl SlitherIntegration {
    pub fn new() -> Self {
        Self {
            slither_findings: Vec::new(),
        }
    }

    /// Convert VulnerabilityConfidence to f64 score
    fn confidence_to_score(&self, confidence: &VulnerabilityConfidence) -> f64 {
        match confidence {
            VulnerabilityConfidence::High => 0.9,
            VulnerabilityConfidence::Medium => 0.7,
            VulnerabilityConfidence::Low => 0.5,
        }
    }

    /// Convert f64 score to VulnerabilityConfidence
    fn score_to_confidence(&self, score: f64) -> VulnerabilityConfidence {
        if score >= 0.8 {
            VulnerabilityConfidence::High
        } else if score >= 0.6 {
            VulnerabilityConfidence::Medium
        } else {
            VulnerabilityConfidence::Low
        }
    }

    /// Load Slither findings from JSON file
    pub fn load_from_file(&mut self, path: &Path) -> Result<usize, String> {
        let file = File::open(path)
            .map_err(|e| format!("Failed to open Slither JSON: {}", e))?;
        let reader = BufReader::new(file);

        let output: SlitherOutput = serde_json::from_reader(reader)
            .map_err(|e| format!("Failed to parse Slither JSON: {}", e))?;

        if !output.success {
            return Err(format!("Slither analysis failed: {:?}", output.error));
        }

        self.slither_findings = output.results
            .map(|r| r.detectors)
            .unwrap_or_default();

        Ok(self.slither_findings.len())
    }

    /// Load findings from JSON string
    pub fn load_from_string(&mut self, json: &str) -> Result<usize, String> {
        let output: SlitherOutput = serde_json::from_str(json)
            .map_err(|e| format!("Failed to parse Slither JSON: {}", e))?;

        if !output.success {
            return Err(format!("Slither analysis failed: {:?}", output.error));
        }

        self.slither_findings = output.results
            .map(|r| r.detectors)
            .unwrap_or_default();

        Ok(self.slither_findings.len())
    }

    /// Correlate 41Swara findings with Slither findings
    pub fn correlate(&self, swara_findings: &[Vulnerability]) -> Vec<CorrelatedFinding> {
        let mut results = Vec::new();
        let mut matched_slither: HashSet<usize> = HashSet::new();

        // First pass: Match Swara findings with Slither
        for swara in swara_findings {
            let mut best_match: Option<(usize, f64)> = None;

            for (idx, slither) in self.slither_findings.iter().enumerate() {
                if matched_slither.contains(&idx) {
                    continue;
                }

                let similarity = self.calculate_similarity(swara, slither);
                if similarity > 0.7 {
                    if best_match.is_none() || similarity > best_match.unwrap().1 {
                        best_match = Some((idx, similarity));
                    }
                }
            }

            if let Some((idx, similarity)) = best_match {
                matched_slither.insert(idx);
                let slither = &self.slither_findings[idx];

                results.push(CorrelatedFinding {
                    swara_finding: Some(swara.clone()),
                    slither_finding: Some(slither.clone()),
                    correlation: if similarity > 0.9 {
                        CorrelationType::BothFound
                    } else {
                        CorrelationType::Similar
                    },
                    adjusted_confidence: self.calculate_combined_confidence(swara, slither),
                    unified_severity: self.get_unified_severity(swara.severity.clone(), &slither.impact),
                });
            } else {
                results.push(CorrelatedFinding {
                    swara_finding: Some(swara.clone()),
                    slither_finding: None,
                    correlation: CorrelationType::SwaraOnly,
                    adjusted_confidence: self.confidence_to_score(&swara.confidence),
                    unified_severity: swara.severity.clone(),
                });
            }
        }

        // Second pass: Add unmatched Slither findings
        for (idx, slither) in self.slither_findings.iter().enumerate() {
            if !matched_slither.contains(&idx) {
                results.push(CorrelatedFinding {
                    swara_finding: None,
                    slither_finding: Some(slither.clone()),
                    correlation: CorrelationType::SlitherOnly,
                    adjusted_confidence: self.slither_confidence_to_score(&slither.confidence),
                    unified_severity: self.slither_impact_to_severity(&slither.impact),
                });
            }
        }

        results
    }

    /// Calculate similarity between a Swara finding and Slither finding
    fn calculate_similarity(&self, swara: &Vulnerability, slither: &SlitherFinding) -> f64 {
        let mut score = 0.0;
        let mut factors = 0.0;

        // Category/Check matching
        let category_match = self.categories_match(&swara.category, &slither.check);
        score += if category_match { 0.4 } else { 0.0 };
        factors += 0.4;

        // Line number matching
        if let Some(line) = slither.elements.first()
            .and_then(|e| e.source_mapping.as_ref())
            .and_then(|sm| sm.lines.as_ref())
            .and_then(|l| l.first())
        {
            let line_diff = (swara.line_number as i64 - *line as i64).abs();
            if line_diff == 0 {
                score += 0.3;
            } else if line_diff <= 5 {
                score += 0.2;
            } else if line_diff <= 20 {
                score += 0.1;
            }
        }
        factors += 0.3;

        // Description similarity (simple word overlap)
        let swara_desc_lower = swara.description.to_lowercase();
        let slither_desc_lower = slither.description.to_lowercase();

        let swara_words: HashSet<&str> = swara_desc_lower
            .split_whitespace()
            .filter(|w| w.len() > 3)
            .collect();
        let slither_words: HashSet<&str> = slither_desc_lower
            .split_whitespace()
            .filter(|w| w.len() > 3)
            .collect();

        let intersection = swara_words.intersection(&slither_words).count();
        let union = swara_words.union(&slither_words).count();
        if union > 0 {
            score += 0.3 * (intersection as f64 / union as f64);
        }
        factors += 0.3;

        score / factors
    }

    /// Check if vulnerability categories match
    fn categories_match(&self, swara_cat: &VulnerabilityCategory, slither_check: &str) -> bool {
        let slither_lower = slither_check.to_lowercase();

        match swara_cat {
            VulnerabilityCategory::Reentrancy | VulnerabilityCategory::CallbackReentrancy => {
                slither_lower.contains("reentrancy") || slither_lower.contains("reentrant")
            }
            VulnerabilityCategory::AccessControl => {
                slither_lower.contains("access") ||
                slither_lower.contains("protected") ||
                slither_lower.contains("unprotected") ||
                slither_lower.contains("arbitrary") ||
                slither_lower.contains("suicidal")
            }
            VulnerabilityCategory::ArithmeticIssues => {
                slither_lower.contains("divide") ||
                slither_lower.contains("overflow") ||
                slither_lower.contains("underflow")
            }
            VulnerabilityCategory::UncheckedReturnValues => {
                slither_lower.contains("unchecked") ||
                slither_lower.contains("low-level") ||
                slither_lower.contains("return")
            }
            VulnerabilityCategory::DelegateCalls => {
                slither_lower.contains("delegatecall") ||
                slither_lower.contains("controlled")
            }
            VulnerabilityCategory::OracleManipulation => {
                slither_lower.contains("oracle") ||
                slither_lower.contains("price")
            }
            VulnerabilityCategory::GasOptimization => {
                slither_lower.contains("gas") ||
                slither_lower.contains("costly") ||
                slither_lower.contains("dead-code")
            }
            _ => false
        }
    }

    /// Calculate combined confidence when both tools find the issue
    fn calculate_combined_confidence(&self, swara: &Vulnerability, slither: &SlitherFinding) -> f64 {
        let swara_conf = self.confidence_to_score(&swara.confidence);
        let slither_conf = self.slither_confidence_to_score(&slither.confidence);

        // Both tools finding = higher confidence (but not just summing)
        let base = (swara_conf + slither_conf) / 2.0;
        let boost = 0.15; // Correlation boost

        (base + boost).min(1.0)
    }

    /// Convert Slither confidence string to numeric score
    fn slither_confidence_to_score(&self, confidence: &str) -> f64 {
        match confidence.to_lowercase().as_str() {
            "high" => 0.9,
            "medium" => 0.7,
            "low" => 0.5,
            _ => 0.6,
        }
    }

    /// Get unified severity when both tools report
    fn get_unified_severity(
        &self,
        swara: VulnerabilitySeverity,
        slither_impact: &str,
    ) -> VulnerabilitySeverity {
        let slither_sev = self.slither_impact_to_severity(slither_impact);

        // Take the more severe of the two
        match (swara, slither_sev) {
            (VulnerabilitySeverity::Critical, _) | (_, VulnerabilitySeverity::Critical) => {
                VulnerabilitySeverity::Critical
            }
            (VulnerabilitySeverity::High, _) | (_, VulnerabilitySeverity::High) => {
                VulnerabilitySeverity::High
            }
            (VulnerabilitySeverity::Medium, _) | (_, VulnerabilitySeverity::Medium) => {
                VulnerabilitySeverity::Medium
            }
            (VulnerabilitySeverity::Low, _) | (_, VulnerabilitySeverity::Low) => {
                VulnerabilitySeverity::Low
            }
            _ => VulnerabilitySeverity::Info,
        }
    }

    /// Convert Slither impact to severity
    fn slither_impact_to_severity(&self, impact: &str) -> VulnerabilitySeverity {
        match impact.to_lowercase().as_str() {
            "high" => VulnerabilitySeverity::High,
            "medium" => VulnerabilitySeverity::Medium,
            "low" => VulnerabilitySeverity::Low,
            "informational" => VulnerabilitySeverity::Info,
            "optimization" => VulnerabilitySeverity::Info,
            _ => VulnerabilitySeverity::Medium,
        }
    }

    /// Generate unified report from correlated findings
    pub fn generate_unified_report(&self, correlations: &[CorrelatedFinding]) -> String {
        let mut report = String::new();

        report.push_str("# Unified Security Analysis Report\n\n");
        report.push_str("## Tools Used\n");
        report.push_str("- 41Swara Smart Contract Scanner\n");
        report.push_str("- Trail of Bits Slither\n\n");

        // Statistics
        let both_found = correlations.iter()
            .filter(|c| c.correlation == CorrelationType::BothFound)
            .count();
        let similar = correlations.iter()
            .filter(|c| c.correlation == CorrelationType::Similar)
            .count();
        let swara_only = correlations.iter()
            .filter(|c| c.correlation == CorrelationType::SwaraOnly)
            .count();
        let slither_only = correlations.iter()
            .filter(|c| c.correlation == CorrelationType::SlitherOnly)
            .count();

        report.push_str("## Correlation Statistics\n\n");
        report.push_str("| Category | Count |\n");
        report.push_str("|----------|-------|\n");
        report.push_str(&format!("| Both Tools Found (High Confidence) | {} |\n", both_found));
        report.push_str(&format!("| Similar Findings | {} |\n", similar));
        report.push_str(&format!("| 41Swara Only | {} |\n", swara_only));
        report.push_str(&format!("| Slither Only | {} |\n", slither_only));
        report.push_str(&format!("| **Total Unique** | **{}** |\n\n", correlations.len()));

        // High confidence findings (both found)
        if both_found > 0 || similar > 0 {
            report.push_str("## High Confidence Findings (Corroborated)\n\n");
            report.push_str("These issues were detected by both tools:\n\n");

            for (idx, corr) in correlations.iter()
                .filter(|c| c.correlation == CorrelationType::BothFound || c.correlation == CorrelationType::Similar)
                .enumerate()
            {
                report.push_str(&format!("### HCF-{:02}: ", idx + 1));

                if let Some(swara) = &corr.swara_finding {
                    report.push_str(&format!("{}\n\n", swara.title));
                    report.push_str(&format!("**Severity:** {:?}\n", corr.unified_severity));
                    report.push_str(&format!("**Confidence:** {:.0}% (corroborated)\n", corr.adjusted_confidence * 100.0));
                    report.push_str(&format!("**41Swara:** {}\n", swara.description));
                }

                if let Some(slither) = &corr.slither_finding {
                    report.push_str(&format!("**Slither ({}):** {}\n\n", slither.check, slither.description));
                }

                report.push_str("---\n\n");
            }
        }

        // Swara-only findings
        if swara_only > 0 {
            report.push_str("## 41Swara-Only Findings\n\n");
            report.push_str("These issues were found by 41Swara's advanced analysis:\n\n");

            for (idx, corr) in correlations.iter()
                .filter(|c| c.correlation == CorrelationType::SwaraOnly)
                .enumerate()
            {
                if let Some(swara) = &corr.swara_finding {
                    report.push_str(&format!("### S-{:02}: {}\n\n", idx + 1, swara.title));
                    report.push_str(&format!("**Severity:** {:?}\n", swara.severity));
                    report.push_str(&format!("**Confidence:** {:?}\n", swara.confidence));
                    report.push_str(&format!("**Description:** {}\n", swara.description));
                    report.push_str(&format!("**Line:** {}\n\n", swara.line_number));
                }
            }
        }

        // Slither-only findings
        if slither_only > 0 {
            report.push_str("## Slither-Only Findings\n\n");
            report.push_str("These issues were found by Slither:\n\n");

            for (idx, corr) in correlations.iter()
                .filter(|c| c.correlation == CorrelationType::SlitherOnly)
                .enumerate()
            {
                if let Some(slither) = &corr.slither_finding {
                    report.push_str(&format!("### L-{:02}: {} ({})\n\n", idx + 1, slither.check, slither.impact));
                    report.push_str(&format!("**Description:** {}\n\n", slither.description));
                }
            }
        }

        report
    }

    /// Convert Slither finding to 41Swara Vulnerability format
    pub fn convert_to_vulnerability(&self, slither: &SlitherFinding) -> Vulnerability {
        let severity = self.slither_impact_to_severity(&slither.impact);
        let confidence_score = self.slither_confidence_to_score(&slither.confidence);

        let line_number = slither.elements.first()
            .and_then(|e| e.source_mapping.as_ref())
            .and_then(|sm| sm.lines.as_ref())
            .and_then(|l| l.first())
            .copied()
            .unwrap_or(1);

        let code_snippet = slither.elements.first()
            .map(|e| e.name.clone())
            .unwrap_or_default();

        let category = self.slither_check_to_category(&slither.check);
        let swc_id = category.get_swc_id();
        let confidence = self.score_to_confidence(confidence_score);
        Vulnerability {
            title: format!("[Slither] {}", slither.check),
            description: slither.description.clone(),
            severity,
            category,
            line_number,
            end_line_number: None,
            code_snippet,
            context_before: None,
            context_after: None,
            recommendation: format!("See Slither detector '{}' for remediation guidance", slither.check),
            confidence_percent: confidence.to_percent(),
            confidence,
            swc_id,
            fix_suggestion: None,
        }
    }

    /// Map Slither check name to vulnerability category
    fn slither_check_to_category(&self, check: &str) -> VulnerabilityCategory {
        let check_lower = check.to_lowercase();

        if check_lower.contains("reentrancy") {
            VulnerabilityCategory::Reentrancy
        } else if check_lower.contains("arbitrary") || check_lower.contains("suicidal") || check_lower.contains("unprotected") {
            VulnerabilityCategory::AccessControl
        } else if check_lower.contains("unchecked") || check_lower.contains("low-level") {
            VulnerabilityCategory::UncheckedReturnValues
        } else if check_lower.contains("delegatecall") {
            VulnerabilityCategory::DelegateCalls
        } else if check_lower.contains("timestamp") {
            VulnerabilityCategory::TimeManipulation
        } else if check_lower.contains("assembly") {
            VulnerabilityCategory::AssemblyUsage
        } else if check_lower.contains("optimization") || check_lower.contains("gas") {
            VulnerabilityCategory::GasOptimization
        } else {
            VulnerabilityCategory::LogicError
        }
    }

    /// Get number of loaded Slither findings
    pub fn finding_count(&self) -> usize {
        self.slither_findings.len()
    }
}

impl Default for SlitherIntegration {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_confidence_conversion() {
        let integration = SlitherIntegration::new();

        assert_eq!(integration.slither_confidence_to_score("High"), 0.9);
        assert_eq!(integration.slither_confidence_to_score("Medium"), 0.7);
        assert_eq!(integration.slither_confidence_to_score("Low"), 0.5);
    }

    #[test]
    fn test_impact_conversion() {
        let integration = SlitherIntegration::new();

        assert_eq!(
            integration.slither_impact_to_severity("High"),
            VulnerabilitySeverity::High
        );
        assert_eq!(
            integration.slither_impact_to_severity("Medium"),
            VulnerabilitySeverity::Medium
        );
    }
}
