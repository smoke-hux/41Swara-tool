//! AST Analysis Bridge
//!
//! Coordinates the AST parser, CFG builder, and taint analyzer into a unified
//! analysis pipeline. Produces Vulnerability structs compatible with the main scanner.

use crate::ast::cfg::CFGBuilder;
use crate::ast::dataflow::{DataFlowAnalyzer, TaintSink, TaintSource};
use crate::ast::parser::ASTParser;
use crate::vulnerabilities::{
    Vulnerability, VulnerabilityCategory, VulnerabilityConfidence, VulnerabilitySeverity,
};

/// Bridge between raw source content and structured AST+CFG+taint analysis.
pub struct ASTAnalysisBridge {
    ast_parser: ASTParser,
}

impl ASTAnalysisBridge {
    pub fn new() -> Self {
        Self {
            ast_parser: ASTParser::new(),
        }
    }

    /// Run full structural analysis: AST parse -> CFG reentrancy -> taint tracking.
    pub fn analyze(&self, content: &str) -> Vec<Vulnerability> {
        let mut findings = Vec::new();

        // Parse source into AST
        let ast = self.ast_parser.parse(content);

        if ast.contracts.is_empty() {
            return findings;
        }

        // Run taint analysis across all contracts
        let mut taint_analyzer = DataFlowAnalyzer::new();
        let taint_results = taint_analyzer.analyze(&ast);

        // Convert dangerous taint flows to vulnerability findings
        for result in taint_results {
            if let Some(vuln) = self.taint_to_vulnerability(&result, content) {
                findings.push(vuln);
            }
        }

        // Build CFG for each function and run reentrancy detection
        for contract in &ast.contracts {
            for function in &contract.functions {
                let mut cfg_builder = CFGBuilder::new();
                let cfg = cfg_builder.build_cfg(function);

                // Path-sensitive reentrancy detection (CEI violation on all paths)
                let reentrancy_patterns = cfg.find_reentrancy_patterns();
                for (call_line, write_line) in reentrancy_patterns {
                    let snippet = get_line_content(content, call_line);
                    findings.push(Vulnerability {
                        severity: VulnerabilitySeverity::High,
                        category: VulnerabilityCategory::Reentrancy,
                        title: "CFG-Confirmed: State Change After External Call".to_string(),
                        description: format!(
                            "Path-sensitive analysis confirms external call at line {} \
                             followed by state write at line {} in function '{}'. \
                             All execution paths through this function exhibit this pattern.",
                            call_line, write_line, function.name
                        ),
                        line_number: call_line,
                        end_line_number: Some(write_line),
                        code_snippet: snippet,
                        context_before: None,
                        context_after: None,
                        recommendation: "Apply checks-effects-interactions (CEI) pattern: \
                            move all state changes before external calls, or use a \
                            ReentrancyGuard modifier."
                            .to_string(),
                        confidence: VulnerabilityConfidence::High,
                        confidence_percent: 90,
                        swc_id: Some(crate::vulnerabilities::SwcId {
                            id: "SWC-107".to_string(),
                            title: "Reentrancy".to_string(),
                            cwe_id: Some("CWE-841".to_string()),
                        }),
                        fix_suggestion: Some(
                            "// Move state changes before external call:\n\
                             balances[msg.sender] = 0; // effect first\n\
                             (bool success,) = msg.sender.call{value: amount}(\"\"); // then interact"
                                .to_string(),
                        ),
                        cvss_score: None,
                        cvss_vector: None,
                        exploit_references: Vec::new(),
                        attack_path: None,
                    });
                }
            }
        }

        findings
    }

    /// Convert a taint analysis result to a Vulnerability finding.
    /// Only converts genuinely dangerous flows (delegatecall, selfdestruct, create2).
    fn taint_to_vulnerability(
        &self,
        result: &crate::ast::dataflow::TaintResult,
        content: &str,
    ) -> Option<Vulnerability> {
        let (severity, category, title) = match (&result.source, &result.sink) {
            // Critical: user-controlled delegatecall target
            (
                TaintSource::FunctionParameter(_) | TaintSource::Calldata,
                TaintSink::DelegateCall,
            ) => (
                VulnerabilitySeverity::Critical,
                VulnerabilityCategory::DelegateCalls,
                "Taint Flow: User Input to DelegateCall".to_string(),
            ),
            // Critical: user-controlled selfdestruct
            (_, TaintSink::Selfdestruct) => (
                VulnerabilitySeverity::Critical,
                VulnerabilityCategory::UnsafeExternalCalls,
                "Taint Flow: Unvalidated Selfdestruct".to_string(),
            ),
            // High: user-controlled external call target
            (
                TaintSource::FunctionParameter(_) | TaintSource::Calldata,
                TaintSink::ExternalCall,
            ) => (
                VulnerabilitySeverity::High,
                VulnerabilityCategory::UnsafeExternalCalls,
                "Taint Flow: User Input to External Call".to_string(),
            ),
            // High: user-controlled CREATE2 salt
            (TaintSource::FunctionParameter(_), TaintSink::Create2) => (
                VulnerabilitySeverity::High,
                VulnerabilityCategory::LogicError,
                "Taint Flow: User Input to CREATE2".to_string(),
            ),
            // Medium: unvalidated array index from external input
            (TaintSource::FunctionParameter(_) | TaintSource::Calldata, TaintSink::ArrayIndex) => (
                VulnerabilitySeverity::Medium,
                VulnerabilityCategory::InputValidationFailure,
                "Taint Flow: Unvalidated Array Index".to_string(),
            ),
            // Skip less dangerous flows to avoid noise
            _ => return None,
        };

        let snippet = get_line_content(content, result.sink_line);

        Some(Vulnerability {
            severity,
            category,
            title,
            description: result.description.clone(),
            line_number: result.sink_line,
            end_line_number: None,
            code_snippet: snippet,
            context_before: None,
            context_after: None,
            recommendation: format!(
                "Validate all user-controlled inputs before use. Taint path: {}",
                result.path.join(" -> ")
            ),
            confidence: VulnerabilityConfidence::Medium,
            confidence_percent: 70,
            swc_id: None,
            fix_suggestion: None,
            cvss_score: None,
            cvss_vector: None,
            exploit_references: Vec::new(),
            attack_path: None,
        })
    }
}

/// Get a line's content from the source (1-indexed).
fn get_line_content(content: &str, line: usize) -> String {
    content
        .lines()
        .nth(line.saturating_sub(1))
        .unwrap_or("")
        .trim()
        .to_string()
}
