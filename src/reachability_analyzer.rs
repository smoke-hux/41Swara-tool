//! Reachability Analyzer
//!
//! Validates whether detected vulnerabilities are actually reachable through
//! call paths from external entry points. This significantly reduces false positives
//! by filtering out vulnerabilities in dead code or unreachable functions.

#![allow(dead_code)]

use std::collections::{HashMap, HashSet, VecDeque};
use regex::Regex;
use crate::vulnerabilities::Vulnerability;

/// Represents a node in the call graph
#[derive(Debug, Clone)]
pub struct CallGraphNode {
    pub name: String,
    pub visibility: Visibility,
    pub calls: Vec<String>,
    pub modifiers: Vec<String>,
    pub line: usize,
    pub is_constructor: bool,
    pub is_fallback: bool,
    pub is_receive: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Visibility {
    External,
    Public,
    Internal,
    Private,
}

/// Call graph for the contract
#[derive(Debug)]
pub struct CallGraph {
    pub nodes: HashMap<String, CallGraphNode>,
    pub entry_points: Vec<String>,
    pub inheritance_chain: Vec<String>,
}

/// Reachability analysis result for a vulnerability
#[derive(Debug, Clone)]
pub struct ReachabilityResult {
    pub is_reachable: bool,
    pub call_paths: Vec<Vec<String>>,
    pub entry_points: Vec<String>,
    pub confidence_adjustment: i8, // -30 to +30 adjustment to confidence
    pub reason: String,
}

pub struct ReachabilityAnalyzer {
    verbose: bool,
}

impl ReachabilityAnalyzer {
    pub fn new(verbose: bool) -> Self {
        Self { verbose }
    }

    /// Build a call graph from contract source code
    pub fn build_call_graph(&self, content: &str) -> CallGraph {
        let mut nodes = HashMap::new();
        let mut entry_points = Vec::new();
        let inheritance_chain = self.extract_inheritance(content);

        // Extract all functions
        let func_pattern = Regex::new(
            r"function\s+(\w+)\s*\(([^)]*)\)\s*((?:external|public|internal|private|view|pure|payable|virtual|override|\s|,)*)"
        ).unwrap();

        let constructor_pattern = Regex::new(r"constructor\s*\(").unwrap();
        let fallback_pattern = Regex::new(r"fallback\s*\(\s*\)").unwrap();
        let receive_pattern = Regex::new(r"receive\s*\(\s*\)\s*external\s*payable").unwrap();

        let lines: Vec<&str> = content.lines().collect();

        for (idx, line) in lines.iter().enumerate() {
            // Check for constructor
            if constructor_pattern.is_match(line) {
                let calls = self.extract_function_calls(&lines, idx);
                nodes.insert("constructor".to_string(), CallGraphNode {
                    name: "constructor".to_string(),
                    visibility: Visibility::Public,
                    calls,
                    modifiers: vec![],
                    line: idx + 1,
                    is_constructor: true,
                    is_fallback: false,
                    is_receive: false,
                });
                entry_points.push("constructor".to_string());
            }

            // Check for fallback
            if fallback_pattern.is_match(line) {
                let calls = self.extract_function_calls(&lines, idx);
                nodes.insert("fallback".to_string(), CallGraphNode {
                    name: "fallback".to_string(),
                    visibility: Visibility::External,
                    calls,
                    modifiers: vec![],
                    line: idx + 1,
                    is_constructor: false,
                    is_fallback: true,
                    is_receive: false,
                });
                entry_points.push("fallback".to_string());
            }

            // Check for receive
            if receive_pattern.is_match(line) {
                let calls = self.extract_function_calls(&lines, idx);
                nodes.insert("receive".to_string(), CallGraphNode {
                    name: "receive".to_string(),
                    visibility: Visibility::External,
                    calls,
                    modifiers: vec![],
                    line: idx + 1,
                    is_constructor: false,
                    is_fallback: false,
                    is_receive: true,
                });
                entry_points.push("receive".to_string());
            }

            // Check for regular functions
            if let Some(caps) = func_pattern.captures(line) {
                let name = caps.get(1).map_or("", |m| m.as_str()).to_string();
                let modifiers_str = caps.get(3).map_or("", |m| m.as_str());

                let visibility = if modifiers_str.contains("external") {
                    Visibility::External
                } else if modifiers_str.contains("public") {
                    Visibility::Public
                } else if modifiers_str.contains("internal") {
                    Visibility::Internal
                } else if modifiers_str.contains("private") {
                    Visibility::Private
                } else {
                    Visibility::Public // default
                };

                let calls = self.extract_function_calls(&lines, idx);
                let modifiers = self.extract_modifiers(line);

                let is_entry_point = matches!(visibility, Visibility::External | Visibility::Public);

                if is_entry_point {
                    entry_points.push(name.clone());
                }

                nodes.insert(name.clone(), CallGraphNode {
                    name,
                    visibility,
                    calls,
                    modifiers,
                    line: idx + 1,
                    is_constructor: false,
                    is_fallback: false,
                    is_receive: false,
                });
            }
        }

        CallGraph {
            nodes,
            entry_points,
            inheritance_chain,
        }
    }

    /// Extract inheritance chain from contract
    fn extract_inheritance(&self, content: &str) -> Vec<String> {
        let inherit_pattern = Regex::new(r"contract\s+\w+\s+is\s+([^{]+)").unwrap();

        if let Some(caps) = inherit_pattern.captures(content) {
            let parents = caps.get(1).map_or("", |m| m.as_str());
            return parents.split(',')
                .map(|p| p.trim().split('(').next().unwrap_or("").trim().to_string())
                .filter(|p| !p.is_empty())
                .collect();
        }

        vec![]
    }

    /// Extract function calls from a function body
    fn extract_function_calls(&self, lines: &[&str], start_idx: usize) -> Vec<String> {
        let mut calls = Vec::new();
        let call_pattern = Regex::new(r"\b([a-z_]\w*)\s*\(").unwrap();

        // Keywords to exclude
        let keywords: HashSet<&str> = [
            "if", "for", "while", "require", "assert", "revert", "emit",
            "return", "new", "delete", "mapping", "memory", "storage",
            "calldata", "bytes", "string", "uint", "int", "bool", "address"
        ].iter().cloned().collect();

        let mut brace_count = 0;
        let mut started = false;

        for line in lines.iter().skip(start_idx).take(100) {
            for ch in line.chars() {
                if ch == '{' {
                    brace_count += 1;
                    started = true;
                } else if ch == '}' {
                    brace_count -= 1;
                }
            }

            // Find function calls in this line
            for caps in call_pattern.captures_iter(line) {
                if let Some(name) = caps.get(1) {
                    let func_name = name.as_str();
                    if !keywords.contains(func_name) && !calls.contains(&func_name.to_string()) {
                        calls.push(func_name.to_string());
                    }
                }
            }

            if started && brace_count == 0 {
                break;
            }
        }

        calls
    }

    /// Extract modifiers from function signature
    fn extract_modifiers(&self, line: &str) -> Vec<String> {
        let modifier_pattern = Regex::new(r"\b(only\w+|nonReentrant|whenNotPaused|whenPaused|initializer)\b").unwrap();

        modifier_pattern.captures_iter(line)
            .filter_map(|c| c.get(1))
            .map(|m| m.as_str().to_string())
            .collect()
    }

    /// Check if a line number is reachable from any entry point
    pub fn is_line_reachable(&self, call_graph: &CallGraph, target_line: usize, content: &str) -> ReachabilityResult {
        // First, find which function contains this line
        let target_function = self.find_function_at_line(call_graph, target_line, content);

        if target_function.is_none() {
            // Lines outside functions (pragma, state variables, imports, etc.) are
            // always reachable — they're contract-level declarations, not dead code.
            return ReachabilityResult {
                is_reachable: true,
                call_paths: vec![],
                entry_points: vec![],
                confidence_adjustment: 0,
                reason: "Contract-level declaration (outside function scope)".to_string(),
            };
        }

        let target_func = target_function.unwrap();

        // Check if the function itself is an entry point
        if call_graph.entry_points.contains(&target_func) {
            return ReachabilityResult {
                is_reachable: true,
                call_paths: vec![vec![target_func.clone()]],
                entry_points: vec![target_func],
                confidence_adjustment: 20,
                reason: "Directly callable external/public function".to_string(),
            };
        }

        // Find all paths from entry points to this function
        let paths = self.find_all_paths_to(call_graph, &target_func);

        if paths.is_empty() {
            return ReachabilityResult {
                is_reachable: false,
                call_paths: vec![],
                entry_points: vec![],
                confidence_adjustment: -25,
                reason: format!("Function '{}' is not reachable from any entry point", target_func),
            };
        }

        let entry_points: Vec<String> = paths.iter()
            .filter_map(|path| path.first().cloned())
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();

        ReachabilityResult {
            is_reachable: true,
            call_paths: paths.clone(),
            entry_points: entry_points.clone(),
            confidence_adjustment: if paths.len() > 3 { 15 } else { 10 },
            reason: format!("Reachable via {} path(s) from {} entry point(s)", paths.len(), entry_points.len()),
        }
    }

    /// Find which function contains a given line
    fn find_function_at_line(&self, call_graph: &CallGraph, line: usize, content: &str) -> Option<String> {
        let mut best_match: Option<(String, usize)> = None;

        for (name, node) in &call_graph.nodes {
            if node.line <= line {
                // Check if this is closer than current best
                if best_match.is_none() || node.line > best_match.as_ref().unwrap().1 {
                    // Verify line is within function body
                    let func_end = self.find_function_end(content, node.line);
                    if line <= func_end {
                        best_match = Some((name.clone(), node.line));
                    }
                }
            }
        }

        best_match.map(|(name, _)| name)
    }

    /// Find the end line of a function
    fn find_function_end(&self, content: &str, start_line: usize) -> usize {
        let lines: Vec<&str> = content.lines().collect();
        let mut brace_count = 0;
        let mut started = false;

        for (i, line) in lines.iter().enumerate().skip(start_line.saturating_sub(1)) {
            for ch in line.chars() {
                if ch == '{' {
                    brace_count += 1;
                    started = true;
                } else if ch == '}' {
                    brace_count -= 1;
                }
            }

            if started && brace_count == 0 {
                return i + 1;
            }
        }

        lines.len()
    }

    /// Find all paths from entry points to a target function using BFS
    fn find_all_paths_to(&self, call_graph: &CallGraph, target: &str) -> Vec<Vec<String>> {
        let mut all_paths = Vec::new();

        for entry in &call_graph.entry_points {
            let paths = self.bfs_paths(call_graph, entry, target);
            all_paths.extend(paths);
        }

        all_paths
    }

    /// BFS to find paths between two nodes
    fn bfs_paths(&self, call_graph: &CallGraph, start: &str, target: &str) -> Vec<Vec<String>> {
        let mut paths = Vec::new();
        let mut queue: VecDeque<Vec<String>> = VecDeque::new();

        queue.push_back(vec![start.to_string()]);

        while let Some(path) = queue.pop_front() {
            let current = path.last().unwrap();

            // Found target
            if current == target {
                paths.push(path);
                continue;
            }

            // Limit path length to prevent infinite loops
            if path.len() > 10 {
                continue;
            }

            // Explore neighbors
            if let Some(node) = call_graph.nodes.get(current) {
                for called in &node.calls {
                    if !path.contains(called) {
                        let mut new_path = path.clone();
                        new_path.push(called.clone());
                        queue.push_back(new_path);
                    }
                }
            }
        }

        paths
    }

    /// Filter vulnerabilities based on reachability
    pub fn filter_unreachable_vulnerabilities(
        &self,
        vulnerabilities: Vec<Vulnerability>,
        content: &str,
    ) -> Vec<Vulnerability> {
        let call_graph = self.build_call_graph(content);

        vulnerabilities.into_iter()
            .filter(|vuln| {
                let result = self.is_line_reachable(&call_graph, vuln.line_number, content);
                if !result.is_reachable && self.verbose {
                    println!("  ⚠️  Filtering unreachable vulnerability at line {}: {}",
                            vuln.line_number, result.reason);
                }
                result.is_reachable
            })
            .collect()
    }

    /// Adjust vulnerability confidence based on reachability analysis
    pub fn adjust_confidence(
        &self,
        vulnerabilities: &mut [Vulnerability],
        content: &str,
    ) {
        let call_graph = self.build_call_graph(content);

        for vuln in vulnerabilities.iter_mut() {
            let result = self.is_line_reachable(&call_graph, vuln.line_number, content);

            // Adjust confidence based on reachability
            let new_confidence = (vuln.confidence_percent as i16 + result.confidence_adjustment as i16)
                .max(0)
                .min(100) as u8;

            vuln.confidence_percent = new_confidence;
            vuln.confidence = crate::vulnerabilities::VulnerabilityConfidence::from_percent(new_confidence);

            // Add reachability info to description if verbose
            if self.verbose && result.is_reachable && !result.call_paths.is_empty() {
                let shortest_path = result.call_paths.iter()
                    .min_by_key(|p| p.len())
                    .unwrap();
                if !vuln.description.contains("Reachable via") {
                    vuln.description = format!("{} (Reachable via: {})",
                        vuln.description,
                        shortest_path.join(" -> "));
                }
            }
        }
    }

    /// Analyze external call chains for security implications
    pub fn analyze_external_call_chains(&self, content: &str) -> Vec<Vulnerability> {
        let call_graph = self.build_call_graph(content);
        let mut vulnerabilities = Vec::new();

        // Find functions that make external calls
        let external_call_pattern = Regex::new(r"\.call\{|\.delegatecall\(|\.staticcall\(|\.transfer\(|\.send\(").unwrap();

        for (func_name, node) in &call_graph.nodes {
            // Check if this function or any function it calls makes external calls
            let makes_external_call = self.check_transitive_external_calls(&call_graph, func_name, content, &external_call_pattern);

            if makes_external_call && !node.modifiers.iter().any(|m| m.contains("nonReentrant")) {
                // Check if any caller of this function also makes external calls
                for (caller_name, caller_node) in &call_graph.nodes {
                    if caller_node.calls.contains(func_name) {
                        let caller_has_external = external_call_pattern.is_match(content);

                        if caller_has_external && matches!(caller_node.visibility, Visibility::External | Visibility::Public) {
                            vulnerabilities.push(Vulnerability::new(
                                crate::vulnerabilities::VulnerabilitySeverity::Medium,
                                crate::vulnerabilities::VulnerabilityCategory::Reentrancy,
                                format!("Nested External Calls: {} -> {}", caller_name, func_name),
                                "External function calls another function that makes external calls - potential reentrancy chain".to_string(),
                                caller_node.line,
                                format!("function {}", caller_name),
                                "Add nonReentrant modifier or ensure CEI pattern throughout call chain".to_string(),
                            ));
                        }
                    }
                }
            }
        }

        vulnerabilities
    }

    /// Check if a function or its callees make external calls
    fn check_transitive_external_calls(
        &self,
        call_graph: &CallGraph,
        func_name: &str,
        content: &str,
        pattern: &Regex,
    ) -> bool {
        let mut visited = HashSet::new();
        let mut to_check = vec![func_name.to_string()];

        while let Some(current) = to_check.pop() {
            if visited.contains(&current) {
                continue;
            }
            visited.insert(current.clone());

            if let Some(node) = call_graph.nodes.get(&current) {
                // Get function body
                let body = self.get_function_body(content, node.line);
                if pattern.is_match(&body) {
                    return true;
                }

                // Add callees to check
                for callee in &node.calls {
                    if !visited.contains(callee) {
                        to_check.push(callee.clone());
                    }
                }
            }
        }

        false
    }

    /// Get function body starting from a line
    fn get_function_body(&self, content: &str, start_line: usize) -> String {
        let lines: Vec<&str> = content.lines().collect();
        let mut body = String::new();
        let mut brace_count = 0;
        let mut started = false;

        for line in lines.iter().skip(start_line.saturating_sub(1)) {
            for ch in line.chars() {
                if ch == '{' {
                    brace_count += 1;
                    started = true;
                } else if ch == '}' {
                    brace_count -= 1;
                }
            }

            body.push_str(line);
            body.push('\n');

            if started && brace_count == 0 {
                break;
            }
        }

        body
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_call_graph_building() {
        let content = r#"
contract Test {
    function external_entry() external {
        internal_helper();
    }

    function internal_helper() internal {
        private_work();
    }

    function private_work() private {
        // does stuff
    }

    function unreachable() internal {
        // never called
    }
}
"#;
        let analyzer = ReachabilityAnalyzer::new(false);
        let graph = analyzer.build_call_graph(content);

        assert!(graph.entry_points.contains(&"external_entry".to_string()));
        assert!(!graph.entry_points.contains(&"internal_helper".to_string()));
    }

    #[test]
    fn test_reachability_check() {
        let content = r#"
contract Test {
    function public_entry() public {
        helper();
    }

    function helper() internal {
        // line 8
    }
}
"#;
        let analyzer = ReachabilityAnalyzer::new(false);
        let graph = analyzer.build_call_graph(content);

        // helper should be reachable via public_entry
        let result = analyzer.is_line_reachable(&graph, 8, content);
        assert!(result.is_reachable);
    }
}
