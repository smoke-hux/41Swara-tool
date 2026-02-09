//! Reachability Analyzer
//!
//! This module performs reachability analysis on Solidity smart contracts to determine
//! which code paths are reachable from external entry points (public/external functions,
//! constructors, fallback, and receive functions). It builds an intra-contract call graph
//! and uses BFS traversal to find paths from entry points to any given function.
//!
//! The analyzer serves three main purposes in the scanning pipeline:
//! 1. **Filtering**: Removes vulnerabilities found in unreachable (dead) code, reducing
//!    false positives significantly.
//! 2. **Confidence adjustment**: Increases or decreases the confidence score of a
//!    vulnerability based on how many call paths reach the affected code.
//! 3. **Call chain analysis**: Detects nested external calls across function boundaries,
//!    identifying potential reentrancy chains that span multiple functions.
//!
//! The analysis is conservative: contract-level declarations (state variables, pragmas,
//! imports) outside any function body are always considered reachable.

#![allow(dead_code)]

use std::collections::{HashMap, HashSet, VecDeque};
use regex::Regex;
use crate::vulnerabilities::Vulnerability;

/// Represents a single function (or special function) as a node in the call graph.
///
/// Each node stores metadata about the function's visibility, the functions it calls,
/// any access-control modifiers applied to it, and flags for special function types
/// (constructor, fallback, receive).
#[derive(Debug, Clone)]
pub struct CallGraphNode {
    /// The name of the function (e.g., "transfer", "constructor", "fallback").
    pub name: String,
    /// The Solidity visibility specifier (external, public, internal, private).
    pub visibility: Visibility,
    /// Names of other functions called within this function's body.
    pub calls: Vec<String>,
    /// Access-control or state modifiers applied to this function (e.g., "onlyOwner", "nonReentrant").
    pub modifiers: Vec<String>,
    /// The 1-indexed source line where this function is declared.
    pub line: usize,
    /// Whether this is the contract constructor.
    pub is_constructor: bool,
    /// Whether this is the fallback function (invoked on calls with no matching selector).
    pub is_fallback: bool,
    /// Whether this is the receive function (invoked on plain Ether transfers).
    pub is_receive: bool,
}

/// Solidity function visibility specifier.
///
/// Determines whether a function is an external entry point that can be called
/// from outside the contract. `External` and `Public` functions are entry points;
/// `Internal` and `Private` functions are not directly callable externally.
#[derive(Debug, Clone, PartialEq)]
pub enum Visibility {
    /// Callable only from outside the contract (not from other internal functions).
    External,
    /// Callable both externally and internally.
    Public,
    /// Callable only from within the contract or derived contracts.
    Internal,
    /// Callable only from within the defining contract.
    Private,
}

/// The complete call graph for a single contract.
///
/// Maps function names to their `CallGraphNode` representations and tracks which
/// functions serve as external entry points. Also records the inheritance chain
/// for context (though cross-contract resolution is not yet implemented).
#[derive(Debug)]
pub struct CallGraph {
    /// All functions in the contract, keyed by function name.
    pub nodes: HashMap<String, CallGraphNode>,
    /// Names of functions that are externally callable entry points
    /// (public, external, constructor, fallback, receive).
    pub entry_points: Vec<String>,
    /// Parent contracts in the inheritance chain (e.g., `["Ownable", "ReentrancyGuard"]`).
    pub inheritance_chain: Vec<String>,
}

/// The result of a reachability query for a specific line or vulnerability.
///
/// Contains whether the target is reachable, the call paths that reach it,
/// which entry points lead to it, and a confidence adjustment value that
/// modifies the vulnerability's confidence score.
#[derive(Debug, Clone)]
pub struct ReachabilityResult {
    /// Whether the target line/function is reachable from any entry point.
    pub is_reachable: bool,
    /// All discovered call paths from entry points to the target function.
    /// Each path is a list of function names (e.g., `["deposit", "internal_transfer", "target"]`).
    pub call_paths: Vec<Vec<String>>,
    /// The distinct entry point function names that can reach the target.
    pub entry_points: Vec<String>,
    /// Confidence adjustment applied to vulnerabilities at this location.
    /// Range: -30 (likely unreachable, reduce confidence) to +30 (highly reachable, boost confidence).
    pub confidence_adjustment: i8,
    /// Human-readable explanation of the reachability determination.
    pub reason: String,
}

/// Performs reachability analysis on Solidity smart contract source code.
///
/// Builds a call graph from the contract source, then uses BFS-based graph
/// traversal to determine which internal functions are reachable from external
/// entry points. This is used to filter out false-positive vulnerabilities in
/// dead code and to adjust confidence scores based on how reachable the
/// vulnerable code is.
pub struct ReachabilityAnalyzer {
    /// When true, prints diagnostic messages about filtered vulnerabilities and call paths.
    verbose: bool,
}

impl ReachabilityAnalyzer {
    /// Creates a new `ReachabilityAnalyzer`.
    ///
    /// # Arguments
    /// * `verbose` - If true, emit diagnostic output when filtering or adjusting vulnerabilities.
    pub fn new(verbose: bool) -> Self {
        Self { verbose }
    }

    /// Build a call graph from contract source code.
    ///
    /// Parses the source line-by-line to identify all functions (regular, constructor,
    /// fallback, receive), extract their visibility, modifiers, and internal calls,
    /// and classify them as entry points or internal-only.
    ///
    /// # Arguments
    /// * `content` - The full Solidity source code of the contract.
    ///
    /// # Returns
    /// A `CallGraph` containing all discovered nodes and entry points.
    pub fn build_call_graph(&self, content: &str) -> CallGraph {
        let mut nodes = HashMap::new();
        let mut entry_points = Vec::new();
        let inheritance_chain = self.extract_inheritance(content);

        // Regex to match regular function declarations and capture:
        //   Group 1: function name
        //   Group 2: parameter list (unused here, but captured for completeness)
        //   Group 3: visibility and modifier keywords after the parameter list
        let func_pattern = Regex::new(
            r"function\s+(\w+)\s*\(([^)]*)\)\s*((?:external|public|internal|private|view|pure|payable|virtual|override|\s|,)*)"
        ).unwrap();

        // Patterns for special Solidity functions that don't use the `function` keyword
        let constructor_pattern = Regex::new(r"constructor\s*\(").unwrap();
        let fallback_pattern = Regex::new(r"fallback\s*\(\s*\)").unwrap();
        let receive_pattern = Regex::new(r"receive\s*\(\s*\)\s*external\s*payable").unwrap();

        let lines: Vec<&str> = content.lines().collect();

        for (idx, line) in lines.iter().enumerate() {
            // Check for constructor — always an entry point (called once at deployment)
            if constructor_pattern.is_match(line) {
                let calls = self.extract_function_calls(&lines, idx);
                nodes.insert("constructor".to_string(), CallGraphNode {
                    name: "constructor".to_string(),
                    visibility: Visibility::Public,
                    calls,
                    modifiers: vec![],
                    line: idx + 1, // Convert 0-indexed to 1-indexed line number
                    is_constructor: true,
                    is_fallback: false,
                    is_receive: false,
                });
                entry_points.push("constructor".to_string());
            }

            // Check for fallback — entry point (called when no function selector matches)
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

            // Check for receive — entry point (called on plain Ether transfers with no calldata)
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

            // Check for regular named functions
            if let Some(caps) = func_pattern.captures(line) {
                let name = caps.get(1).map_or("", |m| m.as_str()).to_string();
                let modifiers_str = caps.get(3).map_or("", |m| m.as_str());

                // Determine visibility from the modifier keywords after the parameter list.
                // Solidity defaults to public if no visibility is specified.
                let visibility = if modifiers_str.contains("external") {
                    Visibility::External
                } else if modifiers_str.contains("public") {
                    Visibility::Public
                } else if modifiers_str.contains("internal") {
                    Visibility::Internal
                } else if modifiers_str.contains("private") {
                    Visibility::Private
                } else {
                    Visibility::Public // default visibility in Solidity
                };

                // Extract internal function calls made within this function's body
                let calls = self.extract_function_calls(&lines, idx);
                // Extract access-control modifiers (e.g., onlyOwner, nonReentrant)
                let modifiers = self.extract_modifiers(line);

                // External and public functions are directly callable entry points
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

    /// Extract the inheritance chain from a contract declaration.
    ///
    /// Parses `contract Foo is Bar, Baz(arg)` and returns `["Bar", "Baz"]`.
    /// Constructor arguments in the `is` clause are stripped.
    fn extract_inheritance(&self, content: &str) -> Vec<String> {
        let inherit_pattern = Regex::new(r"contract\s+\w+\s+is\s+([^{]+)").unwrap();

        if let Some(caps) = inherit_pattern.captures(content) {
            let parents = caps.get(1).map_or("", |m| m.as_str());
            // Split by comma, strip constructor args (everything after '('), and trim whitespace
            return parents.split(',')
                .map(|p| p.trim().split('(').next().unwrap_or("").trim().to_string())
                .filter(|p| !p.is_empty())
                .collect();
        }

        vec![]
    }

    /// Extract function calls from a function body starting at `start_idx`.
    ///
    /// Scans up to 100 lines from the function declaration, tracking brace depth
    /// to find the end of the function body. Collects all identifier-followed-by-paren
    /// patterns, excluding Solidity keywords and built-in statements.
    ///
    /// # Arguments
    /// * `lines` - All source lines of the contract.
    /// * `start_idx` - The 0-indexed line where the function declaration begins.
    ///
    /// # Returns
    /// A deduplicated list of function names called within the function body.
    fn extract_function_calls(&self, lines: &[&str], start_idx: usize) -> Vec<String> {
        let mut calls = Vec::new();
        // Match lowercase/underscore-starting identifiers followed by '(' — likely function calls
        let call_pattern = Regex::new(r"\b([a-z_]\w*)\s*\(").unwrap();

        // Solidity keywords and built-in statements that look like function calls but aren't
        let keywords: HashSet<&str> = [
            "if", "for", "while", "require", "assert", "revert", "emit",
            "return", "new", "delete", "mapping", "memory", "storage",
            "calldata", "bytes", "string", "uint", "int", "bool", "address"
        ].iter().cloned().collect();

        // Track brace depth to know when the function body ends
        let mut brace_count = 0;
        let mut started = false;

        // Scan at most 100 lines to avoid runaway parsing on malformed input
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
                    // Exclude Solidity keywords and avoid duplicates
                    if !keywords.contains(func_name) && !calls.contains(&func_name.to_string()) {
                        calls.push(func_name.to_string());
                    }
                }
            }

            // If we've entered the function body and braces are balanced, we've reached the end
            if started && brace_count == 0 {
                break;
            }
        }

        calls
    }

    /// Extract access-control and state modifiers from a function signature line.
    ///
    /// Looks for common modifier patterns like `onlyOwner`, `nonReentrant`,
    /// `whenNotPaused`, `whenPaused`, and `initializer`. These are used later
    /// to determine if a function already has reentrancy protection.
    fn extract_modifiers(&self, line: &str) -> Vec<String> {
        let modifier_pattern = Regex::new(r"\b(only\w+|nonReentrant|whenNotPaused|whenPaused|initializer)\b").unwrap();

        modifier_pattern.captures_iter(line)
            .filter_map(|c| c.get(1))
            .map(|m| m.as_str().to_string())
            .collect()
    }

    /// Check if a specific source line is reachable from any external entry point.
    ///
    /// This is the primary query method for reachability analysis. It:
    /// 1. Identifies which function contains the target line.
    /// 2. If the line is outside any function (contract-level declaration), returns reachable.
    /// 3. If the containing function is itself an entry point, returns reachable with high confidence.
    /// 4. Otherwise, performs BFS from all entry points to find call paths to the function.
    ///
    /// # Arguments
    /// * `call_graph` - A pre-built call graph for the contract.
    /// * `target_line` - The 1-indexed source line to check.
    /// * `content` - The full contract source (used to find function boundaries).
    ///
    /// # Returns
    /// A `ReachabilityResult` with reachability status, paths, and confidence adjustment.
    pub fn is_line_reachable(&self, call_graph: &CallGraph, target_line: usize, content: &str) -> ReachabilityResult {
        // Determine which function (if any) contains the target line
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

        // If the function itself is an entry point, it's directly reachable with high confidence
        if call_graph.entry_points.contains(&target_func) {
            return ReachabilityResult {
                is_reachable: true,
                call_paths: vec![vec![target_func.clone()]],
                entry_points: vec![target_func],
                confidence_adjustment: 20, // Boost confidence — directly callable
                reason: "Directly callable external/public function".to_string(),
            };
        }

        // BFS from all entry points to find call paths reaching the target function
        let paths = self.find_all_paths_to(call_graph, &target_func);

        if paths.is_empty() {
            // No entry point can reach this function — it's dead code
            return ReachabilityResult {
                is_reachable: false,
                call_paths: vec![],
                entry_points: vec![],
                confidence_adjustment: -25, // Reduce confidence — likely a false positive
                reason: format!("Function '{}' is not reachable from any entry point", target_func),
            };
        }

        // Collect distinct entry points that lead to the target
        let entry_points: Vec<String> = paths.iter()
            .filter_map(|path| path.first().cloned())
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();

        // More paths means higher confidence the vulnerability is exploitable
        ReachabilityResult {
            is_reachable: true,
            call_paths: paths.clone(),
            entry_points: entry_points.clone(),
            confidence_adjustment: if paths.len() > 3 { 15 } else { 10 },
            reason: format!("Reachable via {} path(s) from {} entry point(s)", paths.len(), entry_points.len()),
        }
    }

    /// Find which function contains a given 1-indexed source line.
    ///
    /// Iterates over all call graph nodes to find the function whose declaration
    /// starts at or before the target line and whose body (ending brace) is at
    /// or after the target line. Returns the closest (innermost) match.
    ///
    /// # Returns
    /// `Some(function_name)` if the line is inside a function, `None` if it's
    /// a contract-level declaration (state variable, pragma, import, etc.).
    fn find_function_at_line(&self, call_graph: &CallGraph, line: usize, content: &str) -> Option<String> {
        let mut best_match: Option<(String, usize)> = None;

        for (name, node) in &call_graph.nodes {
            if node.line <= line {
                // Check if this function starts closer to the target line than any previous match
                if best_match.is_none() || node.line > best_match.as_ref().unwrap().1 {
                    // Verify the target line is actually within this function's body
                    let func_end = self.find_function_end(content, node.line);
                    if line <= func_end {
                        best_match = Some((name.clone(), node.line));
                    }
                }
            }
        }

        best_match.map(|(name, _)| name)
    }

    /// Find the 1-indexed line number where a function's body ends (closing brace).
    ///
    /// Tracks brace depth starting from the function declaration line. When the
    /// brace count returns to zero after being incremented, we've found the
    /// matching closing brace.
    ///
    /// # Arguments
    /// * `content` - The full contract source code.
    /// * `start_line` - The 1-indexed line where the function is declared.
    ///
    /// # Returns
    /// The 1-indexed line number of the function's closing brace, or the total
    /// line count if no matching brace is found (malformed source).
    fn find_function_end(&self, content: &str, start_line: usize) -> usize {
        let lines: Vec<&str> = content.lines().collect();
        let mut brace_count = 0;
        let mut started = false;

        // Start from the function declaration line (convert 1-indexed to 0-indexed with saturating_sub)
        for (i, line) in lines.iter().enumerate().skip(start_line.saturating_sub(1)) {
            for ch in line.chars() {
                if ch == '{' {
                    brace_count += 1;
                    started = true;
                } else if ch == '}' {
                    brace_count -= 1;
                }
            }

            // Balanced braces after entering the function body means we found the end
            if started && brace_count == 0 {
                return i + 1; // Convert back to 1-indexed
            }
        }

        // Fallback: if no closing brace found, assume function extends to end of file
        lines.len()
    }

    /// Find all call paths from any entry point to the target function.
    ///
    /// Iterates over every entry point in the call graph and performs BFS
    /// from each to the target, collecting all discovered paths.
    fn find_all_paths_to(&self, call_graph: &CallGraph, target: &str) -> Vec<Vec<String>> {
        let mut all_paths = Vec::new();

        for entry in &call_graph.entry_points {
            let paths = self.bfs_paths(call_graph, entry, target);
            all_paths.extend(paths);
        }

        all_paths
    }

    /// BFS to find all acyclic paths between two nodes in the call graph.
    ///
    /// Uses a queue of partial paths. For each partial path, extends it by one
    /// step through each callee. Avoids cycles by checking if a node is already
    /// in the current path. Limits path length to 10 to prevent combinatorial
    /// explosion in deeply nested call chains.
    ///
    /// # Arguments
    /// * `call_graph` - The contract's call graph.
    /// * `start` - The entry point function name to start BFS from.
    /// * `target` - The target function name to reach.
    ///
    /// # Returns
    /// A list of paths, where each path is a sequence of function names from
    /// `start` to `target`.
    fn bfs_paths(&self, call_graph: &CallGraph, start: &str, target: &str) -> Vec<Vec<String>> {
        let mut paths = Vec::new();
        let mut queue: VecDeque<Vec<String>> = VecDeque::new();

        // Seed the BFS with a path containing just the start node
        queue.push_back(vec![start.to_string()]);

        while let Some(path) = queue.pop_front() {
            let current = path.last().unwrap();

            // Found target — record this complete path
            if current == target {
                paths.push(path);
                continue;
            }

            // Cap path length at 10 to prevent combinatorial explosion
            if path.len() > 10 {
                continue;
            }

            // Extend the path through each callee of the current function
            if let Some(node) = call_graph.nodes.get(current) {
                for called in &node.calls {
                    // Skip nodes already in the path to avoid cycles
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

    /// Filter out vulnerabilities that are in unreachable code.
    ///
    /// Builds a call graph from the contract source and removes any vulnerability
    /// whose line number falls within a function that cannot be reached from any
    /// external entry point. This is one of the three filtering layers in the
    /// scanner pipeline.
    ///
    /// # Arguments
    /// * `vulnerabilities` - The list of detected vulnerabilities to filter.
    /// * `content` - The full Solidity source code of the contract.
    ///
    /// # Returns
    /// A filtered list containing only vulnerabilities in reachable code.
    pub fn filter_unreachable_vulnerabilities(
        &self,
        vulnerabilities: Vec<Vulnerability>,
        content: &str,
    ) -> Vec<Vulnerability> {
        let call_graph = self.build_call_graph(content);

        vulnerabilities.into_iter()
            .filter(|vuln| {
                let result = self.is_line_reachable(&call_graph, vuln.line_number, content);
                // In verbose mode, log which vulnerabilities are being filtered out
                if !result.is_reachable && self.verbose {
                    println!("  ⚠️  Filtering unreachable vulnerability at line {}: {}",
                            vuln.line_number, result.reason);
                }
                result.is_reachable
            })
            .collect()
    }

    /// Adjust the confidence scores of vulnerabilities based on reachability.
    ///
    /// For each vulnerability, determines how reachable the affected code is and
    /// applies a confidence adjustment:
    /// - Directly callable entry points: +20
    /// - Reachable via many paths (>3): +15
    /// - Reachable via few paths: +10
    /// - Not reachable: -25
    /// - Contract-level (outside functions): no change
    ///
    /// Also appends the shortest call path to the vulnerability description in
    /// verbose mode for debugging purposes.
    ///
    /// # Arguments
    /// * `vulnerabilities` - Mutable slice of vulnerabilities to adjust in place.
    /// * `content` - The full Solidity source code of the contract.
    pub fn adjust_confidence(
        &self,
        vulnerabilities: &mut [Vulnerability],
        content: &str,
    ) {
        let call_graph = self.build_call_graph(content);

        for vuln in vulnerabilities.iter_mut() {
            let result = self.is_line_reachable(&call_graph, vuln.line_number, content);

            // Clamp the adjusted confidence to the valid 0-100 range
            let new_confidence = (vuln.confidence_percent as i16 + result.confidence_adjustment as i16)
                .max(0)
                .min(100) as u8;

            vuln.confidence_percent = new_confidence;
            vuln.confidence = crate::vulnerabilities::VulnerabilityConfidence::from_percent(new_confidence);

            // In verbose mode, annotate the vulnerability description with the shortest call path
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

    /// Analyze external call chains for potential reentrancy vulnerabilities.
    ///
    /// Detects a specific pattern: a public/external function that makes an external
    /// call (`.call{`, `.delegatecall()`, etc.) and also calls an internal function
    /// that itself (transitively) makes external calls. This "nested external call"
    /// pattern can create reentrancy vectors, especially if the `nonReentrant` modifier
    /// is not applied.
    ///
    /// Only checks the caller function's own body for external calls (not the whole
    /// contract), avoiding false positives from unrelated external calls elsewhere.
    ///
    /// # Arguments
    /// * `content` - The full Solidity source code of the contract.
    ///
    /// # Returns
    /// A list of newly generated vulnerabilities for detected nested external call chains.
    pub fn analyze_external_call_chains(&self, content: &str) -> Vec<Vulnerability> {
        let call_graph = self.build_call_graph(content);
        let mut vulnerabilities = Vec::new();

        // Pattern matching Solidity external call syntaxes
        let external_call_pattern = Regex::new(r"\.call\{|\.delegatecall\(|\.staticcall\(|\.transfer\(|\.send\(").unwrap();

        for (func_name, node) in &call_graph.nodes {
            // Check if this function or any function it transitively calls makes an external call
            let makes_external_call = self.check_transitive_external_calls(&call_graph, func_name, content, &external_call_pattern);

            // Only flag if the function lacks nonReentrant protection
            if makes_external_call && !node.modifiers.iter().any(|m| m.contains("nonReentrant")) {
                // Look for callers of this function that also make external calls —
                // this creates a nested external call chain (caller -> callee, both with external calls)
                for (caller_name, caller_node) in &call_graph.nodes {
                    if caller_node.calls.contains(func_name) {
                        // Check only the caller's function body (not the whole contract)
                        // to avoid false positives from unrelated external calls
                        let caller_body = self.get_function_body(content, caller_node.line);
                        let caller_has_external = external_call_pattern.is_match(&caller_body);

                        // Only report if the caller is externally accessible (entry point)
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

    /// Check if a function or any function it transitively calls makes external calls.
    ///
    /// Performs iterative DFS through the call graph starting from `func_name`.
    /// For each visited function, extracts its body and checks for external call
    /// patterns. Tracks visited nodes to avoid infinite loops from recursive calls.
    ///
    /// # Arguments
    /// * `call_graph` - The contract's call graph.
    /// * `func_name` - The function to start checking from.
    /// * `content` - The full contract source (used to extract function bodies).
    /// * `pattern` - Regex matching external call syntaxes.
    ///
    /// # Returns
    /// `true` if any function in the transitive call chain makes an external call.
    fn check_transitive_external_calls(
        &self,
        call_graph: &CallGraph,
        func_name: &str,
        content: &str,
        pattern: &Regex,
    ) -> bool {
        let mut visited = HashSet::new();
        let mut to_check = vec![func_name.to_string()];

        // Iterative DFS to avoid stack overflow on deep call chains
        while let Some(current) = to_check.pop() {
            if visited.contains(&current) {
                continue;
            }
            visited.insert(current.clone());

            if let Some(node) = call_graph.nodes.get(&current) {
                // Extract this function's body and check for external call patterns
                let body = self.get_function_body(content, node.line);
                if pattern.is_match(&body) {
                    return true;
                }

                // Enqueue all callees for transitive checking
                for callee in &node.calls {
                    if !visited.contains(callee) {
                        to_check.push(callee.clone());
                    }
                }
            }
        }

        false
    }

    /// Extract the full text of a function body starting from a given line.
    ///
    /// Tracks brace depth from the function declaration to its closing brace,
    /// collecting all lines in between. Used by `check_transitive_external_calls`
    /// and `analyze_external_call_chains` to scope pattern matching to a single
    /// function rather than the entire contract.
    ///
    /// # Arguments
    /// * `content` - The full contract source code.
    /// * `start_line` - The 1-indexed line where the function is declared.
    ///
    /// # Returns
    /// The full text of the function (declaration through closing brace).
    fn get_function_body(&self, content: &str, start_line: usize) -> String {
        let lines: Vec<&str> = content.lines().collect();
        let mut body = String::new();
        let mut brace_count = 0;
        let mut started = false;

        // Start from the declaration line (convert 1-indexed to 0-indexed)
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

            // Balanced braces after entering the body means we've captured the full function
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
