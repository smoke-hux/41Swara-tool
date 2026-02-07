//! Logic Vulnerability Analyzer
//!
//! Detects business logic vulnerabilities that static pattern matching typically misses.
//! This module uses semantic analysis to identify complex logic bugs, state machine violations,
//! and protocol-specific vulnerabilities.

#![allow(dead_code)]

use std::collections::{HashMap, HashSet};
use regex::Regex;
use crate::vulnerabilities::{Vulnerability, VulnerabilitySeverity, VulnerabilityCategory};

/// Logic vulnerability types that go beyond pattern matching
#[derive(Debug, Clone, PartialEq)]
pub enum LogicVulnType {
    StateTransitionViolation,
    InvariantViolation,
    BusinessLogicBypass,
    InconsistentStateUpdate,
    MissingConditionCheck,
    ImproperAuthorizationFlow,
    RaceConditionWindow,
    IncompleteValidation,
    AsymmetricBehavior,
    UnreachableCode,
}

/// Function representation for semantic analysis
#[derive(Debug, Clone)]
pub struct FunctionInfo {
    pub name: String,
    pub visibility: String,
    pub modifiers: Vec<String>,
    pub parameters: Vec<(String, String)>, // (type, name)
    pub returns: Vec<String>,
    pub state_reads: Vec<String>,
    pub state_writes: Vec<String>,
    pub external_calls: Vec<String>,
    pub line_start: usize,
    pub line_end: usize,
    pub body: String,
}

/// State variable representation
#[derive(Debug, Clone)]
pub struct StateVariable {
    pub name: String,
    pub var_type: String,
    pub visibility: String,
    pub is_constant: bool,
    pub is_immutable: bool,
    pub line: usize,
}

/// Contract state machine representation
#[derive(Debug, Clone)]
pub struct ContractStateMachine {
    pub states: HashSet<String>,
    pub transitions: HashMap<String, Vec<String>>,
    pub current_state_var: Option<String>,
}

pub struct LogicAnalyzer {
    verbose: bool,
}

impl LogicAnalyzer {
    pub fn new(verbose: bool) -> Self {
        Self { verbose }
    }

    /// Main entry point for logic vulnerability analysis
    pub fn analyze(&self, content: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        // Extract contract structure
        let functions = self.extract_functions(content);
        let state_vars = self.extract_state_variables(content);
        let state_machine = self.detect_state_machine(content, &state_vars);

        // 1. State Transition Analysis
        vulnerabilities.extend(self.analyze_state_transitions(content, &functions, &state_machine));

        // 2. Invariant Violation Detection
        vulnerabilities.extend(self.analyze_invariants(content, &functions, &state_vars));

        // 3. Business Logic Bypass Detection
        vulnerabilities.extend(self.detect_logic_bypass(content, &functions));

        // 4. Inconsistent State Update Detection
        vulnerabilities.extend(self.detect_inconsistent_state_updates(content, &functions, &state_vars));

        // 5. Missing Condition Check Detection
        vulnerabilities.extend(self.detect_missing_conditions(content, &functions));

        // 6. Authorization Flow Analysis
        vulnerabilities.extend(self.analyze_authorization_flow(content, &functions));

        // 7. Race Condition Window Detection
        vulnerabilities.extend(self.detect_race_condition_windows(content, &functions));

        // 8. Asymmetric Behavior Detection (deposit vs withdraw, mint vs burn)
        vulnerabilities.extend(self.detect_asymmetric_behavior(content, &functions));

        // 9. Unreachable/Dead Code Detection (beyond simple patterns)
        vulnerabilities.extend(self.detect_unreachable_logic(content, &functions));

        // 10. Protocol-Specific Logic Bugs
        vulnerabilities.extend(self.detect_protocol_logic_bugs(content, &functions));

        vulnerabilities
    }

    /// Extract function information from contract
    fn extract_functions(&self, content: &str) -> Vec<FunctionInfo> {
        let mut functions = Vec::new();
        let func_pattern = Regex::new(
            r"function\s+(\w+)\s*\(([^)]*)\)\s*((?:external|public|internal|private|view|pure|payable|virtual|override|\s|,)*)\s*(?:returns\s*\(([^)]*)\))?\s*\{"
        ).unwrap();

        let modifier_pattern = Regex::new(r"(\w+)(?:\([^)]*\))?").unwrap();
        let state_read_pattern = Regex::new(r"\b([a-z_]\w*)\s*[^=]").unwrap();
        // Match assignment (single =) but exclude comparison (==)
        let state_write_pattern = Regex::new(r"\b([a-z_]\w*)\s*=[^=]").unwrap();
        let external_call_pattern = Regex::new(r"(\w+)\.(?:call|delegatecall|staticcall|transfer|send)\(").unwrap();

        let lines: Vec<&str> = content.lines().collect();

        for (idx, line) in lines.iter().enumerate() {
            if let Some(caps) = func_pattern.captures(line) {
                let name = caps.get(1).map_or("", |m| m.as_str()).to_string();
                let params_str = caps.get(2).map_or("", |m| m.as_str());
                let modifiers_str = caps.get(3).map_or("", |m| m.as_str());
                let returns_str = caps.get(4).map_or("", |m| m.as_str());

                // Parse visibility
                let visibility = if modifiers_str.contains("external") {
                    "external"
                } else if modifiers_str.contains("public") {
                    "public"
                } else if modifiers_str.contains("internal") {
                    "internal"
                } else if modifiers_str.contains("private") {
                    "private"
                } else {
                    "public" // default
                }.to_string();

                // Parse modifiers
                let modifiers: Vec<String> = modifier_pattern
                    .captures_iter(modifiers_str)
                    .filter_map(|c| c.get(1))
                    .map(|m| m.as_str().to_string())
                    .filter(|m| !["external", "public", "internal", "private", "view", "pure", "payable", "virtual", "override"].contains(&m.as_str()))
                    .collect();

                // Parse parameters
                let parameters: Vec<(String, String)> = params_str
                    .split(',')
                    .filter(|p| !p.trim().is_empty())
                    .filter_map(|p| {
                        let parts: Vec<&str> = p.trim().split_whitespace().collect();
                        if parts.len() >= 2 {
                            Some((parts[0].to_string(), parts.last().unwrap().to_string()))
                        } else {
                            None
                        }
                    })
                    .collect();

                // Parse returns
                let returns: Vec<String> = returns_str
                    .split(',')
                    .filter(|r| !r.trim().is_empty())
                    .map(|r| r.trim().split_whitespace().next().unwrap_or("").to_string())
                    .collect();

                // Find function body
                let (body, line_end) = self.extract_function_body(&lines, idx);

                // Extract state reads and writes from body
                let state_reads: Vec<String> = state_read_pattern
                    .captures_iter(&body)
                    .filter_map(|c| c.get(1))
                    .map(|m| m.as_str().to_string())
                    .collect::<HashSet<_>>()
                    .into_iter()
                    .collect();

                let state_writes: Vec<String> = state_write_pattern
                    .captures_iter(&body)
                    .filter_map(|c| c.get(1))
                    .map(|m| m.as_str().to_string())
                    .collect::<HashSet<_>>()
                    .into_iter()
                    .collect();

                let external_calls: Vec<String> = external_call_pattern
                    .captures_iter(&body)
                    .filter_map(|c| c.get(1))
                    .map(|m| m.as_str().to_string())
                    .collect();

                functions.push(FunctionInfo {
                    name,
                    visibility,
                    modifiers,
                    parameters,
                    returns,
                    state_reads,
                    state_writes,
                    external_calls,
                    line_start: idx + 1,
                    line_end,
                    body,
                });
            }
        }

        functions
    }

    /// Extract function body between braces
    fn extract_function_body(&self, lines: &[&str], start_idx: usize) -> (String, usize) {
        let mut brace_count = 0;
        let mut body = String::new();
        let mut started = false;

        for (i, line) in lines.iter().enumerate().skip(start_idx) {
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
                return (body, i + 1);
            }
        }

        (body, lines.len())
    }

    /// Extract state variables from contract
    fn extract_state_variables(&self, content: &str) -> Vec<StateVariable> {
        let mut vars = Vec::new();
        let var_pattern = Regex::new(
            r"^\s*(mapping\s*\([^)]+\)|address|uint\d*|int\d*|bool|bytes\d*|string|bytes)\s+(public|private|internal)?\s*(constant|immutable)?\s*(\w+)"
        ).unwrap();

        for (idx, line) in content.lines().enumerate() {
            if let Some(caps) = var_pattern.captures(line) {
                let var_type = caps.get(1).map_or("", |m| m.as_str()).to_string();
                let visibility = caps.get(2).map_or("internal", |m| m.as_str()).to_string();
                let modifier = caps.get(3).map_or("", |m| m.as_str());
                let name = caps.get(4).map_or("", |m| m.as_str()).to_string();

                vars.push(StateVariable {
                    name,
                    var_type,
                    visibility,
                    is_constant: modifier == "constant",
                    is_immutable: modifier == "immutable",
                    line: idx + 1,
                });
            }
        }

        vars
    }

    /// Detect if contract uses a state machine pattern
    fn detect_state_machine(&self, content: &str, state_vars: &[StateVariable]) -> ContractStateMachine {
        let mut machine = ContractStateMachine {
            states: HashSet::new(),
            transitions: HashMap::new(),
            current_state_var: None,
        };

        // Look for enum-based state machine
        let enum_pattern = Regex::new(r"enum\s+(\w*[Ss]tate\w*)\s*\{([^}]+)\}").unwrap();
        if let Some(caps) = enum_pattern.captures(content) {
            let states_str = caps.get(2).map_or("", |m| m.as_str());
            for state in states_str.split(',') {
                machine.states.insert(state.trim().to_string());
            }
        }

        // Look for state variable
        for var in state_vars {
            if var.name.to_lowercase().contains("state") || var.name.to_lowercase().contains("status") {
                machine.current_state_var = Some(var.name.clone());
                break;
            }
        }

        // Detect state transitions
        if let Some(ref state_var) = machine.current_state_var {
            let transition_pattern = Regex::new(&format!(r"{}\.(\w+).*=.*\.(\w+)", regex::escape(state_var))).unwrap();
            for caps in transition_pattern.captures_iter(content) {
                if let (Some(from), Some(to)) = (caps.get(1), caps.get(2)) {
                    machine.transitions
                        .entry(from.as_str().to_string())
                        .or_insert_with(Vec::new)
                        .push(to.as_str().to_string());
                }
            }
        }

        machine
    }

    /// Analyze state transitions for violations
    fn analyze_state_transitions(
        &self,
        _content: &str,
        functions: &[FunctionInfo],
        state_machine: &ContractStateMachine,
    ) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        if state_machine.current_state_var.is_none() {
            return vulnerabilities;
        }

        let state_var = state_machine.current_state_var.as_ref().unwrap();

        for func in functions {
            // Check if function modifies state without checking current state
            if func.state_writes.iter().any(|w| w == state_var) {
                let has_state_check = func.body.contains(&format!("require({}", state_var)) ||
                                      func.body.contains(&format!("if ({}", state_var)) ||
                                      func.body.contains(&format!("== {}", state_var));

                if !has_state_check && func.visibility == "external" || func.visibility == "public" {
                    vulnerabilities.push(Vulnerability::new(
                        VulnerabilitySeverity::High,
                        VulnerabilityCategory::LogicError,
                        format!("State Transition Without Validation in {}", func.name),
                        "Function modifies contract state without validating current state - potential state machine bypass".to_string(),
                        func.line_start,
                        format!("function {}", func.name),
                        "Add require() to validate current state before transition".to_string(),
                    ));
                }
            }
        }

        // Check for missing state transitions
        for (from_state, to_states) in &state_machine.transitions {
            if to_states.is_empty() {
                vulnerabilities.push(Vulnerability::new(
                    VulnerabilitySeverity::Medium,
                    VulnerabilityCategory::LogicError,
                    format!("Dead State: {}", from_state),
                    "State has no valid transitions - once entered, contract may be stuck".to_string(),
                    1,
                    format!("State: {}", from_state),
                    "Add transition functions or mark as terminal state".to_string(),
                ));
            }
        }

        vulnerabilities
    }

    /// Detect invariant violations
    fn analyze_invariants(
        &self,
        content: &str,
        functions: &[FunctionInfo],
        state_vars: &[StateVariable],
    ) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        // Track variables that should be synchronized
        let balance_vars: Vec<&StateVariable> = state_vars.iter()
            .filter(|v| v.name.to_lowercase().contains("balance") ||
                       v.name.to_lowercase().contains("supply") ||
                       v.name.to_lowercase().contains("total"))
            .collect();

        // Check for balance/supply invariant violations
        for func in functions {
            // If function modifies one balance variable but not corresponding total
            for balance_var in &balance_vars {
                if func.state_writes.contains(&balance_var.name) {
                    // Check for corresponding invariant update
                    let has_total_update = func.state_writes.iter()
                        .any(|w| w.to_lowercase().contains("total") || w.to_lowercase().contains("supply"));

                    if !has_total_update && balance_var.name.contains("balance") {
                        // Check if it's an ERC20 pattern
                        let is_erc20 = content.contains("totalSupply") || content.contains("_totalSupply");

                        if is_erc20 {
                            vulnerabilities.push(Vulnerability::new(
                                VulnerabilitySeverity::High,
                                VulnerabilityCategory::LogicError,
                                format!("Potential Balance Invariant Violation in {}", func.name),
                                "Function modifies balance without updating total supply - may break ERC20 invariant".to_string(),
                                func.line_start,
                                format!("function {} modifies {}", func.name, balance_var.name),
                                "Ensure balance changes are reflected in totalSupply".to_string(),
                            ));
                        }
                    }
                }
            }
        }

        // Check for timestamp/deadline invariants
        for func in functions {
            if func.body.contains("deadline") || func.body.contains("expiry") {
                let has_time_check = func.body.contains("block.timestamp") ||
                                    func.body.contains("block.number");
                let has_validation = func.body.contains("require(") && has_time_check;

                if !has_validation && (func.visibility == "external" || func.visibility == "public") {
                    vulnerabilities.push(Vulnerability::new(
                        VulnerabilitySeverity::Medium,
                        VulnerabilityCategory::LogicError,
                        format!("Unvalidated Deadline/Expiry in {}", func.name),
                        "Function references deadline/expiry without timestamp validation".to_string(),
                        func.line_start,
                        format!("function {}", func.name),
                        "Add require(block.timestamp <= deadline) validation".to_string(),
                    ));
                }
            }
        }

        vulnerabilities
    }

    /// Detect potential business logic bypass
    fn detect_logic_bypass(
        &self,
        content: &str,
        functions: &[FunctionInfo],
    ) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        // Find pairs of functions that should be related
        let critical_pairs = vec![
            ("deposit", "withdraw"),
            ("mint", "burn"),
            ("stake", "unstake"),
            ("lock", "unlock"),
            ("borrow", "repay"),
            ("add", "remove"),
            ("increase", "decrease"),
        ];

        for (action1, action2) in critical_pairs {
            let func1: Vec<&FunctionInfo> = functions.iter()
                .filter(|f| f.name.to_lowercase().contains(action1))
                .collect();
            let func2: Vec<&FunctionInfo> = functions.iter()
                .filter(|f| f.name.to_lowercase().contains(action2))
                .collect();

            // Check for asymmetric access control
            for f1 in &func1 {
                for f2 in &func2 {
                    let f1_has_modifier = !f1.modifiers.is_empty();
                    let f2_has_modifier = !f2.modifiers.is_empty();

                    if f1_has_modifier != f2_has_modifier {
                        let (protected, unprotected) = if f1_has_modifier { (f1, f2) } else { (f2, f1) };

                        vulnerabilities.push(Vulnerability::new(
                            VulnerabilitySeverity::High,
                            VulnerabilityCategory::LogicError,
                            format!("Asymmetric Access Control: {} vs {}", protected.name, unprotected.name),
                            format!("{} has access control but {} does not - potential logic bypass", protected.name, unprotected.name),
                            unprotected.line_start,
                            format!("function {}", unprotected.name),
                            format!("Add matching access control to {} as in {}", unprotected.name, protected.name),
                        ));
                    }
                }
            }
        }

        // Check for functions that bypass intended flow
        for func in functions {
            // Internal functions called by external functions should validate state
            if func.visibility == "internal" && !func.modifiers.is_empty() {
                // Check if there's an external wrapper
                let has_external_wrapper = functions.iter().any(|f| {
                    (f.visibility == "external" || f.visibility == "public") &&
                    f.body.contains(&func.name)
                });

                if !has_external_wrapper {
                    // Check if this internal function is directly accessible via delegatecall
                    if content.contains("delegatecall") {
                        vulnerabilities.push(Vulnerability::new(
                            VulnerabilitySeverity::Medium,
                            VulnerabilityCategory::LogicError,
                            format!("Internal Function May Be Bypassed: {}", func.name),
                            "Internal function with modifiers but no external wrapper - may be bypassed via delegatecall".to_string(),
                            func.line_start,
                            format!("function {}", func.name),
                            "Create external wrapper or ensure delegatecall context is validated".to_string(),
                        ));
                    }
                }
            }
        }

        vulnerabilities
    }

    /// Detect inconsistent state updates
    fn detect_inconsistent_state_updates(
        &self,
        _content: &str,
        functions: &[FunctionInfo],
        state_vars: &[StateVariable],
    ) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        // Build a map of which functions write to which variables
        let mut write_map: HashMap<String, Vec<&FunctionInfo>> = HashMap::new();

        for func in functions {
            for write_var in &func.state_writes {
                write_map.entry(write_var.clone())
                    .or_insert_with(Vec::new)
                    .push(func);
            }
        }

        // Check for variables written by multiple functions with different patterns
        for (var_name, writing_funcs) in &write_map {
            if writing_funcs.len() > 1 {
                // Check if writes are inconsistent (some with checks, some without)
                let funcs_with_checks: Vec<&&FunctionInfo> = writing_funcs.iter()
                    .filter(|f| f.body.contains("require(") || f.body.contains("if ("))
                    .collect();

                let funcs_without_checks: Vec<&&FunctionInfo> = writing_funcs.iter()
                    .filter(|f| !f.body.contains("require(") && !f.body.contains("if ("))
                    .filter(|f| f.visibility == "external" || f.visibility == "public")
                    .collect();

                if !funcs_with_checks.is_empty() && !funcs_without_checks.is_empty() {
                    for func in funcs_without_checks {
                        vulnerabilities.push(Vulnerability::new(
                            VulnerabilitySeverity::Medium,
                            VulnerabilityCategory::LogicError,
                            format!("Inconsistent State Write in {}", func.name),
                            format!("Variable '{}' written without validation here, but validated in other functions", var_name),
                            func.line_start,
                            format!("function {} writes to {}", func.name, var_name),
                            "Add consistent validation when writing state variables".to_string(),
                        ));
                    }
                }
            }
        }

        // Check for partial updates to related variables
        let related_pairs = vec![
            ("amount", "balance"),
            ("price", "rate"),
            ("start", "end"),
            ("min", "max"),
        ];

        for func in functions {
            for (var1, var2) in &related_pairs {
                let writes_var1 = func.state_writes.iter().any(|w| w.to_lowercase().contains(var1));
                let writes_var2 = func.state_writes.iter().any(|w| w.to_lowercase().contains(var2));

                // If function writes one but not both, might be incomplete
                if writes_var1 && !writes_var2 {
                    // Check if the paired variable exists
                    let paired_exists = state_vars.iter().any(|v| v.name.to_lowercase().contains(var2));

                    if paired_exists {
                        vulnerabilities.push(Vulnerability::new(
                            VulnerabilitySeverity::Low,
                            VulnerabilityCategory::LogicError,
                            format!("Partial State Update in {}", func.name),
                            format!("Function updates '{}' related variable but not '{}' - verify this is intentional", var1, var2),
                            func.line_start,
                            format!("function {}", func.name),
                            "Ensure related state variables are updated consistently".to_string(),
                        ));
                    }
                }
            }
        }

        vulnerabilities
    }

    /// Detect missing condition checks
    fn detect_missing_conditions(
        &self,
        content: &str,
        functions: &[FunctionInfo],
    ) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        for func in functions {
            // Check for division without zero check
            if func.body.contains(" / ") || func.body.contains("/=") {
                let divisor_pattern = Regex::new(r"/\s*(\w+)").unwrap();
                for caps in divisor_pattern.captures_iter(&func.body) {
                    if let Some(divisor) = caps.get(1) {
                        let divisor_name = divisor.as_str();
                        // Skip constants and literals
                        if divisor_name.chars().next().map(|c| c.is_numeric()).unwrap_or(false) {
                            continue;
                        }

                        let has_zero_check = func.body.contains(&format!("require({} > 0", divisor_name)) ||
                                            func.body.contains(&format!("require({} != 0", divisor_name)) ||
                                            func.body.contains(&format!("if ({} == 0", divisor_name)) ||
                                            func.body.contains(&format!("{} > 0", divisor_name));

                        if !has_zero_check {
                            vulnerabilities.push(Vulnerability::new(
                                VulnerabilitySeverity::High,
                                VulnerabilityCategory::LogicError,
                                format!("Division Without Zero Check in {}", func.name),
                                format!("Division by '{}' without explicit zero validation", divisor_name),
                                func.line_start,
                                format!("function {} divides by {}", func.name, divisor_name),
                                format!("Add require({} > 0, \"Division by zero\") before division", divisor_name),
                            ));
                            break; // One warning per function
                        }
                    }
                }
            }

            // Check for array access without bounds check
            if func.body.contains("[") && func.body.contains("]") {
                let array_access_pattern = Regex::new(r"(\w+)\[(\w+)\]").unwrap();
                for caps in array_access_pattern.captures_iter(&func.body) {
                    if let (Some(array_name), Some(index)) = (caps.get(1), caps.get(2)) {
                        let index_name = index.as_str();
                        let array_name_str = array_name.as_str();

                        // Skip mappings (they don't have length)
                        if content.contains(&format!("mapping")) && content.contains(array_name_str) {
                            continue;
                        }

                        let has_bounds_check = func.body.contains(&format!("{} < {}.length", index_name, array_name_str)) ||
                                              func.body.contains(&format!("require({}.length >", array_name_str));

                        if !has_bounds_check && !index_name.chars().next().map(|c| c.is_numeric()).unwrap_or(false) {
                            vulnerabilities.push(Vulnerability::new(
                                VulnerabilitySeverity::Medium,
                                VulnerabilityCategory::LogicError,
                                format!("Array Access Without Bounds Check in {}", func.name),
                                format!("Array '{}' accessed with index '{}' without explicit bounds validation", array_name_str, index_name),
                                func.line_start,
                                format!("{}[{}]", array_name_str, index_name),
                                format!("Add require({} < {}.length) before access", index_name, array_name_str),
                            ));
                            break;
                        }
                    }
                }
            }
        }

        vulnerabilities
    }

    /// Analyze authorization flow for gaps
    fn analyze_authorization_flow(
        &self,
        _content: &str,
        functions: &[FunctionInfo],
    ) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        // Find authorization hierarchy
        let mut admin_functions: Vec<&FunctionInfo> = Vec::new();
        let mut user_functions: Vec<&FunctionInfo> = Vec::new();

        for func in functions {
            if func.modifiers.iter().any(|m| m.contains("Owner") || m.contains("Admin") || m.contains("Role")) {
                admin_functions.push(func);
            } else if func.visibility == "external" || func.visibility == "public" {
                user_functions.push(func);
            }
        }

        // Check if admin functions can break user functionality
        for admin_func in &admin_functions {
            for user_func in &user_functions {
                // Check if admin function modifies variables that user function depends on
                let overlap: Vec<_> = admin_func.state_writes.iter()
                    .filter(|w| user_func.state_reads.contains(w))
                    .collect();

                if !overlap.is_empty() {
                    // Check if user function has validation for these variables
                    let has_validation = overlap.iter().any(|var|
                        user_func.body.contains(&format!("require({}", var))
                    );

                    if !has_validation {
                        vulnerabilities.push(Vulnerability::new(
                            VulnerabilitySeverity::Medium,
                            VulnerabilityCategory::LogicError,
                            format!("Admin Can Break User Function: {} -> {}", admin_func.name, user_func.name),
                            format!("Admin function '{}' modifies variables that '{}' depends on without user protection",
                                   admin_func.name, user_func.name),
                            user_func.line_start,
                            format!("Shared state: {:?}", overlap),
                            "Add validation in user functions or add time-lock to admin functions".to_string(),
                        ));
                    }
                }
            }
        }

        vulnerabilities
    }

    /// Detect race condition windows
    fn detect_race_condition_windows(
        &self,
        content: &str,
        functions: &[FunctionInfo],
    ) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        // Check for approve-based race conditions
        for func in functions {
            if func.name.to_lowercase() == "approve" || func.name.to_lowercase().contains("approval") {
                // Check if there's increaseAllowance/decreaseAllowance
                let has_safe_methods = content.contains("increaseAllowance") ||
                                       content.contains("decreaseAllowance");

                if !has_safe_methods {
                    vulnerabilities.push(Vulnerability::new(
                        VulnerabilitySeverity::Medium,
                        VulnerabilityCategory::LogicError,
                        "ERC20 Approve Race Condition".to_string(),
                        "approve() without increaseAllowance/decreaseAllowance - vulnerable to front-running".to_string(),
                        func.line_start,
                        format!("function {}", func.name),
                        "Implement increaseAllowance() and decreaseAllowance() or use permit()".to_string(),
                    ));
                }
            }
        }

        // Check for check-effect-interact pattern violations that create windows
        for func in functions {
            if !func.external_calls.is_empty() {
                // Find if there are state reads after external calls
                let lines: Vec<&str> = func.body.lines().collect();
                let mut after_call = false;

                for line in &lines {
                    if line.contains(".call(") || line.contains(".transfer(") || line.contains(".send(") {
                        after_call = true;
                    }

                    if after_call {
                        // Check for state-dependent operations after call
                        for read_var in &func.state_reads {
                            if line.contains(read_var) &&
                               (line.contains("if") || line.contains("require") || line.contains("assert")) {
                                vulnerabilities.push(Vulnerability::new(
                                    VulnerabilitySeverity::High,
                                    VulnerabilityCategory::LogicError,
                                    format!("State Check After External Call in {}", func.name),
                                    "State-dependent check after external call creates race condition window".to_string(),
                                    func.line_start,
                                    format!("Reads '{}' after external call", read_var),
                                    "Move all state checks before external calls".to_string(),
                                ));
                                break;
                            }
                        }
                    }
                }
            }
        }

        vulnerabilities
    }

    /// Detect asymmetric behavior in paired operations
    fn detect_asymmetric_behavior(
        &self,
        _content: &str,
        functions: &[FunctionInfo],
    ) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        let pairs = vec![
            ("deposit", "withdraw"),
            ("mint", "burn"),
            ("stake", "unstake"),
            ("add", "remove"),
            ("lock", "unlock"),
        ];

        for (action1, action2) in pairs {
            let func1: Option<&FunctionInfo> = functions.iter()
                .find(|f| f.name.to_lowercase().contains(action1) && !f.name.to_lowercase().contains(action2));
            let func2: Option<&FunctionInfo> = functions.iter()
                .find(|f| f.name.to_lowercase().contains(action2) && !f.name.to_lowercase().contains(action1));

            if let (Some(f1), Some(f2)) = (func1, func2) {
                // Check for asymmetric validation
                let f1_requires = f1.body.matches("require(").count();
                let f2_requires = f2.body.matches("require(").count();

                if f1_requires > 0 && f2_requires == 0 {
                    vulnerabilities.push(Vulnerability::new(
                        VulnerabilitySeverity::Medium,
                        VulnerabilityCategory::LogicError,
                        format!("Asymmetric Validation: {} has checks, {} does not", f1.name, f2.name),
                        "Paired operations have asymmetric validation - potential logic bug".to_string(),
                        f2.line_start,
                        format!("{} lacks require() while {} has {}", f2.name, f1.name, f1_requires),
                        format!("Add appropriate validation to {}", f2.name),
                    ));
                }

                // Check for asymmetric event emission
                let f1_events = f1.body.matches("emit ").count();
                let f2_events = f2.body.matches("emit ").count();

                if f1_events > 0 && f2_events == 0 {
                    vulnerabilities.push(Vulnerability::new(
                        VulnerabilitySeverity::Low,
                        VulnerabilityCategory::MissingEvents,
                        format!("Missing Event in {}", f2.name),
                        format!("'{}' emits events but paired '{}' does not", f1.name, f2.name),
                        f2.line_start,
                        format!("function {}", f2.name),
                        "Add event emission for tracking paired operations".to_string(),
                    ));
                }
            }
        }

        vulnerabilities
    }

    /// Detect unreachable or dead logic paths
    fn detect_unreachable_logic(
        &self,
        _content: &str,
        functions: &[FunctionInfo],
    ) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        for func in functions {
            // Check for conditions that are always true/false
            let impossible_conditions = vec![
                ("uint", "< 0", "unsigned integer cannot be negative"),
                ("uint", "< 0)", "unsigned integer cannot be negative"),
                ("== true && == false", "", "contradictory conditions"),
                ("> maxValue && < minValue", "", "impossible range"),
            ];

            for (pattern1, pattern2, reason) in &impossible_conditions {
                if func.body.contains(pattern1) && (pattern2.is_empty() || func.body.contains(pattern2)) {
                    if pattern1.contains("uint") && func.body.contains("uint") {
                        // Check for actual < 0 comparison with uint
                        let uint_negative_check = Regex::new(r"uint\d*\s+\w+[^;]*<\s*0[^0-9]").unwrap();
                        if uint_negative_check.is_match(&func.body) {
                            vulnerabilities.push(Vulnerability::new(
                                VulnerabilitySeverity::Medium,
                                VulnerabilityCategory::LogicError,
                                format!("Impossible Condition in {}", func.name),
                                format!("Condition can never be true: {}", reason),
                                func.line_start,
                                format!("function {}", func.name),
                                "Remove impossible condition or fix logic".to_string(),
                            ));
                        }
                    }
                }
            }

            // Check for code after return/revert
            let lines: Vec<&str> = func.body.lines().collect();
            let mut found_return = false;
            let mut brace_depth = 0;

            for (i, line) in lines.iter().enumerate() {
                for ch in line.chars() {
                    if ch == '{' { brace_depth += 1; }
                    if ch == '}' { brace_depth -= 1; }
                }

                if (line.contains("return") || line.contains("revert")) &&
                   !line.contains("//") && brace_depth == 1 {
                    found_return = true;
                }

                if found_return && brace_depth == 1 && i + 1 < lines.len() {
                    let next_line = lines[i + 1].trim();
                    if !next_line.is_empty() && !next_line.starts_with("}") && !next_line.starts_with("//") {
                        vulnerabilities.push(Vulnerability::new(
                            VulnerabilitySeverity::Low,
                            VulnerabilityCategory::UnusedCode,
                            format!("Unreachable Code in {}", func.name),
                            "Code exists after return/revert statement and will never execute".to_string(),
                            func.line_start + i + 1,
                            next_line.to_string(),
                            "Remove unreachable code or fix control flow".to_string(),
                        ));
                        break;
                    }
                }
            }
        }

        vulnerabilities
    }

    /// Detect protocol-specific logic bugs
    fn detect_protocol_logic_bugs(
        &self,
        content: &str,
        functions: &[FunctionInfo],
    ) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        // ERC4626 Vault Logic Bugs
        if content.contains("ERC4626") || (content.contains("deposit") && content.contains("shares")) {
            vulnerabilities.extend(self.detect_erc4626_logic_bugs(content, functions));
        }

        // AMM Logic Bugs
        if content.contains("swap") && (content.contains("reserve") || content.contains("liquidity")) {
            vulnerabilities.extend(self.detect_amm_logic_bugs(content, functions));
        }

        // Lending Protocol Logic Bugs
        if content.contains("borrow") && content.contains("collateral") {
            vulnerabilities.extend(self.detect_lending_logic_bugs(content, functions));
        }

        // Staking Logic Bugs
        if content.contains("stake") && content.contains("reward") {
            vulnerabilities.extend(self.detect_staking_logic_bugs(content, functions));
        }

        vulnerabilities
    }

    fn detect_erc4626_logic_bugs(&self, content: &str, functions: &[FunctionInfo]) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        // First depositor inflation attack
        for func in functions {
            if func.name.to_lowercase() == "deposit" {
                let has_minimum_shares = func.body.contains("minShares") ||
                                        func.body.contains("MIN_DEPOSIT") ||
                                        content.contains("_initialConvertToShares");

                if !has_minimum_shares {
                    vulnerabilities.push(Vulnerability::high_confidence(
                        VulnerabilitySeverity::Critical,
                        VulnerabilityCategory::LogicError,
                        "ERC4626 First Depositor Inflation Attack".to_string(),
                        "Vault lacks protection against first depositor inflation attack".to_string(),
                        func.line_start,
                        format!("function {}", func.name),
                        "Implement virtual shares/assets offset or minimum deposit requirement".to_string(),
                    ));
                }
            }
        }

        // Share rounding issues
        for func in functions {
            if func.name == "convertToShares" || func.name == "convertToAssets" {
                let has_rounding_direction = func.body.contains("mulDivDown") ||
                                            func.body.contains("mulDivUp") ||
                                            func.body.contains("Math.Rounding");

                if !has_rounding_direction && func.body.contains("/") {
                    vulnerabilities.push(Vulnerability::new(
                        VulnerabilitySeverity::High,
                        VulnerabilityCategory::LogicError,
                        format!("Uncontrolled Rounding Direction in {}", func.name),
                        "Share conversion without explicit rounding direction - exploitable for value extraction".to_string(),
                        func.line_start,
                        format!("function {}", func.name),
                        "Use mulDivDown for deposits, mulDivUp for withdrawals".to_string(),
                    ));
                }
            }
        }

        vulnerabilities
    }

    fn detect_amm_logic_bugs(&self, content: &str, functions: &[FunctionInfo]) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        for func in functions {
            if func.name.to_lowercase().contains("swap") {
                // K-value validation
                let has_k_check = func.body.contains("k >=") ||
                                  func.body.contains("invariant") ||
                                  func.body.contains("reserve0 * reserve1");

                if !has_k_check && content.contains("reserve") {
                    vulnerabilities.push(Vulnerability::new(
                        VulnerabilitySeverity::High,
                        VulnerabilityCategory::LogicError,
                        format!("Missing K-Value Invariant Check in {}", func.name),
                        "AMM swap without k-value invariant validation".to_string(),
                        func.line_start,
                        format!("function {}", func.name),
                        "Add require(k_after >= k_before) to maintain AMM invariant".to_string(),
                    ));
                }

                // Minimum output check
                let has_min_output = func.body.contains("amountOutMin") ||
                                    func.body.contains("minReturn") ||
                                    func.body.contains(">= minAmount");

                if !has_min_output {
                    vulnerabilities.push(Vulnerability::new(
                        VulnerabilitySeverity::High,
                        VulnerabilityCategory::LogicError,
                        "Missing Minimum Output in Swap".to_string(),
                        "Swap function allows zero output - enables sandwich attacks".to_string(),
                        func.line_start,
                        format!("function {}", func.name),
                        "Add minAmountOut parameter and require(amountOut >= minAmountOut)".to_string(),
                    ));
                }
            }
        }

        vulnerabilities
    }

    fn detect_lending_logic_bugs(&self, content: &str, functions: &[FunctionInfo]) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        for func in functions {
            // Health factor check in liquidation
            if func.name.to_lowercase().contains("liquidat") {
                let has_health_check = func.body.contains("healthFactor") ||
                                       func.body.contains("isHealthy") ||
                                       func.body.contains("collateralValue");

                if !has_health_check {
                    vulnerabilities.push(Vulnerability::new(
                        VulnerabilitySeverity::Critical,
                        VulnerabilityCategory::LogicError,
                        "Liquidation Without Health Factor Check".to_string(),
                        "Liquidation function doesn't verify position is underwater".to_string(),
                        func.line_start,
                        format!("function {}", func.name),
                        "Add health factor validation before allowing liquidation".to_string(),
                    ));
                }
            }

            // Interest accrual timing
            if func.name.to_lowercase().contains("borrow") || func.name.to_lowercase().contains("repay") {
                let has_accrual = func.body.contains("accrueInterest") ||
                                  func.body.contains("_accrual") ||
                                  func.body.contains("updateInterest");

                if !has_accrual && content.contains("interest") {
                    vulnerabilities.push(Vulnerability::new(
                        VulnerabilitySeverity::High,
                        VulnerabilityCategory::LogicError,
                        format!("Missing Interest Accrual in {}", func.name),
                        "Borrow/repay without interest accrual - enables interest manipulation".to_string(),
                        func.line_start,
                        format!("function {}", func.name),
                        "Call accrueInterest() at the start of borrow/repay functions".to_string(),
                    ));
                }
            }
        }

        vulnerabilities
    }

    fn detect_staking_logic_bugs(&self, content: &str, functions: &[FunctionInfo]) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        for func in functions {
            // Reward update before state change
            if func.name.to_lowercase().contains("stake") || func.name.to_lowercase().contains("withdraw") {
                let has_reward_update = func.body.contains("updateReward") ||
                                        func.body.contains("_updateRewards") ||
                                        func.body.contains("earned(");

                if !has_reward_update && content.contains("reward") {
                    vulnerabilities.push(Vulnerability::new(
                        VulnerabilitySeverity::High,
                        VulnerabilityCategory::LogicError,
                        format!("Missing Reward Update in {}", func.name),
                        "Staking/withdrawal without reward update - rewards may be lost or duplicated".to_string(),
                        func.line_start,
                        format!("function {}", func.name),
                        "Call updateReward(msg.sender) before changing stake amounts".to_string(),
                    ));
                }
            }

            // Reward per token calculation
            if func.name.to_lowercase().contains("reward") && func.name.to_lowercase().contains("per") {
                let has_zero_supply_check = func.body.contains("totalSupply == 0") ||
                                            func.body.contains("totalSupply() == 0") ||
                                            func.body.contains("if (totalStaked == 0");

                if !has_zero_supply_check {
                    vulnerabilities.push(Vulnerability::new(
                        VulnerabilitySeverity::High,
                        VulnerabilityCategory::LogicError,
                        "Reward Calculation Division by Zero Risk".to_string(),
                        "Reward per token calculation without totalSupply zero check".to_string(),
                        func.line_start,
                        format!("function {}", func.name),
                        "Add if (totalSupply == 0) return rewardPerTokenStored;".to_string(),
                    ));
                }
            }
        }

        vulnerabilities
    }
}
