//! Data Flow Analysis
//!
//! Implements taint tracking for detecting user-controlled input reaching
//! dangerous sinks like external calls, state writes, and require statements.


use super::parser::{ContractDefinition, FunctionDefinition, SolidityAST, Statement, Visibility};
use once_cell::sync::Lazy;
use regex::Regex;
use std::collections::{HashMap, HashSet};

static IDENTIFIER_PATTERN: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\b([a-zA-Z_][a-zA-Z0-9_]*)\b").unwrap());

/// Taint sources - origins of potentially malicious data
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum TaintSource {
    MsgSender,
    MsgValue,
    MsgData,
    Calldata,
    StorageRead,
    BlockTimestamp,
    BlockNumber,
    TxOrigin,
    FunctionParameter(String),
}

/// Taint sinks - dangerous operations where tainted data should be validated
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum TaintSink {
    ExternalCall,
    DelegateCall,
    StateWrite,
    Selfdestruct,
    Create,
    Create2,
    Assembly,
    Transfer,
    RequireCondition,
}

/// Result of taint analysis
#[derive(Debug, Clone)]
pub struct TaintResult {
    pub source: TaintSource,
    pub sink: TaintSink,
    pub path: Vec<String>, // Variable names in taint propagation path
    pub sink_line: usize,
    pub description: String,
}

/// Variable taint state
#[derive(Debug, Clone)]
struct TaintState {
    is_tainted: bool,
    sources: HashSet<TaintSource>,
    propagation_path: Vec<String>,
}

impl TaintState {
    fn new() -> Self {
        Self {
            is_tainted: false,
            sources: HashSet::new(),
            propagation_path: vec![],
        }
    }

    fn tainted(source: TaintSource, var_name: &str) -> Self {
        let mut state = Self::new();
        state.is_tainted = true;
        state.sources.insert(source);
        state.propagation_path.push(var_name.to_string());
        state
    }

    fn propagate(&self, to_var: &str) -> Self {
        let mut new_state = self.clone();
        new_state.propagation_path.push(to_var.to_string());
        new_state
    }

    fn merge(&mut self, other: &TaintState) {
        if other.is_tainted {
            self.is_tainted = true;
            self.sources.extend(other.sources.iter().cloned());
            // Keep existing path or use other's if longer
            if other.propagation_path.len() > self.propagation_path.len() {
                self.propagation_path = other.propagation_path.clone();
            }
        }
    }
}

/// Data Flow Analyzer for taint tracking
pub struct DataFlowAnalyzer {
    taint_map: HashMap<String, TaintState>,
    results: Vec<TaintResult>,
}

impl DataFlowAnalyzer {
    pub fn new() -> Self {
        Self {
            taint_map: HashMap::new(),
            results: Vec::new(),
        }
    }

    /// Analyze an entire AST for taint flows
    pub fn analyze(&mut self, ast: &SolidityAST) -> Vec<TaintResult> {
        self.results.clear();
        self.taint_map.clear();

        for contract in &ast.contracts {
            self.analyze_contract(contract);
        }

        self.results.clone()
    }

    /// Analyze a single contract
    fn analyze_contract(&mut self, contract: &ContractDefinition) {
        self.taint_map.clear();

        // Initialize state variable taint (storage reads are taint sources)
        for var in &contract.state_variables {
            // Only public state variables are potentially tainted externally
            if var.visibility == Visibility::Public {
                self.taint_map.insert(
                    var.name.clone(),
                    TaintState::tainted(TaintSource::StorageRead, &var.name),
                );
            }
        }

        // Analyze each function
        for function in &contract.functions {
            self.analyze_function(function);
        }
    }

    /// Analyze a single function
    fn analyze_function(&mut self, function: &FunctionDefinition) {
        // Seed each function with contract-level public storage taint, then track locals.
        let mut local_taint = self.taint_map.clone();

        // Initialize taint from function parameters (calldata is taint source)
        for param in &function.parameters {
            let source = TaintSource::FunctionParameter(param.name.clone());
            local_taint.insert(param.name.clone(), TaintState::tainted(source, &param.name));
        }

        // Add implicit taint sources
        local_taint.insert(
            "msg.sender".to_string(),
            TaintState::tainted(TaintSource::MsgSender, "msg.sender"),
        );
        local_taint.insert(
            "msg.value".to_string(),
            TaintState::tainted(TaintSource::MsgValue, "msg.value"),
        );
        local_taint.insert(
            "msg.data".to_string(),
            TaintState::tainted(TaintSource::MsgData, "msg.data"),
        );
        local_taint.insert(
            "block.timestamp".to_string(),
            TaintState::tainted(TaintSource::BlockTimestamp, "block.timestamp"),
        );
        local_taint.insert(
            "block.number".to_string(),
            TaintState::tainted(TaintSource::BlockNumber, "block.number"),
        );
        local_taint.insert(
            "tx.origin".to_string(),
            TaintState::tainted(TaintSource::TxOrigin, "tx.origin"),
        );

        // Analyze function body
        if let Some(body) = &function.body {
            self.analyze_statements(&body.statements, &mut local_taint);
        }
    }

    /// Analyze statements and track taint propagation
    fn analyze_statements(
        &mut self,
        statements: &[Statement],
        taint_map: &mut HashMap<String, TaintState>,
    ) {
        for stmt in statements {
            match stmt {
                Statement::Assignment {
                    target,
                    value,
                    line,
                } => {
                    let taint = self.compute_expression_taint(value, taint_map);
                    if taint.is_tainted {
                        let propagated = taint.propagate(target);

                        // Check if writing to state (potential sink)
                        if self.is_state_variable(target) {
                            for source in &propagated.sources {
                                self.results.push(TaintResult {
                                    source: source.clone(),
                                    sink: TaintSink::StateWrite,
                                    path: propagated.propagation_path.clone(),
                                    sink_line: *line,
                                    description: format!(
                                        "Tainted data from {:?} flows to state variable '{}'",
                                        source, target
                                    ),
                                });
                            }
                        }

                        taint_map.insert(target.clone(), propagated);
                    }
                }

                Statement::ExternalCall {
                    target,
                    function,
                    value_transfer,
                    line,
                } => {
                    // Check if call target is tainted (dangerous!)
                    if let Some(target_taint) = taint_map.get(target) {
                        if target_taint.is_tainted {
                            for source in &target_taint.sources {
                                self.results.push(TaintResult {
                                    source: source.clone(),
                                    sink: if function == "delegatecall" {
                                        TaintSink::DelegateCall
                                    } else {
                                        TaintSink::ExternalCall
                                    },
                                    path: target_taint.propagation_path.clone(),
                                    sink_line: *line,
                                    description: format!(
                                        "CRITICAL: Tainted address used in external call - {:?} flows to {}.{}()",
                                        source, target, function
                                    ),
                                });
                            }
                        }
                    }

                    // Value transfers with tainted amounts
                    if *value_transfer {
                        // Check if msg.value is being used dangerously
                        if let Some(value_taint) = taint_map.get("msg.value") {
                            if value_taint.is_tainted {
                                for source in &value_taint.sources {
                                    self.results.push(TaintResult {
                                        source: source.clone(),
                                        sink: TaintSink::Transfer,
                                        path: value_taint.propagation_path.clone(),
                                        sink_line: *line,
                                        description: format!(
                                            "External call with value transfer involving {:?}",
                                            source
                                        ),
                                    });
                                }
                            }
                        }
                    }
                }

                Statement::Require { condition, line } => {
                    // Check if require condition uses tainted data
                    let taint = self.compute_expression_taint(condition, taint_map);
                    if taint.is_tainted {
                        for source in &taint.sources {
                            // This is actually a GOOD pattern - validating tainted input
                            // But we track it for completeness
                            self.results.push(TaintResult {
                                source: source.clone(),
                                sink: TaintSink::RequireCondition,
                                path: taint.propagation_path.clone(),
                                sink_line: *line,
                                description: format!(
                                    "Tainted data from {:?} validated in require (good pattern)",
                                    source
                                ),
                            });
                        }
                    }
                }

                Statement::Assembly { content, line } => {
                    // Assembly can access tainted storage directly - flag as dangerous
                    if content.contains("sload") || content.contains("sstore") {
                        self.results.push(TaintResult {
                            source: TaintSource::StorageRead,
                            sink: TaintSink::Assembly,
                            path: vec!["assembly".to_string()],
                            sink_line: *line,
                            description:
                                "Assembly block with storage access - manual review required"
                                    .to_string(),
                        });
                    }

                    // Check for selfdestruct
                    if content.contains("selfdestruct") {
                        self.results.push(TaintResult {
                            source: TaintSource::MsgSender,
                            sink: TaintSink::Selfdestruct,
                            path: vec!["assembly".to_string()],
                            sink_line: *line,
                            description: "CRITICAL: Assembly contains selfdestruct".to_string(),
                        });
                    }

                    // Check for create/create2
                    if content.contains("create") {
                        let sink = if content.contains("create2") {
                            TaintSink::Create2
                        } else {
                            TaintSink::Create
                        };
                        self.results.push(TaintResult {
                            source: TaintSource::Calldata,
                            sink,
                            path: vec!["assembly".to_string()],
                            sink_line: *line,
                            description:
                                "Assembly contains contract creation - verify initialization"
                                    .to_string(),
                        });
                    }
                }

                Statement::UncheckedBlock { statements, .. } => {
                    // Analyze unchecked block - arithmetic here doesn't overflow check
                    self.analyze_statements(statements, taint_map);
                }

                _ => {}
            }
        }
    }

    /// Compute taint state of an expression
    fn compute_expression_taint(
        &self,
        expr: &str,
        taint_map: &HashMap<String, TaintState>,
    ) -> TaintState {
        let mut result = TaintState::new();

        // Check for direct taint sources in expression
        if expr.contains("msg.sender") {
            result.merge(&TaintState::tainted(TaintSource::MsgSender, "msg.sender"));
        }
        if expr.contains("msg.value") {
            result.merge(&TaintState::tainted(TaintSource::MsgValue, "msg.value"));
        }
        if expr.contains("msg.data") {
            result.merge(&TaintState::tainted(TaintSource::MsgData, "msg.data"));
        }
        if expr.contains("block.timestamp") {
            result.merge(&TaintState::tainted(
                TaintSource::BlockTimestamp,
                "block.timestamp",
            ));
        }
        if expr.contains("block.number") {
            result.merge(&TaintState::tainted(
                TaintSource::BlockNumber,
                "block.number",
            ));
        }
        if expr.contains("tx.origin") {
            result.merge(&TaintState::tainted(TaintSource::TxOrigin, "tx.origin"));
        }

        // Check for tainted variables in expression
        for cap in IDENTIFIER_PATTERN.captures_iter(expr) {
            if let Some(var_name) = cap.get(1) {
                if let Some(var_taint) = taint_map.get(var_name.as_str()) {
                    result.merge(var_taint);
                }
            }
        }

        result
    }

    /// Check if a variable name looks like a state variable
    fn is_state_variable(&self, name: &str) -> bool {
        // Heuristics for state variables:
        // - Starts with underscore (common convention)
        // - Starts with s_ (storage prefix convention)
        // - Contains common state variable patterns
        name.starts_with('_')
            || name.starts_with("s_")
            || name.contains("balance")
            || name.contains("Balance")
            || name.contains("owner")
            || name.contains("Owner")
            || name.contains("total")
            || name.contains("Total")
    }
}

impl Default for DataFlowAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}
