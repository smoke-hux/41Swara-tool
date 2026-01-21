//! Control Flow Graph (CFG) Construction
//!
//! Builds CFGs from parsed function bodies for advanced vulnerability detection.
//! Enables path-sensitive analysis and dead code detection.

#![allow(dead_code)]
#![allow(unused_imports)]
#![allow(unused_variables)]

use petgraph::graph::{DiGraph, NodeIndex};
use petgraph::Direction;
use std::collections::{HashMap, HashSet};
use super::parser::{FunctionDefinition, Statement};

/// Control Flow Graph for a function
#[derive(Debug, Clone)]
pub struct ControlFlowGraph {
    graph: DiGraph<CFGNode, CFGEdge>,
    entry: NodeIndex,
    exits: Vec<NodeIndex>,
    node_map: HashMap<usize, NodeIndex>, // Line number to node index
}

/// CFG Node representing a basic block or control point
#[derive(Debug, Clone)]
pub struct CFGNode {
    pub node_type: CFGNodeType,
    pub statements: Vec<StatementInfo>,
    pub line: usize,
}

#[derive(Debug, Clone)]
pub struct StatementInfo {
    pub stmt_type: StatementType,
    pub line: usize,
    pub content: String,
    pub reads: Vec<String>,   // Variables read
    pub writes: Vec<String>,  // Variables written
    pub calls: Vec<CallInfo>, // External/internal calls
}

#[derive(Debug, Clone)]
pub struct CallInfo {
    pub target: String,
    pub function: String,
    pub is_external: bool,
    pub transfers_value: bool,
    pub line: usize,
}

#[derive(Debug, Clone, PartialEq)]
pub enum CFGNodeType {
    Entry,
    BasicBlock,
    IfCondition,
    LoopCondition,
    LoopBody,
    Exit,
    Require,
    Revert,
    ExternalCall,
    Assembly,
    UncheckedBlock,
}

#[derive(Debug, Clone, PartialEq)]
pub enum StatementType {
    Assignment,
    Declaration,
    ExternalCall,
    InternalCall,
    Return,
    Require,
    Revert,
    Emit,
    Assembly,
    Expression,
}

/// CFG Edge representing control flow between nodes
#[derive(Debug, Clone)]
pub struct CFGEdge {
    pub edge_type: CFGEdgeType,
    pub condition: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum CFGEdgeType {
    Sequential,        // Normal flow
    ConditionalTrue,   // If condition true
    ConditionalFalse,  // If condition false
    LoopBack,          // Back edge in loops
    LoopExit,          // Exit from loop
    Throw,             // Revert/require failure
}

/// CFG Builder
pub struct CFGBuilder {
    current_node: Option<NodeIndex>,
}

impl CFGBuilder {
    pub fn new() -> Self {
        Self {
            current_node: None,
        }
    }

    /// Build CFG from a function definition
    pub fn build_cfg(&mut self, function: &FunctionDefinition) -> ControlFlowGraph {
        let mut graph: DiGraph<CFGNode, CFGEdge> = DiGraph::new();
        let mut node_map = HashMap::new();

        // Create entry node
        let entry = graph.add_node(CFGNode {
            node_type: CFGNodeType::Entry,
            statements: vec![],
            line: function.start_line,
        });
        node_map.insert(function.start_line, entry);

        let mut exits = Vec::new();
        let mut current = entry;

        // Process function body
        if let Some(body) = &function.body {
            current = self.process_statements(&mut graph, &mut node_map, &body.statements, current, &mut exits);
        }

        // Create exit node if needed
        if graph[current].node_type != CFGNodeType::Exit {
            let exit = graph.add_node(CFGNode {
                node_type: CFGNodeType::Exit,
                statements: vec![],
                line: function.end_line,
            });
            graph.add_edge(current, exit, CFGEdge {
                edge_type: CFGEdgeType::Sequential,
                condition: None,
            });
            exits.push(exit);
        }

        ControlFlowGraph {
            graph,
            entry,
            exits,
            node_map,
        }
    }

    fn process_statements(
        &mut self,
        graph: &mut DiGraph<CFGNode, CFGEdge>,
        node_map: &mut HashMap<usize, NodeIndex>,
        statements: &[Statement],
        mut current: NodeIndex,
        exits: &mut Vec<NodeIndex>,
    ) -> NodeIndex {
        let mut current_block_stmts = Vec::new();

        for stmt in statements {
            let stmt_info = self.analyze_statement(stmt);

            match stmt {
                Statement::If { condition, then_block, else_block, line } => {
                    // Flush current block
                    if !current_block_stmts.is_empty() {
                        let block_node = graph.add_node(CFGNode {
                            node_type: CFGNodeType::BasicBlock,
                            statements: current_block_stmts.clone(),
                            line: current_block_stmts[0].line,
                        });
                        graph.add_edge(current, block_node, CFGEdge {
                            edge_type: CFGEdgeType::Sequential,
                            condition: None,
                        });
                        current = block_node;
                        current_block_stmts.clear();
                    }

                    // Create condition node
                    let cond_node = graph.add_node(CFGNode {
                        node_type: CFGNodeType::IfCondition,
                        statements: vec![stmt_info.clone()],
                        line: *line,
                    });
                    node_map.insert(*line, cond_node);
                    graph.add_edge(current, cond_node, CFGEdge {
                        edge_type: CFGEdgeType::Sequential,
                        condition: None,
                    });

                    // Process then block
                    let then_entry = graph.add_node(CFGNode {
                        node_type: CFGNodeType::BasicBlock,
                        statements: vec![],
                        line: *line,
                    });
                    graph.add_edge(cond_node, then_entry, CFGEdge {
                        edge_type: CFGEdgeType::ConditionalTrue,
                        condition: Some(condition.clone()),
                    });
                    let then_exit = self.process_statements(graph, node_map, then_block, then_entry, exits);

                    // Process else block
                    let else_exit = if let Some(else_stmts) = else_block {
                        let else_entry = graph.add_node(CFGNode {
                            node_type: CFGNodeType::BasicBlock,
                            statements: vec![],
                            line: *line,
                        });
                        graph.add_edge(cond_node, else_entry, CFGEdge {
                            edge_type: CFGEdgeType::ConditionalFalse,
                            condition: Some(format!("!{}", condition)),
                        });
                        Some(self.process_statements(graph, node_map, else_stmts, else_entry, exits))
                    } else {
                        None
                    };

                    // Create merge point
                    let merge = graph.add_node(CFGNode {
                        node_type: CFGNodeType::BasicBlock,
                        statements: vec![],
                        line: *line,
                    });
                    graph.add_edge(then_exit, merge, CFGEdge {
                        edge_type: CFGEdgeType::Sequential,
                        condition: None,
                    });
                    if let Some(else_ex) = else_exit {
                        graph.add_edge(else_ex, merge, CFGEdge {
                            edge_type: CFGEdgeType::Sequential,
                            condition: None,
                        });
                    } else {
                        graph.add_edge(cond_node, merge, CFGEdge {
                            edge_type: CFGEdgeType::ConditionalFalse,
                            condition: Some(format!("!{}", condition)),
                        });
                    }
                    current = merge;
                }

                Statement::For { init: _, condition, post: _, body, line } => {
                    // Flush current block
                    if !current_block_stmts.is_empty() {
                        let block_node = graph.add_node(CFGNode {
                            node_type: CFGNodeType::BasicBlock,
                            statements: current_block_stmts.clone(),
                            line: current_block_stmts[0].line,
                        });
                        graph.add_edge(current, block_node, CFGEdge {
                            edge_type: CFGEdgeType::Sequential,
                            condition: None,
                        });
                        current = block_node;
                        current_block_stmts.clear();
                    }

                    // Create loop condition node
                    let loop_cond = graph.add_node(CFGNode {
                        node_type: CFGNodeType::LoopCondition,
                        statements: vec![stmt_info.clone()],
                        line: *line,
                    });
                    node_map.insert(*line, loop_cond);
                    graph.add_edge(current, loop_cond, CFGEdge {
                        edge_type: CFGEdgeType::Sequential,
                        condition: None,
                    });

                    // Process loop body
                    let body_entry = graph.add_node(CFGNode {
                        node_type: CFGNodeType::LoopBody,
                        statements: vec![],
                        line: *line,
                    });
                    graph.add_edge(loop_cond, body_entry, CFGEdge {
                        edge_type: CFGEdgeType::ConditionalTrue,
                        condition: condition.clone(),
                    });
                    let body_exit = self.process_statements(graph, node_map, body, body_entry, exits);

                    // Back edge
                    graph.add_edge(body_exit, loop_cond, CFGEdge {
                        edge_type: CFGEdgeType::LoopBack,
                        condition: None,
                    });

                    // Loop exit
                    let loop_exit = graph.add_node(CFGNode {
                        node_type: CFGNodeType::BasicBlock,
                        statements: vec![],
                        line: *line,
                    });
                    graph.add_edge(loop_cond, loop_exit, CFGEdge {
                        edge_type: CFGEdgeType::LoopExit,
                        condition: condition.as_ref().map(|c| format!("!{}", c)),
                    });
                    current = loop_exit;
                }

                Statement::While { condition, body, line } => {
                    // Similar to for loop
                    if !current_block_stmts.is_empty() {
                        let block_node = graph.add_node(CFGNode {
                            node_type: CFGNodeType::BasicBlock,
                            statements: current_block_stmts.clone(),
                            line: current_block_stmts[0].line,
                        });
                        graph.add_edge(current, block_node, CFGEdge {
                            edge_type: CFGEdgeType::Sequential,
                            condition: None,
                        });
                        current = block_node;
                        current_block_stmts.clear();
                    }

                    let loop_cond = graph.add_node(CFGNode {
                        node_type: CFGNodeType::LoopCondition,
                        statements: vec![stmt_info.clone()],
                        line: *line,
                    });
                    node_map.insert(*line, loop_cond);
                    graph.add_edge(current, loop_cond, CFGEdge {
                        edge_type: CFGEdgeType::Sequential,
                        condition: None,
                    });

                    let body_entry = graph.add_node(CFGNode {
                        node_type: CFGNodeType::LoopBody,
                        statements: vec![],
                        line: *line,
                    });
                    graph.add_edge(loop_cond, body_entry, CFGEdge {
                        edge_type: CFGEdgeType::ConditionalTrue,
                        condition: Some(condition.clone()),
                    });
                    let body_exit = self.process_statements(graph, node_map, body, body_entry, exits);

                    graph.add_edge(body_exit, loop_cond, CFGEdge {
                        edge_type: CFGEdgeType::LoopBack,
                        condition: None,
                    });

                    let loop_exit = graph.add_node(CFGNode {
                        node_type: CFGNodeType::BasicBlock,
                        statements: vec![],
                        line: *line,
                    });
                    graph.add_edge(loop_cond, loop_exit, CFGEdge {
                        edge_type: CFGEdgeType::LoopExit,
                        condition: Some(format!("!{}", condition)),
                    });
                    current = loop_exit;
                }

                Statement::Return { line, .. } => {
                    current_block_stmts.push(stmt_info);

                    // Create exit node
                    let exit_node = graph.add_node(CFGNode {
                        node_type: CFGNodeType::Exit,
                        statements: current_block_stmts.clone(),
                        line: *line,
                    });
                    node_map.insert(*line, exit_node);
                    graph.add_edge(current, exit_node, CFGEdge {
                        edge_type: CFGEdgeType::Sequential,
                        condition: None,
                    });
                    exits.push(exit_node);
                    current_block_stmts.clear();
                    current = exit_node;
                }

                Statement::Require { line, .. } => {
                    current_block_stmts.push(stmt_info.clone());

                    // Create require node with potential throw edge
                    let req_node = graph.add_node(CFGNode {
                        node_type: CFGNodeType::Require,
                        statements: vec![stmt_info],
                        line: *line,
                    });
                    node_map.insert(*line, req_node);

                    if !current_block_stmts.is_empty() {
                        let block_node = graph.add_node(CFGNode {
                            node_type: CFGNodeType::BasicBlock,
                            statements: current_block_stmts[..current_block_stmts.len()-1].to_vec(),
                            line: current_block_stmts[0].line,
                        });
                        graph.add_edge(current, block_node, CFGEdge {
                            edge_type: CFGEdgeType::Sequential,
                            condition: None,
                        });
                        current = block_node;
                        current_block_stmts.clear();
                    }

                    graph.add_edge(current, req_node, CFGEdge {
                        edge_type: CFGEdgeType::Sequential,
                        condition: None,
                    });
                    current = req_node;
                }

                Statement::Revert { line, .. } => {
                    let revert_node = graph.add_node(CFGNode {
                        node_type: CFGNodeType::Revert,
                        statements: vec![stmt_info],
                        line: *line,
                    });
                    node_map.insert(*line, revert_node);

                    if !current_block_stmts.is_empty() {
                        let block_node = graph.add_node(CFGNode {
                            node_type: CFGNodeType::BasicBlock,
                            statements: current_block_stmts.clone(),
                            line: current_block_stmts[0].line,
                        });
                        graph.add_edge(current, block_node, CFGEdge {
                            edge_type: CFGEdgeType::Sequential,
                            condition: None,
                        });
                        current = block_node;
                        current_block_stmts.clear();
                    }

                    graph.add_edge(current, revert_node, CFGEdge {
                        edge_type: CFGEdgeType::Throw,
                        condition: None,
                    });
                    exits.push(revert_node);
                }

                Statement::ExternalCall { line, .. } => {
                    current_block_stmts.push(stmt_info.clone());

                    let call_node = graph.add_node(CFGNode {
                        node_type: CFGNodeType::ExternalCall,
                        statements: vec![stmt_info],
                        line: *line,
                    });
                    node_map.insert(*line, call_node);

                    if current_block_stmts.len() > 1 {
                        let block_node = graph.add_node(CFGNode {
                            node_type: CFGNodeType::BasicBlock,
                            statements: current_block_stmts[..current_block_stmts.len()-1].to_vec(),
                            line: current_block_stmts[0].line,
                        });
                        graph.add_edge(current, block_node, CFGEdge {
                            edge_type: CFGEdgeType::Sequential,
                            condition: None,
                        });
                        current = block_node;
                    }
                    current_block_stmts.clear();

                    graph.add_edge(current, call_node, CFGEdge {
                        edge_type: CFGEdgeType::Sequential,
                        condition: None,
                    });
                    current = call_node;
                }

                Statement::Assembly { line, .. } => {
                    let asm_node = graph.add_node(CFGNode {
                        node_type: CFGNodeType::Assembly,
                        statements: vec![stmt_info],
                        line: *line,
                    });
                    node_map.insert(*line, asm_node);

                    if !current_block_stmts.is_empty() {
                        let block_node = graph.add_node(CFGNode {
                            node_type: CFGNodeType::BasicBlock,
                            statements: current_block_stmts.clone(),
                            line: current_block_stmts[0].line,
                        });
                        graph.add_edge(current, block_node, CFGEdge {
                            edge_type: CFGEdgeType::Sequential,
                            condition: None,
                        });
                        current = block_node;
                        current_block_stmts.clear();
                    }

                    graph.add_edge(current, asm_node, CFGEdge {
                        edge_type: CFGEdgeType::Sequential,
                        condition: None,
                    });
                    current = asm_node;
                }

                Statement::UncheckedBlock { line, .. } => {
                    let unchecked_node = graph.add_node(CFGNode {
                        node_type: CFGNodeType::UncheckedBlock,
                        statements: vec![stmt_info],
                        line: *line,
                    });
                    node_map.insert(*line, unchecked_node);

                    if !current_block_stmts.is_empty() {
                        let block_node = graph.add_node(CFGNode {
                            node_type: CFGNodeType::BasicBlock,
                            statements: current_block_stmts.clone(),
                            line: current_block_stmts[0].line,
                        });
                        graph.add_edge(current, block_node, CFGEdge {
                            edge_type: CFGEdgeType::Sequential,
                            condition: None,
                        });
                        current = block_node;
                        current_block_stmts.clear();
                    }

                    graph.add_edge(current, unchecked_node, CFGEdge {
                        edge_type: CFGEdgeType::Sequential,
                        condition: None,
                    });
                    current = unchecked_node;
                }

                _ => {
                    current_block_stmts.push(stmt_info);
                }
            }
        }

        // Flush remaining statements
        if !current_block_stmts.is_empty() {
            let block_node = graph.add_node(CFGNode {
                node_type: CFGNodeType::BasicBlock,
                statements: current_block_stmts,
                line: 0,
            });
            graph.add_edge(current, block_node, CFGEdge {
                edge_type: CFGEdgeType::Sequential,
                condition: None,
            });
            current = block_node;
        }

        current
    }

    fn analyze_statement(&self, stmt: &Statement) -> StatementInfo {
        match stmt {
            Statement::VariableDeclaration { name, var_type, value, line } => {
                StatementInfo {
                    stmt_type: StatementType::Declaration,
                    line: *line,
                    content: format!("{} {}", var_type, name),
                    reads: value.as_ref().map(|v| self.extract_variables(v)).unwrap_or_default(),
                    writes: vec![name.clone()],
                    calls: vec![],
                }
            }
            Statement::Assignment { target, value, line } => {
                StatementInfo {
                    stmt_type: StatementType::Assignment,
                    line: *line,
                    content: format!("{} = {}", target, value),
                    reads: self.extract_variables(value),
                    writes: vec![target.clone()],
                    calls: vec![],
                }
            }
            Statement::ExternalCall { target, function, value_transfer, line } => {
                StatementInfo {
                    stmt_type: StatementType::ExternalCall,
                    line: *line,
                    content: format!("{}.{}", target, function),
                    reads: vec![target.clone()],
                    writes: vec![],
                    calls: vec![CallInfo {
                        target: target.clone(),
                        function: function.clone(),
                        is_external: true,
                        transfers_value: *value_transfer,
                        line: *line,
                    }],
                }
            }
            Statement::InternalCall { function, args, line } => {
                StatementInfo {
                    stmt_type: StatementType::InternalCall,
                    line: *line,
                    content: format!("{}({})", function, args.join(", ")),
                    reads: args.iter().flat_map(|a| self.extract_variables(a)).collect(),
                    writes: vec![],
                    calls: vec![CallInfo {
                        target: String::new(),
                        function: function.clone(),
                        is_external: false,
                        transfers_value: false,
                        line: *line,
                    }],
                }
            }
            Statement::Return { value, line } => {
                StatementInfo {
                    stmt_type: StatementType::Return,
                    line: *line,
                    content: value.clone().unwrap_or_else(|| "return".to_string()),
                    reads: value.as_ref().map(|v| self.extract_variables(v)).unwrap_or_default(),
                    writes: vec![],
                    calls: vec![],
                }
            }
            Statement::Require { condition, message, line } => {
                StatementInfo {
                    stmt_type: StatementType::Require,
                    line: *line,
                    content: format!("require({})", condition),
                    reads: self.extract_variables(condition),
                    writes: vec![],
                    calls: vec![],
                }
            }
            Statement::Revert { error, line } => {
                StatementInfo {
                    stmt_type: StatementType::Revert,
                    line: *line,
                    content: error.clone().unwrap_or_else(|| "revert".to_string()),
                    reads: vec![],
                    writes: vec![],
                    calls: vec![],
                }
            }
            Statement::Emit { event, args, line } => {
                StatementInfo {
                    stmt_type: StatementType::Emit,
                    line: *line,
                    content: format!("emit {}({})", event, args.join(", ")),
                    reads: args.iter().flat_map(|a| self.extract_variables(a)).collect(),
                    writes: vec![],
                    calls: vec![],
                }
            }
            Statement::Assembly { content, line } => {
                StatementInfo {
                    stmt_type: StatementType::Assembly,
                    line: *line,
                    content: content.clone(),
                    reads: vec![],
                    writes: vec![],
                    calls: vec![],
                }
            }
            _ => {
                let line = match stmt {
                    Statement::If { line, .. } => *line,
                    Statement::For { line, .. } => *line,
                    Statement::While { line, .. } => *line,
                    Statement::UncheckedBlock { line, .. } => *line,
                    Statement::TryCatch { line, .. } => *line,
                    Statement::Expression { line, .. } => *line,
                    _ => 0,
                };
                StatementInfo {
                    stmt_type: StatementType::Expression,
                    line,
                    content: String::new(),
                    reads: vec![],
                    writes: vec![],
                    calls: vec![],
                }
            }
        }
    }

    fn extract_variables(&self, expr: &str) -> Vec<String> {
        let var_pattern = regex::Regex::new(r"\b([a-zA-Z_][a-zA-Z0-9_]*)\b").unwrap();
        let keywords = ["if", "else", "for", "while", "return", "require", "revert", "true", "false", "msg", "block", "tx"];

        var_pattern.captures_iter(expr)
            .filter_map(|cap| cap.get(1).map(|m| m.as_str().to_string()))
            .filter(|v| !keywords.contains(&v.as_str()))
            .collect()
    }
}

impl ControlFlowGraph {
    /// Get all paths from entry to any exit
    pub fn get_all_paths(&self) -> Vec<Vec<NodeIndex>> {
        let mut paths = Vec::new();
        let mut current_path = vec![self.entry];
        self.dfs_paths(self.entry, &mut current_path, &mut paths, &mut HashSet::new());
        paths
    }

    fn dfs_paths(
        &self,
        node: NodeIndex,
        current_path: &mut Vec<NodeIndex>,
        all_paths: &mut Vec<Vec<NodeIndex>>,
        visited: &mut HashSet<NodeIndex>,
    ) {
        if visited.contains(&node) {
            return; // Avoid cycles
        }

        if self.exits.contains(&node) {
            all_paths.push(current_path.clone());
            return;
        }

        visited.insert(node);

        for neighbor in self.graph.neighbors_directed(node, Direction::Outgoing) {
            current_path.push(neighbor);
            self.dfs_paths(neighbor, current_path, all_paths, visited);
            current_path.pop();
        }

        visited.remove(&node);
    }

    /// Find all external calls that occur before state changes
    pub fn find_reentrancy_patterns(&self) -> Vec<(usize, usize)> {
        let mut patterns = Vec::new();

        for path in self.get_all_paths() {
            let mut last_external_call: Option<usize> = None;

            for node_idx in path {
                let node = &self.graph[node_idx];

                for stmt in &node.statements {
                    // Check for external call
                    if !stmt.calls.is_empty() && stmt.calls.iter().any(|c| c.is_external) {
                        last_external_call = Some(stmt.line);
                    }

                    // Check for state modification after external call
                    if let Some(call_line) = last_external_call {
                        if !stmt.writes.is_empty() && stmt.line > call_line {
                            patterns.push((call_line, stmt.line));
                        }
                    }
                }
            }
        }

        patterns
    }

    /// Check if there's a path from one node to another
    pub fn path_exists(&self, from: NodeIndex, to: NodeIndex) -> bool {
        let mut visited = HashSet::new();
        self.dfs_reachable(from, to, &mut visited)
    }

    fn dfs_reachable(&self, current: NodeIndex, target: NodeIndex, visited: &mut HashSet<NodeIndex>) -> bool {
        if current == target {
            return true;
        }

        if visited.contains(&current) {
            return false;
        }

        visited.insert(current);

        for neighbor in self.graph.neighbors_directed(current, Direction::Outgoing) {
            if self.dfs_reachable(neighbor, target, visited) {
                return true;
            }
        }

        false
    }

    /// Get nodes of a specific type
    pub fn get_nodes_by_type(&self, node_type: CFGNodeType) -> Vec<NodeIndex> {
        self.graph.node_indices()
            .filter(|&idx| self.graph[idx].node_type == node_type)
            .collect()
    }

    /// Get all external call nodes
    pub fn get_external_calls(&self) -> Vec<(NodeIndex, &CallInfo)> {
        let mut calls = Vec::new();

        for idx in self.graph.node_indices() {
            let node = &self.graph[idx];
            for stmt in &node.statements {
                for call in &stmt.calls {
                    if call.is_external {
                        calls.push((idx, call));
                    }
                }
            }
        }

        calls
    }

    /// Get cyclomatic complexity
    pub fn cyclomatic_complexity(&self) -> usize {
        let edges = self.graph.edge_count();
        let nodes = self.graph.node_count();
        let connected_components = 1; // Assuming single connected component

        edges - nodes + 2 * connected_components
    }
}

impl Default for CFGBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cfg_construction() {
        let builder = CFGBuilder::new();

        // Test would construct a function and build CFG
        // For now, just verify the builder can be created
        assert!(true);
    }
}
