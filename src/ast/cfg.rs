//! Control Flow Graph (CFG) Construction
//!
//! Builds a CFG from a parsed function body and uses it to flag external calls that
//! are followed by state writes (a CEI violation).
//!
//! ## Scope and limitations
//!
//! `super::parser::parse_statements` emits a *flat*, line-ordered statement list: it
//! never produces `if`/`for`/`while`/`try` statements, so this builder never sees a
//! branch or a loop. The graph it produces is therefore a straight chain of nodes in
//! source order (with `revert` nodes hanging off it as dead-end successors), and
//! `find_reentrancy_patterns` is in practice a linear scan over the function rather
//! than a path-sensitive analysis. `path_exists` is retained because it is what makes
//! the scan directional — it rejects writes that sit *before* the call — but on a
//! chain it agrees with a simple source-order comparison.

use super::parser::{FunctionDefinition, Statement};
use petgraph::graph::{DiGraph, NodeIndex};
use petgraph::Direction;
use std::collections::HashSet;

/// Control Flow Graph for a function
#[derive(Debug, Clone)]
pub struct ControlFlowGraph {
    graph: DiGraph<CFGNode, CFGEdge>,
}

/// CFG Node representing a basic block or control point
#[derive(Debug, Clone)]
pub struct CFGNode {
    pub node_type: CFGNodeType,
    pub statements: Vec<StatementInfo>,
}

#[derive(Debug, Clone)]
pub struct StatementInfo {
    pub line: usize,
    pub writes: Vec<String>,  // Variables written
    pub calls: Vec<CallInfo>, // External/internal calls
}

#[derive(Debug, Clone)]
pub struct CallInfo {
    pub is_external: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub enum CFGNodeType {
    Entry,
    BasicBlock,
    Exit,
    Require,
    Revert,
    ExternalCall,
    Assembly,
    UncheckedBlock,
}

/// CFG Edge representing control flow between nodes.
///
/// Carries no payload: with a flat statement list there are no conditional or loop
/// edges to distinguish.
#[derive(Debug, Clone)]
pub struct CFGEdge;

/// CFG Builder
pub struct CFGBuilder;

impl CFGBuilder {
    pub fn new() -> Self {
        Self
    }

    /// Build CFG from a function definition
    pub fn build_cfg(&mut self, function: &FunctionDefinition) -> ControlFlowGraph {
        let mut graph: DiGraph<CFGNode, CFGEdge> = DiGraph::new();

        // Create entry node
        let entry = graph.add_node(CFGNode {
            node_type: CFGNodeType::Entry,
            statements: vec![],
        });

        let mut current = entry;

        // Process function body
        if let Some(body) = &function.body {
            current = self.process_statements(&mut graph, &body.statements, current);
        }

        // Create exit node if needed
        if graph[current].node_type != CFGNodeType::Exit {
            let exit = graph.add_node(CFGNode {
                node_type: CFGNodeType::Exit,
                statements: vec![],
            });
            graph.add_edge(current, exit, CFGEdge);
        }

        ControlFlowGraph { graph }
    }

    /// Append the (flat) statement list to the graph as a chain of nodes.
    fn process_statements(
        &mut self,
        graph: &mut DiGraph<CFGNode, CFGEdge>,
        statements: &[Statement],
        mut current: NodeIndex,
    ) -> NodeIndex {
        let mut current_block_stmts = Vec::new();

        for stmt in statements {
            let stmt_info = self.analyze_statement(stmt);

            match stmt {
                Statement::Return { .. } => {
                    current_block_stmts.push(stmt_info);

                    // Create exit node
                    let exit_node = graph.add_node(CFGNode {
                        node_type: CFGNodeType::Exit,
                        statements: current_block_stmts.clone(),
                    });
                    graph.add_edge(current, exit_node, CFGEdge);
                    current_block_stmts.clear();
                    current = exit_node;
                }

                Statement::Require { .. } => {
                    current_block_stmts.push(stmt_info.clone());

                    // Create require node
                    let req_node = graph.add_node(CFGNode {
                        node_type: CFGNodeType::Require,
                        statements: vec![stmt_info],
                    });

                    if !current_block_stmts.is_empty() {
                        let block_node = graph.add_node(CFGNode {
                            node_type: CFGNodeType::BasicBlock,
                            statements: current_block_stmts[..current_block_stmts.len() - 1]
                                .to_vec(),
                        });
                        graph.add_edge(current, block_node, CFGEdge);
                        current = block_node;
                        current_block_stmts.clear();
                    }

                    graph.add_edge(current, req_node, CFGEdge);
                    current = req_node;
                }

                Statement::Revert { .. } => {
                    let revert_node = graph.add_node(CFGNode {
                        node_type: CFGNodeType::Revert,
                        statements: vec![stmt_info],
                    });

                    if !current_block_stmts.is_empty() {
                        let block_node = graph.add_node(CFGNode {
                            node_type: CFGNodeType::BasicBlock,
                            statements: current_block_stmts.clone(),
                        });
                        graph.add_edge(current, block_node, CFGEdge);
                        current = block_node;
                        current_block_stmts.clear();
                    }

                    graph.add_edge(current, revert_node, CFGEdge);
                }

                Statement::ExternalCall { .. } => {
                    current_block_stmts.push(stmt_info.clone());

                    let call_node = graph.add_node(CFGNode {
                        node_type: CFGNodeType::ExternalCall,
                        statements: vec![stmt_info],
                    });

                    if current_block_stmts.len() > 1 {
                        let block_node = graph.add_node(CFGNode {
                            node_type: CFGNodeType::BasicBlock,
                            statements: current_block_stmts[..current_block_stmts.len() - 1]
                                .to_vec(),
                        });
                        graph.add_edge(current, block_node, CFGEdge);
                        current = block_node;
                    }
                    current_block_stmts.clear();

                    graph.add_edge(current, call_node, CFGEdge);
                    current = call_node;
                }

                Statement::Assembly { .. } => {
                    let asm_node = graph.add_node(CFGNode {
                        node_type: CFGNodeType::Assembly,
                        statements: vec![stmt_info],
                    });

                    if !current_block_stmts.is_empty() {
                        let block_node = graph.add_node(CFGNode {
                            node_type: CFGNodeType::BasicBlock,
                            statements: current_block_stmts.clone(),
                        });
                        graph.add_edge(current, block_node, CFGEdge);
                        current = block_node;
                        current_block_stmts.clear();
                    }

                    graph.add_edge(current, asm_node, CFGEdge);
                    current = asm_node;
                }

                Statement::UncheckedBlock { .. } => {
                    let unchecked_node = graph.add_node(CFGNode {
                        node_type: CFGNodeType::UncheckedBlock,
                        statements: vec![stmt_info],
                    });

                    if !current_block_stmts.is_empty() {
                        let block_node = graph.add_node(CFGNode {
                            node_type: CFGNodeType::BasicBlock,
                            statements: current_block_stmts.clone(),
                        });
                        graph.add_edge(current, block_node, CFGEdge);
                        current = block_node;
                        current_block_stmts.clear();
                    }

                    graph.add_edge(current, unchecked_node, CFGEdge);
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
            });
            graph.add_edge(current, block_node, CFGEdge);
            current = block_node;
        }

        current
    }

    fn analyze_statement(&self, stmt: &Statement) -> StatementInfo {
        match stmt {
            Statement::Assignment { target, line, .. } => StatementInfo {
                line: *line,
                writes: vec![target.clone()],
                calls: vec![],
            },
            Statement::ExternalCall { line, .. } => StatementInfo {
                line: *line,
                writes: vec![],
                calls: vec![CallInfo { is_external: true }],
            },
            Statement::Return { line }
            | Statement::Require { line, .. }
            | Statement::Revert { line }
            | Statement::Emit { line }
            | Statement::Assembly { line, .. }
            | Statement::UncheckedBlock { line, .. }
            | Statement::Expression { line } => StatementInfo {
                line: *line,
                writes: vec![],
                calls: vec![],
            },
        }
    }
}

impl ControlFlowGraph {
    /// Find external calls that are followed by a state write.
    ///
    /// For every statement holding an external call, report each later-line write
    /// that is reachable from it. Because the graph is a chain (see the module
    /// docs), "reachable" degenerates to "occurs after in source order", so this is
    /// effectively a linear scan of the function.
    pub fn find_reentrancy_patterns(&self) -> Vec<(usize, usize)> {
        let mut patterns = Vec::new();
        let mut seen = HashSet::new();
        let nodes: Vec<NodeIndex> = self.graph.node_indices().collect();

        for call_node in &nodes {
            for call_stmt in &self.graph[*call_node].statements {
                if call_stmt.calls.iter().any(|call| call.is_external) {
                    for write_node in &nodes {
                        if !self.path_exists(*call_node, *write_node) {
                            continue;
                        }

                        for write_stmt in &self.graph[*write_node].statements {
                            if !write_stmt.writes.is_empty() && write_stmt.line > call_stmt.line {
                                let pattern = (call_stmt.line, write_stmt.line);
                                if seen.insert(pattern) {
                                    patterns.push(pattern);
                                }
                            }
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

    fn dfs_reachable(
        &self,
        current: NodeIndex,
        target: NodeIndex,
        visited: &mut HashSet<NodeIndex>,
    ) -> bool {
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
}

impl Default for CFGBuilder {
    fn default() -> Self {
        Self::new()
    }
}
