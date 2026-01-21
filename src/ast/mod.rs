//! AST-Based Analysis Engine
//!
//! This module provides advanced static analysis capabilities using proper
//! AST parsing, control flow graphs, and data flow analysis for Solidity contracts.

pub mod parser;
pub mod cfg;
pub mod dataflow;

pub use parser::ASTParser;
pub use cfg::{ControlFlowGraph, CFGNode, CFGEdge};
pub use dataflow::{DataFlowAnalyzer, TaintSource, TaintSink, TaintResult};
