//! AST-Based Analysis Engine
//!
//! This module provides advanced static analysis capabilities using proper
//! AST parsing, control flow graphs, and data flow analysis for Solidity contracts.
//!
//! - `parser`: Regex-based Solidity AST extraction (contracts, functions, variables)
//! - `cfg`: Control flow graph construction and path-sensitive analysis
//! - `dataflow`: Taint tracking from sources (msg.sender, calldata) to sinks (call, delegatecall)
//! - `bridge`: Unified analysis coordinator that produces Vulnerability findings

#![allow(dead_code)]

pub mod parser;
pub mod cfg;
pub mod dataflow;
pub mod bridge;

