//! AST-Based Analysis Engine
//!
//! This module provides static analysis using regex-based AST extraction, a control
//! flow graph, and taint tracking for Solidity contracts.
//!
//! - `parser`: Regex-based Solidity AST extraction (contracts, state variables,
//!   functions, and a flat per-line statement list)
//! - `cfg`: Control flow graph construction over that flat statement list, used to
//!   flag external calls followed by state writes. Because the parser never emits
//!   branch statements, the graph is a straight chain and the check is a linear
//!   scan rather than a path-sensitive analysis (see the `cfg` module docs).
//! - `dataflow`: Taint tracking from sources (msg.sender, calldata) to sinks (call, delegatecall)
//! - `bridge`: Unified analysis coordinator that produces Vulnerability findings

pub mod bridge;
pub mod cfg;
pub mod dataflow;
pub mod parser;
