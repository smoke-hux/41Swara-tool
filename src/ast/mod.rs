//! AST-Based Analysis Engine
//!
//! This module provides advanced static analysis capabilities using proper
//! AST parsing, control flow graphs, and data flow analysis for Solidity contracts.

#![allow(dead_code)]

pub mod parser;
pub mod cfg;
pub mod dataflow;

