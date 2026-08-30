//! Solidity AST Parser
//!
//! Provides AST-like parsing for Solidity contracts using regex-based extraction.
//! A parse produces the contracts in a file, each with its state variables and its
//! functions; a function body is reduced to a *flat*, line-ordered list of
//! `Statement`s (see `parse_statements` — no nested blocks are ever produced).
//!
//! This parser deliberately covers only what the CFG (`super::cfg`) and taint
//! (`super::dataflow`) analyses consume. Compiler/pragma version handling lives in
//! `crate::parser`, not here.

use once_cell::sync::Lazy;
use regex::Regex;

// Compiled once per process — parse_functions runs for every contract in every
// scanned file.
static CONSTRUCTOR_DEF_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"constructor\s*\((?P<params>[^)]*)\)\s*(?P<modifiers>[^{]*)?\{").unwrap()
});
static FALLBACK_DEF_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"fallback\s*\(\)\s*(?P<modifiers>[^{]*)?\{").unwrap());
static RECEIVE_DEF_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"receive\s*\(\)\s*(?P<modifiers>[^{]*)?\{").unwrap());

/// Represents a parsed Solidity source file
#[derive(Debug, Clone)]
pub struct SolidityAST {
    pub contracts: Vec<ContractDefinition>,
}

/// Contract definition including interfaces, libraries, and abstract contracts
#[derive(Debug, Clone)]
pub struct ContractDefinition {
    pub state_variables: Vec<StateVariable>,
    pub functions: Vec<FunctionDefinition>,
}

/// State variable definition
#[derive(Debug, Clone)]
pub struct StateVariable {
    pub name: String,
    pub visibility: Visibility,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Visibility {
    Public,
    Private,
    Internal,
    External,
}

/// Function definition
#[derive(Debug, Clone)]
pub struct FunctionDefinition {
    pub name: String,
    pub parameters: Vec<Parameter>,
    pub body: Option<FunctionBody>,
}

/// Function parameter
#[derive(Debug, Clone)]
pub struct Parameter {
    pub name: String,
}

/// Function body as a flat, line-ordered statement list
#[derive(Debug, Clone)]
pub struct FunctionBody {
    pub statements: Vec<Statement>,
}

/// Statement kinds recognised by `parse_statements`.
///
/// Every variant is produced by a single-line regex match, so the list is flat:
/// control-flow constructs (`if`/`for`/`while`/`try`) are not represented and their
/// bodies appear as ordinary sibling statements.
#[derive(Debug, Clone)]
pub enum Statement {
    Assignment {
        target: String,
        value: String,
        line: usize,
    },
    ExternalCall {
        target: String,
        function: String,
        value_transfer: bool,
        line: usize,
    },
    Return {
        line: usize,
    },
    Require {
        condition: String,
        line: usize,
    },
    Revert {
        line: usize,
    },
    Emit {
        line: usize,
    },
    Assembly {
        content: String,
        line: usize,
    },
    UncheckedBlock {
        statements: Vec<Statement>,
        line: usize,
    },
    Expression {
        line: usize,
    },
}

/// AST Parser for Solidity
pub struct ASTParser {
    // Compiled regex patterns for efficiency
    contract_pattern: Regex,
    function_pattern: Regex,
    state_var_pattern: Regex,
    external_call_pattern: Regex,
    require_pattern: Regex,
    emit_pattern: Regex,
    assignment_pattern: Regex,
}

impl ASTParser {
    pub fn new() -> Self {
        Self {
            contract_pattern: Regex::new(
                r"(?P<type>contract|interface|library|abstract\s+contract)\s+(?P<name>\w+)(?:\s+is\s+(?P<inheritance>[^{]+))?\s*\{"
            ).unwrap(),
            function_pattern: Regex::new(
                r"function\s+(?P<name>\w+)\s*\((?P<params>[^)]*)\)\s*(?P<modifiers>[^{;]*)(?:\{|;)"
            ).unwrap(),
            state_var_pattern: Regex::new(
                r"(?P<type>mapping\([^)]+\)|\w+(?:\[\])?)(?:\s+(?P<visibility>public|private|internal|external))?(?:\s+(?P<mutability>immutable|constant))?\s+(?P<name>\w+)(?:\s*=\s*(?P<value>[^;]+))?;"
            ).unwrap(),
            external_call_pattern: Regex::new(
                r"(?P<target>\w+)\.(?P<method>call|delegatecall|staticcall|transfer|send)\s*(?:\{[^}]*\})?\s*\("
            ).unwrap(),
            require_pattern: Regex::new(
                r"require\s*\(\s*(?P<condition>[^,)]+)(?:,\s*(?P<message>[^)]+))?\s*\)"
            ).unwrap(),
            emit_pattern: Regex::new(
                r"emit\s+(?P<event>\w+)\s*\((?P<args>[^)]*)\)"
            ).unwrap(),
            assignment_pattern: Regex::new(
                r"(?P<target>\w+(?:\[[^\]]+\])?)\s*(?P<op>[+\-*/]?=)\s*(?P<value>[^;]+)"
            ).unwrap(),
        }
    }

    /// Parse a Solidity source file into an AST
    pub fn parse(&self, content: &str) -> SolidityAST {
        SolidityAST {
            contracts: self.parse_contracts(content),
        }
    }

    fn parse_contracts(&self, content: &str) -> Vec<ContractDefinition> {
        let mut contracts = Vec::new();

        for captures in self.contract_pattern.captures_iter(content) {
            let match_start = captures.get(0).map(|m| m.start()).unwrap_or(0);
            let start_line = content[..match_start].matches('\n').count() + 1;
            let contract_content = &content[match_start..];

            contracts.push(ContractDefinition {
                state_variables: self.parse_state_variables(contract_content),
                functions: self.parse_functions(contract_content, start_line),
            });
        }

        contracts
    }

    fn parse_state_variables(&self, content: &str) -> Vec<StateVariable> {
        let mut variables = Vec::new();

        for captures in self.state_var_pattern.captures_iter(content) {
            let name = captures
                .name("name")
                .map(|m| m.as_str().to_string())
                .unwrap_or_default();
            let visibility = match captures.name("visibility").map(|m| m.as_str()) {
                Some("public") => Visibility::Public,
                Some("private") => Visibility::Private,
                Some("external") => Visibility::External,
                _ => Visibility::Internal,
            };

            variables.push(StateVariable { name, visibility });
        }

        variables
    }

    fn parse_functions(&self, content: &str, base_line: usize) -> Vec<FunctionDefinition> {
        let mut functions = Vec::new();

        // Also check for constructor, fallback, and receive
        let special_patterns: [(&Regex, &str); 3] = [
            (&CONSTRUCTOR_DEF_RE, "constructor"),
            (&FALLBACK_DEF_RE, "fallback"),
            (&RECEIVE_DEF_RE, "receive"),
        ];

        for (pattern, name) in special_patterns {
            for captures in pattern.captures_iter(content) {
                let match_start = captures.get(0).map(|m| m.start()).unwrap_or(0);

                let parameters = captures
                    .name("params")
                    .map(|m| self.parse_parameters(m.as_str()))
                    .unwrap_or_default();

                let body = self.extract_function_body(content, match_start, base_line);

                functions.push(FunctionDefinition {
                    name: name.to_string(),
                    parameters,
                    body,
                });
            }
        }

        // Regular functions
        for captures in self.function_pattern.captures_iter(content) {
            let name = captures
                .name("name")
                .map(|m| m.as_str().to_string())
                .unwrap_or_default();
            let params_str = captures.name("params").map(|m| m.as_str()).unwrap_or("");

            let match_start = captures.get(0).map(|m| m.start()).unwrap_or(0);

            let parameters = self.parse_parameters(params_str);
            let body = self.extract_function_body(content, match_start, base_line);

            functions.push(FunctionDefinition {
                name,
                parameters,
                body,
            });
        }

        functions
    }

    fn parse_parameters(&self, params_str: &str) -> Vec<Parameter> {
        let mut parameters = Vec::new();

        if params_str.trim().is_empty() {
            return parameters;
        }

        for param in params_str.split(',') {
            let parts: Vec<&str> = param.split_whitespace().collect();
            if parts.is_empty() {
                continue;
            }

            let name = parts
                .last()
                .filter(|&&n| n != "memory" && n != "storage" && n != "calldata")
                .map(|&s| s.to_string())
                .unwrap_or_default();

            parameters.push(Parameter { name });
        }

        parameters
    }

    fn extract_function_body(
        &self,
        content: &str,
        start: usize,
        base_line: usize,
    ) -> Option<FunctionBody> {
        // Find opening brace
        let brace_start = content[start..].find('{')?;
        let body_start = start + brace_start + 1;

        // Find matching closing brace
        let mut brace_count = 1;
        let mut body_end = body_start;

        for (i, c) in content[body_start..].char_indices() {
            match c {
                '{' => brace_count += 1,
                '}' => {
                    brace_count -= 1;
                    if brace_count == 0 {
                        body_end = body_start + i;
                        break;
                    }
                }
                _ => {}
            }
        }

        let raw_content = &content[body_start..body_end];
        // Compute file-level line number for the body start:
        // base_line is the contract's start line (1-based), plus newlines from
        // the contract start to the body opening brace.
        let body_base_line = base_line + content[..body_start].matches('\n').count();

        Some(FunctionBody {
            statements: self.parse_statements(raw_content, body_base_line),
        })
    }

    /// Split a function body into a flat list of statements, one per source line.
    ///
    /// This is a line-oriented regex scan, not a recursive-descent parse: braces are
    /// ignored, so `if`/`for`/`while`/`try` headers fall through to
    /// `Statement::Expression` and the statements inside their blocks are emitted as
    /// ordinary siblings. Nothing here ever produces a nested statement list, so
    /// downstream consumers see straight-line code only.
    fn parse_statements(&self, content: &str, base_line: usize) -> Vec<Statement> {
        let mut statements = Vec::new();

        for (line_idx, line) in content.lines().enumerate() {
            let line_num = base_line + line_idx + 1;
            let trimmed = line.trim();

            // Skip empty lines and comments
            if trimmed.is_empty() || trimmed.starts_with("//") || trimmed.starts_with("*") {
                continue;
            }

            // External calls
            if let Some(captures) = self.external_call_pattern.captures(trimmed) {
                let target = captures
                    .name("target")
                    .map(|m| m.as_str().to_string())
                    .unwrap_or_default();
                let method = captures.name("method").map(|m| m.as_str()).unwrap_or("");
                let value_transfer = method == "call" && trimmed.contains("value:");

                statements.push(Statement::ExternalCall {
                    target,
                    function: method.to_string(),
                    value_transfer,
                    line: line_num,
                });
            }
            // Require statements
            else if let Some(captures) = self.require_pattern.captures(trimmed) {
                let condition = captures
                    .name("condition")
                    .map(|m| m.as_str().to_string())
                    .unwrap_or_default();

                statements.push(Statement::Require {
                    condition,
                    line: line_num,
                });
            }
            // Emit statements
            else if self.emit_pattern.is_match(trimmed) {
                statements.push(Statement::Emit { line: line_num });
            }
            // Return statements
            else if trimmed.starts_with("return") {
                statements.push(Statement::Return { line: line_num });
            }
            // Revert statements
            else if trimmed.starts_with("revert") {
                statements.push(Statement::Revert { line: line_num });
            }
            // Assembly blocks
            else if trimmed.starts_with("assembly") {
                statements.push(Statement::Assembly {
                    content: trimmed.to_string(),
                    line: line_num,
                });
            }
            // Unchecked blocks
            else if trimmed.starts_with("unchecked") {
                statements.push(Statement::UncheckedBlock {
                    statements: vec![],
                    line: line_num,
                });
            }
            // Assignments
            else if let Some(captures) = self.assignment_pattern.captures(trimmed) {
                let target = captures
                    .name("target")
                    .map(|m| m.as_str().to_string())
                    .unwrap_or_default();
                let value = captures
                    .name("value")
                    .map(|m| m.as_str().to_string())
                    .unwrap_or_default();

                statements.push(Statement::Assignment {
                    target,
                    value,
                    line: line_num,
                });
            }
            // Generic expressions
            else if !trimmed.starts_with('{') && !trimmed.starts_with('}') {
                statements.push(Statement::Expression { line: line_num });
            }
        }

        statements
    }
}

impl Default for ASTParser {
    fn default() -> Self {
        Self::new()
    }
}
