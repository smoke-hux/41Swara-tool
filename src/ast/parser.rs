//! Solidity AST Parser
//!
//! Provides AST-like parsing for Solidity contracts using regex-based extraction.
//! Supports contract, function, modifier, and statement-level analysis.

#![allow(dead_code)]
#![allow(unused_variables)]

use regex::Regex;

/// Represents a parsed Solidity contract
#[derive(Debug, Clone)]
pub struct SolidityAST {
    pub pragma: Option<PragmaDirective>,
    pub imports: Vec<ImportDirective>,
    pub contracts: Vec<ContractDefinition>,
}

/// Pragma directive (e.g., pragma solidity ^0.8.0)
#[derive(Debug, Clone)]
pub struct PragmaDirective {
    pub version: String,
    pub line: usize,
}

/// Import directive
#[derive(Debug, Clone)]
pub struct ImportDirective {
    pub path: String,
    pub symbols: Vec<String>,
    pub line: usize,
}

/// Contract definition including interfaces, libraries, and abstract contracts
#[derive(Debug, Clone)]
pub struct ContractDefinition {
    pub name: String,
    pub contract_type: ContractType,
    pub inheritance: Vec<String>,
    pub state_variables: Vec<StateVariable>,
    pub functions: Vec<FunctionDefinition>,
    pub modifiers: Vec<ModifierDefinition>,
    pub events: Vec<EventDefinition>,
    pub errors: Vec<ErrorDefinition>,
    pub structs: Vec<StructDefinition>,
    pub enums: Vec<EnumDefinition>,
    pub start_line: usize,
    pub end_line: usize,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ContractType {
    Contract,
    Interface,
    Library,
    Abstract,
}

/// State variable definition
#[derive(Debug, Clone)]
pub struct StateVariable {
    pub name: String,
    pub var_type: String,
    pub visibility: Visibility,
    pub mutability: Mutability,
    pub initial_value: Option<String>,
    pub line: usize,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Visibility {
    Public,
    Private,
    Internal,
    External,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Mutability {
    Mutable,
    Immutable,
    Constant,
}

/// Function definition
#[derive(Debug, Clone)]
pub struct FunctionDefinition {
    pub name: String,
    pub visibility: Visibility,
    pub state_mutability: StateMutability,
    pub modifiers: Vec<String>,
    pub parameters: Vec<Parameter>,
    pub return_parameters: Vec<Parameter>,
    pub body: Option<FunctionBody>,
    pub is_constructor: bool,
    pub is_fallback: bool,
    pub is_receive: bool,
    pub start_line: usize,
    pub end_line: usize,
}

#[derive(Debug, Clone, PartialEq)]
pub enum StateMutability {
    Pure,
    View,
    Payable,
    NonPayable,
}

/// Function parameter
#[derive(Debug, Clone)]
pub struct Parameter {
    pub name: String,
    pub param_type: String,
    pub storage_location: Option<StorageLocation>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum StorageLocation {
    Memory,
    Storage,
    Calldata,
}

/// Function body with statements
#[derive(Debug, Clone)]
pub struct FunctionBody {
    pub statements: Vec<Statement>,
    pub raw_content: String,
}

/// Statement types in Solidity
#[derive(Debug, Clone)]
pub enum Statement {
    VariableDeclaration {
        name: String,
        var_type: String,
        value: Option<String>,
        line: usize,
    },
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
    InternalCall {
        function: String,
        args: Vec<String>,
        line: usize,
    },
    If {
        condition: String,
        then_block: Vec<Statement>,
        else_block: Option<Vec<Statement>>,
        line: usize,
    },
    For {
        init: Option<Box<Statement>>,
        condition: Option<String>,
        post: Option<String>,
        body: Vec<Statement>,
        line: usize,
    },
    While {
        condition: String,
        body: Vec<Statement>,
        line: usize,
    },
    Return {
        value: Option<String>,
        line: usize,
    },
    Require {
        condition: String,
        message: Option<String>,
        line: usize,
    },
    Revert {
        error: Option<String>,
        line: usize,
    },
    Emit {
        event: String,
        args: Vec<String>,
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
    TryCatch {
        call: String,
        try_block: Vec<Statement>,
        catch_blocks: Vec<(String, Vec<Statement>)>,
        line: usize,
    },
    Expression {
        content: String,
        line: usize,
    },
}

/// Modifier definition
#[derive(Debug, Clone)]
pub struct ModifierDefinition {
    pub name: String,
    pub parameters: Vec<Parameter>,
    pub body: Option<FunctionBody>,
    pub start_line: usize,
    pub end_line: usize,
}

/// Event definition
#[derive(Debug, Clone)]
pub struct EventDefinition {
    pub name: String,
    pub parameters: Vec<EventParameter>,
    pub line: usize,
}

#[derive(Debug, Clone)]
pub struct EventParameter {
    pub name: String,
    pub param_type: String,
    pub indexed: bool,
}

/// Error definition
#[derive(Debug, Clone)]
pub struct ErrorDefinition {
    pub name: String,
    pub parameters: Vec<Parameter>,
    pub line: usize,
}

/// Struct definition
#[derive(Debug, Clone)]
pub struct StructDefinition {
    pub name: String,
    pub members: Vec<(String, String)>,
    pub line: usize,
}

/// Enum definition
#[derive(Debug, Clone)]
pub struct EnumDefinition {
    pub name: String,
    pub values: Vec<String>,
    pub line: usize,
}

/// AST Parser for Solidity
pub struct ASTParser {
    // Compiled regex patterns for efficiency
    pragma_pattern: Regex,
    import_pattern: Regex,
    contract_pattern: Regex,
    function_pattern: Regex,
    modifier_def_pattern: Regex,
    state_var_pattern: Regex,
    event_pattern: Regex,
    error_pattern: Regex,
    struct_pattern: Regex,
    enum_pattern: Regex,
    external_call_pattern: Regex,
    require_pattern: Regex,
    emit_pattern: Regex,
    assignment_pattern: Regex,
}

impl ASTParser {
    pub fn new() -> Self {
        Self {
            pragma_pattern: Regex::new(r"pragma\s+solidity\s*([^;]+);").unwrap(),
            import_pattern: Regex::new(r#"import\s+(?:\{([^}]+)\}\s+from\s+)?["']([^"']+)["']"#).unwrap(),
            contract_pattern: Regex::new(
                r"(?P<type>contract|interface|library|abstract\s+contract)\s+(?P<name>\w+)(?:\s+is\s+(?P<inheritance>[^{]+))?\s*\{"
            ).unwrap(),
            function_pattern: Regex::new(
                r"function\s+(?P<name>\w+)\s*\((?P<params>[^)]*)\)\s*(?P<modifiers>[^{;]*)(?:\{|;)"
            ).unwrap(),
            modifier_def_pattern: Regex::new(
                r"modifier\s+(?P<name>\w+)\s*(?:\((?P<params>[^)]*)\))?\s*\{"
            ).unwrap(),
            state_var_pattern: Regex::new(
                r"(?P<type>mapping\([^)]+\)|\w+(?:\[\])?)(?:\s+(?P<visibility>public|private|internal|external))?(?:\s+(?P<mutability>immutable|constant))?\s+(?P<name>\w+)(?:\s*=\s*(?P<value>[^;]+))?;"
            ).unwrap(),
            event_pattern: Regex::new(
                r"event\s+(?P<name>\w+)\s*\((?P<params>[^)]*)\)\s*;"
            ).unwrap(),
            error_pattern: Regex::new(
                r"error\s+(?P<name>\w+)\s*\((?P<params>[^)]*)\)\s*;"
            ).unwrap(),
            struct_pattern: Regex::new(
                r"struct\s+(?P<name>\w+)\s*\{"
            ).unwrap(),
            enum_pattern: Regex::new(
                r"enum\s+(?P<name>\w+)\s*\{"
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
        let lines: Vec<&str> = content.lines().collect();

        let pragma = self.parse_pragma(content, &lines);
        let imports = self.parse_imports(content, &lines);
        let contracts = self.parse_contracts(content, &lines);

        SolidityAST {
            pragma,
            imports,
            contracts,
        }
    }

    fn parse_pragma(&self, content: &str, lines: &[&str]) -> Option<PragmaDirective> {
        if let Some(captures) = self.pragma_pattern.captures(content) {
            let version = captures.get(1).map(|m| m.as_str().trim().to_string())?;
            let match_start = captures.get(0)?.start();
            let line = content[..match_start].matches('\n').count() + 1;

            Some(PragmaDirective { version, line })
        } else {
            None
        }
    }

    fn parse_imports(&self, content: &str, _lines: &[&str]) -> Vec<ImportDirective> {
        let mut imports = Vec::new();

        for captures in self.import_pattern.captures_iter(content) {
            let symbols = captures.get(1)
                .map(|m| m.as_str().split(',').map(|s| s.trim().to_string()).collect())
                .unwrap_or_default();
            let path = captures.get(2).map(|m| m.as_str().to_string()).unwrap_or_default();
            let match_start = captures.get(0).map(|m| m.start()).unwrap_or(0);
            let line = content[..match_start].matches('\n').count() + 1;

            imports.push(ImportDirective { path, symbols, line });
        }

        imports
    }

    fn parse_contracts(&self, content: &str, lines: &[&str]) -> Vec<ContractDefinition> {
        let mut contracts = Vec::new();

        for captures in self.contract_pattern.captures_iter(content) {
            let contract_type_str = captures.name("type").map(|m| m.as_str()).unwrap_or("contract");
            let name = captures.name("name").map(|m| m.as_str().to_string()).unwrap_or_default();
            let inheritance = captures.name("inheritance")
                .map(|m| m.as_str().split(',').map(|s| s.trim().to_string()).collect())
                .unwrap_or_default();

            let match_start = captures.get(0).map(|m| m.start()).unwrap_or(0);
            let start_line = content[..match_start].matches('\n').count() + 1;

            // Find the end of the contract
            let end_line = self.find_matching_brace(content, match_start);
            let contract_content = &content[match_start..];

            let contract_type = match contract_type_str {
                "interface" => ContractType::Interface,
                "library" => ContractType::Library,
                s if s.contains("abstract") => ContractType::Abstract,
                _ => ContractType::Contract,
            };

            let state_variables = self.parse_state_variables(contract_content, start_line);
            let functions = self.parse_functions(contract_content, start_line, lines);
            let modifiers = self.parse_modifiers(contract_content, start_line);
            let events = self.parse_events(contract_content, start_line);
            let errors = self.parse_errors(contract_content, start_line);
            let structs = self.parse_structs(contract_content, start_line);
            let enums = self.parse_enums(contract_content, start_line);

            contracts.push(ContractDefinition {
                name,
                contract_type,
                inheritance,
                state_variables,
                functions,
                modifiers,
                events,
                errors,
                structs,
                enums,
                start_line,
                end_line,
            });
        }

        contracts
    }

    fn find_matching_brace(&self, content: &str, start: usize) -> usize {
        let mut brace_count = 0;
        let mut in_string = false;
        let mut string_char = ' ';

        for (i, c) in content[start..].char_indices() {
            if !in_string {
                match c {
                    '"' | '\'' => {
                        in_string = true;
                        string_char = c;
                    }
                    '{' => brace_count += 1,
                    '}' => {
                        brace_count -= 1;
                        if brace_count == 0 {
                            return content[..start + i + 1].matches('\n').count() + 1;
                        }
                    }
                    _ => {}
                }
            } else if c == string_char && content[start..].chars().nth(i.saturating_sub(1)) != Some('\\') {
                in_string = false;
            }
        }

        content.matches('\n').count() + 1
    }

    fn parse_state_variables(&self, content: &str, base_line: usize) -> Vec<StateVariable> {
        let mut variables = Vec::new();

        for captures in self.state_var_pattern.captures_iter(content) {
            let var_type = captures.name("type").map(|m| m.as_str().to_string()).unwrap_or_default();
            let name = captures.name("name").map(|m| m.as_str().to_string()).unwrap_or_default();
            let visibility = match captures.name("visibility").map(|m| m.as_str()) {
                Some("public") => Visibility::Public,
                Some("private") => Visibility::Private,
                Some("external") => Visibility::External,
                _ => Visibility::Internal,
            };
            let mutability = match captures.name("mutability").map(|m| m.as_str()) {
                Some("immutable") => Mutability::Immutable,
                Some("constant") => Mutability::Constant,
                _ => Mutability::Mutable,
            };
            let initial_value = captures.name("value").map(|m| m.as_str().to_string());

            let match_start = captures.get(0).map(|m| m.start()).unwrap_or(0);
            let line = base_line + content[..match_start].matches('\n').count();

            variables.push(StateVariable {
                name,
                var_type,
                visibility,
                mutability,
                initial_value,
                line,
            });
        }

        variables
    }

    fn parse_functions(&self, content: &str, base_line: usize, _lines: &[&str]) -> Vec<FunctionDefinition> {
        let mut functions = Vec::new();

        // Also check for constructor, fallback, and receive
        let special_patterns = vec![
            (Regex::new(r"constructor\s*\((?P<params>[^)]*)\)\s*(?P<modifiers>[^{]*)?\{").unwrap(), true, false, false),
            (Regex::new(r"fallback\s*\(\)\s*(?P<modifiers>[^{]*)?\{").unwrap(), false, true, false),
            (Regex::new(r"receive\s*\(\)\s*(?P<modifiers>[^{]*)?\{").unwrap(), false, false, true),
        ];

        for (pattern, is_constructor, is_fallback, is_receive) in special_patterns {
            for captures in pattern.captures_iter(content) {
                let match_start = captures.get(0).map(|m| m.start()).unwrap_or(0);
                let start_line = base_line + content[..match_start].matches('\n').count();
                let end_line = self.find_matching_brace(content, match_start);

                let parameters = captures.name("params")
                    .map(|m| self.parse_parameters(m.as_str()))
                    .unwrap_or_default();

                let modifiers = captures.name("modifiers")
                    .map(|m| self.extract_modifiers(m.as_str()))
                    .unwrap_or_default();

                let body = self.extract_function_body(content, match_start);

                functions.push(FunctionDefinition {
                    name: if is_constructor { "constructor".to_string() }
                          else if is_fallback { "fallback".to_string() }
                          else { "receive".to_string() },
                    visibility: Visibility::Public,
                    state_mutability: if is_receive { StateMutability::Payable } else { StateMutability::NonPayable },
                    modifiers,
                    parameters,
                    return_parameters: vec![],
                    body,
                    is_constructor,
                    is_fallback,
                    is_receive,
                    start_line,
                    end_line,
                });
            }
        }

        // Regular functions
        for captures in self.function_pattern.captures_iter(content) {
            let name = captures.name("name").map(|m| m.as_str().to_string()).unwrap_or_default();
            let params_str = captures.name("params").map(|m| m.as_str()).unwrap_or("");
            let modifiers_str = captures.name("modifiers").map(|m| m.as_str()).unwrap_or("");

            let match_start = captures.get(0).map(|m| m.start()).unwrap_or(0);
            let start_line = base_line + content[..match_start].matches('\n').count();
            let end_line = self.find_matching_brace(content, match_start);

            let parameters = self.parse_parameters(params_str);
            let modifiers = self.extract_modifiers(modifiers_str);
            let (visibility, state_mutability, return_params) = self.parse_function_modifiers(modifiers_str);

            let body = self.extract_function_body(content, match_start);

            functions.push(FunctionDefinition {
                name,
                visibility,
                state_mutability,
                modifiers,
                parameters,
                return_parameters: return_params,
                body,
                is_constructor: false,
                is_fallback: false,
                is_receive: false,
                start_line,
                end_line,
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
            let parts: Vec<&str> = param.trim().split_whitespace().collect();
            if parts.is_empty() {
                continue;
            }

            let param_type = parts[0].to_string();
            let storage_location = parts.iter()
                .find_map(|&p| match p {
                    "memory" => Some(StorageLocation::Memory),
                    "storage" => Some(StorageLocation::Storage),
                    "calldata" => Some(StorageLocation::Calldata),
                    _ => None,
                });
            let name = parts.last()
                .filter(|&&n| n != "memory" && n != "storage" && n != "calldata")
                .map(|&s| s.to_string())
                .unwrap_or_default();

            parameters.push(Parameter {
                name,
                param_type,
                storage_location,
            });
        }

        parameters
    }

    fn extract_modifiers(&self, modifiers_str: &str) -> Vec<String> {
        let mut modifiers = Vec::new();
        let modifier_pattern = Regex::new(r"(\w+)(?:\([^)]*\))?").unwrap();

        let keywords = ["public", "private", "internal", "external", "pure", "view", "payable", "virtual", "override", "returns"];

        for captures in modifier_pattern.captures_iter(modifiers_str) {
            if let Some(m) = captures.get(1) {
                let modifier_name = m.as_str();
                if !keywords.contains(&modifier_name) {
                    modifiers.push(modifier_name.to_string());
                }
            }
        }

        modifiers
    }

    fn parse_function_modifiers(&self, modifiers_str: &str) -> (Visibility, StateMutability, Vec<Parameter>) {
        let visibility = if modifiers_str.contains("public") {
            Visibility::Public
        } else if modifiers_str.contains("external") {
            Visibility::External
        } else if modifiers_str.contains("private") {
            Visibility::Private
        } else {
            Visibility::Internal
        };

        let state_mutability = if modifiers_str.contains("pure") {
            StateMutability::Pure
        } else if modifiers_str.contains("view") {
            StateMutability::View
        } else if modifiers_str.contains("payable") {
            StateMutability::Payable
        } else {
            StateMutability::NonPayable
        };

        // Parse return parameters
        let return_params = if let Some(returns_start) = modifiers_str.find("returns") {
            if let Some(paren_start) = modifiers_str[returns_start..].find('(') {
                if let Some(paren_end) = modifiers_str[returns_start + paren_start..].find(')') {
                    let returns_str = &modifiers_str[returns_start + paren_start + 1..returns_start + paren_start + paren_end];
                    self.parse_parameters(returns_str)
                } else {
                    vec![]
                }
            } else {
                vec![]
            }
        } else {
            vec![]
        };

        (visibility, state_mutability, return_params)
    }

    fn extract_function_body(&self, content: &str, start: usize) -> Option<FunctionBody> {
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

        let raw_content = content[body_start..body_end].to_string();
        let statements = self.parse_statements(&raw_content, 0);

        Some(FunctionBody {
            statements,
            raw_content,
        })
    }

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
                let target = captures.name("target").map(|m| m.as_str().to_string()).unwrap_or_default();
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
                let condition = captures.name("condition").map(|m| m.as_str().to_string()).unwrap_or_default();
                let message = captures.name("message").map(|m| m.as_str().to_string());

                statements.push(Statement::Require {
                    condition,
                    message,
                    line: line_num,
                });
            }
            // Emit statements
            else if let Some(captures) = self.emit_pattern.captures(trimmed) {
                let event = captures.name("event").map(|m| m.as_str().to_string()).unwrap_or_default();
                let args = captures.name("args")
                    .map(|m| m.as_str().split(',').map(|s| s.trim().to_string()).collect())
                    .unwrap_or_default();

                statements.push(Statement::Emit {
                    event,
                    args,
                    line: line_num,
                });
            }
            // Return statements
            else if trimmed.starts_with("return") {
                let value = trimmed.strip_prefix("return")
                    .map(|s| s.trim().trim_end_matches(';').trim().to_string())
                    .filter(|s| !s.is_empty());

                statements.push(Statement::Return {
                    value,
                    line: line_num,
                });
            }
            // Revert statements
            else if trimmed.starts_with("revert") {
                let error = trimmed.strip_prefix("revert")
                    .map(|s| s.trim().trim_end_matches(';').trim().to_string())
                    .filter(|s| !s.is_empty());

                statements.push(Statement::Revert {
                    error,
                    line: line_num,
                });
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
                let target = captures.name("target").map(|m| m.as_str().to_string()).unwrap_or_default();
                let value = captures.name("value").map(|m| m.as_str().to_string()).unwrap_or_default();

                statements.push(Statement::Assignment {
                    target,
                    value,
                    line: line_num,
                });
            }
            // Generic expressions
            else if !trimmed.starts_with('{') && !trimmed.starts_with('}') {
                statements.push(Statement::Expression {
                    content: trimmed.to_string(),
                    line: line_num,
                });
            }
        }

        statements
    }

    fn parse_modifiers(&self, content: &str, base_line: usize) -> Vec<ModifierDefinition> {
        let mut modifiers = Vec::new();

        for captures in self.modifier_def_pattern.captures_iter(content) {
            let name = captures.name("name").map(|m| m.as_str().to_string()).unwrap_or_default();
            let params_str = captures.name("params").map(|m| m.as_str()).unwrap_or("");

            let match_start = captures.get(0).map(|m| m.start()).unwrap_or(0);
            let start_line = base_line + content[..match_start].matches('\n').count();
            let end_line = self.find_matching_brace(content, match_start);

            let parameters = self.parse_parameters(params_str);
            let body = self.extract_function_body(content, match_start);

            modifiers.push(ModifierDefinition {
                name,
                parameters,
                body,
                start_line,
                end_line,
            });
        }

        modifiers
    }

    fn parse_events(&self, content: &str, base_line: usize) -> Vec<EventDefinition> {
        let mut events = Vec::new();

        for captures in self.event_pattern.captures_iter(content) {
            let name = captures.name("name").map(|m| m.as_str().to_string()).unwrap_or_default();
            let params_str = captures.name("params").map(|m| m.as_str()).unwrap_or("");

            let match_start = captures.get(0).map(|m| m.start()).unwrap_or(0);
            let line = base_line + content[..match_start].matches('\n').count();

            let parameters = self.parse_event_parameters(params_str);

            events.push(EventDefinition {
                name,
                parameters,
                line,
            });
        }

        events
    }

    fn parse_event_parameters(&self, params_str: &str) -> Vec<EventParameter> {
        let mut parameters = Vec::new();

        for param in params_str.split(',') {
            let parts: Vec<&str> = param.trim().split_whitespace().collect();
            if parts.is_empty() {
                continue;
            }

            let indexed = parts.contains(&"indexed");
            let param_type = parts[0].to_string();
            let name = parts.last()
                .filter(|&&n| n != "indexed")
                .map(|&s| s.to_string())
                .unwrap_or_default();

            parameters.push(EventParameter {
                name,
                param_type,
                indexed,
            });
        }

        parameters
    }

    fn parse_errors(&self, content: &str, base_line: usize) -> Vec<ErrorDefinition> {
        let mut errors = Vec::new();

        for captures in self.error_pattern.captures_iter(content) {
            let name = captures.name("name").map(|m| m.as_str().to_string()).unwrap_or_default();
            let params_str = captures.name("params").map(|m| m.as_str()).unwrap_or("");

            let match_start = captures.get(0).map(|m| m.start()).unwrap_or(0);
            let line = base_line + content[..match_start].matches('\n').count();

            let parameters = self.parse_parameters(params_str);

            errors.push(ErrorDefinition {
                name,
                parameters,
                line,
            });
        }

        errors
    }

    fn parse_structs(&self, content: &str, base_line: usize) -> Vec<StructDefinition> {
        let mut structs = Vec::new();

        for captures in self.struct_pattern.captures_iter(content) {
            let name = captures.name("name").map(|m| m.as_str().to_string()).unwrap_or_default();

            let match_start = captures.get(0).map(|m| m.start()).unwrap_or(0);
            let line = base_line + content[..match_start].matches('\n').count();

            // Parse struct members (simplified)
            let members: Vec<(String, String)> = vec![];

            structs.push(StructDefinition {
                name,
                members,
                line,
            });
        }

        structs
    }

    fn parse_enums(&self, content: &str, base_line: usize) -> Vec<EnumDefinition> {
        let mut enums = Vec::new();

        for captures in self.enum_pattern.captures_iter(content) {
            let name = captures.name("name").map(|m| m.as_str().to_string()).unwrap_or_default();

            let match_start = captures.get(0).map(|m| m.start()).unwrap_or(0);
            let line = base_line + content[..match_start].matches('\n').count();

            // Parse enum values (simplified)
            let values: Vec<String> = vec![];

            enums.push(EnumDefinition {
                name,
                values,
                line,
            });
        }

        enums
    }

    /// Get function by name from a contract
    pub fn get_function<'a>(&self, contract: &'a ContractDefinition, name: &str) -> Option<&'a FunctionDefinition> {
        contract.functions.iter().find(|f| f.name == name)
    }

    /// Check if a function modifies state
    pub fn function_modifies_state(&self, function: &FunctionDefinition) -> bool {
        match function.state_mutability {
            StateMutability::Pure | StateMutability::View => false,
            _ => true,
        }
    }

    /// Get all external calls from a function body
    pub fn get_external_calls<'a>(&self, function: &'a FunctionDefinition) -> Vec<&'a Statement> {
        function.body.as_ref()
            .map(|body| {
                body.statements.iter()
                    .filter(|s| matches!(s, Statement::ExternalCall { .. }))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Check if a function has a specific modifier
    pub fn has_modifier(&self, function: &FunctionDefinition, modifier_name: &str) -> bool {
        function.modifiers.iter().any(|m| m == modifier_name)
    }
}

impl Default for ASTParser {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_contract() {
        let parser = ASTParser::new();
        let content = r#"
pragma solidity ^0.8.0;

contract SimpleContract {
    uint256 public balance;

    function deposit() external payable {
        balance += msg.value;
    }

    function withdraw(uint256 amount) external {
        require(balance >= amount, "Insufficient balance");
        balance -= amount;
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
    }
}
        "#;

        let ast = parser.parse(content);

        assert!(ast.pragma.is_some());
        assert_eq!(ast.contracts.len(), 1);
        assert_eq!(ast.contracts[0].name, "SimpleContract");
        assert!(!ast.contracts[0].functions.is_empty());
    }

    #[test]
    fn test_parse_function_modifiers() {
        let parser = ASTParser::new();
        let content = r#"
pragma solidity ^0.8.0;

contract ModifiedContract {
    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    function protectedFunction() external onlyOwner {
        // Protected logic
    }
}
        "#;

        let ast = parser.parse(content);

        assert!(!ast.contracts[0].modifiers.is_empty());
    }
}
