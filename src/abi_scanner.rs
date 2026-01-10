use serde_json::{Value, Map};
use std::collections::{HashMap, HashSet};
use crate::vulnerabilities::{Vulnerability, VulnerabilitySeverity, VulnerabilityCategory};

#[derive(Debug, Clone)]
pub struct ABIFunction {
    pub name: String,
    pub function_type: String, // "function", "constructor", "fallback", "receive"
    pub state_mutability: String, // "pure", "view", "nonpayable", "payable"
    pub inputs: Vec<ABIParameter>,
    pub outputs: Vec<ABIParameter>,
}

#[derive(Debug, Clone)]
pub struct ABIEvent {
    pub name: String,
    pub inputs: Vec<ABIParameter>,
    pub anonymous: bool,
}

#[derive(Debug, Clone)]
pub struct ABIParameter {
    pub name: String,
    pub param_type: String,
    pub indexed: Option<bool>, // Only for events
    pub components: Option<Vec<ABIParameter>>, // For structs/tuples
}

#[derive(Debug)]
pub struct ABIAnalysis {
    pub functions: Vec<ABIFunction>,
    pub events: Vec<ABIEvent>,
    pub errors: Vec<ABIFunction>, // Custom errors
}

pub struct ABIScanner {
    verbose: bool,
}

impl ABIScanner {
    pub fn new(verbose: bool) -> Self {
        Self { verbose }
    }

    pub fn parse_abi(&self, abi_content: &str) -> Result<ABIAnalysis, String> {
        let abi: Value = serde_json::from_str(abi_content)
            .map_err(|e| format!("Invalid JSON format: {}", e))?;

        let abi_array = abi.as_array()
            .ok_or("ABI must be an array")?;

        let mut functions = Vec::new();
        let mut events = Vec::new();
        let mut errors = Vec::new();

        for item in abi_array {
            let item_type = item.get("type")
                .and_then(|t| t.as_str())
                .unwrap_or("function");

            match item_type {
                "function" | "constructor" | "fallback" | "receive" => {
                    if let Ok(func) = self.parse_function(item) {
                        functions.push(func);
                    }
                }
                "event" => {
                    if let Ok(event) = self.parse_event(item) {
                        events.push(event);
                    }
                }
                "error" => {
                    if let Ok(error) = self.parse_error(item) {
                        errors.push(error);
                    }
                }
                _ => {}
            }
        }

        Ok(ABIAnalysis {
            functions,
            events,
            errors,
        })
    }

    fn parse_function(&self, item: &Value) -> Result<ABIFunction, String> {
        let name = item.get("name")
            .and_then(|n| n.as_str())
            .unwrap_or("")
            .to_string();

        let function_type = item.get("type")
            .and_then(|t| t.as_str())
            .unwrap_or("function")
            .to_string();

        let state_mutability = item.get("stateMutability")
            .and_then(|s| s.as_str())
            .unwrap_or("nonpayable")
            .to_string();

        let inputs = self.parse_parameters(item.get("inputs"))?;
        let outputs = self.parse_parameters(item.get("outputs"))?;

        Ok(ABIFunction {
            name,
            function_type,
            state_mutability,
            inputs,
            outputs,
        })
    }

    fn parse_event(&self, item: &Value) -> Result<ABIEvent, String> {
        let name = item.get("name")
            .and_then(|n| n.as_str())
            .unwrap_or("")
            .to_string();

        let anonymous = item.get("anonymous")
            .and_then(|a| a.as_bool())
            .unwrap_or(false);

        let inputs = self.parse_parameters(item.get("inputs"))?;

        Ok(ABIEvent {
            name,
            inputs,
            anonymous,
        })
    }

    fn parse_error(&self, item: &Value) -> Result<ABIFunction, String> {
        let name = item.get("name")
            .and_then(|n| n.as_str())
            .unwrap_or("")
            .to_string();

        let inputs = self.parse_parameters(item.get("inputs"))?;

        Ok(ABIFunction {
            name,
            function_type: "error".to_string(),
            state_mutability: "pure".to_string(),
            inputs,
            outputs: Vec::new(),
        })
    }

    fn parse_parameters(&self, params: Option<&Value>) -> Result<Vec<ABIParameter>, String> {
        let empty_vec = Vec::new();
        let params_array = match params {
            Some(p) => p.as_array().unwrap_or(&empty_vec),
            None => return Ok(Vec::new()),
        };

        let mut parameters = Vec::new();

        for param in params_array {
            let name = param.get("name")
                .and_then(|n| n.as_str())
                .unwrap_or("")
                .to_string();

            let param_type = param.get("type")
                .and_then(|t| t.as_str())
                .unwrap_or("")
                .to_string();

            let indexed = param.get("indexed")
                .and_then(|i| i.as_bool());

            let components = if param.get("components").is_some() {
                Some(self.parse_parameters(param.get("components"))?)
            } else {
                None
            };

            parameters.push(ABIParameter {
                name,
                param_type,
                indexed,
                components,
            });
        }

        Ok(parameters)
    }

    pub fn scan_abi(&self, analysis: &ABIAnalysis) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        // Scan functions for vulnerabilities
        vulnerabilities.extend(self.analyze_functions(&analysis.functions));

        // Scan events for security issues
        vulnerabilities.extend(self.analyze_events(&analysis.events));

        // Analyze overall contract security patterns
        vulnerabilities.extend(self.analyze_contract_patterns(analysis));

        if self.verbose {
            println!("🔍 ABI Analysis complete: {} functions, {} events, {} vulnerabilities found",
                analysis.functions.len(), analysis.events.len(), vulnerabilities.len());
        }

        vulnerabilities
    }

    fn analyze_functions(&self, functions: &[ABIFunction]) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        // Check for missing access control patterns
        let mut _has_owner_functions = false;
        let mut has_pause_functions = false;
        let mut _has_admin_functions = false;

        for (idx, function) in functions.iter().enumerate() {
            // Check for dangerous state-changing functions without protection indicators
            if self.is_critical_function(&function.name) && function.state_mutability == "nonpayable" {
                vulnerabilities.push(Vulnerability {
                    severity: VulnerabilitySeverity::Critical,
                    category: VulnerabilityCategory::ABIAccessControl,
                    title: format!("Critical Function '{}' Lacks Access Control Indicators", function.name),
                    description: "Critical state-changing function in ABI without clear access control pattern".to_string(),
                    line_number: idx + 1,
                    code_snippet: format!("function {}({}) {}",
                        function.name,
                        self.format_parameters(&function.inputs),
                        function.state_mutability
                    ),
                    recommendation: "Ensure function has proper access control (onlyOwner, roles, etc.)".to_string(),
                });
            }

            // Check for functions that should be view/pure but aren't
            if self.should_be_readonly(&function.name) && function.state_mutability == "nonpayable" {
                vulnerabilities.push(Vulnerability {
                    severity: VulnerabilitySeverity::Medium,
                    category: VulnerabilityCategory::ABIFunctionVisibility,
                    title: format!("Function '{}' Should Be Read-Only", function.name),
                    description: "Function appears to be a getter but is marked as state-changing".to_string(),
                    line_number: idx + 1,
                    code_snippet: format!("function {}() {}", function.name, function.state_mutability),
                    recommendation: "Mark function as 'view' or 'pure' if it doesn't modify state".to_string(),
                });
            }

            // Check for payable functions without value validation
            if function.state_mutability == "payable" && !function.name.contains("deposit") && !function.name.contains("fund") {
                vulnerabilities.push(Vulnerability {
                    severity: VulnerabilitySeverity::High,
                    category: VulnerabilityCategory::ABIParameterValidation,
                    title: format!("Payable Function '{}' May Lack Value Validation", function.name),
                    description: "Payable function without clear value handling purpose".to_string(),
                    line_number: idx + 1,
                    code_snippet: format!("function {}() payable", function.name),
                    recommendation: "Verify proper value validation and handling in implementation".to_string(),
                });
            }

            // Check for missing parameter validation indicators
            for param in &function.inputs {
                if param.param_type == "address" && !param.name.contains("_") {
                    vulnerabilities.push(Vulnerability {
                        severity: VulnerabilitySeverity::Medium,
                        category: VulnerabilityCategory::ABIParameterValidation,
                        title: format!("Address Parameter '{}' May Lack Validation", param.name),
                        description: "Address parameter without validation naming convention".to_string(),
                        line_number: idx + 1,
                        code_snippet: format!("address {}", param.name),
                        recommendation: "Ensure zero address validation and proper address checks".to_string(),
                    });
                }

                if param.param_type.starts_with("uint") && param.name.contains("amount") {
                    vulnerabilities.push(Vulnerability {
                        severity: VulnerabilitySeverity::Medium,
                        category: VulnerabilityCategory::ABIParameterValidation,
                        title: format!("Amount Parameter '{}' May Lack Bounds Checking", param.name),
                        description: "Amount parameter should have proper bounds validation".to_string(),
                        line_number: idx + 1,
                        code_snippet: format!("{} {}", param.param_type, param.name),
                        recommendation: "Implement proper bounds checking for amount parameters".to_string(),
                    });
                }
            }

            // Track contract patterns
            if function.name.contains("owner") || function.name.contains("Owner") {
                _has_owner_functions = true;
            }
            if function.name.contains("pause") || function.name.contains("Pause") {
                has_pause_functions = true;
            }
            if function.name.contains("admin") || function.name.contains("Admin") {
                _has_admin_functions = true;
            }
        }

        // Check for missing emergency functions
        if !has_pause_functions && self.has_state_changing_functions(functions) {
            vulnerabilities.push(Vulnerability {
                severity: VulnerabilitySeverity::Medium,
                category: VulnerabilityCategory::ABIAccessControl,
                title: "Missing Emergency Pause Functionality".to_string(),
                description: "Contract has state-changing functions but no pause mechanism in ABI".to_string(),
                line_number: 1,
                code_snippet: "Contract ABI".to_string(),
                recommendation: "Consider implementing pause/unpause functions for emergency stops".to_string(),
            });
        }

        vulnerabilities
    }

    fn analyze_events(&self, events: &[ABIEvent]) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        // Check for missing critical events
        let event_names: HashSet<String> = events.iter().map(|e| e.name.to_lowercase()).collect();

        let critical_events = vec!["transfer", "approval", "ownershipTransferred", "paused", "unpaused"];

        for critical_event in critical_events {
            if !event_names.contains(critical_event) {
                vulnerabilities.push(Vulnerability {
                    severity: VulnerabilitySeverity::Low,
                    category: VulnerabilityCategory::ABIEventSecurity,
                    title: format!("Missing Critical Event: {}", critical_event),
                    description: format!("Important event '{}' not found in ABI", critical_event),
                    line_number: 1,
                    code_snippet: "Events section".to_string(),
                    recommendation: format!("Consider adding {} event for transparency", critical_event),
                });
            }
        }

        // Check for events with too many indexed parameters
        for (idx, event) in events.iter().enumerate() {
            let indexed_count = event.inputs.iter()
                .filter(|p| p.indexed.unwrap_or(false))
                .count();

            if indexed_count > 3 {
                vulnerabilities.push(Vulnerability {
                    severity: VulnerabilitySeverity::Low,
                    category: VulnerabilityCategory::ABIEventSecurity,
                    title: format!("Event '{}' Has Too Many Indexed Parameters", event.name),
                    description: "Events can have maximum 3 indexed parameters".to_string(),
                    line_number: idx + 1,
                    code_snippet: format!("event {}", event.name),
                    recommendation: "Reduce indexed parameters to 3 or fewer".to_string(),
                });
            }

            // Check for sensitive data in events
            for param in &event.inputs {
                if param.name.to_lowercase().contains("password") ||
                   param.name.to_lowercase().contains("secret") ||
                   param.name.to_lowercase().contains("private") {
                    vulnerabilities.push(Vulnerability {
                        severity: VulnerabilitySeverity::Critical,
                        category: VulnerabilityCategory::ABIEventSecurity,
                        title: format!("Sensitive Data in Event Parameter: {}", param.name),
                        description: "Event parameter appears to contain sensitive information".to_string(),
                        line_number: idx + 1,
                        code_snippet: format!("event {}(...{} {}...)", event.name, param.param_type, param.name),
                        recommendation: "Never emit sensitive data in events - all events are publicly visible".to_string(),
                    });
                }
            }
        }

        vulnerabilities
    }

    fn analyze_contract_patterns(&self, analysis: &ABIAnalysis) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        // Check for token standard compliance
        if self.appears_to_be_token(&analysis.functions) {
            vulnerabilities.extend(self.check_token_standard_compliance(&analysis.functions, &analysis.events));
        }

        // Check for upgrade patterns
        if self.appears_to_be_upgradeable(&analysis.functions) {
            vulnerabilities.extend(self.check_upgrade_security(&analysis.functions));
        }

        // Check for proxy patterns
        if self.appears_to_be_proxy(&analysis.functions) {
            vulnerabilities.push(Vulnerability {
                severity: VulnerabilitySeverity::High,
                category: VulnerabilityCategory::ABIUpgradeability,
                title: "Proxy Pattern Detected".to_string(),
                description: "Contract appears to use proxy pattern - verify implementation security".to_string(),
                line_number: 1,
                code_snippet: "Proxy functions detected".to_string(),
                recommendation: "Ensure proper access control on proxy functions and validate implementation contracts".to_string(),
            });
        }

        vulnerabilities
    }

    fn check_token_standard_compliance(&self, functions: &[ABIFunction], events: &[ABIEvent]) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        // Check ERC-20 compliance
        let required_erc20_functions = vec!["totalSupply", "balanceOf", "transfer", "transferFrom", "approve", "allowance"];
        let required_erc20_events = vec!["Transfer", "Approval"];

        let function_names: HashSet<String> = functions.iter().map(|f| f.name.clone()).collect();
        let event_names: HashSet<String> = events.iter().map(|e| e.name.clone()).collect();

        for required_func in required_erc20_functions {
            if !function_names.contains(required_func) {
                vulnerabilities.push(Vulnerability {
                    severity: VulnerabilitySeverity::Medium,
                    category: VulnerabilityCategory::ABITokenStandard,
                    title: format!("Missing ERC-20 Function: {}", required_func),
                    description: "Token contract missing required ERC-20 function".to_string(),
                    line_number: 1,
                    code_snippet: format!("Missing: function {}()", required_func),
                    recommendation: "Implement all required ERC-20 functions for standard compliance".to_string(),
                });
            }
        }

        for required_event in required_erc20_events {
            if !event_names.contains(required_event) {
                vulnerabilities.push(Vulnerability {
                    severity: VulnerabilitySeverity::Medium,
                    category: VulnerabilityCategory::ABITokenStandard,
                    title: format!("Missing ERC-20 Event: {}", required_event),
                    description: "Token contract missing required ERC-20 event".to_string(),
                    line_number: 1,
                    code_snippet: format!("Missing: event {}()", required_event),
                    recommendation: "Implement all required ERC-20 events for standard compliance".to_string(),
                });
            }
        }

        vulnerabilities
    }

    fn check_upgrade_security(&self, functions: &[ABIFunction]) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        // Check for proper upgrade access control
        let upgrade_functions: Vec<&ABIFunction> = functions.iter()
            .filter(|f| f.name.contains("upgrade") || f.name.contains("Upgrade") || f.name.contains("implementation"))
            .collect();

        if !upgrade_functions.is_empty() {
            vulnerabilities.push(Vulnerability {
                severity: VulnerabilitySeverity::Critical,
                category: VulnerabilityCategory::ABIUpgradeability,
                title: "Upgradeable Contract Detected".to_string(),
                description: "Contract has upgrade functions - verify proper access control and timelock".to_string(),
                line_number: 1,
                code_snippet: "Upgrade functions detected".to_string(),
                recommendation: "Ensure upgrade functions have proper access control and consider timelock mechanisms".to_string(),
            });
        }

        vulnerabilities
    }

    // Helper functions
    fn is_critical_function(&self, name: &str) -> bool {
        let critical_patterns = vec![
            "mint", "burn", "transfer", "approve", "withdraw", "deposit",
            "pause", "unpause", "destroy", "kill", "upgrade", "initialize",
            "setOwner", "changeOwner", "grantRole", "revokeRole"
        ];

        critical_patterns.iter().any(|pattern|
            name.to_lowercase().contains(pattern)
        )
    }

    fn should_be_readonly(&self, name: &str) -> bool {
        let readonly_patterns = vec![
            "get", "view", "read", "check", "is", "has", "balance", "total",
            "allowance", "owner", "paused", "name", "symbol", "decimals"
        ];

        readonly_patterns.iter().any(|pattern|
            name.to_lowercase().starts_with(pattern)
        )
    }

    fn has_state_changing_functions(&self, functions: &[ABIFunction]) -> bool {
        functions.iter().any(|f| f.state_mutability == "nonpayable" || f.state_mutability == "payable")
    }

    fn appears_to_be_token(&self, functions: &[ABIFunction]) -> bool {
        let token_functions = vec!["transfer", "balanceOf", "totalSupply"];
        let function_names: HashSet<String> = functions.iter().map(|f| f.name.clone()).collect();

        token_functions.iter().any(|tf| function_names.contains(*tf))
    }

    fn appears_to_be_upgradeable(&self, functions: &[ABIFunction]) -> bool {
        functions.iter().any(|f|
            f.name.contains("upgrade") ||
            f.name.contains("implementation") ||
            f.name.contains("initialize")
        )
    }

    fn appears_to_be_proxy(&self, functions: &[ABIFunction]) -> bool {
        functions.iter().any(|f|
            f.name.contains("proxy") ||
            f.name.contains("delegate") ||
            f.name == "fallback" ||
            f.function_type == "fallback"
        )
    }

    fn format_parameters(&self, params: &[ABIParameter]) -> String {
        params.iter()
            .map(|p| format!("{} {}", p.param_type, p.name))
            .collect::<Vec<_>>()
            .join(", ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_abi() {
        let scanner = ABIScanner::new(false);
        let abi_json = r#"[
            {
                "type": "function",
                "name": "transfer",
                "inputs": [
                    {"name": "to", "type": "address"},
                    {"name": "amount", "type": "uint256"}
                ],
                "outputs": [{"name": "", "type": "bool"}],
                "stateMutability": "nonpayable"
            }
        ]"#;

        let analysis = scanner.parse_abi(abi_json).unwrap();
        assert_eq!(analysis.functions.len(), 1);
        assert_eq!(analysis.functions[0].name, "transfer");
    }

    #[test]
    fn test_detect_critical_function() {
        let scanner = ABIScanner::new(false);
        assert!(scanner.is_critical_function("mint"));
        assert!(scanner.is_critical_function("transferOwnership"));
        assert!(!scanner.is_critical_function("getName"));
    }
}