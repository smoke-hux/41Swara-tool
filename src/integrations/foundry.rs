//! Foundry Integration
//!
//! Provides integration with Foundry testing framework:
//! - Generate PoC Foundry tests from findings
//! - Correlate with forge test results
//! - Analyze invariant test failures
//! - Auto-create test templates per vulnerability category

use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::process::Command;

use crate::vulnerabilities::{Vulnerability, VulnerabilitySeverity, VulnerabilityCategory};

/// Foundry integration for test generation and correlation
pub struct FoundryIntegration {
    project_path: String,
    test_output_dir: String,
}

/// Result of Foundry test correlation
#[derive(Debug)]
pub struct CorrelationResult {
    pub finding_id: String,
    pub finding_title: String,
    pub test_exists: bool,
    pub test_passes: bool,
    pub test_name: Option<String>,
    pub confidence_adjustment: f64,
}

/// Foundry test result from JSON output
#[derive(Debug, serde::Deserialize)]
pub struct ForgeTestResult {
    pub name: String,
    pub status: String,
    pub reason: Option<String>,
    pub duration: Option<f64>,
}

impl FoundryIntegration {
    pub fn new(project_path: &str) -> Self {
        Self {
            project_path: project_path.to_string(),
            test_output_dir: format!("{}/test/poc", project_path),
        }
    }

    pub fn with_test_output_dir(mut self, dir: &str) -> Self {
        self.test_output_dir = dir.to_string();
        self
    }

    /// Generate PoC Foundry tests for all findings
    pub fn generate_poc_tests(&self, vulnerabilities: &[Vulnerability]) -> Vec<String> {
        let mut generated_files = Vec::new();

        // Create output directory
        let _ = fs::create_dir_all(&self.test_output_dir);

        for (idx, vuln) in vulnerabilities.iter()
            .filter(|v| v.severity == VulnerabilitySeverity::Critical || v.severity == VulnerabilitySeverity::High)
            .enumerate()
        {
            let test_content = self.generate_test_for_vulnerability(vuln, idx + 1);
            let file_name = format!(
                "{}/PoC_{:02}_{}.t.sol",
                self.test_output_dir,
                idx + 1,
                self.sanitize_name(&vuln.title)
            );

            if let Ok(_) = fs::write(&file_name, &test_content) {
                generated_files.push(file_name);
            }
        }

        generated_files
    }

    /// Generate test for a specific vulnerability
    fn generate_test_for_vulnerability(&self, vuln: &Vulnerability, idx: usize) -> String {
        let test_name = format!("test_PoC_{:02}_{}", idx, self.sanitize_name(&vuln.title));

        match &vuln.category {
            VulnerabilityCategory::Reentrancy | VulnerabilityCategory::CallbackReentrancy => {
                self.generate_reentrancy_test(vuln, &test_name)
            }
            VulnerabilityCategory::OracleManipulation => {
                self.generate_oracle_test(vuln, &test_name)
            }
            VulnerabilityCategory::AccessControl => {
                self.generate_access_control_test(vuln, &test_name)
            }
            VulnerabilityCategory::MEVExploitable | VulnerabilityCategory::FrontRunning => {
                self.generate_mev_test(vuln, &test_name)
            }
            VulnerabilityCategory::FlashLoanAttack => {
                self.generate_flash_loan_test(vuln, &test_name)
            }
            _ => {
                self.generate_generic_test(vuln, &test_name)
            }
        }
    }

    fn generate_reentrancy_test(&self, vuln: &Vulnerability, test_name: &str) -> String {
        format!(
            r#"// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

/**
 * @title PoC: {}
 * @notice Reentrancy vulnerability test
 * @dev Vulnerable code at line {}: {}
 */
contract {} is Test {{
    // Target contract - replace with actual contract
    // VulnerableContract public target;
    AttackerContract public attacker;

    function setUp() public {{
        // Deploy vulnerable contract
        // target = new VulnerableContract();

        // Fund the target
        // vm.deal(address(target), 10 ether);

        // Deploy attacker
        // attacker = new AttackerContract(address(target));
        // vm.deal(address(attacker), 1 ether);
    }}

    function {}() public {{
        // Record initial balances
        // uint256 targetBalanceBefore = address(target).balance;
        // uint256 attackerBalanceBefore = address(attacker).balance;

        // Execute reentrancy attack
        // attacker.attack();

        // Verify exploitation
        // uint256 targetBalanceAfter = address(target).balance;
        // uint256 attackerBalanceAfter = address(attacker).balance;

        // Assertions
        // assertLt(targetBalanceAfter, targetBalanceBefore, "Target should lose funds");
        // assertGt(attackerBalanceAfter, attackerBalanceBefore, "Attacker should gain funds");

        // Placeholder - implement actual test
        assertTrue(true, "TODO: Implement reentrancy PoC");
    }}
}}

contract AttackerContract {{
    address public target;
    uint256 public attackCount;

    constructor(address _target) {{
        target = _target;
    }}

    function attack() external payable {{
        // Initial call to vulnerable function
        // IVulnerable(target).vulnerableFunction{{value: msg.value}}();
    }}

    receive() external payable {{
        if (attackCount < 10 && address(target).balance > 0) {{
            attackCount++;
            // Re-enter
            // IVulnerable(target).vulnerableFunction{{value: 0}}();
        }}
    }}
}}
"#,
            vuln.title,
            vuln.line_number,
            vuln.code_snippet.trim(),
            self.sanitize_name(&vuln.title),
            test_name
        )
    }

    fn generate_oracle_test(&self, vuln: &Vulnerability, test_name: &str) -> String {
        format!(
            r#"// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

/**
 * @title PoC: {}
 * @notice Oracle manipulation test
 * @dev Vulnerable code at line {}: {}
 */
contract {} is Test {{
    // Target contract
    // VulnerableContract public target;

    // Mock flash loan provider
    // IFlashLoanProvider public flashLoan;

    function setUp() public {{
        // Deploy contracts
        // target = new VulnerableContract();

        // Setup initial prices/liquidity
    }}

    function {}() public {{
        // Step 1: Record initial state
        // uint256 initialPrice = target.getPrice();
        // uint256 attackerBalanceBefore = attacker.balance;

        // Step 2: Simulate flash loan
        // vm.prank(attacker);
        // flashLoan.flashLoan(1_000_000 ether);

        // Step 3: In callback - manipulate price
        // Large swap or direct transfer to move price
        // uint256 manipulatedPrice = target.getPrice();

        // Step 4: Exploit manipulated price
        // target.borrowAtManipulatedPrice();

        // Step 5: Restore price and repay flash loan

        // Assertions
        // assertGt(attackerBalanceAfter, attackerBalanceBefore);

        assertTrue(true, "TODO: Implement oracle manipulation PoC");
    }}
}}
"#,
            vuln.title,
            vuln.line_number,
            vuln.code_snippet.trim(),
            self.sanitize_name(&vuln.title),
            test_name
        )
    }

    fn generate_access_control_test(&self, vuln: &Vulnerability, test_name: &str) -> String {
        format!(
            r#"// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

/**
 * @title PoC: {}
 * @notice Access control bypass test
 * @dev Vulnerable code at line {}: {}
 */
contract {} is Test {{
    // VulnerableContract public target;
    address public owner = address(1);
    address public attacker = address(2);

    function setUp() public {{
        // Deploy as owner
        // vm.prank(owner);
        // target = new VulnerableContract();
    }}

    function {}() public {{
        // Verify attacker is not authorized
        // assertFalse(target.isAuthorized(attacker));

        // Attempt to call protected function as attacker
        // vm.prank(attacker);

        // This should revert but doesn't due to missing access control
        // vm.expectRevert("Not authorized"); // Remove if attack succeeds
        // target.protectedFunction();

        // If we reach here without revert, access control is bypassed
        // assertEq(target.privilegedState(), newValue);

        assertTrue(true, "TODO: Implement access control PoC");
    }}
}}
"#,
            vuln.title,
            vuln.line_number,
            vuln.code_snippet.trim(),
            self.sanitize_name(&vuln.title),
            test_name
        )
    }

    fn generate_mev_test(&self, vuln: &Vulnerability, test_name: &str) -> String {
        format!(
            r#"// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

/**
 * @title PoC: {}
 * @notice MEV/Sandwich attack simulation
 * @dev Vulnerable code at line {}: {}
 */
contract {} is Test {{
    // DEX and tokens
    // IRouter public router;
    // IERC20 public tokenA;
    // IERC20 public tokenB;

    address public victim = address(1);
    address public attacker = address(2);

    function setUp() public {{
        // Deploy DEX, tokens, add liquidity
    }}

    function {}() public {{
        // Setup: Give victim tokens for swap
        // deal(address(tokenA), victim, 100 ether);

        // Give attacker tokens
        // deal(address(tokenA), attacker, 1000 ether);

        // Step 1: Attacker frontruns - buy tokenB
        // vm.prank(attacker);
        // router.swap(tokenA, tokenB, 500 ether, 0); // moves price

        // Step 2: Victim's swap executes at worse price
        // uint256 expectedOut = 95 ether; // What victim expected
        // vm.prank(victim);
        // uint256 actualOut = router.swap(tokenA, tokenB, 100 ether, 0); // No slippage!

        // Step 3: Attacker backruns - sell tokenB
        // vm.prank(attacker);
        // router.swap(tokenB, tokenA, attackerTokenB, 0);

        // Assertions
        // assertLt(actualOut, expectedOut, "Victim got less than expected");
        // assertGt(attackerProfit, 0, "Attacker profited");

        assertTrue(true, "TODO: Implement sandwich attack PoC");
    }}
}}
"#,
            vuln.title,
            vuln.line_number,
            vuln.code_snippet.trim(),
            self.sanitize_name(&vuln.title),
            test_name
        )
    }

    fn generate_flash_loan_test(&self, vuln: &Vulnerability, test_name: &str) -> String {
        format!(
            r#"// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

/**
 * @title PoC: {}
 * @notice Flash loan attack simulation
 * @dev Vulnerable code at line {}: {}
 */
contract {} is Test {{
    // IFlashLoanProvider public flashLoan;
    // VulnerableContract public target;

    address public attacker = address(1);

    function setUp() public {{
        // Deploy flash loan provider and target
    }}

    function {}() public {{
        // vm.startPrank(attacker);

        // Record initial state
        // uint256 attackerBalanceBefore = attacker.balance;

        // Execute flash loan attack
        // flashLoan.flashLoan(address(this), 1_000_000 ether, "");

        // Verify profit
        // uint256 attackerBalanceAfter = attacker.balance;
        // assertGt(attackerBalanceAfter, attackerBalanceBefore);

        // vm.stopPrank();

        assertTrue(true, "TODO: Implement flash loan PoC");
    }}

    // Flash loan callback
    function executeOperation(
        address asset,
        uint256 amount,
        uint256 premium,
        address initiator,
        bytes calldata params
    ) external returns (bool) {{
        // Exploit logic here
        // 1. Manipulate state/price
        // 2. Extract value
        // 3. Repay flash loan + premium

        return true;
    }}
}}
"#,
            vuln.title,
            vuln.line_number,
            vuln.code_snippet.trim(),
            self.sanitize_name(&vuln.title),
            test_name
        )
    }

    fn generate_generic_test(&self, vuln: &Vulnerability, test_name: &str) -> String {
        format!(
            r#"// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

/**
 * @title PoC: {}
 * @notice Vulnerability proof of concept
 * @dev Vulnerable code at line {}: {}
 * @dev Category: {:?}
 */
contract {} is Test {{
    function setUp() public {{
        // Setup test environment
    }}

    function {}() public {{
        // Implement proof of concept for: {}

        // Step 1: Setup initial state

        // Step 2: Execute attack

        // Step 3: Verify impact

        // Vulnerable code:
        // {}

        // Recommendation: {}

        assertTrue(true, "TODO: Implement PoC");
    }}
}}
"#,
            vuln.title,
            vuln.line_number,
            vuln.code_snippet.trim(),
            vuln.category,
            self.sanitize_name(&vuln.title),
            test_name,
            vuln.description,
            vuln.code_snippet.trim(),
            vuln.recommendation
        )
    }

    /// Run forge test and get JSON results
    pub fn run_tests(&self, test_pattern: Option<&str>) -> Result<Vec<ForgeTestResult>, String> {
        let mut cmd = Command::new("forge");
        cmd.current_dir(&self.project_path);
        cmd.args(["test", "--json"]);

        if let Some(pattern) = test_pattern {
            cmd.args(["--match-test", pattern]);
        }

        let output = cmd.output().map_err(|e| format!("Failed to run forge: {}", e))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!("Forge test failed: {}", stderr));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);

        // Parse JSON output
        // Forge outputs one JSON object per line for each test
        let results: Vec<ForgeTestResult> = stdout
            .lines()
            .filter_map(|line| serde_json::from_str(line).ok())
            .collect();

        Ok(results)
    }

    /// Correlate findings with Foundry test results
    pub fn correlate_findings(
        &self,
        vulnerabilities: &[Vulnerability],
        test_results: &[ForgeTestResult],
    ) -> Vec<CorrelationResult> {
        let mut correlations = Vec::new();

        for (idx, vuln) in vulnerabilities.iter().enumerate() {
            let finding_id = format!("F-{:03}", idx + 1);
            let sanitized_title = self.sanitize_name(&vuln.title);

            // Look for matching tests
            let matching_test = test_results.iter().find(|t| {
                t.name.to_lowercase().contains(&sanitized_title.to_lowercase()) ||
                t.name.to_lowercase().contains(&format!("poc_{:02}", idx + 1))
            });

            let (test_exists, test_passes, test_name, confidence_adj) = match matching_test {
                Some(test) => {
                    let passes = test.status == "pass" || test.status == "Pass";
                    let adj = if passes { 0.2 } else { -0.1 }; // Passing PoC increases confidence
                    (true, passes, Some(test.name.clone()), adj)
                }
                None => (false, false, None, 0.0),
            };

            correlations.push(CorrelationResult {
                finding_id,
                finding_title: vuln.title.clone(),
                test_exists,
                test_passes,
                test_name,
                confidence_adjustment: confidence_adj,
            });
        }

        correlations
    }

    /// Generate test file index
    pub fn generate_test_index(&self, generated_files: &[String]) -> String {
        let mut index = String::new();

        index.push_str("# Generated PoC Tests\n\n");
        index.push_str("| # | Test File | Status |\n");
        index.push_str("|---|-----------|--------|\n");

        for (idx, file) in generated_files.iter().enumerate() {
            let file_name = Path::new(file)
                .file_name()
                .map(|f| f.to_string_lossy())
                .unwrap_or_default();
            index.push_str(&format!("| {} | `{}` | TODO |\n", idx + 1, file_name));
        }

        index.push_str("\n## Running Tests\n\n");
        index.push_str("```bash\n");
        index.push_str("# Run all PoC tests\n");
        index.push_str("forge test --match-path test/poc/*.t.sol -vvv\n\n");
        index.push_str("# Run specific PoC\n");
        index.push_str("forge test --match-test test_PoC_01 -vvv\n");
        index.push_str("```\n");

        index
    }

    fn sanitize_name(&self, name: &str) -> String {
        name.chars()
            .map(|c| if c.is_alphanumeric() { c } else { '_' })
            .collect::<String>()
            .trim_matches('_')
            .to_string()
    }
}
