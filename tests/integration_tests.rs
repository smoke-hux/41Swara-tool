//! Integration tests for 41Swara Smart Contract Scanner
//!
//! Tests detection accuracy and false positive rates across contract categories.
//! These tests run the actual scanner binary on test contracts and verify the JSON output.

use std::process::Command;

/// Run the scanner on a file and return the JSON stdout.
fn scan_file(path: &str) -> String {
    scan_file_with_args(path, &[])
}

/// Run the scanner on a file with extra CLI arguments and return the JSON stdout.
fn scan_file_with_args(path: &str, extra_args: &[&str]) -> String {
    let mut args = vec![
        "run",
        "--bin",
        "41swara",
        "--quiet",
        "--",
        path,
        "--format",
        "json",
        "--min-severity",
        "info",
    ];
    args.extend(extra_args.iter().copied());

    let output = Command::new("cargo")
        .args(args)
        .output()
        .expect("Failed to run scanner");
    String::from_utf8_lossy(&output.stdout).to_string()
}

/// Count findings of a given severity in JSON output.
fn count_severity(json: &str, severity: &str) -> usize {
    let parsed: serde_json::Value = match serde_json::from_str(json) {
        Ok(v) => v,
        Err(_) => return 0,
    };
    parsed["results"]
        .as_array()
        .map(|results| {
            results
                .iter()
                .flat_map(|r| r["vulnerabilities"].as_array())
                .flatten()
                .filter(|v| v["severity"].as_str() == Some(severity))
                .count()
        })
        .unwrap_or(0)
}

/// Check if any finding contains a specific string (category, title, etc.).
fn has_finding_containing(json: &str, needle: &str) -> bool {
    let needle_lower = needle.to_lowercase();
    json.to_lowercase().contains(&needle_lower)
}

/// Count how many expected strings appear in the scan output.
fn count_matching_needles(json: &str, needles: &[&str]) -> usize {
    needles
        .iter()
        .filter(|needle| has_finding_containing(json, needle))
        .count()
}

/// Get total vulnerability count from JSON output.
fn total_findings(json: &str) -> usize {
    let parsed: serde_json::Value = match serde_json::from_str(json) {
        Ok(v) => v,
        Err(_) => return 0,
    };
    parsed["total_vulnerabilities"].as_u64().unwrap_or(0) as usize
}

// =========================================================================
// Reentrancy Detection
// =========================================================================

#[test]
fn test_detects_classic_reentrancy() {
    let output = scan_file("tests/contracts/reentrancy/classic_reentrancy.sol");
    assert!(
        has_finding_containing(&output, "Reentrancy")
            || has_finding_containing(&output, "reentrancy")
            || has_finding_containing(&output, "external call"),
        "Expected reentrancy detection in classic_reentrancy.sol.\nOutput: {}",
        &output[..output.len().min(500)]
    );
}

#[test]
fn test_no_critical_reentrancy_with_guard() {
    let output = scan_file("tests/contracts/reentrancy/safe_reentrancy.sol");
    let critical = count_severity(&output, "Critical");
    assert_eq!(
        critical, 0,
        "False positive: safe_reentrancy.sol with nonReentrant guard should have 0 Critical, got {}",
        critical
    );
}

// =========================================================================
// Access Control Detection
// =========================================================================

#[test]
fn test_detects_unprotected_admin() {
    let output = scan_file("tests/contracts/access_control/unprotected_admin.sol");
    let total = total_findings(&output);
    assert!(
        total > 0,
        "Expected findings in unprotected_admin.sol, got 0"
    );
    assert!(
        has_finding_containing(&output, "access")
            || has_finding_containing(&output, "control")
            || has_finding_containing(&output, "withdraw")
            || has_finding_containing(&output, "setFee"),
        "Expected access control detection in unprotected_admin.sol"
    );
}

#[test]
fn test_no_critical_with_ownable() {
    let output = scan_file("tests/contracts/access_control/ownable_safe.sol");
    let critical = count_severity(&output, "Critical");
    assert_eq!(
        critical, 0,
        "False positive: ownable_safe.sol with onlyOwner should have 0 Critical, got {}",
        critical
    );
}

// =========================================================================
// DeFi Vulnerability Detection
// =========================================================================

#[test]
fn test_detects_defi_vulnerabilities() {
    let output = scan_file("tests/contracts/defi/vulnerable_vault.sol");
    let total = total_findings(&output);
    assert!(
        total > 0,
        "Expected findings in vulnerable_vault.sol, got 0"
    );
}

#[test]
fn test_detects_erc4626_slash_liability_drift() {
    let output = scan_file("tests/contracts/defi/erc4626_slash_liability_drift.sol");
    assert!(
        has_finding_containing(&output, "ERC4626 Liability Drift After Slash"),
        "Expected cross-function slash/liability drift detection.\nOutput: {}",
        &output[..output.len().min(800)]
    );
}

#[test]
fn test_detects_phase6_modern_vulnerabilities() {
    let output = scan_file("tests/contracts/modern/phase6_modern_vulnerabilities.sol");
    let needles = [
        "Permit2 Missing Deadline Check",
        "LayerZero Missing Chain ID Validation",
        "User-Controlled CREATE2 Salt",
        "CRITICAL: Merkle Proof Without Address Binding",
    ];
    let hits = count_matching_needles(&output, &needles);
    assert!(
        hits == needles.len(),
        "Expected modern Phase 6 coverage across Permit2/LayerZero/CREATE2/Merkle detector families, got {hits} hits.\nOutput: {}",
        &output[..output.len().min(1200)]
    );
}

#[test]
fn test_fast_mode_with_advanced_detectors_flag_runs_phase6_suite() {
    let fast_output = scan_file_with_args(
        "tests/contracts/modern/phase6_modern_vulnerabilities.sol",
        &["--fast"],
    );
    let advanced_output = scan_file_with_args(
        "tests/contracts/modern/phase6_modern_vulnerabilities.sol",
        &["--fast", "--advanced-detectors"],
    );

    assert!(
        !has_finding_containing(&fast_output, "Permit2 Missing Deadline Check"),
        "Fast mode without --advanced-detectors should not run the Phase 6 suite"
    );
    assert!(
        has_finding_containing(&advanced_output, "Permit2 Missing Deadline Check"),
        "Expected --fast --advanced-detectors to run the Phase 6 detector suite"
    );
}

#[test]
fn test_detects_2025_exploit_corpus() {
    let output = scan_file("test_contracts/test_2025_exploits.sol");
    let needles = [
        "Flash Loan Attack Vector Detected",
        "ERC-4626 Vault Logic - Zero Supply Risk",
        "DAO Attack Pattern Detected",
        "Missing Access Control on State-Changing Function",
        "Bridge Proof Verification",
        "Missing Initializer Modifier",
        "First Depositor Attack Vector",
    ];
    let hits = count_matching_needles(&output, &needles);
    assert!(
        hits >= 6,
        "Expected broad coverage across the bundled 2025 exploit corpus, got {hits} hits.\nOutput: {}",
        &output[..output.len().min(1200)]
    );
}

#[test]
fn test_detects_2026_exploit_corpus() {
    let output = scan_file("test_contracts/test_2026_exploits.sol");
    let needles = [
        "MulticallStateReset",
        "EIP7702TxOriginBypass",
        "ReadOnlyReentrancy",
        "ERC2771MulticallSpoofing",
        "MulticallMsgValueReuse",
        "AVSSlashingRisk",
        "CLMMMathOverflow",
        "DonationAttackVector",
        "IsContractPostPectra",
        "UnsafeMulticallDelegatecall",
    ];
    let hits = count_matching_needles(&output, &needles);
    assert!(
        hits >= 7,
        "Expected broad coverage across the bundled 2026 exploit corpus, got {hits} hits.\nOutput: {}",
        &output[..output.len().min(1200)]
    );
}

// =========================================================================
// False Positive Regression
// =========================================================================

#[test]
fn test_no_critical_false_positives_safe_erc20() {
    let output = scan_file("tests/contracts/false_positives/safe_erc20_usage.sol");
    let critical = count_severity(&output, "Critical");
    assert_eq!(
        critical, 0,
        "False positive: safe_erc20_usage.sol should have 0 Critical findings, got {}",
        critical
    );
}

// =========================================================================
// v0.7.0 Exploit Pattern Detection
// =========================================================================

#[test]
fn test_detects_multicall_msg_value() {
    let output = scan_file("tests/contracts/v07_exploits/multicall_msg_value.sol");
    assert!(
        has_finding_containing(&output, "multicall")
            || has_finding_containing(&output, "delegatecall")
            || has_finding_containing(&output, "msg.value"),
        "Expected multicall/delegatecall/msg.value detection"
    );
}

#[test]
fn test_detects_cross_chain_vulnerability() {
    let output = scan_file("tests/contracts/v07_exploits/cross_chain_unvalidated.sol");
    let total = total_findings(&output);
    assert!(
        total > 0,
        "Expected findings in cross_chain_unvalidated.sol, got 0"
    );
}

// =========================================================================
// Output Format Validation
// =========================================================================

#[test]
fn test_json_output_is_valid() {
    let output = scan_file("tests/contracts/reentrancy/classic_reentrancy.sol");
    let parsed: Result<serde_json::Value, _> = serde_json::from_str(&output);
    assert!(
        parsed.is_ok(),
        "JSON output should be valid JSON: {}",
        &output[..output.len().min(200)]
    );
    let json = parsed.unwrap();
    assert!(
        json["version"].is_string(),
        "JSON should have version field"
    );
    assert!(
        json["files_scanned"].is_number(),
        "JSON should have files_scanned field"
    );
    assert!(json["results"].is_array(), "JSON should have results array");
}

#[test]
fn test_sarif_output_is_valid() {
    let output = Command::new("cargo")
        .args([
            "run",
            "--bin",
            "41swara",
            "--quiet",
            "--",
            "tests/contracts/reentrancy/classic_reentrancy.sol",
            "--format",
            "sarif",
        ])
        .output()
        .expect("Failed to run scanner");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: Result<serde_json::Value, _> = serde_json::from_str(&stdout);
    assert!(parsed.is_ok(), "SARIF output should be valid JSON");
    let sarif = parsed.unwrap();
    assert!(sarif["$schema"].is_string(), "SARIF should have $schema");
    assert!(sarif["runs"].is_array(), "SARIF should have runs array");
}

// =========================================================================
// v0.8.0 False Positive Regression Tests
// =========================================================================

#[test]
fn test_fp_reentrancy_guard_no_critical() {
    let output = scan_file("tests/contracts/false_positives/fp_reentrancy_guard.sol");
    let critical = count_severity(&output, "Critical");
    let high = count_severity(&output, "High");
    assert_eq!(
        critical, 0,
        "FP regression: fp_reentrancy_guard.sol with nonReentrant should have 0 Critical, got {}",
        critical
    );
    assert_eq!(
        high, 0,
        "FP regression: fp_reentrancy_guard.sol with nonReentrant should have 0 High, got {}",
        high
    );
}

#[test]
fn test_fp_ownable_functions_no_critical() {
    let output = scan_file("tests/contracts/false_positives/fp_ownable_functions.sol");
    let critical = count_severity(&output, "Critical");
    assert_eq!(
        critical, 0,
        "FP regression: fp_ownable_functions.sol with onlyOwner should have 0 Critical, got {}",
        critical
    );
}

#[test]
fn test_fp_safemath_0_8_no_arithmetic() {
    let output = scan_file("tests/contracts/false_positives/fp_safemath_0_8.sol");
    assert!(
        !has_finding_containing(&output, "ArithmeticIssues"),
        "FP regression: Solidity 0.8+ should not flag arithmetic overflow/underflow"
    );
}

#[test]
fn test_fp_view_functions_no_state_warnings() {
    let output = scan_file("tests/contracts/false_positives/fp_view_functions.sol");
    let critical = count_severity(&output, "Critical");
    let high = count_severity(&output, "High");
    assert_eq!(
        critical, 0,
        "FP regression: view/pure contract should have 0 Critical, got {}",
        critical
    );
    assert_eq!(
        high, 0,
        "FP regression: view/pure contract should have 0 High, got {}",
        high
    );
}

#[test]
fn test_fp_transfer_2300_gas_no_reentrancy() {
    let output = scan_file("tests/contracts/false_positives/fp_transfer_2300_gas.sol");
    let critical = count_severity(&output, "Critical");
    assert_eq!(
        critical, 0,
        "FP regression: .transfer()/.send() with 2300 gas should have 0 Critical reentrancy, got {}",
        critical
    );
}

#[test]
fn test_fp_input_validation_helpers_no_input_validation_findings() {
    let output = scan_file("tests/contracts/false_positives/fp_input_validation_helpers.sol");
    assert!(
        !has_finding_containing(&output, "Array Parameter Detected"),
        "FP regression: validated array inputs should not trigger array parameter findings"
    );
    assert!(
        !has_finding_containing(&output, "Unchecked Raw Calldata"),
        "FP regression: validated bytes calldata should not trigger raw calldata findings"
    );
    assert!(
        !has_finding_containing(&output, "Contract Check Bypassable During Construction"),
        "FP regression: internal isContract helper should not trigger constructor bypass finding"
    );
    assert!(
        !has_finding_containing(&output, "Cross-Chain Receiver Without Source Validation"),
        "FP regression: generic payload handlers should not be treated as cross-chain receivers without bridge context"
    );
}

#[test]
fn test_fp_proxy_upgrade_safe_no_proxy_admin_findings() {
    let output = scan_file("tests/contracts/false_positives/fp_proxy_upgrade_safe.sol");
    assert!(
        !has_finding_containing(&output, "Proxy Upgrade Function Detected"),
        "FP regression: upgrade function protected by _checkOwner() should not trigger proxy-upgrade finding"
    );
    assert!(
        !has_finding_containing(&output, "Unprotected Proxy Admin Function"),
        "FP regression: transferOwnership protected by _checkOwner() should not trigger proxy-admin finding"
    );
    assert!(
        !has_finding_containing(&output, "Aevo-Pattern Proxy Vulnerability"),
        "FP regression: protected proxy admin functions should not match Aevo-pattern finding"
    );
}

#[test]
fn test_fp_defi_custom_guards_no_pause_or_slippage_findings() {
    let output = scan_file("tests/contracts/false_positives/fp_defi_custom_guards.sol");
    assert!(
        !has_finding_containing(&output, "Missing Emergency Stop"),
        "FP regression: custom pause guards should satisfy emergency-stop detection"
    );
    assert!(
        !has_finding_containing(&output, "Missing Slippage Protection"),
        "FP regression: minReceived/minSharesOut validation should satisfy slippage detection"
    );
    assert!(
        !has_finding_containing(&output, "Sandwich Attack Vulnerable Swap"),
        "FP regression: swap with minReceived and expiry should not be flagged as sandwich vulnerable"
    );
}

#[test]
fn test_fp_meta_tx_safe_no_meta_tx_findings() {
    let output = scan_file("tests/contracts/false_positives/fp_meta_tx_safe.sol");
    assert!(
        !has_finding_containing(&output, "MinimalForwarder Pattern"),
        "FP regression: forwarder with verification and nonce invalidation should not trigger generic forwarder finding"
    );
    assert!(
        !has_finding_containing(&output, "Meta-Transaction Replay Risk"),
        "FP regression: _useNonce() pattern should suppress meta-tx replay finding"
    );
    assert!(
        !has_finding_containing(&output, "Mutable Trusted Forwarder"),
        "FP regression: owner-gated trusted-forwarder setter should not be flagged"
    );
}

#[test]
fn test_fp_erc4626_slash_liability_sync_no_drift_finding() {
    let output = scan_file("tests/contracts/false_positives/fp_erc4626_slash_liability_sync.sol");
    assert!(
        !has_finding_containing(&output, "ERC4626 Liability Drift After Slash"),
        "FP regression: slash paths that update liability accounting should not trigger drift finding"
    );
}

#[test]
fn test_fp_permit_safe_no_signature_replay_findings() {
    let output = scan_file("tests/contracts/false_positives/fp_permit_safe.sol");
    assert!(
        !has_finding_containing(&output, "Missing Signature Deadline"),
        "FP regression: permit with explicit deadline check should not trigger deadline finding"
    );
    assert!(
        !has_finding_containing(&output, "ERC-2612 Permit Implementation"),
        "FP regression: safe permit flow should not trigger generic permit warning"
    );
    assert!(
        !has_finding_containing(&output, "Permit Signature Replay Attack"),
        "FP regression: nonce + domain-separator protected permit should not trigger replay finding"
    );
    assert!(
        !has_finding_containing(&output, "ecrecover Usage Detected"),
        "FP regression: ecrecover with explicit zero-address and signer validation should not trigger bypass finding"
    );
}

// =========================================================================
// v0.8.0 Finding Quality: Bounds & Consolidation
// =========================================================================

#[test]
fn test_classic_reentrancy_bounded_findings() {
    let output = scan_file("tests/contracts/reentrancy/classic_reentrancy.sol");
    let total = total_findings(&output);
    assert!(
        total <= 10,
        "Finding flood: classic_reentrancy.sol should have ≤10 findings after dedup, got {}",
        total
    );
}

#[test]
fn test_compiler_findings_consolidated() {
    let output = scan_file("tests/contracts/reentrancy/classic_reentrancy.sol");
    let parsed: serde_json::Value = serde_json::from_str(&output).unwrap_or_default();
    let compiler_count = parsed["results"]
        .as_array()
        .map(|results| {
            results
                .iter()
                .flat_map(|r| r["vulnerabilities"].as_array())
                .flatten()
                .filter(|v| v["category"].as_str() == Some("CompilerBug"))
                .count()
        })
        .unwrap_or(0);
    assert!(
        compiler_count <= 1,
        "Compiler findings should be consolidated to ≤1, got {}",
        compiler_count
    );
}

// =========================================================================
// v0.8.0 CVSS Enrichment Validation
// =========================================================================

#[test]
fn test_cvss_present_in_json_output() {
    let output = scan_file("tests/contracts/reentrancy/classic_reentrancy.sol");
    let parsed: serde_json::Value = serde_json::from_str(&output).unwrap_or_default();
    let vulns: Vec<&serde_json::Value> = parsed["results"]
        .as_array()
        .map(|results| {
            results
                .iter()
                .flat_map(|r| r["vulnerabilities"].as_array())
                .flatten()
                .collect()
        })
        .unwrap_or_default();

    assert!(!vulns.is_empty(), "Should have findings to test CVSS on");

    let with_cvss = vulns.iter().filter(|v| v["cvss_score"].is_f64()).count();
    assert!(
        with_cvss > 0,
        "At least some findings should have cvss_score in JSON output, got 0 out of {}",
        vulns.len()
    );
}

#[test]
fn test_cvss_vector_format() {
    let output = scan_file("tests/contracts/reentrancy/classic_reentrancy.sol");
    let parsed: serde_json::Value = serde_json::from_str(&output).unwrap_or_default();
    let vulns: Vec<&serde_json::Value> = parsed["results"]
        .as_array()
        .map(|results| {
            results
                .iter()
                .flat_map(|r| r["vulnerabilities"].as_array())
                .flatten()
                .collect()
        })
        .unwrap_or_default();

    for v in &vulns {
        if let Some(vector) = v["cvss_vector"].as_str() {
            assert!(
                vector.starts_with("CVSS:3.1/"),
                "CVSS vector should start with 'CVSS:3.1/', got: {}",
                vector
            );
        }
    }
}

// =========================================================================
// v0.8.0 Version Validation
// =========================================================================

#[test]
fn test_json_output_version_0_8() {
    let output = scan_file("tests/contracts/reentrancy/classic_reentrancy.sol");
    let parsed: serde_json::Value = serde_json::from_str(&output).unwrap_or_default();
    let version = parsed["version"].as_str().unwrap_or("");
    assert_eq!(
        version, "0.8.1",
        "Scanner version in JSON should be 0.8.1, got '{}'",
        version
    );
}
