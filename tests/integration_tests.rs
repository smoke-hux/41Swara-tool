//! Integration tests for 41Swara Smart Contract Scanner
//!
//! Tests detection accuracy and false positive rates across contract categories.
//! These tests run the actual scanner binary on test contracts and verify the JSON output.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

fn scanner_bin() -> &'static Path {
    static SCANNER_BIN: OnceLock<PathBuf> = OnceLock::new();

    SCANNER_BIN
        .get_or_init(|| {
            option_env!("CARGO_BIN_EXE_41swara")
                .map(PathBuf::from)
                .or_else(|| std::env::var_os("CARGO_BIN_EXE_41swara").map(PathBuf::from))
                .unwrap_or_else(|| PathBuf::from("target/debug/41swara"))
        })
        .as_path()
}

fn generated_fixture_root() -> &'static Path {
    static GENERATED_FIXTURE_ROOT: OnceLock<PathBuf> = OnceLock::new();

    GENERATED_FIXTURE_ROOT
        .get_or_init(|| {
            let root = std::env::temp_dir()
                .join(format!("41swara-generated-fixtures-{}", std::process::id()));
            fs::create_dir_all(&root).expect("Failed to create generated fixture root");
            root
        })
        .as_path()
}

fn generated_fixture_source(path: &str) -> Option<&'static str> {
    match path {
        "tests/contracts/defi/erc4626_slash_liability_drift.sol" => Some(
            r#"// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20Like {
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
}

contract ERC4626SlashLiabilityDrift {
    IERC20Like public asset;
    uint256 public totalSupply;
    uint256 public weeklyRevenue;

    constructor(IERC20Like asset_) {
        asset = asset_;
    }

    function buyDbr(uint256 amount) external {
        weeklyRevenue += amount;
    }

    function slash(address receiver, uint256 amount) external {
        require(asset.transfer(receiver, amount), "transfer failed");
    }

    function totalAssets() public view returns (uint256) {
        uint256 assets = asset.balanceOf(address(this));
        return assets - weeklyRevenue;
    }

    function convertToShares(uint256 assets) external view returns (uint256) {
        if (totalSupply == 0) {
            return assets;
        }

        return assets * totalSupply / totalAssets();
    }
}
"#,
        ),
        "tests/contracts/modern/phase6_modern_vulnerabilities.sol" => Some(
            r#"// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Permit2 string is intentionally present to trigger the dedicated analyzer.
contract VulnerablePermit2Consumer {
    function permitTransferFrom(bytes calldata permit, bytes calldata signature) external {
        bytes memory data = abi.encode(permit, signature);
        require(data.length > 0, "empty");
    }
}

// LayerZero string is intentionally present to trigger the dedicated analyzer.
contract VulnerableLayerZeroReceiver {
    function lzReceive(
        uint16 _srcChainId,
        bytes calldata _srcAddress,
        uint64 nonce,
        bytes calldata _payload
    ) external {
        (address to, uint256 amount) = abi.decode(_payload, (address, uint256));
        if (to == address(0)) {
            amount;
            nonce;
            _srcChainId;
            _srcAddress;
        }
    }
}

contract VulnerableCreate2Factory {
    function deploy(bytes32 salt, bytes memory code) external returns (address deployed) {
        assembly {
            deployed := create2(0, add(code, 0x20), mload(code), salt)
        }
    }

    function destroy() external {
        selfdestruct(payable(msg.sender));
    }
}

library MerkleProof {
    function verify(bytes32[] calldata proof, bytes32 root, bytes32 leaf) internal pure returns (bool) {
        return proof.length >= 0 && root != bytes32(0) && leaf != bytes32(0);
    }
}

contract VulnerableMerkleDistributor {
    bytes32 public merkleRoot;

    function claim(bytes32[] calldata proof, uint256 amount, string calldata memo, bytes calldata extra) external {
        bytes32 leaf = keccak256(abi.encodePacked(memo, extra));
        require(MerkleProof.verify(proof, merkleRoot, leaf), "invalid");
        require(amount > 0, "zero");
    }
}
"#,
        ),
        "tests/contracts/false_positives/fp_defi_custom_guards.sol" => Some(
            r#"// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title DeFi flows with custom pause, slippage, and deadline protection
contract SafeLiquidityRouter {
    bool public emergencyShutdown;

    modifier whenActive() {
        require(!emergencyShutdown, "paused");
        _;
    }

    function setEmergencyShutdown(bool status) external {
        emergencyShutdown = status;
    }

    function swapExactTokens(
        address tokenIn,
        address tokenOut,
        uint256 amountIn,
        uint256 minReceived,
        uint256 expiry
    ) external whenActive returns (uint256 amountOut) {
        require(block.timestamp <= expiry, "expired");
        amountOut = quote(tokenIn, tokenOut, amountIn);
        require(amountOut >= minReceived, "slippage");
    }

    function addLiquidity(
        address token,
        uint256 amount,
        uint256 minSharesOut,
        uint256 validUntil
    ) external whenActive returns (uint256 shares) {
        require(token != address(0), "zero token");
        require(block.timestamp <= validUntil, "expired");
        shares = amount;
        require(shares >= minSharesOut, "slippage");
    }

    function quote(address, address, uint256 amountIn) internal pure returns (uint256) {
        return amountIn;
    }
}
"#,
        ),
        "tests/contracts/false_positives/fp_erc4626_slash_liability_sync.sol" => Some(
            r#"// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20LiabilitySync {
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
}

contract ERC4626SlashLiabilitySync {
    IERC20LiabilitySync public asset;
    uint256 public totalSupply;
    uint256 public weeklyRevenue;

    constructor(IERC20LiabilitySync asset_) {
        asset = asset_;
    }

    function buyDbr(uint256 amount) external {
        weeklyRevenue += amount;
    }

    function slash(address receiver, uint256 amount) external {
        if (weeklyRevenue >= amount) {
            weeklyRevenue -= amount;
        } else {
            weeklyRevenue = 0;
        }

        require(asset.transfer(receiver, amount), "transfer failed");
    }

    function totalAssets() public view returns (uint256) {
        uint256 assets = asset.balanceOf(address(this));
        if (assets <= weeklyRevenue) {
            return 0;
        }

        return assets - weeklyRevenue;
    }

    function convertToShares(uint256 assets) external view returns (uint256) {
        if (totalSupply == 0) {
            return assets;
        }

        return assets * totalSupply / totalAssets();
    }
}
"#,
        ),
        "tests/contracts/false_positives/fp_input_validation_helpers.sol" => Some(
            r#"// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title Safe input handling patterns that should not trigger validation findings
contract SafeInputValidationHelpers {
    function processPayload(bytes calldata payload) external {
        require(payload.length == 64, "invalid payload");
        (address recipient, uint256 amount) = abi.decode(payload, (address, uint256));
        require(recipient != address(0), "zero recipient");
        require(amount > 0, "zero amount");
    }

    function batchUpdate(address[] calldata users, uint256[] calldata amounts) external pure returns (uint256) {
        require(users.length == amounts.length, "length mismatch");
        require(users.length > 0 && users.length <= 100, "invalid length");
        return users.length;
    }

    function _isContract(address account) internal view returns (bool) {
        return account.code.length > 0;
    }
}
"#,
        ),
        "tests/contracts/false_positives/fp_meta_tx_safe.sol" => Some(
            r#"// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title Safe forwarder pattern with verification, deadline, and nonce usage
contract SafeTrustedForwarder {
    struct ForwardRequest {
        address from;
        address to;
        uint256 value;
        uint256 gas;
        uint256 nonce;
        uint256 deadline;
        bytes data;
    }

    address private _owner;
    address public trustedForwarder;
    mapping(address => uint256) private _nonces;

    modifier onlyOwner() {
        require(msg.sender == _owner, "not owner");
        _;
    }

    constructor(address initialForwarder) {
        _owner = msg.sender;
        trustedForwarder = initialForwarder;
    }

    function setTrustedForwarder(address newForwarder) external onlyOwner {
        require(newForwarder != address(0), "zero forwarder");
        trustedForwarder = newForwarder;
    }

    function execute(ForwardRequest calldata req, bytes calldata signature)
        external
        returns (bool, bytes memory)
    {
        require(_verify(req, signature), "bad sig");
        require(block.timestamp <= req.deadline, "expired");
        _useNonce(req.from);
        return (true, req.data);
    }

    function _verify(ForwardRequest calldata req, bytes calldata signature) internal view returns (bool) {
        return signature.length > 0 && req.to != address(0) && req.nonce == _nonces[req.from];
    }

    function _useNonce(address from) internal {
        _nonces[from] = _nonces[from] + 1;
    }
}
"#,
        ),
        "tests/contracts/false_positives/fp_permit_safe.sol" => Some(
            r#"// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title Permit flow with deadline, domain separation, and nonce invalidation
contract SafePermitFlow {
    mapping(address => uint256) public nonces;
    bytes32 public immutable DOMAIN_SEPARATOR;

    constructor() {
        DOMAIN_SEPARATOR = keccak256(abi.encode(block.chainid, address(this)));
    }

    function permit(
        address owner,
        address spender,
        uint256 value,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        require(block.timestamp <= deadline, "expired");
        bytes32 digest = keccak256(
            abi.encode(DOMAIN_SEPARATOR, owner, spender, value, nonces[owner], deadline)
        );
        address recovered = ecrecover(digest, v, r, s);
        require(recovered != address(0), "invalid sig");
        require(recovered == owner, "bad sig");
        nonces[owner] = nonces[owner] + 1;
    }
}
"#,
        ),
        "tests/contracts/false_positives/fp_proxy_upgrade_safe.sol" => Some(
            r#"// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title Upgrade/admin functions protected by internal owner checks
contract SafeProxyUpgrade {
    address private _owner;
    address public implementation;

    constructor() {
        _owner = msg.sender;
    }

    function _checkOwner() internal view {
        require(msg.sender == _owner, "not owner");
    }

    function transferOwnership(address newOwner) public {
        _checkOwner();
        require(newOwner != address(0), "zero owner");
        _owner = newOwner;
    }

    function upgradeTo(address newImplementation) public {
        _checkOwner();
        require(newImplementation != address(0), "zero implementation");
        implementation = newImplementation;
    }

    function setImplementation(address newImplementation) public {
        _checkOwner();
        require(newImplementation != address(0), "zero implementation");
        implementation = newImplementation;
    }
}
"#,
        ),
        _ => None,
    }
}

fn resolve_test_path(path: &str) -> PathBuf {
    if let Some(source) = generated_fixture_source(path) {
        let generated_path = generated_fixture_root().join(path);
        if !generated_path.exists() {
            if let Some(parent) = generated_path.parent() {
                fs::create_dir_all(parent).expect("Failed to create generated fixture parent");
            }
            fs::write(&generated_path, source).expect("Failed to write generated fixture");
        }
        return generated_path;
    }

    let original = PathBuf::from(path);
    assert!(original.exists(), "Missing test fixture: {path}");
    original
}

/// Run the scanner on a file and return the JSON stdout.
fn scan_file(path: &str) -> String {
    scan_file_with_args(path, &[])
}

/// Run the scanner on a file with extra CLI arguments and return the JSON stdout.
fn scan_file_with_args(path: &str, extra_args: &[&str]) -> String {
    let resolved_path = resolve_test_path(path);

    let output = Command::new(scanner_bin())
        .arg(&resolved_path)
        .args(["--format", "json", "--min-severity", "info"])
        .args(extra_args)
        .output()
        .expect("Failed to run scanner");

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    assert!(
        matches!(output.status.code(), Some(0..=3)),
        "Scanner command failed for {path}\nstatus: {}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        stdout,
        stderr
    );

    assert!(
        !stdout.trim().is_empty(),
        "Scanner command produced no stdout for {path}\nstatus: {}\nstderr:\n{}",
        output.status,
        stderr
    );

    stdout
}

fn fake_tool_path(tool_name: &str) -> PathBuf {
    let fake_bin = generated_fixture_root().join("fake-bin");
    fs::create_dir_all(&fake_bin).expect("Failed to create fake tool dir");
    fs::write(fake_bin.join(tool_name), "#!/bin/sh\nexit 0\n").expect("Failed to write fake tool");
    fake_bin
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

/// Check if a finding with an exact title exists.
fn has_finding_title(json: &str, title: &str) -> bool {
    let parsed: serde_json::Value = match serde_json::from_str(json) {
        Ok(v) => v,
        Err(_) => return false,
    };
    parsed["results"]
        .as_array()
        .map(|results| {
            results
                .iter()
                .flat_map(|r| r["vulnerabilities"].as_array())
                .flatten()
                .any(|v| v["title"].as_str() == Some(title))
        })
        .unwrap_or(false)
}

/// Check if a finding with an exact title exists at a specific line.
fn has_finding_title_at_line(json: &str, title: &str, line: u64) -> bool {
    let parsed: serde_json::Value = match serde_json::from_str(json) {
        Ok(v) => v,
        Err(_) => return false,
    };
    parsed["results"]
        .as_array()
        .map(|results| {
            results
                .iter()
                .flat_map(|r| r["vulnerabilities"].as_array())
                .flatten()
                .any(|v| {
                    v["title"].as_str() == Some(title) && v["line_number"].as_u64() == Some(line)
                })
        })
        .unwrap_or(false)
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
        "False positive: safe_reentrancy.sol with nonReentrant guard should have 0 Critical, got {critical}"
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
        "False positive: ownable_safe.sol with onlyOwner should have 0 Critical, got {critical}"
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

#[test]
fn test_detects_false_negative_return_bomb_pattern() {
    let output = scan_file("test_contracts/FalseNegativeTest.sol");
    assert!(
        has_finding_title(&output, "Return Bomb Risk - Unbounded Return Data"),
        "Expected return bomb detection in FalseNegativeTest.sol.\nOutput: {}",
        &output[..output.len().min(1200)]
    );
}

#[test]
fn test_detects_false_negative_is_contract_bypass_pattern() {
    let output = scan_file("test_contracts/FalseNegativeTest.sol");
    assert!(
        has_finding_title(&output, "Contract Check Bypassable During Construction")
            || has_finding_title(&output, "extcodesize/isContract Unreliable Post-EIP-7702"),
        "Expected isContract/code.length bypass detection in FalseNegativeTest.sol.\nOutput: {}",
        &output[..output.len().min(1200)]
    );
}

#[test]
fn test_detects_false_negative_signature_malleability_pattern() {
    let output = scan_file("test_contracts/FalseNegativeTest.sol");
    assert!(
        has_finding_containing(&output, "Signature Malleability"),
        "Expected signature malleability detection in FalseNegativeTest.sol.\nOutput: {}",
        &output[..output.len().min(1200)]
    );
}

#[test]
fn test_interface_signatures_do_not_trigger_access_control_findings() {
    let output = scan_file("test_contracts/FalseNegativeTest.sol");
    assert!(
        !has_finding_title_at_line(
            &output,
            "Missing Access Control on State-Changing Function",
            47
        ),
        "Interface declarations should not be treated as vulnerable implementations.\nOutput: {}",
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
        "False positive: safe_erc20_usage.sol should have 0 Critical findings, got {critical}"
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

#[test]
fn test_dynamic_tool_catalog_json() {
    let output = Command::new(scanner_bin())
        .args(["--dynamic-list-tools", "--format", "json"])
        .output()
        .expect("Failed to run scanner");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "dynamic tool catalog failed\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );

    let catalog: serde_json::Value =
        serde_json::from_str(&stdout).expect("catalog should be valid JSON");
    let ids: Vec<&str> = catalog
        .as_array()
        .expect("catalog should be a JSON array")
        .iter()
        .filter_map(|tool| tool["id"].as_str())
        .collect();

    for expected in ["echidna", "forge-fuzz", "halmos", "certora", "forta"] {
        assert!(ids.contains(&expected), "missing dynamic tool {expected}");
    }
}

#[test]
fn test_dynamic_dry_run_json_output() {
    let resolved_path = resolve_test_path("tests/contracts/reentrancy/classic_reentrancy.sol");
    let fake_bin = fake_tool_path("echidna-test");
    let path = format!(
        "{}:{}",
        fake_bin.display(),
        std::env::var("PATH").unwrap_or_default()
    );

    let output = Command::new(scanner_bin())
        .arg(&resolved_path)
        .args([
            "--format",
            "json",
            "--min-severity",
            "info",
            "--dynamic-analysis",
            "--dynamic-dry-run",
            "--dynamic-tool",
            "echidna",
        ])
        .env("PATH", path)
        .output()
        .expect("Failed to run scanner");

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    assert!(
        matches!(output.status.code(), Some(0..=3)),
        "dynamic dry-run failed\nstatus: {}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        stdout,
        stderr
    );

    let parsed: serde_json::Value =
        serde_json::from_str(&stdout).expect("dynamic dry-run output should be valid JSON");
    let run = &parsed["dynamic_analysis"]["runs"][0];
    assert_eq!(run["tool_id"].as_str(), Some("echidna"));
    assert_eq!(run["status"].as_str(), Some("Planned"));
    assert_eq!(run["command"].as_str(), Some("echidna-test"));
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
        "FP regression: fp_reentrancy_guard.sol with nonReentrant should have 0 Critical, got {critical}"
    );
    assert_eq!(
        high, 0,
        "FP regression: fp_reentrancy_guard.sol with nonReentrant should have 0 High, got {high}"
    );
}

#[test]
fn test_fp_ownable_functions_no_critical() {
    let output = scan_file("tests/contracts/false_positives/fp_ownable_functions.sol");
    let critical = count_severity(&output, "Critical");
    assert_eq!(
        critical, 0,
        "FP regression: fp_ownable_functions.sol with onlyOwner should have 0 Critical, got {critical}"
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
        "FP regression: view/pure contract should have 0 Critical, got {critical}"
    );
    assert_eq!(
        high, 0,
        "FP regression: view/pure contract should have 0 High, got {high}"
    );
}

#[test]
fn test_fp_transfer_2300_gas_no_reentrancy() {
    let output = scan_file("tests/contracts/false_positives/fp_transfer_2300_gas.sol");
    let critical = count_severity(&output, "Critical");
    assert_eq!(
        critical, 0,
        "FP regression: .transfer()/.send() with 2300 gas should have 0 Critical reentrancy, got {critical}"
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
        "Finding flood: classic_reentrancy.sol should have ≤10 findings after dedup, got {total}"
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
        "Compiler findings should be consolidated to ≤1, got {compiler_count}"
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
                "CVSS vector should start with 'CVSS:3.1/', got: {vector}"
            );
        }
    }
}

// =========================================================================
// v0.9.0 Version Validation
// =========================================================================

#[test]
fn test_json_output_version_0_9() {
    let output = scan_file("tests/contracts/reentrancy/classic_reentrancy.sol");
    let parsed: serde_json::Value = serde_json::from_str(&output).unwrap_or_default();
    let version = parsed["version"].as_str().unwrap_or("");
    assert_eq!(
        version, "0.9.0",
        "Scanner version in JSON should be 0.9.0, got '{version}'"
    );
}
