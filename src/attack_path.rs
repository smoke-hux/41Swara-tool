//! Attack Path Narrative Generator.
//!
//! Generates human-readable attack path descriptions for each vulnerability
//! category, using actual function names from the scanned code. Security
//! researchers need to understand *how* an exploit would work, not just
//! *that* it exists.

use regex::Regex;
use crate::vulnerabilities::{Vulnerability, VulnerabilityCategory};

/// Generate an attack path narrative for a vulnerability.
fn generate_attack_path(vuln: &Vulnerability, content: &str) -> Option<String> {
    let fn_name = extract_nearby_function(content, vuln.line_number).unwrap_or("targetFunction".to_string());
    let contract_name = extract_contract_name(content).unwrap_or("Contract".to_string());

    match &vuln.category {
        VulnerabilityCategory::Reentrancy
        | VulnerabilityCategory::CallbackReentrancy
        | VulnerabilityCategory::ERC777CallbackReentrancy
        | VulnerabilityCategory::DepositForReentrancy => Some(format!(
            "1. Attacker deploys malicious contract with fallback/receive function\n\
             2. Attacker calls {contract_name}.{fn_name}() which makes external call\n\
             3. During the external call, attacker's fallback re-enters {fn_name}()\n\
             4. State variables (balances) haven't been updated yet — attacker drains funds\n\
             5. Re-entry repeats until contract is drained or gas runs out"
        )),

        VulnerabilityCategory::ReadOnlyReentrancy => Some(format!(
            "1. Attacker identifies {contract_name}.{fn_name}() reads state during callback\n\
             2. Attacker triggers external call that invokes a callback\n\
             3. During callback, attacker calls a view function that returns stale state\n\
             4. A dependent protocol uses the stale view return value for pricing/collateral\n\
             5. Attacker profits from the inconsistent state between contracts"
        )),

        VulnerabilityCategory::AccessControl
        | VulnerabilityCategory::RoleBasedAccessControl => Some(format!(
            "1. Attacker identifies {contract_name}.{fn_name}() lacks access control\n\
             2. Attacker calls the unprotected function directly from an EOA\n\
             3. Function executes privileged operations without verifying caller\n\
             4. Attacker gains owner privileges, drains funds, or corrupts state"
        )),

        VulnerabilityCategory::UnprotectedAdminSweep => Some(format!(
            "1. Compromised or malicious admin identifies sweep function in {contract_name}\n\
             2. Admin calls {fn_name}() without timelock — no delay for users to exit\n\
             3. All protocol funds are transferred to admin-controlled address\n\
             4. Users have no warning and cannot withdraw before sweep executes"
        )),

        VulnerabilityCategory::FlashLoanAttack => Some(format!(
            "1. Attacker borrows large amount via flash loan (Aave/dYdX/Balancer)\n\
             2. Attacker uses borrowed funds to manipulate market state\n\
             3. Attacker calls {contract_name}.{fn_name}() at manipulated prices\n\
             4. Function executes with attacker-favorable pricing\n\
             5. Attacker repays flash loan and keeps profit — all in one transaction"
        )),

        VulnerabilityCategory::OracleManipulation => Some(format!(
            "1. Attacker manipulates spot reserves via flash loan or large swap\n\
             2. {contract_name}.{fn_name}() reads manipulated on-chain price\n\
             3. Function uses inflated/deflated price for collateral/liquidation calculation\n\
             4. Attacker borrows against inflated collateral or liquidates at favorable price\n\
             5. Attacker exits position after oracle price normalizes"
        )),

        VulnerabilityCategory::DonationAttackVector => Some(format!(
            "1. Attacker is the first depositor in {contract_name}\n\
             2. Attacker deposits minimal amount (1 wei) to get 1 share\n\
             3. Attacker donates large amount directly to vault (e.g., 10 ETH transfer)\n\
             4. Share price becomes 10 ETH + 1 per share\n\
             5. Next depositor with < 10 ETH gets 0 shares (rounding down) — funds lost to attacker"
        )),

        VulnerabilityCategory::MulticallMsgValueReuse => Some(format!(
            "1. Attacker calls {contract_name} multicall/batch with msg.value = X\n\
             2. First sub-call in batch uses msg.value = X correctly\n\
             3. Subsequent sub-calls ALSO see msg.value = X (delegatecall preserves it)\n\
             4. Attacker effectively spends X once but gets N*X worth of operations\n\
             5. With 10 sub-calls and 1 ETH: attacker gets 10 ETH worth of value"
        )),

        VulnerabilityCategory::MulticallStateReset => Some(format!(
            "1. Attacker crafts a multicall batch targeting {contract_name}.{fn_name}()\n\
             2. First operation in batch triggers solvency/invariant check\n\
             3. Batch framework resets the check flag between operations\n\
             4. Subsequent operations bypass the solvency check\n\
             5. Attacker extracts funds that should have been blocked by invariant"
        )),

        VulnerabilityCategory::CLMMMathOverflow => Some(format!(
            "1. Attacker identifies bit-shift overflow in {contract_name} tick/sqrt math\n\
             2. Attacker crafts input values that trigger overflow in checked_shlw or similar\n\
             3. Overflow produces an astronomically large liquidity value\n\
             4. {fn_name}() mints or swaps based on the overflowed value\n\
             5. Attacker receives massive token amounts for minimal input"
        )),

        VulnerabilityCategory::InconsistentRounding => Some(format!(
            "1. Attacker identifies mulDown+divUp (or similar) rounding mismatch in {contract_name}\n\
             2. Attacker repeatedly exploits the rounding direction inconsistency\n\
             3. Each iteration skims a small amount from the protocol\n\
             4. Over many transactions, the accumulated rounding error drains significant funds\n\
             5. Attack may be combined with flash loans to amplify per-transaction profit"
        )),

        VulnerabilityCategory::UnvalidatedCrossChainReceiver => Some(format!(
            "1. Attacker identifies {contract_name} accepts cross-chain messages\n\
             2. {fn_name}() does not validate the source chain or sender address\n\
             3. Attacker sends forged message from unauthorized chain/contract\n\
             4. Receiver processes forged message as legitimate\n\
             5. Attacker triggers arbitrary state changes or fund transfers"
        )),

        VulnerabilityCategory::ArbitraryReceiverCallback => Some(format!(
            "1. Attacker calls {contract_name}.{fn_name}() with attacker-controlled receiver\n\
             2. Function invokes callback on receiver BEFORE updating protocol state\n\
             3. During callback, attacker re-enters or manipulates dependent state\n\
             4. When original function resumes, it operates on corrupted state\n\
             5. Attacker profits from the state inconsistency"
        )),

        VulnerabilityCategory::ERC2771MulticallSpoofing => Some(format!(
            "1. Attacker identifies {contract_name} uses ERC2771Context with multicall\n\
             2. Attacker crafts multicall payload that appends fake msg.sender to calldata\n\
             3. _msgSender() in ERC2771Context reads the appended address as trusted sender\n\
             4. Attacker impersonates any address, including admin/owner\n\
             5. Attacker executes privileged operations as the spoofed sender"
        )),

        VulnerabilityCategory::DelegateCalls => Some(format!(
            "1. Attacker identifies delegatecall target in {contract_name}.{fn_name}()\n\
             2. Attacker deploys malicious implementation contract\n\
             3. Attacker manipulates the delegatecall target address\n\
             4. delegatecall executes malicious code in the context of {contract_name}\n\
             5. Attacker can selfdestruct, modify storage slots, or drain all funds"
        )),

        VulnerabilityCategory::SignatureVulnerabilities
        | VulnerabilityCategory::SignatureReplay => Some(format!(
            "1. Attacker captures or observes a valid signed message/transaction\n\
             2. Missing nonce/chainId/deadline allows replay on same or different chain\n\
             3. Attacker replays the signature against {contract_name}.{fn_name}()\n\
             4. Contract accepts the replayed signature as valid\n\
             5. Original signer's authorized action is duplicated without consent"
        )),

        VulnerabilityCategory::GovernanceAttack => Some(format!(
            "1. Attacker flash-borrows governance tokens\n\
             2. Attacker creates and votes on malicious proposal in same tx block\n\
             3. {contract_name} governance executes proposal via {fn_name}()\n\
             4. Malicious proposal drains treasury or changes critical parameters\n\
             5. Attacker returns flash loan — attack costs only gas fees"
        )),

        VulnerabilityCategory::UninitializedImplementation
        | VulnerabilityCategory::DoubleInitialization => Some(format!(
            "1. Attacker finds {contract_name} implementation is not initialized\n\
             2. Attacker calls initialize() directly on the implementation contract\n\
             3. Attacker becomes owner/admin of the implementation\n\
             4. Attacker uses admin powers to selfdestruct or modify logic\n\
             5. Proxy contract now delegates to corrupted/destroyed implementation"
        )),

        VulnerabilityCategory::FeeOnTransferAssumption => Some(format!(
            "1. Protocol assumes transferFrom(amount) delivers exactly `amount`\n\
             2. User deposits fee-on-transfer token into {contract_name}\n\
             3. {fn_name}() credits user with `amount` but only receives `amount - fee`\n\
             4. Protocol becomes under-collateralized over many deposits\n\
             5. Last withdrawers cannot withdraw — protocol is insolvent"
        )),

        VulnerabilityCategory::MissingSlippageProtection => Some(format!(
            "1. Attacker monitors mempool for {contract_name}.{fn_name}() calls\n\
             2. Function has no minOutput parameter — accepts any output amount\n\
             3. Attacker front-runs with large swap to move price unfavorably\n\
             4. Victim's transaction executes at much worse price\n\
             5. Attacker back-runs to capture the MEV profit (sandwich attack)"
        )),

        _ => None,
    }
}

/// Extract the function name closest to a given line number.
fn extract_nearby_function(content: &str, line_number: usize) -> Option<String> {
    let re = Regex::new(r"function\s+(\w+)\s*\(").ok()?;
    let lines: Vec<&str> = content.lines().collect();

    // Search backwards from the vulnerability line to find the enclosing function
    let start = line_number.saturating_sub(1);
    for i in (0..=start.min(lines.len().saturating_sub(1))).rev() {
        if let Some(caps) = re.captures(lines[i]) {
            return Some(caps[1].to_string());
        }
    }
    None
}

/// Extract the contract name from source.
fn extract_contract_name(content: &str) -> Option<String> {
    let re = Regex::new(r"contract\s+(\w+)").ok()?;
    re.captures(content).map(|caps| caps[1].to_string())
}

/// Enrich vulnerabilities with attack path narratives.
pub fn enrich_with_attack_paths(vulnerabilities: &mut [Vulnerability], content: &str) {
    for vuln in vulnerabilities.iter_mut() {
        if vuln.attack_path.is_none() {
            vuln.attack_path = generate_attack_path(vuln, content);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vulnerabilities::VulnerabilitySeverity;

    fn make_vuln(cat: VulnerabilityCategory, line: usize) -> Vulnerability {
        Vulnerability::new(
            VulnerabilitySeverity::High, cat,
            "Test".into(), "Test".into(), line, "code".into(), "Fix".into(),
        )
    }

    #[test]
    fn test_reentrancy_attack_path() {
        let content = "contract Vault {\n  function withdraw() external {\n    msg.sender.call{value: bal}(\"\");\n  }\n}";
        let mut vuln = make_vuln(VulnerabilityCategory::Reentrancy, 3);
        enrich_with_attack_paths(std::slice::from_mut(&mut vuln), content);
        assert!(vuln.attack_path.is_some());
        let path = vuln.attack_path.unwrap();
        assert!(path.contains("withdraw"), "Should reference actual function name");
        assert!(path.contains("Vault"), "Should reference contract name");
    }

    #[test]
    fn test_no_attack_path_for_gas() {
        let content = "contract C {\n  function foo() public {}\n}";
        let mut vuln = make_vuln(VulnerabilityCategory::GasOptimization, 2);
        enrich_with_attack_paths(std::slice::from_mut(&mut vuln), content);
        assert!(vuln.attack_path.is_none());
    }
}
