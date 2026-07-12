//! Attack Path Narrative Generator.
//!
//! Generates human-readable attack path descriptions for each vulnerability
//! category, using actual function names from the scanned code. Security
//! researchers need to understand *how* an exploit would work, not just
//! *that* it exists.

use crate::vulnerabilities::{Vulnerability, VulnerabilityCategory};
use once_cell::sync::Lazy;
use regex::Regex;

// Compiled once per process — enrichment runs for every finding in every file.
static NEARBY_FN_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"function\s+(\w+)\s*\(").unwrap());
static CONTRACT_NAME_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"contract\s+(\w+)").unwrap());

/// Generate an attack path narrative for a vulnerability.
fn generate_attack_path(vuln: &Vulnerability, content: &str) -> Option<String> {
    let fn_name =
        extract_nearby_function(content, vuln.line_number).unwrap_or("targetFunction".to_string());
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

        // === 2026 patterns (v0.9.0) ===
        VulnerabilityCategory::ERC4337PaymasterAbuse => Some(format!(
            "1. Attacker submits a UserOperation that targets {contract_name} as paymaster\n\
             2. validatePaymasterUserOp accepts userOp without nonce/replay/budget enforcement\n\
             3. Attacker re-broadcasts the same op via a different bundler (or replays signature)\n\
             4. Paymaster sponsors gas repeatedly until its EntryPoint deposit is drained\n\
             5. Bundler/attacker captures the sponsored gas as profit"
        )),
        VulnerabilityCategory::EIP1271SignatureReplay => Some(format!(
            "1. Smart-wallet {contract_name}.isValidSignature returns MAGICVALUE on stored sig\n\
             2. Attacker observes a previously authorized off-chain signature\n\
             3. Attacker submits the signature to a different protocol that calls isValidSignature\n\
             4. Wallet returns valid because there is no per-hash consumed flag\n\
             5. Attacker triggers the signed action twice (or on the wrong domain)"
        )),
        VulnerabilityCategory::Permit2UnlimitedApproval => Some(format!(
            "1. User signs a Permit2 approval with type(uint).max amount and no expiration\n\
             2. Spender contract is later compromised or upgraded with malicious logic\n\
             3. Attacker calls transferFrom via Permit2 against the user's wallet\n\
             4. Permit2 honors the unlimited allowance — no per-call signature needed\n\
             5. Attacker drains the user's full balance of the approved token"
        )),
        VulnerabilityCategory::LRTRehypothecation => Some(format!(
            "1. User deposits collateral into {contract_name} restaking vault\n\
             2. Vault delegates the same collateral to multiple AVS operators in {fn_name}()\n\
             3. totalAssets is incremented per delegation but underlying collateral is unchanged\n\
             4. An AVS slashing event consumes more than the unique deposit amount\n\
             5. Withdrawal queue cannot be honored — late withdrawers absorb the loss"
        )),
        VulnerabilityCategory::StorageLayoutCollision => Some(format!(
            "1. Auditor approves V1 of {contract_name} (upgradeable)\n\
             2. Developer adds a new parent contract above existing parents in V2\n\
             3. Storage slot of `owner` (or balances) shifts by N slots\n\
             4. Proxy upgrade goes through — old `owner` slot now points to attacker-controlled data\n\
             5. Attacker calls onlyOwner-protected function and takes control"
        )),
        VulnerabilityCategory::GovernanceFlashloanVoting => Some(format!(
            "1. Attacker flash-borrows large amount of governance token\n\
             2. Attacker calls {contract_name}.{fn_name}() — vote weight comes from live balanceOf\n\
             3. Vote is recorded with the borrowed weight\n\
             4. Attacker repays the flash loan in the same transaction\n\
             5. Proposal passes (or fails) on rented voting power; treasury is drained or paused"
        )),
        VulnerabilityCategory::SandwichResistantMissing => Some(format!(
            "1. Attacker watches mempool for {contract_name}.{fn_name}() (rebalance/harvest)\n\
             2. Attacker front-runs with a swap that skews the AMM pool price\n\
             3. {fn_name}() executes at the manipulated price — buys high or sells low\n\
             4. Attacker back-runs with the inverse trade\n\
             5. Searcher pockets the spread; LPs / vault depositors absorb the loss"
        )),
        VulnerabilityCategory::LayerZeroSingleDVN => Some(format!(
            "1. {contract_name} configures a single required DVN to verify inbound messages\n\
             2. Attacker DDoSes / isolates that DVN's RPC nodes so honest verification stalls\n\
             3. Attacker feeds the isolated verifier a forged cross-chain message\n\
             4. The single DVN attests the forged message as valid\n\
             5. {contract_name} releases/mints funds to the attacker (Kelp DAO, $293M, 2026-04)"
        )),
        VulnerabilityCategory::EIP7702DelegateStorageCollision => Some(format!(
            "1. User's EOA delegates (EIP-7702) to {contract_name}, which uses raw slot-0 storage\n\
             2. User later re-delegates the same EOA to a second implementation with a different layout\n\
             3. The new code reinterprets slot 0 — what was `owner` is now e.g. a `nonce`\n\
             4. Guard/owner checks read attacker-favorable garbage or are silently bypassed\n\
             5. Attacker drives {fn_name}() or a privileged path to seize or brick the account"
        )),
        VulnerabilityCategory::ERC7683UnvalidatedFill => Some(format!(
            "1. Attacker crafts malicious `originData` for {contract_name}.{fn_name}()\n\
             2. fill() abi.decodes originData without binding it to a verified orderId\n\
             3. No filler allowlist / replay guard rejects the call\n\
             4. Settler releases escrowed output tokens against the forged order\n\
             5. Attacker double-fills or drains the destination settler's balance"
        )),
        VulnerabilityCategory::ERC6909FlashAccountingDrain => Some(format!(
            "1. Attacker enters the V4 unlock callback and calls {contract_name}.{fn_name}()\n\
             2. Hook's ERC-6909 claim accounting diverges from raw ERC-20 balances\n\
             3. Attacker syncs, claims on behalf of the PoolManager, and settles the delta\n\
             4. poolManager.take() sends real tokens to the attacker-controlled recipient\n\
             5. The transient delta nets to zero on paper while the pool's currency is gone"
        )),
        VulnerabilityCategory::TransientStorageCompilerBug => Some(format!(
            "1. {contract_name} compiles with solc 0.8.28-0.8.33 via the IR pipeline\n\
             2. It clears a persistent and a transient variable of the same type\n\
             3. The shared Yul clearing helper collides; one emits the wrong opcode (sstore<->tstore)\n\
             4. A transient reentrancy lock persists, or persistent state is silently zeroed\n\
             5. Attacker exploits the corrupted guard/state that the developer believed was cleared"
        )),

        _ => None,
    }
}

/// Extract the function name closest to a given line number.
fn extract_nearby_function(content: &str, line_number: usize) -> Option<String> {
    let re = &*NEARBY_FN_RE;
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
    CONTRACT_NAME_RE
        .captures(content)
        .map(|caps| caps[1].to_string())
}

/// Enrich vulnerabilities with attack path narratives.
pub fn enrich_with_attack_paths(vulnerabilities: &mut [Vulnerability], content: &str) {
    for vuln in vulnerabilities.iter_mut() {
        if vuln.attack_path.is_none() {
            vuln.attack_path = generate_attack_path(vuln, content);
        }
    }
}
