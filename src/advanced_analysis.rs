//! Advanced analysis module for the 41Swara smart contract security scanner.
//!
//! This module provides deep, domain-specific vulnerability detection beyond
//! basic pattern matching. It covers:
//!
//! - **Control flow analysis**: Reentrancy, flash loan vectors, sandwich attacks
//! - **Complexity metrics**: Cyclomatic complexity per function
//! - **Access control auditing**: Unprotected critical functions
//! - **Storage layout checks**: Upgradeable contract pitfalls
//! - **Gas optimization**: Storage reads in loops, batching opportunities
//! - **DeFi-specific**: Oracle manipulation, slippage, liquidity, yield farming
//! - **NFT-specific**: Minting caps, unsafe transfers, metadata mutability, royalties
//! - **Known exploit patterns**: DAO, Parity, integer overflow, unchecked calls
//! - **REKT.news patterns**: Aevo proxy, Omni callback, signature replay, MEV, precision
//! - **OWASP 2025 Top 10**: Flash loan callbacks, logic errors, meta-transactions,
//!   unchecked math, governance attacks, bridge vulnerabilities
//! - **Phase 6 (2025)**: ERC4626 inflation, read-only reentrancy, Permit2, LayerZero,
//!   EIP-4337, transient storage, CREATE2 collision, Merkle tree exploits
//! - **L2/Base chain**: Sequencer downtime, gas oracle, PUSH0, Uniswap V4 hooks,
//!   Chainlink CCIP, EigenLayer restaking
//! - **Research paper vulns**: ERC-777 reentrancy, greedy contracts, double claiming,
//!   emergency stops, signature verification bypass


use crate::vulnerabilities::{Vulnerability, VulnerabilityCategory, VulnerabilitySeverity};
use once_cell::sync::Lazy;
use regex::Regex;
use std::collections::{HashMap, HashSet};

/// Per-call-site regex cache. Each macro expansion creates its own `static Lazy<Regex>`,
/// so the pattern is compiled exactly once for the lifetime of the process — even when
/// the surrounding function runs once per scanned file in a 1,000-file sweep.
///
/// Use only with `'static` string literals. For dynamic patterns (e.g. `format!`-built),
/// fall back to `Regex::new(...)` directly.
macro_rules! re {
    ($pat:expr) => {{
        static RE: Lazy<Regex> = Lazy::new(|| Regex::new($pat).unwrap());
        &*RE
    }};
}

/// The primary advanced analyzer that runs multi-category vulnerability detection
/// on Solidity smart contract source code.
///
/// Each public `analyze_*` method returns a `Vec<Vulnerability>` that the scanner
/// merges into the final report. The analyzer is stateless; all analysis is performed
/// per-invocation on the raw source text.
pub struct AdvancedAnalyzer;


/// Expand the `uint`/`int` aliases to their explicit 256-bit widths so callers can
/// parse a width off the type name without special-casing the bare form.
fn normalize_int_type(ty: &str) -> String {
    match ty {
        "uint" => "uint256".to_string(),
        "int" => "int256".to_string(),
        other => other.to_string(),
    }
}

#[derive(Debug, Clone)]
struct ExtractedFunction {
    name: String,
    start_line: usize,
    signature: String,
    body: String,
}

impl AdvancedAnalyzer {
    /// Create a new `AdvancedAnalyzer`.
    pub fn new() -> Self {
        Self
    }

    fn strip_comment_lines(&self, content: &str) -> String {
        // Delegates to the shared, string-aware stripper (see parser::strip_comments).
        crate::parser::strip_comments(content)
    }

    // ========================================================================
    // CONTROL FLOW ANALYSIS
    // Detects reentrancy, flash loan vectors, and sandwich attack surfaces
    // by inspecting statement ordering and external call patterns.
    // ========================================================================

    /// Analyze control flow patterns for complex vulnerabilities.
    ///
    /// Checks for:
    /// - State changes after external calls (reentrancy)
    /// - Flash loan attack vectors (manipulable price sources)
    /// - MEV / sandwich attack surfaces (swaps without slippage protection)
    pub fn analyze_control_flow(&self, content: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        // Check for reentrancy patterns with state changes after external calls
        vulnerabilities.extend(self.detect_reentrancy_pattern(content));

        // Check for flash loan attack vectors
        if let Some(vuln) = self.detect_flash_loan_vulnerability(content) {
            vulnerabilities.push(vuln);
        }

        // Check for sandwich attack vulnerabilities
        if let Some(vuln) = self.detect_sandwich_attack_vector(content) {
            vulnerabilities.push(vuln);
        }

        vulnerabilities
    }

    // Checks-Effects-Interactions analysis, scoped per function.
    //
    // For every function without a reentrancy guard, finds control-transferring
    // external calls and reports writes to *contract state variables* that happen
    // after them. Two things matter for accuracy:
    //
    // 1. The call surface must include gas-forwarding helpers, not just `.call{}`.
    //    OpenZeppelin's `Address.sendValue` forwards all remaining gas, so it is
    //    exactly as reentrant as a raw `.call{value:}` -- missing it hides the
    //    canonical "refund before zeroing the slot" bug. `.transfer()`/`.send()`
    //    stay excluded: their 2300 gas stipend cannot re-enter.
    // 2. The guard check is per-function. A contract where *one* function is
    //    `nonReentrant` says nothing about its other functions, so a file-wide
    //    `contains("nonReentrant")` bail-out silently disables the whole detector.
    fn detect_reentrancy_pattern(&self, content: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();
        let state_vars = self.extract_state_variable_names(content);
        if state_vars.is_empty() {
            return vulnerabilities;
        }

        // Calls that hand control to an untrusted callee with enough gas to re-enter.
        // `.transfer(`/`.send(` are deliberately absent (2300 gas stipend).
        let external_call = re!(
            r"\.call\{|\.call\s*\.\s*value\s*\(|\bsendValue\s*\(|\bfunctionCallWithValue\s*\(|\bfunctionCall\s*\(|\.delegatecall\s*\("
        );
        let guard = re!(r"\bnonReentrant\b|\bnoReentrancy\b|\block\b\s*\(");

        for func in self.extract_functions(content) {
            // Guards and read-only functions cannot be exploited this way.
            if guard.is_match(&func.signature) {
                continue;
            }
            if re!(r"\b(view|pure)\b").is_match(&func.signature) {
                continue;
            }

            let body_lines: Vec<&str> = func.body.lines().collect();
            let mut call_idx: Option<usize> = None;
            // Variables already written *before* the call. A variable that is written
            // on both sides of the call is a set/reset guard -- OpenZeppelin's
            // `AccessManager.execute` saves `_executionId`, sets it, calls, then
            // restores it -- not a checks-effects-interactions violation.
            let mut written_before: HashSet<String> = HashSet::new();

            for (i, raw) in body_lines.iter().enumerate() {
                let line = raw.trim();
                if line.starts_with("//") || line.starts_with("*") || line.starts_with("/*") {
                    continue;
                }

                if call_idx.is_none() {
                    // try/catch bounds the callee's effect on our control flow far less
                    // than it looks, but it is a deliberate pattern -- keep skipping it.
                    if external_call.is_match(line) && !line.contains("try ") {
                        call_idx = Some(i);
                    } else if let Some(var) = self.state_write_target(line, &state_vars) {
                        written_before.insert(var);
                    }
                    continue;
                }

                let Some(ci) = call_idx else { continue };
                if let Some(var) = self.state_write_target(line, &state_vars) {
                    if written_before.contains(&var) {
                        continue;
                    }
                    let call_line = func.start_line + ci;
                    let write_line = func.start_line + i;
                    vulnerabilities.push(Vulnerability::high_confidence(
                        VulnerabilitySeverity::Critical,
                        VulnerabilityCategory::Reentrancy,
                        format!("State Change After External Call in {}", func.name),
                        format!(
                            "`{}` performs an external call on line {} and only then writes to the \
                             state variable `{}` on line {}. The callee regains control before that \
                             write lands, so it can re-enter `{}` while the stale state still passes \
                             every check -- the classic drain pattern.",
                            func.name, call_line, var, write_line, func.name
                        ),
                        call_line,
                        body_lines[ci].trim().to_string(),
                        format!(
                            "Apply checks-effects-interactions: move the `{}` write above the \
                             external call, or add a `nonReentrant` guard to `{}`.",
                            var, func.name
                        ),
                    ));
                    break; // one finding per function
                }
            }
        }

        vulnerabilities
    }

    // Returns the state variable a line writes to, if any.
    //
    // Recognises plain assignment, compound assignment, `delete`, `push`/`pop`, and
    // `++`/`--`. Comparisons (`==`, `!=`, `>=`, `<=`) and writes to locals are ignored,
    // which is what keeps this from firing on every `require(...)` after a call.
    fn state_write_target(&self, line: &str, state_vars: &HashSet<String>) -> Option<String> {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed == "}" || trimmed.starts_with("return") {
            return None;
        }
        // A local declaration shadows nothing we care about: `uint256 x = ...`.
        if re!(r"^\s*(?:uint\d*|int\d*|address|bool|bytes\d*|string|mapping)\b[^=]*\s+(?:memory|calldata|storage)?\s*\w+\s*=").is_match(trimmed) {
            return None;
        }

        let assign = re!(r"^([A-Za-z_]\w*)\s*(?:\[[^\]]*\]|\.\w+)*\s*(?:\+|-|\*|/|\|| &|\^)?=[^=]");
        let delete_re = re!(r"^delete\s+([A-Za-z_]\w*)");
        let push_pop = re!(r"^([A-Za-z_]\w*)\s*(?:\[[^\]]*\])*\s*\.\s*(?:push|pop)\s*\(");
        let incdec = re!(r"^([A-Za-z_]\w*)\s*(?:\[[^\]]*\]|\.\w+)*\s*(?:\+\+|--)");

        for re_candidate in [&assign, &delete_re, &push_pop, &incdec] {
            if let Some(caps) = re_candidate.captures(trimmed) {
                let name = caps.get(1)?.as_str();
                if state_vars.contains(name) {
                    return Some(name.to_string());
                }
            }
        }
        None
    }

    /// Unchecked arithmetic on contract state, for Solidity < 0.8.0.
    ///
    /// Only called when the pragma resolves to a pre-0.8 compiler, where `+`, `-`,
    /// and `*` wrap silently. The regex rules this complements only match local
    /// *declarations* (`uint256 x = a + b;`), which is the low-risk case -- a local
    /// that overflows usually just reverts downstream. The damaging pattern is an
    /// accumulator held in storage (`totalFees = totalFees + fee;`): it wraps, and
    /// the wrapped value persists.
    ///
    /// Narrow accumulators (`uint8` .. `uint64`) are escalated, because the value
    /// needed to wrap them is reachable in practice -- `uint64` tops out around
    /// 18.4 ETH when the variable holds wei.
    pub fn detect_legacy_unchecked_arithmetic(&self, content: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();
        let types = self.extract_state_variable_types(content);
        if types.is_empty() {
            return vulnerabilities;
        }

        // `using SafeMath for uint256` alone proves nothing -- what matters is whether
        // *this* statement routes through it, so the check is per line below.
        let safemath_call = re!(r"\.\s*(?:add|sub|mul|div)\s*\(");
        let compound = re!(r"^([A-Za-z_]\w*)\s*(?:\[[^\]]*\])?\s*(\+=|-=|\*=)");
        let assign = re!(r"^([A-Za-z_]\w*)\s*(?:\[[^\]]*\])?\s*=\s*(.+)$");
        let arith = re!(r"[^=!<>+*/-]\s*[+*-]\s*[^=]|\bSafeCast\b");

        for func in self.extract_functions(content) {
            if re!(r"\b(view|pure)\b").is_match(&func.signature) {
                continue;
            }

            for (i, raw) in func.body.lines().enumerate() {
                let line = raw.trim();
                if line.starts_with("//") || line.starts_with("*") || safemath_call.is_match(line) {
                    continue;
                }
                if line.contains("unchecked") {
                    continue;
                }

                let (var, op_desc) = if let Some(caps) = compound.captures(line) {
                    (
                        caps.get(1).map_or("", |m| m.as_str()).to_string(),
                        caps.get(2).map_or("", |m| m.as_str()).to_string(),
                    )
                } else if let Some(caps) = assign.captures(line) {
                    let name = caps.get(1).map_or("", |m| m.as_str()).to_string();
                    let rhs = caps.get(2).map_or("", |m| m.as_str());
                    // Only self-referencing arithmetic: `x = x + y` accumulates, while
                    // `x = someQuote()` just overwrites and cannot wrap.
                    if !rhs.contains(&name) || !arith.is_match(rhs) {
                        continue;
                    }
                    (name, "=".to_string())
                } else {
                    continue;
                };

                let Some(ty) = types.get(&var) else { continue };
                if !ty.starts_with("uint") && !ty.starts_with("int") {
                    continue;
                }

                let width: u32 = ty
                    .trim_start_matches("uint")
                    .trim_start_matches("int")
                    .parse()
                    .unwrap_or(256);
                let narrow = width < 128;
                let severity = if narrow {
                    VulnerabilitySeverity::High
                } else {
                    VulnerabilitySeverity::Medium
                };

                let mut description = format!(
                    "`{}` updates the `{}` state variable `{}` with `{}` under a pre-0.8.0 \
                     compiler, which wraps silently instead of reverting.",
                    func.name, ty, var, op_desc
                );
                if narrow {
                    description.push_str(&format!(
                        " `{}` is a narrow accumulator: it wraps at {} and the wrapped value is \
                         then written to storage permanently, so accumulated funds or counts are lost.",
                        ty,
                        if width == 64 {
                            "~18.4e18 (18.4 ETH in wei)".to_string()
                        } else {
                            format!("2^{}", width)
                        }
                    ));
                }

                vulnerabilities.push(Vulnerability::high_confidence(
                    severity,
                    VulnerabilityCategory::ArithmeticIssues,
                    format!("Unchecked Arithmetic on State Variable `{}`", var),
                    description,
                    func.start_line + i,
                    line.to_string(),
                    format!(
                        "Upgrade to Solidity 0.8.x for checked arithmetic, or route the update \
                         through SafeMath (`{}.add(...)`). Widening `{}` to `uint256` removes the \
                         narrow-accumulator risk.",
                        var, var
                    ),
                ));
            }
        }

        vulnerabilities
    }

    /// Map contract-level state variable names to their declared elementary type.
    ///
    /// Mapping value types are unwrapped (`mapping(address => uint64) x` yields
    /// `uint64` for `x`) so accumulator-width checks work on mappings too.
    fn extract_state_variable_types(&self, content: &str) -> HashMap<String, String> {
        let mut types = HashMap::new();
        let mapping_re = re!(
            r"^\s*mapping\s*\(.*=>\s*([A-Za-z_]\w*)\s*\)\s*(?:(?:public|private|internal)\s+)*([A-Za-z_]\w*)\s*;"
        );
        let plain_re = re!(
            r"^\s*(uint\d*|int\d*|address|bool|bytes\d*|string)\s+(?:(?:public|private|internal|constant|immutable|override)\s+)*([A-Za-z_]\w*)\s*(?:=|;)"
        );
        let container_re = re!(r"^\s*(?:abstract\s+)?(?:contract|library|interface)\s+\w+");

        let mut depth: i32 = 0;
        let mut in_container = false;

        for line in content.lines() {
            if !in_container && container_re.is_match(line) {
                in_container = true;
            }
            if in_container && depth == 1 && !line.trim().starts_with("//") {
                if let Some(caps) = mapping_re.captures(line) {
                    types.insert(
                        caps[2].to_string(),
                        normalize_int_type(&caps[1]),
                    );
                } else if let Some(caps) = plain_re.captures(line) {
                    types.insert(caps[2].to_string(), normalize_int_type(&caps[1]));
                }
            }
            depth += line.matches('{').count() as i32;
            depth -= line.matches('}').count() as i32;
            if depth <= 0 {
                depth = 0;
                in_container = false;
            }
        }

        types
    }

    /// Push payments to an address the contract does not control.
    ///
    /// `(bool ok,) = recipient.call{value: x}(""); require(ok);` looks defensive, but
    /// when `recipient` is an arbitrary address the require hands that address a veto:
    /// a contract with no `receive`/`fallback`, or one that simply reverts, makes the
    /// whole transaction fail. If the call sits in a state-machine step -- paying out a
    /// winner, closing a round -- the protocol is stuck there permanently.
    ///
    /// Payments to `msg.sender` are excluded: the caller can only grief themselves.
    pub fn detect_push_payment_dos(&self, content: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();
        let value_call =
            re!(r"([A-Za-z_]\w*)\s*\.\s*call\{\s*value\s*:[^}]*\}|\bsendValue\s*\(\s*([A-Za-z_]\w*)");
        let success_require = re!(r"require\s*\(\s*\w*(?i:success|sent|ok)\w*|if\s*\(\s*!\s*\w*(?i:success|sent|ok)");
        let safe_mint = re!(r"\b_safeMint\s*\(|\bsafeTransferFrom\s*\(");

        for func in self.extract_functions(content) {
            if re!(r"\b(view|pure)\b").is_match(&func.signature) {
                continue;
            }

            let body_lines: Vec<&str> = func.body.lines().collect();
            for (i, raw) in body_lines.iter().enumerate() {
                let line = raw.trim();
                if line.starts_with("//") || line.starts_with("*") {
                    continue;
                }
                let Some(caps) = value_call.captures(line) else {
                    continue;
                };
                let recipient = caps
                    .get(1)
                    .or_else(|| caps.get(2))
                    .map_or("", |m| m.as_str())
                    .to_string();

                // Self-payment can only block the caller's own transaction.
                if recipient.contains("msg") || recipient == "sender" || recipient.is_empty() {
                    continue;
                }
                // Withdrawal-style functions ARE the pull pattern already.
                let fname = func.name.to_lowercase();
                if fname.contains("withdraw") || fname.contains("claim") || fname.contains("redeem")
                {
                    continue;
                }

                // The revert-on-failure has to be present for the recipient to hold a veto.
                let window_end = (i + 4).min(body_lines.len());
                let window = body_lines[i..window_end].join(" ");
                let reverts_on_failure = success_require.is_match(&window);
                let mints_after = body_lines[i..].iter().any(|l| safe_mint.is_match(l));

                if !reverts_on_failure && !mints_after {
                    continue;
                }

                let mut description = format!(
                    "`{}` pushes ETH to `{}` and reverts if the transfer fails. `{}` is not the \
                     caller, so whoever controls that address decides whether this function can \
                     ever succeed: a contract without a payable `receive`/`fallback`, or one that \
                     reverts on purpose, blocks it for everyone.",
                    func.name, recipient, recipient
                );
                if mints_after {
                    description.push_str(
                        " The function also calls `_safeMint`/`safeTransferFrom` afterwards, which \
                         invokes a receiver hook on the same address -- a second veto over the \
                         same transaction.",
                    );
                }

                vulnerabilities.push(Vulnerability::high_confidence(
                    VulnerabilitySeverity::Medium,
                    VulnerabilityCategory::DoSAttacks,
                    format!("Push Payment to Arbitrary Recipient in {}", func.name),
                    description,
                    func.start_line + i,
                    line.to_string(),
                    "Use the pull-payment pattern: record the amount owed \
                     (`pendingWithdrawals[recipient] += amount`) and let the recipient claim it in \
                     a separate transaction, so one uncooperative address cannot stall the protocol."
                        .to_string(),
                ));
                break;
            }
        }

        vulnerabilities
    }

    /// Address state variables assigned from a parameter with no zero-address check.
    ///
    /// Covers constructors as well as setters. `address(0)` is the default value of
    /// every unset address, so assigning one silently is indistinguishable from never
    /// having configured the variable -- fees routed to `address(0)` are burned, and an
    /// owner set to `address(0)` locks the contract out of its own admin functions.
    pub fn detect_missing_zero_address_check(&self, content: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();
        let types = self.extract_state_variable_types(content);
        if types.is_empty() {
            return vulnerabilities;
        }

        let param_re = re!(r"address\s+(?:payable\s+)?(?:memory\s+|calldata\s+)?([A-Za-z_]\w*)");
        let assign_re = re!(r"^([A-Za-z_]\w*)\s*=\s*([A-Za-z_]\w*)\s*;");

        for func in self.extract_functions_with_constructors(content) {
            if re!(r"\b(view|pure)\b").is_match(&func.signature) {
                continue;
            }

            // Address-typed parameters of this function.
            let params: HashSet<String> = param_re
                .captures_iter(&func.signature)
                .filter_map(|c| c.get(1).map(|m| m.as_str().to_string()))
                .collect();
            if params.is_empty() {
                continue;
            }

            for (i, raw) in func.body.lines().enumerate() {
                let line = raw.trim();
                if line.starts_with("//") || line.starts_with("*") {
                    continue;
                }
                let Some(caps) = assign_re.captures(line) else {
                    continue;
                };
                let target = caps.get(1).map_or("", |m| m.as_str());
                let source = caps.get(2).map_or("", |m| m.as_str());

                if !params.contains(source) {
                    continue;
                }
                if types.get(target).map(String::as_str) != Some("address") {
                    continue;
                }

                // Any zero-check on this parameter anywhere in the function counts,
                // including OpenZeppelin-style custom errors.
                // Built per-parameter, so it cannot use the cached `re!` macro.
                let escaped = regex::escape(source);
                let Ok(guard) = Regex::new(&format!(
                    r"(?:require|assert|if)\s*\([^)]*\b{0}\b[^)]*address\s*\(\s*0\s*\)|\b{0}\b\s*!=\s*address\s*\(\s*0\s*\)|address\s*\(\s*0\s*\)\s*!=\s*\b{0}\b",
                    escaped
                )) else {
                    continue;
                };
                if guard.is_match(&func.body) {
                    continue;
                }

                vulnerabilities.push(Vulnerability::new(
                    VulnerabilitySeverity::Low,
                    VulnerabilityCategory::InputValidationFailure,
                    format!("Missing Zero-Address Check on `{}`", target),
                    format!(
                        "`{}` assigns the parameter `{}` to the address state variable `{}` without \
                         checking it against `address(0)`. Passing zero -- by mistake or from an \
                         uninitialised caller-side variable -- is accepted silently, and value sent \
                         to `{}` afterwards is unrecoverable.",
                        func.name, source, target, target
                    ),
                    func.start_line + i,
                    line.to_string(),
                    format!(
                        "Validate before assigning: `require({} != address(0), \"zero address\");`",
                        source
                    ),
                ));
            }
        }

        vulnerabilities
    }

    /// Lookup functions that return `0` to mean "not found".
    ///
    /// Index 0 is a perfectly valid position in an array, so a caller cannot tell
    /// "found at index 0" from "absent". Anyone at index 0 who trusts the return value
    /// -- to request a refund, claim a slot, or index into the array -- acts on the
    /// wrong entry, and callers that treat 0 as "absent" lock that position out.
    pub fn detect_ambiguous_sentinel_index(&self, content: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();
        let loop_re = re!(r"\bfor\s*\(");
        let return_var = re!(r"^return\s+([A-Za-z_]\w*)\s*;");
        let return_zero = re!(r"^return\s+0\s*;");

        for func in self.extract_functions(content) {
            // Only index lookups: an unsigned return with no explicit "found" flag.
            if !re!(r"returns\s*\(\s*uint\d*\s*\)").is_match(&func.signature) {
                continue;
            }

            let body_lines: Vec<&str> = func.body.lines().collect();
            let mut in_loop = false;
            let mut returns_index_in_loop = false;
            let mut trailing_zero_line: Option<usize> = None;

            for (i, raw) in body_lines.iter().enumerate() {
                let line = raw.trim();
                if loop_re.is_match(line) {
                    in_loop = true;
                }
                if in_loop && return_var.is_match(line) {
                    returns_index_in_loop = true;
                }
                if return_zero.is_match(line) {
                    trailing_zero_line = Some(i);
                }
            }

            let (true, Some(zero_line)) = (returns_index_in_loop, trailing_zero_line) else {
                continue;
            };

            vulnerabilities.push(Vulnerability::new(
                VulnerabilitySeverity::Low,
                VulnerabilityCategory::LogicError,
                format!("Ambiguous Sentinel Return in {}", func.name),
                format!(
                    "`{}` scans an array, returns the matching index, and falls through to \
                     `return 0` when nothing matches. Index 0 is itself a valid position, so the \
                     caller cannot distinguish \"found at index 0\" from \"not present\". The entry \
                     at index 0 is effectively unaddressable, and callers that treat 0 as \"absent\" \
                     will act on the wrong element.",
                    func.name
                ),
                func.start_line + zero_line,
                body_lines[zero_line].trim().to_string(),
                "Return an explicit found flag (`returns (uint256 index, bool found)`), revert when \
                 there is no match, or use a 1-based index where 0 is reserved for \"absent\"."
                    .to_string(),
            ));
        }

        vulnerabilities
    }

    /// Like [`Self::extract_functions`], plus constructors.
    ///
    /// `extract_functions` keys off the `function` keyword, so it never sees a
    /// `constructor(...)` -- which is exactly where addresses are first wired up.
    fn extract_functions_with_constructors(&self, content: &str) -> Vec<ExtractedFunction> {
        let mut functions = self.extract_functions(content);
        let ctor_re = re!(r"^\s*constructor\s*\(");
        let lines: Vec<&str> = content.lines().collect();

        let mut idx = 0;
        while idx < lines.len() {
            if !ctor_re.is_match(lines[idx]) {
                idx += 1;
                continue;
            }

            let mut signature = String::new();
            let mut body = String::new();
            let mut depth: i32 = 0;
            let mut saw_open = false;
            let mut end_idx = idx;

            for (scan_idx, line) in lines.iter().enumerate().skip(idx) {
                if !saw_open {
                    signature.push(' ');
                    signature.push_str(line.trim());
                }
                body.push_str(line);
                body.push('\n');
                depth += line.matches('{').count() as i32;
                if line.contains('{') {
                    saw_open = true;
                }
                depth -= line.matches('}').count() as i32;
                end_idx = scan_idx;
                if saw_open && depth <= 0 {
                    break;
                }
            }

            functions.push(ExtractedFunction {
                name: "constructor".to_string(),
                start_line: idx + 1,
                signature: signature.trim().to_string(),
                body,
            });
            idx = end_idx + 1;
        }

        functions
    }

    // Detect flash loan attack vulnerabilities by looking for contracts that
    // rely on manipulable spot price sources (getReserves, balanceOf(this))
    // in the presence of flash loan callbacks.
    fn detect_flash_loan_vulnerability(&self, content: &str) -> Option<Vulnerability> {
        let flash_loan_pattern = re!(r"flashLoan|executeOperation|onFlashLoan");
        let price_dependency = re!(r"getReserves|balanceOf\(address\(this\)\)");

        if flash_loan_pattern.is_match(content) || price_dependency.is_match(content) {
            for (idx, line) in content.lines().enumerate() {
                if price_dependency.is_match(line) {
                    return Some(Vulnerability::high_confidence(
                        VulnerabilitySeverity::Critical,
                        VulnerabilityCategory::OracleManipulation,
                        "Flash Loan Attack Vector Detected".to_string(),
                        "Contract relies on manipulable price sources vulnerable to flash loans"
                            .to_string(),
                        idx + 1,
                        line.to_string(),
                        "Use TWAP oracles or Chainlink price feeds instead of spot prices"
                            .to_string(),
                    ));
                }
            }
        }

        None
    }

    // Detect MEV/sandwich attack vulnerabilities by identifying swap functions
    // that lack slippage protection parameters (amountOutMin, slippage, etc.).
    fn detect_sandwich_attack_vector(&self, content: &str) -> Option<Vulnerability> {
        let swap_pattern = re!(r"function\s+swap|swapExact|swapTokens");
        let slippage_pattern = re!(r"amountOutMin|slippage");

        if swap_pattern.is_match(content) && !slippage_pattern.is_match(content) {
            for (idx, line) in content.lines().enumerate() {
                if swap_pattern.is_match(line) {
                    return Some(Vulnerability::new(
                        VulnerabilitySeverity::High,
                        VulnerabilityCategory::FrontRunning,
                        "MEV/Sandwich Attack Vulnerability".to_string(),
                        "Swap function without slippage protection is vulnerable to sandwich attacks".to_string(),
                        idx + 1,
                        line.to_string(),
                        "Implement slippage protection and consider using commit-reveal pattern".to_string(),
                    ));
                }
            }
        }

        None
    }

    // ========================================================================
    // COMPLEXITY ANALYSIS
    // Computes a simplified cyclomatic complexity for each function and flags
    // those exceeding a threshold of 10.
    // ========================================================================

    /// Compute cyclomatic complexity for every function in the contract.
    ///
    /// Complexity is incremented for `if`, `for`, `while`, `&&`, and `||`.
    /// Functions with complexity > 10 are reported as low-severity issues.
    pub fn analyze_complexity(&self, content: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();
        let function_pattern = re!(r"function\s+(\w+)\s*\([^)]*\)[^{]*\{");

        let mut in_function = false;
        let mut function_name = String::new();
        let mut function_start = 0;
        let mut brace_count = 0;
        let mut complexity = 0;

        for (idx, line) in content.lines().enumerate() {
            if let Some(captures) = function_pattern.captures(line) {
                in_function = true;
                function_name = captures.get(1).map_or("", |m| m.as_str()).to_string();
                function_start = idx + 1;
                brace_count = 1;
                complexity = 1; // Base complexity
            }

            if in_function {
                // Count control flow statements
                if line.contains("if ") || line.contains("if(") {
                    complexity += 1;
                }
                if line.contains("for ") || line.contains("for(") {
                    complexity += 1;
                }
                if line.contains("while ") || line.contains("while(") {
                    complexity += 1;
                }
                if line.contains(" && ") || line.contains(" || ") {
                    complexity += 1;
                }

                // Track braces
                for ch in line.chars() {
                    if ch == '{' {
                        brace_count += 1;
                    } else if ch == '}' {
                        brace_count -= 1;
                        if brace_count == 0 {
                            in_function = false;

                            if complexity > 10 {
                                vulnerabilities.push(Vulnerability::new(
                                    VulnerabilitySeverity::Low,
                                    VulnerabilityCategory::ComplexityIssues,
                                    format!("High Complexity in {function_name}"),
                                    format!("Function has cyclomatic complexity of {complexity}"),
                                    function_start,
                                    format!("function {function_name}"),
                                    "Consider breaking down complex functions into smaller pieces"
                                        .to_string(),
                                ));
                            }
                        }
                    }
                }
            }
        }

        vulnerabilities
    }

    // ========================================================================
    // ACCESS CONTROL ANALYSIS
    // Identifies critical functions (withdraw, mint, burn, upgrade, etc.)
    // that are externally / publicly visible but lack access control modifiers.
    // ========================================================================

    /// Detect access control issues by cross-referencing defined modifiers
    /// against critical function signatures.
    ///
    /// Critical function names include: withdraw, transfer, mint, burn, pause,
    /// unpause, setOwner, changeOwner, upgrade, initialize, destroy.
    pub fn analyze_access_control(&self, content: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        // Find all modifiers
        let modifier_pattern = re!(r"modifier\s+(\w+)");
        let mut modifiers = HashSet::new();

        for captures in modifier_pattern.captures_iter(content) {
            if let Some(name) = captures.get(1) {
                modifiers.insert(name.as_str().to_string());
            }
        }

        // Find critical functions without modifiers
        let critical_functions = vec![
            "withdraw",
            "transfer",
            "mint",
            "burn",
            "pause",
            "unpause",
            "setOwner",
            "changeOwner",
            "upgrade",
            "initialize",
            "destroy",
        ];

        // Standard ERC-20/ERC-4626 functions that are SUPPOSED to be public and
        // operate on the caller's own tokens — these don't need access control.
        let is_erc20_or_erc4626 = content.contains("ERC20")
            || content.contains("ERC4626")
            || content.contains("IERC20")
            || content.contains("allowance")
            || (content.contains("balanceOf") && content.contains("totalSupply"));
        let erc_standard_functions = ["transfer",
            "transferfrom",
            "approve",
            "mint",
            "burn",
            "deposit",
            "withdraw",
            "redeem"];

        // Match the start of a function declaration (may span multiple lines)
        let function_start_pattern = re!(r"function\s+(\w+)\s*\(");

        let lines: Vec<&str> = content.lines().collect();
        for (idx, line) in lines.iter().enumerate() {
            if let Some(captures) = function_start_pattern.captures(line) {
                let function_name = captures.get(1).map_or("", |m| m.as_str());

                // Check if it's a critical function
                let is_critical = critical_functions
                    .iter()
                    .any(|cf| function_name.to_lowercase().contains(cf));
                if !is_critical {
                    continue;
                }

                // Skip standard ERC-20/ERC-4626 interface functions — these are
                // public by design and operate on the caller's own tokens.
                if is_erc20_or_erc4626 {
                    let fn_lower = function_name.to_lowercase();
                    if erc_standard_functions.iter().any(|ef| fn_lower == *ef) {
                        continue;
                    }
                }

                // Skip if function body uses msg.sender balance deduction or
                // safeTransferFrom from the caller (ERC-4626 deposit pattern)
                let fn_body: String = lines
                    .iter()
                    .skip(idx)
                    .take(20)
                    .copied()
                    .collect::<Vec<_>>()
                    .join("\n");
                if fn_body.contains("balanceOf[msg.sender]")
                    || fn_body.contains("balances[msg.sender]")
                    || fn_body.contains("safeTransferFrom(msg.sender")
                    || fn_body.contains("transferFrom(msg.sender")
                    // Token-standard self-service semantics: spending the caller's own
                    // allowance/approval is the access control (transferFrom pattern).
                    || fn_body.contains("_spendAllowance(")
                    || fn_body.contains("isApprovedForAll")
                    || fn_body.contains("_burn(msg.sender")
                    || fn_body.contains("_burn(_msgSender()")
                    // Caller acts on their own behalf: forwarding _msgSender()/msg.sender
                    // as the subject is self-service, not an admin operation.
                    || fn_body.contains("(_msgSender()")
                    || fn_body.contains("(msg.sender,")
                {
                    continue;
                }

                // Interface/abstract declarations end with `;` before any body opens —
                // nothing to protect (e.g. ITransparentUpgradeableProxy.upgradeToAndCall).
                let semi = fn_body.find(';');
                let brace = fn_body.find('{');
                if matches!((semi, brace), (Some(s), Some(b)) if s < b) || brace.is_none() {
                    continue;
                }

                // Thin overload wrappers forward to a same-name overload or an
                // underscore-prefixed variant that carries the real authorization
                // check (possibly beyond this 20-line window).
                let body_after_sig = fn_body.split_once('{').map_or("", |(_, b)| b);
                if body_after_sig.contains(&format!("{function_name}(")) {
                    continue;
                }

                // Read the full function signature (from `function` keyword to opening `{`)
                // This handles multi-line signatures with modifiers on separate lines
                let full_sig = {
                    let mut sig = String::new();
                    for &sig_line in lines.iter().skip(idx).take(10) {
                        sig.push_str(sig_line);
                        sig.push(' ');
                        if sig_line.contains('{') {
                            break;
                        }
                    }
                    sig
                };

                // Check if it has any custom modifier defined in this contract
                let has_modifier = modifiers.iter().any(|m| full_sig.contains(m.as_str()));

                // Check for well-known imported/inherited modifiers
                let has_known_modifier = full_sig.contains("nonReentrant")
                    || full_sig.contains("onlyOwner")
                    || full_sig.contains("onlyRole")
                    || full_sig.contains("onlyAdmin")
                    || full_sig.contains("whenNotPaused")
                    || full_sig.contains("initializer")
                    || full_sig.contains("restricted")
                    || re!(r"\bonly\w+").is_match(&full_sig);

                // Check visibility: skip private/internal functions
                let is_private_or_internal =
                    full_sig.contains("private") || full_sig.contains("internal");

                let fn_body: String = lines
                    .iter()
                    .skip(idx)
                    .take(20)
                    .copied()
                    .collect::<Vec<_>>()
                    .join("\n");

                // Check if the function body uses msg.sender balance (user withdrawal, not admin)
                let is_user_facing = fn_body.contains("msg.sender")
                    && (fn_body.contains("balances[") || fn_body.contains("balance["));

                // A tx.origin-based guard IS an (unsafe) authorization check — the
                // dedicated TxOriginAuth detector reports the real problem, so don't
                // double-report this as a missing-access-control finding.
                let has_tx_origin_guard = fn_body.contains("tx.origin");

                // An inline sender/role guard also counts as access control.
                let has_inline_guard = fn_body.contains("require(msg.sender ==")
                    || fn_body.contains("require(msg.sender==")
                    || fn_body.contains("_checkOwner()")
                    || fn_body.contains("_checkRole(");

                if !has_modifier
                    && !has_known_modifier
                    && !is_user_facing
                    && !is_private_or_internal
                    && !has_tx_origin_guard
                    && !has_inline_guard
                {
                    vulnerabilities.push(Vulnerability::high_confidence(
                        VulnerabilitySeverity::Critical,
                        VulnerabilityCategory::AccessControl,
                        format!("Unprotected Critical Function: {function_name}"),
                        "Critical function lacks access control modifiers".to_string(),
                        idx + 1,
                        line.to_string(),
                        "Add appropriate access control modifiers (onlyOwner, onlyRole, etc.)"
                            .to_string(),
                    ));
                }
            }
        }

        vulnerabilities
    }

    // ========================================================================
    // STORAGE LAYOUT ANALYSIS
    // Checks upgradeable contract patterns for common pitfalls such as
    // missing storage gaps and constructors in proxy implementations.
    // ========================================================================

    /// Detect storage layout issues in upgradeable contracts.
    ///
    /// Flags:
    /// - Missing `__gap` storage variable for future-proof slot reservation
    /// - Constructor usage in contracts that should use `initializer` functions
    pub fn analyze_storage_layout(&self, content: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        // REMOVED: loose "Missing Storage Gap" duplicate. It fired whenever the file
        // merely contained the word "Initializable"/"upgradeable" anywhere (imports,
        // comments) and reported at line 1 with a fabricated snippet.
        // detect_storage_collision_proxy() covers this with real contract-line checks.

        // Check for constructor usage in upgradeable contract patterns.
        // Require an actual (non-comment) contract declaration inheriting an
        // upgradeable/initializable base — merely mentioning "upgradeable" in prose or
        // imports is not enough. Proxies/beacons legitimately have constructors.
        let is_upgradeable_impl = content.lines().any(|l| {
            let t = l.trim_start();
            if t.starts_with("//") || t.starts_with('*') || t.starts_with("/*") {
                return false;
            }
            re!(r"contract\s+(\w+)\s+is\s+[^{]*(Upgradeable|Initializable)")
                .captures(l)
                .is_some_and(|c| {
                    let name = &c[1];
                    !name.ends_with("Proxy") && !name.ends_with("Beacon")
                })
        });
        if is_upgradeable_impl
            && (content.contains("constructor(") || content.contains("constructor ("))
                // A constructor that calls _disableInitializers() is the OZ-recommended
                // pattern for implementation contracts — not a defect.
                && !content.contains("_disableInitializers")
            {
                vulnerabilities.push(Vulnerability::high_confidence(
                    VulnerabilitySeverity::Critical,
                    VulnerabilityCategory::StateVariable,
                    "Constructor in Upgradeable Contract".to_string(),
                    "Upgradeable contracts should not use constructors".to_string(),
                    1,
                    "constructor()".to_string(),
                    "Use initializer functions instead of constructors in upgradeable contracts"
                        .to_string(),
                ));
            }

        vulnerabilities
    }

    // ========================================================================
    // GAS OPTIMIZATION ANALYSIS
    // Identifies patterns that waste gas: storage reads inside loops,
    // redundant storage writes, and short strings that could be bytes32.
    // ========================================================================

    /// Analyze gas optimization opportunities in the contract.
    ///
    /// Reports:
    /// - Storage reads inside `for` loops (should cache in memory)
    /// - Variables written more than twice (consider batching)
    /// - Short string literals that would be cheaper as `bytes32`
    pub fn analyze_gas_optimization(&self, content: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        // Check for storage vs memory usage in loops
        let loop_pattern = re!(r"for\s*\([^)]*\)");
        let storage_read_pattern = re!(r"storage\w+\[");

        let lines: Vec<&str> = content.lines().collect();

        for (idx, line) in lines.iter().enumerate() {
            if loop_pattern.is_match(line) {
                // Check next few lines for storage reads
                for (offset, check_line) in lines[(idx + 1)..lines.len().min(idx + 5)]
                    .iter()
                    .enumerate()
                {
                    if storage_read_pattern.is_match(check_line) {
                        vulnerabilities.push(Vulnerability::new(
                            VulnerabilitySeverity::Low,
                            VulnerabilityCategory::GasOptimization,
                            "Storage Read in Loop".to_string(),
                            "Reading from storage in loops is expensive".to_string(),
                            idx + 1 + offset + 1,
                            check_line.to_string(),
                            "Cache storage values in memory variables before loops".to_string(),
                        ));
                        break;
                    }
                }
            }
        }

        // Check for multiple storage writes that could be batched
        let storage_write_pattern = re!(r"(\w+)\s*=\s*");
        let mut storage_writes = HashMap::new();

        for line in content.lines() {
            if storage_write_pattern.is_match(line) {
                *storage_writes.entry(line).or_insert(0) += 1;
            }
        }

        for (line, count) in storage_writes {
            if count > 2 {
                vulnerabilities.push(Vulnerability::new(
                    VulnerabilitySeverity::Info,
                    VulnerabilityCategory::GasOptimization,
                    "Multiple Storage Writes".to_string(),
                    format!("Variable written {count} times - consider batching"),
                    1,
                    line.to_string(),
                    "Batch storage operations to save gas".to_string(),
                ));
            }
        }

        // Check for string/bytes that could be bytes32
        let string_pattern = re!(r#"string\s+(public\s+)?\w+\s*=\s*"[^"]{1,32}""#);

        for (idx, line) in content.lines().enumerate() {
            if string_pattern.is_match(line) {
                vulnerabilities.push(Vulnerability::new(
                    VulnerabilitySeverity::Info,
                    VulnerabilityCategory::GasOptimization,
                    "Short String Could Be bytes32".to_string(),
                    "Short strings are more efficient as bytes32".to_string(),
                    idx + 1,
                    line.to_string(),
                    "Consider using bytes32 for short fixed-length strings".to_string(),
                ));
            }
        }

        vulnerabilities
    }

    // ========================================================================
    // DEFI-SPECIFIC VULNERABILITY DETECTION
    // Targets DeFi protocol patterns: oracle manipulation, slippage, liquidity
    // pool edge cases, and yield farming reward precision issues.
    // ========================================================================

    /// Analyze DeFi-specific vulnerabilities.
    ///
    /// Runs sub-detectors for:
    /// - Price oracle manipulation (spot price without TWAP/Chainlink)
    /// - Missing slippage protection on swap functions
    /// - Liquidity removal without proper balance validation
    /// - Yield farming reward calculation precision loss
    pub fn analyze_defi_vulnerabilities(&self, content: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        // Detect price oracle manipulation vulnerabilities
        if let Some(vuln) = self.detect_price_oracle_manipulation(content) {
            vulnerabilities.push(vuln);
        }

        // Detect slippage issues
        vulnerabilities.extend(self.detect_slippage_issues(content));

        // Detect liquidity pool vulnerabilities
        vulnerabilities.extend(self.detect_liquidity_vulnerabilities(content));

        // Detect yield farming issues
        vulnerabilities.extend(self.detect_yield_farming_issues(content));

        vulnerabilities
    }

    // Check for on-chain price sources that are trivially manipulable via
    // flash loans (contract balance, spot reserves, token0 price). Only flags
    // when TWAP, Chainlink, and price validation are all absent.
    fn detect_price_oracle_manipulation(&self, content: &str) -> Option<Vulnerability> {
        let unsafe_price_sources = vec![
            (
                "balanceOf(address(this))",
                "Using contract balance as price source",
            ),
            (
                "token.balanceOf(address(this))",
                "Using token balance as price oracle",
            ),
            (".getReserves()", "Using spot reserves without TWAP"),
            (".token0()", "Spot price from pair without protection"),
        ];

        for (idx, line) in content.lines().enumerate() {
            for (pattern, desc) in &unsafe_price_sources {
                if line.contains(pattern)
                    && (line.contains("price") || line.contains("Price") || line.contains("amount"))
                {
                    // Check if there's TWAP or price validation
                    if !content.contains("TWAP")
                        && !content.contains("Chainlink")
                        && !content.contains("priceValidation")
                        && !content.contains("minPrice")
                    {
                        return Some(Vulnerability::high_confidence(
                            VulnerabilitySeverity::Critical,
                            VulnerabilityCategory::OracleManipulation,
                            "Price Oracle Manipulation Risk".to_string(),
                            format!("{desc} - vulnerable to flash loan attacks"),
                            idx + 1,
                            line.to_string(),
                            "Use Chainlink price feeds, TWAP oracles, or multiple oracle sources"
                                .to_string(),
                        ));
                    }
                }
            }
        }

        None
    }

    // Flag swap functions whose signature lacks slippage parameters
    // (minAmount, amountOutMin, slippage, minReturn).
    fn detect_slippage_issues(&self, content: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();
        let swap_pattern = re!(r"function\s+swap");

        for (idx, line) in content.lines().enumerate() {
            if swap_pattern.is_match(line) {
                // Check if function has slippage protection parameters
                if !line.contains("minAmount")
                    && !line.contains("amountOutMin")
                    && !line.contains("slippage")
                    && !line.contains("minReturn")
                {
                    vulnerabilities.push(Vulnerability::new(
                        VulnerabilitySeverity::High,
                        VulnerabilityCategory::FrontRunning,
                        "Missing Slippage Protection".to_string(),
                        "Swap function lacks slippage protection parameters".to_string(),
                        idx + 1,
                        line.to_string(),
                        "Add amountOutMin or similar slippage protection parameter".to_string(),
                    ));
                }
            }
        }

        vulnerabilities
    }

    // Check removeLiquidity functions for proper balance validation.
    // Generic withdraw() is excluded: Solidity 0.8+ has built-in underflow protection
    // and most withdraw patterns safely read balances[msg.sender] (reverts on underflow).
    fn detect_liquidity_vulnerabilities(&self, content: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        // Only flag explicit liquidity removal, not generic withdraw
        let remove_liquidity_pattern = re!(r"removeLiquidity");

        for (idx, line) in content.lines().enumerate() {
            if remove_liquidity_pattern.is_match(line) && line.contains("function") {
                // Look ahead for balance/amount checks
                let next_lines: Vec<&str> = content.lines().skip(idx).take(15).collect();
                let has_balance_check = next_lines.iter().any(|l| {
                    l.contains("require(amount")
                        || l.contains("require(balance")
                        || l.contains("if (amount")
                        || l.contains("if (balance")
                        || l.contains("balances[")
                        || l.contains("_balances[")
                        || l.contains("SafeERC20")
                        || l.contains("safeTransfer")
                });

                if !has_balance_check {
                    vulnerabilities.push(Vulnerability::new(
                        VulnerabilitySeverity::Medium,
                        VulnerabilityCategory::DoSAttacks,
                        "Insufficient Balance Validation".to_string(),
                        "Liquidity removal function may not properly validate balances".to_string(),
                        idx + 1,
                        line.to_string(),
                        "Add proper balance validation before liquidity operations".to_string(),
                    ));
                }
            }
        }

        vulnerabilities
    }

    // Detect reward calculation lines that divide without proper precision
    // scaling (1e18, PRECISION, MULTIPLIER). Only triggers when a division
    // appears in the reward calculation.
    fn detect_yield_farming_issues(&self, content: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        // Detect reward calculation issues
        if content.contains("reward") || content.contains("Reward") {
            let reward_calc_pattern = re!(r"reward\w*\s*=.*\*|reward\w*\s*=.*/");

            for (idx, line) in content.lines().enumerate() {
                if reward_calc_pattern.is_match(line) {
                    // Check for proper precision handling
                    if !content.contains("1e18")
                        && !content.contains("PRECISION")
                        && !content.contains("MULTIPLIER")
                        && line.contains("/")
                    {
                        vulnerabilities.push(Vulnerability::new(
                            VulnerabilitySeverity::Medium,
                            VulnerabilityCategory::PrecisionLoss,
                            "Reward Calculation Precision Loss".to_string(),
                            "Reward calculations may lose precision without proper scaling"
                                .to_string(),
                            idx + 1,
                            line.to_string(),
                            "Use proper precision constants (e.g., 1e18) for reward calculations"
                                .to_string(),
                        ));
                    }
                }
            }
        }

        vulnerabilities
    }

    // ========================================================================
    // NFT-SPECIFIC VULNERABILITY DETECTION
    // Covers ERC-721 and ERC-1155 contracts: minting caps, unsafe transfers,
    // metadata mutability, and EIP-2981 royalty validation.
    // ========================================================================

    /// Analyze NFT-specific vulnerabilities for ERC-721 and ERC-1155 contracts.
    ///
    /// Checks:
    /// - Mint without supply cap or duplicate token ID protection
    /// - `transferFrom` instead of `safeTransferFrom`
    /// - Mutable metadata after minting
    /// - Uncapped royalty percentages (EIP-2981)
    pub fn analyze_nft_vulnerabilities(&self, content: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        // Check if this is an NFT contract
        let is_nft = content.contains("ERC721") || content.contains("ERC1155");

        if is_nft {
            vulnerabilities.extend(self.detect_nft_minting_issues(content));
            vulnerabilities.extend(self.detect_nft_transfer_issues(content));
            vulnerabilities.extend(self.detect_nft_metadata_issues(content));
            vulnerabilities.extend(self.detect_nft_royalty_issues(content));
        }

        vulnerabilities
    }

    // Check mint functions for (a) a supply cap (maxSupply, MAX_SUPPLY, totalSupply<)
    // and (b) duplicate token ID protection (_exists check).
    fn detect_nft_minting_issues(&self, content: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();
        let mint_pattern = re!(r"function\s+mint");

        for (idx, line) in content.lines().enumerate() {
            if mint_pattern.is_match(line) {
                // Check for supply cap
                let has_supply_cap = content.contains("maxSupply")
                    || content.contains("MAX_SUPPLY")
                    || content.contains("totalSupply() <")
                    || content.contains("require(_tokenId");

                if !has_supply_cap {
                    vulnerabilities.push(Vulnerability::new(
                        VulnerabilitySeverity::Medium,
                        VulnerabilityCategory::AccessControl,
                        "NFT Unlimited Minting".to_string(),
                        "Mint function lacks supply cap, allowing unlimited minting".to_string(),
                        idx + 1,
                        line.to_string(),
                        "Implement maximum supply check to prevent unlimited minting".to_string(),
                    ));
                }

                // Check for duplicate token ID protection
                let has_exists_check = content.contains("_exists(")
                    || content.contains("ownerOf(tokenId)")
                    || content.contains("require(!_exists");

                if !has_exists_check {
                    vulnerabilities.push(Vulnerability::new(
                        VulnerabilitySeverity::High,
                        VulnerabilityCategory::AccessControl,
                        "NFT Duplicate Token ID Risk".to_string(),
                        "Mint function may not prevent duplicate token IDs".to_string(),
                        idx + 1,
                        line.to_string(),
                        "Add _exists() check before minting to prevent duplicates".to_string(),
                    ));
                }
            }
        }

        vulnerabilities
    }

    // Flag usage of transferFrom without safeTransferFrom, which risks sending
    // NFTs to contracts that cannot handle them (tokens become permanently locked).
    fn detect_nft_transfer_issues(&self, content: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        // Check for unsafe transfers
        if content.contains("transferFrom") && !content.contains("safeTransferFrom") {
            for (idx, line) in content.lines().enumerate() {
                if line.contains("transferFrom") && !line.contains("safeTransferFrom") {
                    vulnerabilities.push(Vulnerability::new(
                        VulnerabilitySeverity::Medium,
                        VulnerabilityCategory::UnsafeExternalCalls,
                        "Unsafe NFT Transfer".to_string(),
                        "Using transferFrom instead of safeTransferFrom can lead to locked NFTs"
                            .to_string(),
                        idx + 1,
                        line.to_string(),
                        "Use safeTransferFrom to ensure recipient can handle ERC721 tokens"
                            .to_string(),
                    ));
                }
            }
        }

        vulnerabilities
    }

    // Check whether the tokenURI function body contains mutable metadata patterns
    // (baseURI assignment, _tokenURIs mapping, setTokenURI) that could allow
    // metadata rug-pulls after minting.
    fn detect_nft_metadata_issues(&self, content: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        // Check for mutable metadata
        let token_uri_pattern = re!(r"function\s+tokenURI");

        for (idx, line) in content.lines().enumerate() {
            if token_uri_pattern.is_match(line) {
                // Check if metadata can be changed
                let next_lines: Vec<&str> = content.lines().skip(idx).take(10).collect();
                let has_mutable_metadata = next_lines.iter().any(|l| {
                    l.contains("baseURI =")
                        || l.contains("_tokenURIs[")
                        || l.contains("setTokenURI")
                });

                if has_mutable_metadata {
                    vulnerabilities.push(Vulnerability::new(
                        VulnerabilitySeverity::Medium,
                        VulnerabilityCategory::AccessControl,
                        "Mutable NFT Metadata".to_string(),
                        "Token metadata can be changed after minting".to_string(),
                        idx + 1,
                        line.to_string(),
                        "Consider making metadata immutable or clearly document mutability risks"
                            .to_string(),
                    ));
                }
            }
        }

        vulnerabilities
    }

    // Verify EIP-2981 royalty implementations cap the percentage at 100%
    // (10000 basis points). Scans 15 lines after royaltyInfo for a require()
    // containing a ceiling value.
    fn detect_nft_royalty_issues(&self, content: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        // Check EIP-2981 royalty implementation
        if content.contains("royaltyInfo") || content.contains("ERC2981") {
            // Check for proper royalty validation
            let royalty_pattern = re!(r"royalty|royaltyInfo");

            for (idx, line) in content.lines().enumerate() {
                if royalty_pattern.is_match(line) {
                    // Check for percentage validation (should not exceed 100%)
                    let next_lines: Vec<&str> = content.lines().skip(idx).take(15).collect();
                    let has_validation = next_lines.iter().any(|l| {
                        l.contains("require(")
                            && (l.contains("10000") || l.contains("100") || l.contains("<="))
                    });

                    if !has_validation {
                        vulnerabilities.push(Vulnerability::new(
                            VulnerabilitySeverity::Medium,
                            VulnerabilityCategory::AccessControl,
                            "Uncapped NFT Royalty".to_string(),
                            "Royalty percentage lacks upper bound validation".to_string(),
                            idx + 1,
                            line.to_string(),
                            "Add require() to cap royalty percentage at 100% (10000 basis points)"
                                .to_string(),
                        ));
                    }
                }
            }
        }

        vulnerabilities
    }

    // ========================================================================
    // KNOWN EXPLOIT PATTERN DETECTION
    // Matches structural patterns from historically significant attacks:
    // The DAO, Parity wallet, BEC token overflow, and unchecked calls.
    // ========================================================================

    /// Detect known exploit patterns from past high-profile attacks.
    ///
    /// Covers:
    /// - The DAO attack pattern (reentrancy in withdraw)
    /// - Parity wallet bug (delegatecall to user-controlled address)
    /// - Integer overflow in token transfers (pre-Solidity 0.8 without SafeMath)
    /// - Unchecked low-level call return values
    pub fn detect_known_exploits(&self, content: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        // DAO attack pattern (reentrancy in withdrawals)
        vulnerabilities.extend(self.detect_dao_attack_pattern(content));

        // Parity wallet bug pattern (delegatecall to user-controlled address)
        vulnerabilities.extend(self.detect_parity_bug_pattern(content));

        // Integer overflow in token transfers (pre-0.8.0)
        vulnerabilities.extend(self.detect_integer_overflow_token_pattern(content));

        // Unchecked external call pattern
        vulnerabilities.extend(self.detect_unchecked_call_pattern(content));

        vulnerabilities
    }

    // Classic DAO reentrancy: looks for withdraw functions where .call{value:}
    // appears before a balance state update, without nonReentrant guard.
    // Scans up to 25 lines of the function body.
    fn detect_dao_attack_pattern(&self, content: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        // Look for withdraw pattern with external call before state update
        let withdraw_pattern = re!(r"function\s+withdraw");

        for (idx, line) in content.lines().enumerate() {
            if withdraw_pattern.is_match(line) {
                let func_body: Vec<&str> = content.lines().skip(idx).take(25).collect();

                let mut has_call = false;
                let mut call_line = 0;
                let mut has_state_update_after = false;

                for (i, body_line) in func_body.iter().enumerate() {
                    if body_line.contains(".call{value:") || body_line.contains(".call.value") {
                        has_call = true;
                        call_line = i;
                    }
                    if has_call && i > call_line
                        && (body_line.contains("balance") && body_line.contains("=")
                            || body_line.contains("balances[") && body_line.contains("="))
                        {
                            has_state_update_after = true;
                            break;
                        }
                }

                if has_call && has_state_update_after && !content.contains("nonReentrant") {
                    vulnerabilities.push(Vulnerability::high_confidence(
                        VulnerabilitySeverity::Critical,
                        VulnerabilityCategory::Reentrancy,
                        "DAO Attack Pattern Detected".to_string(),
                        "Classic DAO attack pattern: external call before balance update in withdraw function".to_string(),
                        idx + 1,
                        line.to_string(),
                        "Update balance before external call and use ReentrancyGuard".to_string(),
                    ));
                }
            }
        }

        vulnerabilities
    }

    // Parity wallet bug: delegatecall targeting an address that may be
    // user-controlled (msg.sender, _target, target, implementation) without
    // an accompanying require() validation on the same line.
    fn detect_parity_bug_pattern(&self, content: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        // Proxy contracts (ERC-1967/beacon) and delegatecall utility libraries use
        // delegatecall-to-stored-implementation by design — that's the proxy pattern,
        // not the Parity wallet bug (which was an UNPROTECTED public library init).
        // The library exemption only applies to library-ONLY files: a helper library
        // bundled next to contracts must not disable analysis of those contracts.
        let library_only = re!(r"(?m)^\s*library\s+\w+").is_match(content)
            && !re!(r"(?m)^\s*(abstract\s+)?contract\s+\w+").is_match(content);
        if content.contains("_IMPLEMENTATION_SLOT")
            || content.contains("ERC1967")
            || content.contains("IBeacon")
            || library_only
            || re!(r"(?m)^\s*abstract\s+contract\s+\w*Proxy\b").is_match(content)
        {
            return vulnerabilities;
        }

        // Detect delegatecall with user-controlled address
        let delegatecall_pattern = re!(r"delegatecall");

        for (idx, line) in content.lines().enumerate() {
            if delegatecall_pattern.is_match(line) {
                // Check if address comes from function parameter or storage without validation
                if (line.contains("msg.sender")
                    || line.contains("_target")
                    || line.contains("target")
                    || line.contains("implementation"))
                    && !line.contains("require(")
                {
                    vulnerabilities.push(Vulnerability::high_confidence(
                        VulnerabilitySeverity::Critical,
                        VulnerabilityCategory::DelegateCalls,
                        "Parity Wallet Bug Pattern".to_string(),
                        "Delegatecall with potentially user-controlled address without validation"
                            .to_string(),
                        idx + 1,
                        line.to_string(),
                        "Whitelist allowed delegatecall targets and validate all addresses"
                            .to_string(),
                    ));
                }
            }
        }

        vulnerabilities
    }

    // Integer overflow in pre-0.8.0 token contracts: flags balance arithmetic
    // (+=, -=, +, -) on balances[]/\_balances[] when SafeMath is absent and
    // the pragma targets Solidity 0.4.x through 0.7.x.
    fn detect_integer_overflow_token_pattern(&self, content: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        // Check if this is pre-0.8.0 and has token transfer with arithmetic
        if content.contains("pragma solidity")
            && (content.contains("0.4.")
                || content.contains("0.5.")
                || content.contains("0.6.")
                || content.contains("0.7."))
            && (content.contains("balanceOf") || content.contains("transfer"))
            && !content.contains("SafeMath")
        {
            for (idx, line) in content.lines().enumerate() {
                if (line.contains("balances[") || line.contains("_balances["))
                    && (line.contains("+=")
                        || line.contains("-=")
                        || line.contains("+")
                        || line.contains("-"))
                {
                    vulnerabilities.push(Vulnerability::high_confidence(
                        VulnerabilitySeverity::Critical,
                        VulnerabilityCategory::ArithmeticIssues,
                        "Token Integer Overflow Risk".to_string(),
                        "Token balance arithmetic without SafeMath in pre-0.8.0 Solidity"
                            .to_string(),
                        idx + 1,
                        line.to_string(),
                        "Use SafeMath library or upgrade to Solidity 0.8.0+".to_string(),
                    ));
                }
            }
        }

        vulnerabilities
    }

    // Detect low-level calls (.call, .delegatecall, .staticcall) whose return
    // value is not captured into (bool ...) or immediately checked via require/if.
    fn detect_unchecked_call_pattern(&self, content: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        for (idx, line) in content.lines().enumerate() {
            if line.contains(".call(")
                || line.contains(".delegatecall(")
                || line.contains(".staticcall(")
            {
                // Check if return value is checked
                let is_checked = line.contains("(bool")
                    || line.contains("require(")
                    || line.contains("if (")
                    || line.contains("if(");

                // Check next line too
                let lines_vec: Vec<&str> = content.lines().collect();
                let next_line_checked = if idx + 1 < lines_vec.len() {
                    lines_vec[idx + 1].contains("require(") || lines_vec[idx + 1].contains("if (")
                } else {
                    false
                };

                if !is_checked && !next_line_checked {
                    vulnerabilities.push(Vulnerability::new(
                        VulnerabilitySeverity::High,
                        VulnerabilityCategory::UncheckedReturnValues,
                        "Unchecked Low-Level Call".to_string(),
                        "Low-level call return value not checked - silent failures possible".to_string(),
                        idx + 1,
                        line.to_string(),
                        "Check return value: (bool success, ) = target.call(...); require(success);".to_string(),
                    ));
                }
            }
        }

        vulnerabilities
    }

    // ============================================================================
    // REKT.NEWS COMPREHENSIVE PATTERN DETECTION
    // High-severity real-world exploit patterns from $3.1B+ in losses (2024-2025)
    // ============================================================================

    /// Analyze patterns sourced from REKT.news incident reports ($3.1B+ in losses).
    ///
    /// Sub-detectors cover:
    /// - Aevo/Ribbon proxy admin + oracle manipulation ($2.7M)
    /// - Omni NFT callback reentrancy ($1.43M)
    /// - Input validation failures (34.6% of all exploits, $69M)
    /// - Signature replay (cross-chain incidents)
    /// - MEV exploitation ($675M surface)
    /// - Precision attack / decimal mismatch
    pub fn analyze_rekt_news_patterns(&self, content: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_aevo_proxy_pattern(content));
        vulnerabilities.extend(self.detect_omni_callback_pattern(content));
        vulnerabilities.extend(self.detect_input_validation_patterns(content));
        vulnerabilities.extend(self.detect_signature_replay_patterns(content));
        vulnerabilities.extend(self.detect_mev_exploitation_patterns(content));
        vulnerabilities.extend(self.detect_precision_attack_patterns(content));

        vulnerabilities
    }

    // Aevo/Ribbon Finance Pattern ($2.7M - Dec 2025):
    // Two sub-checks for proxy contracts:
    //   1. transferOwnership without access control modifier
    //   2. setOracle-style functions without governance/timelock protection
    fn detect_aevo_proxy_pattern(&self, content: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        // Check for proxy pattern
        let is_proxy = content.contains("TransparentUpgradeableProxy")
            || content.contains("UUPSUpgradeable")
            || content.contains("Proxy")
            || content.contains("implementation");

        if !is_proxy {
            return vulnerabilities;
        }

        // Critical: transferOwnership without access control in proxy context
        let transfer_ownership_pattern =
            re!(r"function\s+transferOwnership\s*\([^)]*\)\s+(external|public)\s*\{");

        for (idx, line) in content.lines().enumerate() {
            if transfer_ownership_pattern.is_match(line) {
                // Check for access control in next 5 lines
                let next_lines: Vec<&str> = content.lines().skip(idx).take(5).collect();
                let has_access_control = next_lines.iter().any(|l| {
                    l.contains("onlyOwner")
                        || l.contains("onlyAdmin")
                        || l.contains("require(msg.sender")
                        || l.contains("onlyRole")
                });

                if !has_access_control {
                    vulnerabilities.push(Vulnerability::high_confidence(
                        VulnerabilitySeverity::Critical,
                        VulnerabilityCategory::ProxyAdminVulnerability,
                        "CRITICAL: Aevo-Pattern Proxy Vulnerability".to_string(),
                        "Unprotected transferOwnership in proxy contract - exact pattern from $2.7M Aevo exploit".to_string(),
                        idx + 1,
                        line.to_string(),
                        "URGENT: Add onlyOwner/onlyAdmin modifier - this is a known exploit pattern".to_string(),
                    ));
                }
            }
        }

        // Check for oracle manipulation surface in upgradeable contracts
        if content.contains("oracle") || content.contains("Oracle") {
            let set_oracle_pattern = re!(r"function\s+set\w*Oracle\w*\([^)]*\)");

            for (idx, line) in content.lines().enumerate() {
                if set_oracle_pattern.is_match(line) {
                    let next_lines: Vec<&str> = content.lines().skip(idx).take(5).collect();
                    let has_protection = next_lines.iter().any(|l| {
                        l.contains("onlyOwner")
                            || l.contains("timelock")
                            || l.contains("governance")
                    });

                    if !has_protection {
                        vulnerabilities.push(Vulnerability::high_confidence(
                            VulnerabilitySeverity::Critical,
                            VulnerabilityCategory::OracleManipulation,
                            "Unprotected Oracle Configuration (Aevo Pattern)".to_string(),
                            "Oracle configuration functions must be protected - Aevo exploit modified oracle to manipulate prices".to_string(),
                            idx + 1,
                            line.to_string(),
                            "Add governance/timelock protection for oracle modifications".to_string(),
                        ));
                    }
                }
            }
        }

        vulnerabilities
    }

    // Omni NFT Pattern ($1.43M - 2024)
    // Callback reentrancy in ERC721/ERC1155 operations
    fn detect_omni_callback_pattern(&self, content: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        // Check if this is an NFT contract
        let is_nft = content.contains("ERC721") || content.contains("ERC1155");
        if !is_nft {
            return vulnerabilities;
        }

        // Check for ReentrancyGuard
        let has_reentrancy_guard =
            content.contains("ReentrancyGuard") || content.contains("nonReentrant");

        // Critical pattern: State-changing functions using safeTransferFrom
        let lines: Vec<&str> = content.lines().collect();

        for (idx, line) in lines.iter().enumerate() {
            // Look for functions that borrow, lend, mint, or modify balances
            if line.contains("function")
                && (line.contains("borrow")
                    || line.contains("lend")
                    || line.contains("mint")
                    || line.contains("stake")
                    || line.contains("deposit"))
            {
                // Check if function uses safeTransferFrom within it
                let func_body: Vec<&str> = lines.iter().skip(idx).take(30).copied().collect();
                let uses_safe_transfer = func_body
                    .iter()
                    .any(|l| l.contains("safeTransferFrom") || l.contains("_safeMint"));

                if uses_safe_transfer && !has_reentrancy_guard {
                    // Check if state changes happen after the transfer
                    let mut transfer_idx = 0;
                    let mut state_change_after = false;

                    for (i, body_line) in func_body.iter().enumerate() {
                        if body_line.contains("safeTransferFrom") || body_line.contains("_safeMint")
                        {
                            transfer_idx = i;
                        }
                        if i > transfer_idx && transfer_idx > 0
                            && body_line.contains("=")
                                && !body_line.contains("==")
                                && (body_line.contains("balance")
                                    || body_line.contains("amount")
                                    || body_line.contains("debt")
                                    || body_line.contains("collateral"))
                            {
                                state_change_after = true;
                                break;
                            }
                    }

                    if state_change_after {
                        vulnerabilities.push(Vulnerability::high_confidence(
                            VulnerabilitySeverity::Critical,
                            VulnerabilityCategory::CallbackReentrancy,
                            "CRITICAL: Omni-Pattern Callback Reentrancy".to_string(),
                            "State changes after safeTransferFrom enable onERC721Received reentrancy - exact $1.43M Omni exploit pattern".to_string(),
                            idx + 1,
                            line.to_string(),
                            "URGENT: Add ReentrancyGuard OR move all state changes before safeTransferFrom".to_string(),
                        ));
                    }
                }
            }
        }

        vulnerabilities
    }

    // Input Validation Patterns (34.6% of all exploits - $69M in 2024)
    // Most common vulnerability in 2021, 2022, 2024
    fn detect_input_validation_patterns(&self, content: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        // Only flag `bytes calldata` (arbitrary raw data) without validation.
        // Typed calldata params (uint256 calldata, address[] calldata) are standard
        // and safe - the ABI decoder validates their structure automatically.
        let calldata_pattern =
            re!(r"function\s+(\w+)\s*\([^)]*bytes\s+calldata[^)]*\)\s+(external|public)");

        for (idx, line) in content.lines().enumerate() {
            if let Some(captures) = calldata_pattern.captures(line) {
                let func_name = captures.get(1).map_or("", |m| m.as_str());

                // Check if there's validation in next 10 lines
                let next_lines: Vec<&str> = content.lines().skip(idx + 1).take(10).collect();
                let has_validation = next_lines.iter().any(|l| {
                    l.contains("require(")
                        || l.contains("if (")
                        || l.contains("if(")
                        || l.contains("revert")
                        || l.contains("assert(")
                        || l.contains("abi.decode")
                });

                if !has_validation {
                    vulnerabilities.push(Vulnerability::high_confidence(
                        VulnerabilitySeverity::Critical,
                        VulnerabilityCategory::InputValidationFailure,
                        format!("Unchecked Raw Calldata in {func_name}"),
                        "Raw bytes calldata without validation or decoding - potential exploit vector".to_string(),
                        idx + 1,
                        line.to_string(),
                        "Decode and validate raw calldata bytes before processing".to_string(),
                    ));
                }
            }
        }

        // Array parameter without length checks
        let array_pattern =
            re!(r"function\s+(\w+)\s*\([^)]*\[\]\s+(\w+)[^)]*\)\s+(external|public)");

        for (idx, line) in content.lines().enumerate() {
            if let Some(captures) = array_pattern.captures(line) {
                let func_name = captures.get(1).map_or("", |m| m.as_str());
                let array_param = captures.get(2).map_or("", |m| m.as_str());

                let next_lines: Vec<&str> = content.lines().skip(idx).take(10).collect();
                let has_length_check = next_lines
                    .iter()
                    .any(|l| l.contains(&format!("{array_param}.length")) && l.contains("require"));

                // Only a function that itself loops over the array can run into the
                // gas-limit DoS this rule targets. Thin wrappers that forward the array
                // to an internal function (e.g. burnBatch → _burnBatch) validate there.
                let loops_over_array = next_lines
                    .iter()
                    .any(|l| l.contains("for") && l.contains(&format!("{array_param}.length")));

                if !has_length_check && loops_over_array {
                    vulnerabilities.push(Vulnerability::new(
                        VulnerabilitySeverity::Medium,
                        VulnerabilityCategory::InputValidationFailure,
                        format!("Missing Array Length Validation in {func_name}"),
                        "Array parameter without length validation - enables DoS and manipulation"
                            .to_string(),
                        idx + 1,
                        line.to_string(),
                        "Add require(array.length > 0 && array.length <= MAX_LENGTH)".to_string(),
                    ));
                }
            }
        }

        vulnerabilities
    }

    // Signature Replay Patterns (Multiple cross-chain incidents)
    fn detect_signature_replay_patterns(&self, content: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        // Check for signature verification code
        if !content.contains("ecrecover") && !content.contains("ECDSA") {
            return vulnerabilities;
        }

        // Missing nonce tracking
        let ecrecover_pattern = re!(r"ecrecover\s*\(");
        let has_nonce_mapping = content.contains("mapping") && content.contains("nonce");

        for (idx, line) in content.lines().enumerate() {
            if ecrecover_pattern.is_match(line) {
                // Check for nonce in the signature verification function
                let func_body: Vec<&str> = content
                    .lines()
                    .skip(idx.saturating_sub(15))
                    .take(30)
                    .collect();
                let uses_nonce = func_body
                    .iter()
                    .any(|l| l.contains("nonce") && (l.contains("++") || l.contains("+=")));

                if !has_nonce_mapping || !uses_nonce {
                    vulnerabilities.push(Vulnerability::high_confidence(
                        VulnerabilitySeverity::Critical,
                        VulnerabilityCategory::SignatureReplay,
                        "Signature Replay Attack Risk".to_string(),
                        "Signature verification without nonce tracking allows replay attacks"
                            .to_string(),
                        idx + 1,
                        line.to_string(),
                        "Implement nonce mapping and increment after each signature use"
                            .to_string(),
                    ));
                }

                // Missing chain ID — check both local context AND the whole file
                // (DOMAIN_SEPARATOR with chainid may be defined elsewhere in the contract)
                let uses_chainid = func_body.iter().any(|l| {
                    l.contains("chainid") || l.contains("chainId") || l.contains("block.chainid")
                }) || content.contains("block.chainid")
                    || content.contains("DOMAIN_SEPARATOR");

                if !uses_chainid {
                    vulnerabilities.push(Vulnerability::high_confidence(
                        VulnerabilitySeverity::Critical,
                        VulnerabilityCategory::CrossChainReplay,
                        "Cross-Chain Signature Replay Risk".to_string(),
                        "Signature verification without chain ID enables cross-chain replay attacks".to_string(),
                        idx + 1,
                        line.to_string(),
                        "Include block.chainid in EIP-712 domain separator".to_string(),
                    ));
                }
            }
        }

        vulnerabilities
    }

    // MEV Exploitation Patterns ($675M MEV profits in 2025, 19% YoY increase)
    fn detect_mev_exploitation_patterns(&self, content: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        // Swap functions without slippage AND deadline protection
        let swap_pattern = re!(r"function\s+swap\w*\([^)]*\)");

        for (idx, line) in content.lines().enumerate() {
            if swap_pattern.is_match(line) {
                let has_slippage = line.contains("minAmount")
                    || line.contains("amountOutMin")
                    || line.contains("slippage");
                let has_deadline = line.contains("deadline");

                if !has_slippage || !has_deadline {
                    vulnerabilities.push(Vulnerability::high_confidence(
                        VulnerabilitySeverity::Critical,
                        VulnerabilityCategory::MEVExploitable,
                        "MEV Sandwich Attack Vulnerability".to_string(),
                        "Swap without slippage+deadline protection - vulnerable to $675M MEV attack surface".to_string(),
                        idx + 1,
                        line.to_string(),
                        "Add both minAmountOut AND deadline parameters, verify deadline <= block.timestamp".to_string(),
                    ));
                }
            }
        }

        // Public liquidation functions (MEV hotspot)
        let liquidate_pattern =
            re!(r"function\s+liquidate\w*\([^)]*\)\s+(external|public)");

        for (idx, line) in content.lines().enumerate() {
            if liquidate_pattern.is_match(line) {
                // Check if there's MEV protection
                let func_body: Vec<&str> = content.lines().skip(idx).take(20).collect();
                let has_mev_protection = func_body.iter().any(|l| {
                    l.contains("Flashbots")
                        || l.contains("private")
                        || l.contains("commit")
                        || l.contains("reveal")
                });

                if !has_mev_protection {
                    vulnerabilities.push(Vulnerability::new(
                        VulnerabilitySeverity::High,
                        VulnerabilityCategory::MEVExploitable,
                        "Public Liquidation MEV Target".to_string(),
                        "Public liquidation function is prime MEV target - bots will front-run profitable liquidations".to_string(),
                        idx + 1,
                        line.to_string(),
                        "Consider MEV protection: private mempool, Flashbots, or liquidation auctions".to_string(),
                    ));
                }
            }
        }

        vulnerabilities
    }

    // Precision Attack Patterns (Aevo decimal mismatch, numerous rounding exploits)
    fn detect_precision_attack_patterns(&self, content: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        // Mixing different decimal precisions (Aevo pattern)
        let decimal_1e18 = re!(r"1e18|10\s*\*\*\s*18");
        let decimal_1e8 = re!(r"1e8|10\s*\*\*\s*8");

        let has_1e18 = decimal_1e18.is_match(content);
        let has_1e8 = decimal_1e8.is_match(content);

        if has_1e18 && has_1e8 {
            vulnerabilities.push(Vulnerability::high_confidence(
                VulnerabilitySeverity::Critical,
                VulnerabilityCategory::DecimalPrecisionMismatch,
                "CRITICAL: Mixed Decimal Precision (Aevo Pattern)".to_string(),
                "Contract mixes 1e18 and 1e8 decimals - exact Aevo $2.7M exploit pattern"
                    .to_string(),
                1,
                "Multiple decimal standards detected".to_string(),
                "Normalize ALL values to single precision (preferably 1e18) before any operations"
                    .to_string(),
            ));
        }

        // Division before multiplication in pricing (precision loss)
        let price_calc_pattern =
            re!(r"(price|Price|value|Value|rate|Rate)\w*\s*=\s*[^=]*\/[^=]*\*");

        for (idx, line) in content.lines().enumerate() {
            if price_calc_pattern.is_match(line) {
                vulnerabilities.push(Vulnerability::new(
                    VulnerabilitySeverity::High,
                    VulnerabilityCategory::PrecisionLoss,
                    "Precision Loss in Price Calculation".to_string(),
                    "Division before multiplication loses precision in price/value calculations"
                        .to_string(),
                    idx + 1,
                    line.to_string(),
                    "Always multiply before dividing: (a * b) / c not (a / c) * b".to_string(),
                ));
            }
        }

        vulnerabilities
    }

    // ============================================================================
    // 2025 OWASP SMART CONTRACT TOP 10 ADVANCED ANALYSIS
    // Enhanced detection for recent exploits
    // ============================================================================

    /// Analyze 2025 OWASP Top 10 patterns with deep control flow analysis
    pub fn analyze_owasp_2025_patterns(&self, content: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        // Flash Loan Attack patterns (OWASP #4)
        vulnerabilities.extend(self.detect_flash_loan_patterns(content));

        // Logic Error patterns (OWASP #2)
        vulnerabilities.extend(self.detect_logic_error_patterns(content));

        // Meta-transaction/Forwarder patterns (KiloEx)
        vulnerabilities.extend(self.detect_meta_transaction_patterns(content));

        // Unchecked math patterns (Cetus)
        vulnerabilities.extend(self.detect_unchecked_math_patterns(content));

        // Governance attack patterns
        vulnerabilities.extend(self.detect_governance_attack_patterns(content));

        // Bridge vulnerability patterns
        vulnerabilities.extend(self.detect_bridge_vulnerability_patterns(content));

        // FN-5: ERC20 approve race condition
        vulnerabilities.extend(self.detect_erc20_approve_race_condition(content));

        vulnerabilities
    }

    // FN-5: Detect ERC20 approve race condition in custom implementations
    fn detect_erc20_approve_race_condition(&self, content: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        // Only check if contract defines its own approve function
        let approve_pattern = re!(r"function\s+approve\s*\(");
        if !approve_pattern.is_match(content) {
            return vulnerabilities;
        }

        // Skip if importing from OpenZeppelin ERC20 (already handled)
        if content.contains("@openzeppelin") && content.contains("ERC20") {
            return vulnerabilities;
        }

        // Check if increaseAllowance/decreaseAllowance exist
        let has_safe_allowance = content.contains("function increaseAllowance")
            || content.contains("function decreaseAllowance");

        if !has_safe_allowance {
            for (idx, line) in content.lines().enumerate() {
                if approve_pattern.is_match(line) {
                    vulnerabilities.push(Vulnerability::new(
                        VulnerabilitySeverity::Medium,
                        VulnerabilityCategory::LogicError,
                        "ERC20 Approve Race Condition".to_string(),
                        "Custom ERC20 implements approve() without increaseAllowance/decreaseAllowance - vulnerable to front-running".to_string(),
                        idx + 1,
                        line.trim().to_string(),
                        "Add increaseAllowance() and decreaseAllowance() functions, or inherit from OpenZeppelin ERC20".to_string(),
                    ));
                    break; // Only report once
                }
            }
        }

        vulnerabilities
    }

    // Flash Loan Attack Detection (OWASP #4 - $33.8M in 2024)
    fn detect_flash_loan_patterns(&self, content: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        // Check for flash loan callback without proper validation
        let callback_pattern = re!(r"function\s+(executeOperation|onFlashLoan|uniswapV\d+Call|pancakeCall)\s*\([^)]*\)");

        for (idx, line) in content.lines().enumerate() {
            if callback_pattern.is_match(line) {
                let func_body: Vec<&str> = content.lines().skip(idx).take(30).collect();

                // Check for initiator validation
                let has_initiator_check = func_body.iter().any(|l| {
                    l.contains("initiator")
                        && (l.contains("require") || l.contains("==") || l.contains("if"))
                });

                // Check for msg.sender validation (lending pool)
                let has_sender_check = func_body.iter().any(|l| {
                    l.contains("msg.sender")
                        && (l.contains("POOL")
                            || l.contains("lendingPool")
                            || l.contains("require"))
                });

                if !has_initiator_check || !has_sender_check {
                    vulnerabilities.push(Vulnerability::high_confidence(
                        VulnerabilitySeverity::Critical,
                        VulnerabilityCategory::FlashLoanAttack,
                        "Flash Loan Callback Missing Validation".to_string(),
                        "Flash loan callback lacks proper initiator/sender validation - enables arbitrary calls".to_string(),
                        idx + 1,
                        line.to_string(),
                        "Add: require(msg.sender == POOL); require(initiator == address(this));".to_string(),
                    ));
                }
            }
        }

        // Detect price manipulation via balance queries
        let balance_price_pattern =
            re!(r"balanceOf\([^)]*\).*price|price.*balanceOf");

        for (idx, line) in content.lines().enumerate() {
            if balance_price_pattern.is_match(line)
                && !content.contains("TWAP")
                && !content.contains("Chainlink")
            {
                vulnerabilities.push(Vulnerability::high_confidence(
                    VulnerabilitySeverity::Critical,
                    VulnerabilityCategory::FlashLoanAttack,
                    "Flash Loan Price Manipulation Vector".to_string(),
                    "Using balanceOf for pricing is manipulable via flash loans".to_string(),
                    idx + 1,
                    line.to_string(),
                    "Use TWAP oracles or Chainlink price feeds instead".to_string(),
                ));
            }
        }

        vulnerabilities
    }

    // Logic Error Detection (OWASP #2 - $63.8M in 2024)
    fn detect_logic_error_patterns(&self, content: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        // First depositor attack in vaults
        if content.contains("ERC4626") || content.contains("Vault") {
            let has_virtual_shares = content.contains("INITIAL_SHARES")
                || content.contains("_decimalsOffset")
                || content.contains("MIN_SHARES")
                || content.contains("MIN_ASSETS")
                || content.contains("MIN_DEPOSIT")
                || content.contains("INITIAL_DEPOSIT")
                || content.contains("10 **");

            let mint_pattern = re!(r"function\s+deposit\s*\(");

            for (idx, line) in content.lines().enumerate() {
                // Skip import statements and comments
                let trimmed = line.trim();
                if trimmed.starts_with("import")
                    || trimmed.starts_with("//")
                    || trimmed.starts_with("*")
                {
                    continue;
                }

                if mint_pattern.is_match(line) {
                    let func_body: Vec<&str> = content.lines().skip(idx).take(20).collect();
                    let has_zero_check = func_body.iter().any(|l| {
                        l.contains("totalSupply") && (l.contains("== 0") || l.contains("> 0"))
                    });

                    if has_zero_check && !has_virtual_shares {
                        vulnerabilities.push(Vulnerability::high_confidence(
                            VulnerabilitySeverity::Critical,
                            VulnerabilityCategory::LogicError,
                            "First Depositor Attack Vector (Vault)".to_string(),
                            "Vault has zero-supply special case without virtual shares protection"
                                .to_string(),
                            idx + 1,
                            line.to_string(),
                            "Add virtual shares offset: shares = assets + INITIAL_OFFSET"
                                .to_string(),
                        ));
                    }
                }
            }
        }

        // Incorrect state update order (CEI violation)
        // Only flag .call{value:} — .transfer() and .send() use 2300 gas (safe from reentrancy)
        let transfer_pattern = re!(r"\.call\{value:|safeTransfer");
        let state_update_pattern = re!(r"\w+\s*=\s*[^=]|\w+\[.*\]\s*=");

        let lines: Vec<&str> = content.lines().collect();
        for (idx, line) in lines.iter().enumerate() {
            // Skip comments
            if line.trim().starts_with("//")
                || line.trim().starts_with("*")
                || line.trim().starts_with("/*")
                || line.trim().starts_with("///")
            {
                continue;
            }
            if transfer_pattern.is_match(line) {
                // Check if state updates happen AFTER this transfer
                for &future_line in lines.iter().skip(idx + 1).take(9) {
                    if future_line.trim() == "}" {
                        break;
                    }
                    if state_update_pattern.is_match(future_line)
                        && !future_line.contains("==")
                        && !future_line.contains("memory")
                        && (future_line.contains("balance")
                            || future_line.contains("amount")
                            || future_line.contains("shares")
                            || future_line.contains("debt"))
                    {
                        // Check if there's a reentrancy guard
                        if !content.contains("nonReentrant") && !content.contains("ReentrancyGuard")
                        {
                            vulnerabilities.push(Vulnerability::high_confidence(
                                VulnerabilitySeverity::Critical,
                                VulnerabilityCategory::LogicError,
                                "CEI Violation - State After External Call".to_string(),
                                "State modification after external call without reentrancy guard"
                                    .to_string(),
                                idx + 1,
                                line.to_string(),
                                "Move state updates before external calls or add ReentrancyGuard"
                                    .to_string(),
                            ));
                            break;
                        }
                    }
                }
            }
        }

        vulnerabilities
    }

    // Meta-Transaction / Trusted Forwarder Patterns (KiloEx $7.4M)
    fn detect_meta_transaction_patterns(&self, content: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        // Check for MinimalForwarder usage
        if content.contains("MinimalForwarder") || content.contains("ForwardRequest") {
            // Check for proper signature validation
            let execute_pattern = re!(r"function\s+execute\s*\(");

            for (idx, line) in content.lines().enumerate() {
                if execute_pattern.is_match(line) {
                    let func_body: Vec<&str> = content.lines().skip(idx).take(25).collect();

                    let has_signature_check = func_body.iter().any(|l| {
                        l.contains("ecrecover") || l.contains("ECDSA") || l.contains("verify")
                    });

                    let has_nonce_increment = func_body
                        .iter()
                        .any(|l| l.contains("nonce") && (l.contains("++") || l.contains("+= 1")));

                    if !has_signature_check {
                        vulnerabilities.push(Vulnerability::high_confidence(
                            VulnerabilitySeverity::Critical,
                            VulnerabilityCategory::MetaTransactionVulnerability,
                            "CRITICAL: KiloEx-Pattern Forwarder Exploit".to_string(),
                            "Forwarder execute() lacks signature verification - KiloEx $7.4M exploit".to_string(),
                            idx + 1,
                            line.to_string(),
                            "Verify signature matches (from, to, value, gas, nonce, data) hash".to_string(),
                        ));
                    }

                    if !has_nonce_increment {
                        vulnerabilities.push(Vulnerability::new(
                            VulnerabilitySeverity::High,
                            VulnerabilityCategory::MetaTransactionVulnerability,
                            "Meta-Transaction Replay Risk".to_string(),
                            "Execute function doesn't increment nonce - enables replay attacks"
                                .to_string(),
                            idx + 1,
                            line.to_string(),
                            "Increment nonce after successful execution: _nonces[from]++"
                                .to_string(),
                        ));
                    }
                }
            }
        }

        // Check for ERC2771Context issues
        if content.contains("_msgSender()") || content.contains("ERC2771Context") {
            // Check if trusted forwarder can be manipulated
            let set_forwarder = re!(r"function\s+set\w*[Ff]orwarder");

            for (idx, line) in content.lines().enumerate() {
                if set_forwarder.is_match(line) {
                    vulnerabilities.push(Vulnerability::new(
                        VulnerabilitySeverity::High,
                        VulnerabilityCategory::TrustedForwarderBypass,
                        "Mutable Trusted Forwarder".to_string(),
                        "Trusted forwarder can be changed - enables meta-tx hijacking".to_string(),
                        idx + 1,
                        line.to_string(),
                        "Make trustedForwarder immutable, set only in constructor".to_string(),
                    ));
                }
            }
        }

        vulnerabilities
    }

    // Unchecked Math Operations (Cetus $223M Pattern)
    fn detect_unchecked_math_patterns(&self, content: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        // Check for custom safe math implementations
        let custom_math_pattern = re!(r"function\s+\w*(safe|checked|overflow)\w*(Add|Sub|Mul|Div|Shl|Shr)\w*\s*\(");

        for (idx, line) in content.lines().enumerate() {
            if custom_math_pattern.is_match(line) {
                vulnerabilities.push(Vulnerability::new(
                    VulnerabilitySeverity::High,
                    VulnerabilityCategory::UncheckedMathOperation,
                    "Custom Safe Math Implementation (Audit Required)".to_string(),
                    "Custom overflow checks found - Cetus $223M used flawed custom checks"
                        .to_string(),
                    idx + 1,
                    line.to_string(),
                    "Use battle-tested libraries (OpenZeppelin) or Solidity 0.8+ built-ins"
                        .to_string(),
                ));
            }
        }

        // Check for bit shift operations in critical calculations.
        // Grouped alternation: the old `...=.*<<|>>\s*\d+` split at the top level, so
        // ANY constant right-shift (e.g. `vs >> 255`) matched the second branch.
        // Require assignment to a financial variable AND a variable shift amount.
        let shift_in_calc_pattern =
            re!(r"(liquidity|price|amount|value|shares)\w*\s*=.*(<<|>>)\s*[a-zA-Z_]");

        for (idx, line) in content.lines().enumerate() {
            if shift_in_calc_pattern.is_match(line) {
                // Check if it's in unchecked block
                let prev_lines: Vec<&str> = content.lines().take(idx).collect();
                let in_unchecked = prev_lines
                    .iter()
                    .rev()
                    .take(10)
                    .any(|l| l.contains("unchecked"));

                if in_unchecked {
                    vulnerabilities.push(Vulnerability::high_confidence(
                        VulnerabilitySeverity::Critical,
                        VulnerabilityCategory::UncheckedMathOperation,
                        "CRITICAL: Unchecked Bit Shift (Cetus Pattern)".to_string(),
                        "Bit shift in unchecked block - exact Cetus $223M vulnerability"
                            .to_string(),
                        idx + 1,
                        line.to_string(),
                        "Move bit shifts outside unchecked or add explicit bounds validation"
                            .to_string(),
                    ));
                }
            }
        }

        // Check for sqrt/exp in financial calculations
        let complex_math = re!(r"(sqrt|exp|pow)\s*\(.*\)");

        for (idx, line) in content.lines().enumerate() {
            if complex_math.is_match(line) {
                let prev_lines: Vec<&str> = content.lines().take(idx).collect();
                let in_unchecked = prev_lines
                    .iter()
                    .rev()
                    .take(10)
                    .any(|l| l.contains("unchecked"));

                if in_unchecked {
                    vulnerabilities.push(Vulnerability::new(
                        VulnerabilitySeverity::High,
                        VulnerabilityCategory::UncheckedMathOperation,
                        "Complex Math in Unchecked Block".to_string(),
                        "sqrt/exp/pow operations in unchecked block can silently overflow"
                            .to_string(),
                        idx + 1,
                        line.to_string(),
                        "Validate input bounds before complex math, add explicit overflow checks"
                            .to_string(),
                    ));
                }
            }
        }

        vulnerabilities
    }

    // Governance Attack Patterns (Beanstalk $182M)
    fn detect_governance_attack_patterns(&self, content: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        // Check for governance voting functions
        let vote_pattern = re!(r"function\s+(castVote|vote|propose)\w*\s*\(");

        for (idx, line) in content.lines().enumerate() {
            if vote_pattern.is_match(line) {
                let func_body: Vec<&str> = content.lines().skip(idx).take(20).collect();

                // Check for flash loan protection
                let has_snapshot = func_body.iter().any(|l| {
                    l.contains("snapshot")
                        || l.contains("checkpoint")
                        || l.contains("getPastVotes")
                        || l.contains("block.number - 1")
                });

                let has_timelock = content.contains("TimelockController")
                    || content.contains("timelock")
                    || content.contains("delay");

                if !has_snapshot && !has_timelock {
                    vulnerabilities.push(Vulnerability::high_confidence(
                        VulnerabilitySeverity::Critical,
                        VulnerabilityCategory::GovernanceAttack,
                        "Flash Loan Governance Attack (Beanstalk Pattern)".to_string(),
                        "Voting without snapshot allows flash loan vote manipulation - Beanstalk $182M".to_string(),
                        idx + 1,
                        line.to_string(),
                        "Use getPastVotes with snapshot block, add proposal timelock".to_string(),
                    ));
                }
            }
        }

        // Check for emergency functions
        let emergency_pattern =
            re!(r"function\s+emergency\w*\s*\([^)]*\)\s+(external|public)");

        for (idx, line) in content.lines().enumerate() {
            if emergency_pattern.is_match(line) {
                let func_body: Vec<&str> = content.lines().skip(idx).take(10).collect();

                let has_multisig = func_body.iter().any(|l| {
                    l.contains("multisig") || l.contains("onlyOwner") || l.contains("onlyRole")
                });

                let has_timelock = func_body.iter().any(|l| {
                    l.contains("timelock") || l.contains("delay") || l.contains("cooldown")
                });

                if !has_multisig || !has_timelock {
                    vulnerabilities.push(Vulnerability::new(
                        VulnerabilitySeverity::High,
                        VulnerabilityCategory::GovernanceAttack,
                        "Emergency Function Without Safeguards".to_string(),
                        "Emergency function lacks multi-sig or timelock protection".to_string(),
                        idx + 1,
                        line.to_string(),
                        "Require multi-sig AND timelock for emergency functions".to_string(),
                    ));
                }
            }
        }

        vulnerabilities
    }

    // Bridge Vulnerability Patterns
    fn detect_bridge_vulnerability_patterns(&self, content: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        // Only meaningful in cross-chain code. `_execute` in the handler list is far
        // too generic on its own (governors, ERC-4337 accounts, and meta-tx forwarders
        // all define `_execute`), so require actual bridge indicators in the file.
        let is_cross_chain = content.contains("LayerZero")
            || content.contains("lzReceive")
            || content.contains("Wormhole")
            || content.contains("wormhole")
            || content.contains("bridge")
            || content.contains("Bridge")
            || content.contains("srcChain")
            || content.contains("crosschain")
            || content.contains("CrossChain");
        if !is_cross_chain {
            return vulnerabilities;
        }

        // Check for cross-chain message handlers
        let message_handler = re!(r"function\s+(lzReceive|_nonblockingLzReceive|receiveWormholeMessages?|_execute)\s*\(");

        for (idx, line) in content.lines().enumerate() {
            if message_handler.is_match(line) {
                let func_body: Vec<&str> = content.lines().skip(idx).take(25).collect();

                // Check for source chain validation
                let has_chain_check = func_body.iter().any(|l| {
                    l.contains("srcChainId")
                        || l.contains("sourceChain")
                        || l.contains("trustedRemote")
                        || l.contains("_srcChainId")
                });

                // Check for source address validation
                let has_address_check = func_body.iter().any(|l| {
                    l.contains("srcAddress")
                        || l.contains("_srcAddress")
                        || l.contains("trustedRemote[")
                });

                if !has_chain_check || !has_address_check {
                    vulnerabilities.push(Vulnerability::high_confidence(
                        VulnerabilitySeverity::Critical,
                        VulnerabilityCategory::BridgeVulnerability,
                        "Bridge Source Validation Missing".to_string(),
                        "Cross-chain message handler lacks source chain/address verification"
                            .to_string(),
                        idx + 1,
                        line.to_string(),
                        "Validate srcChainId AND trustedRemote[srcChainId] == srcAddress"
                            .to_string(),
                    ));
                }
            }
        }

        // Check for bridge claim functions
        let claim_pattern =
            re!(r"function\s+\w*(claim|withdraw|redeem)\w*\s*\([^)]*proof");

        for (idx, line) in content.lines().enumerate() {
            if claim_pattern.is_match(line) {
                let func_body: Vec<&str> = content.lines().skip(idx).take(20).collect();

                // Check for replay protection
                let has_replay_check = func_body.iter().any(|l| {
                    l.contains("claimed[")
                        || l.contains("processed[")
                        || l.contains("used[")
                        || l.contains("nonce")
                });

                if !has_replay_check {
                    vulnerabilities.push(Vulnerability::high_confidence(
                        VulnerabilitySeverity::Critical,
                        VulnerabilityCategory::BridgeVulnerability,
                        "Bridge Claim Replay Attack".to_string(),
                        "Bridge claim function lacks replay protection - same proof can be used twice".to_string(),
                        idx + 1,
                        line.to_string(),
                        "Mark proofs as claimed: require(!claimed[hash]); claimed[hash] = true;".to_string(),
                    ));
                }
            }
        }

        vulnerabilities
    }

    // ============================================================================
    // PHASE 6: NEW VULNERABILITY DETECTORS (2025)
    // Priority detectors for emerging attack vectors
    // ============================================================================

    /// Analyze all Phase 6 vulnerability patterns
    pub fn analyze_phase6_patterns(&self, content: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_erc4626_inflation_attack(content));
        vulnerabilities.extend(self.detect_read_only_reentrancy(content));
        vulnerabilities.extend(self.detect_permit2_risks(content));
        vulnerabilities.extend(self.detect_layerzero_validation(content));
        vulnerabilities.extend(self.detect_eip4337_vulnerabilities(content));
        vulnerabilities.extend(self.detect_transient_storage_issues(content));
        vulnerabilities.extend(self.detect_create2_collision(content));
        vulnerabilities.extend(self.detect_merkle_tree_vulnerabilities(content));

        vulnerabilities
    }

    // ERC4626 Inflation Attack (Critical)
    // First depositor can manipulate share price to steal from later depositors
    fn detect_erc4626_inflation_attack(&self, content: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        // Check if this is an ERC4626 vault
        if !content.contains("ERC4626")
            && !content.contains("Vault")
            && !content.contains("convertToShares")
            && !content.contains("convertToAssets")
        {
            return vulnerabilities;
        }

        // Check for virtual shares/assets offset (protection)
        let has_virtual_offset = content.contains("_decimalsOffset")
            || content.contains("INITIAL_SHARES")
            || content.contains("VIRTUAL_OFFSET")
            || content.contains("10 ** _decimalsOffset()");

        // Check for minimum deposit/shares requirement (including jDola-style MIN_SHARES/MIN_ASSETS)
        let has_min_deposit = content.contains("MIN_DEPOSIT")
            || content.contains("minDeposit")
            || content.contains("MIN_SHARES")
            || content.contains("MIN_ASSETS")
            || content.contains("INITIAL_DEPOSIT")
            || (content.contains("require(assets") && content.contains(">="));

        // Look for share calculation without protection
        let share_calc_pattern =
            re!(r"shares\s*=\s*assets\s*\*\s*totalSupply\s*/\s*totalAssets");
        let asset_calc_pattern =
            re!(r"assets\s*=\s*shares\s*\*\s*totalAssets\s*/\s*totalSupply");

        for (idx, line) in content.lines().enumerate() {
            if (share_calc_pattern.is_match(line) || asset_calc_pattern.is_match(line))
                && !has_virtual_offset && !has_min_deposit {
                    vulnerabilities.push(Vulnerability::high_confidence(
                        VulnerabilitySeverity::Critical,
                        VulnerabilityCategory::LogicError,
                        "CRITICAL: ERC4626 Inflation Attack".to_string(),
                        "Vault share calculation vulnerable to first depositor inflation attack. Attacker can donate assets after minimal deposit to inflate share price, causing rounding errors that steal from later depositors.".to_string(),
                        idx + 1,
                        line.to_string(),
                        "Add virtual offset to shares/assets: _decimalsOffset() returning 3-6, or require minimum initial deposit of significant amount".to_string(),
                    ));
                }
        }

        // Also check convertToShares/convertToAssets functions
        let convert_pattern = re!(r"function\s+convertTo(Shares|Assets)\s*\(");

        for (idx, line) in content.lines().enumerate() {
            if convert_pattern.is_match(line) {
                let func_body: Vec<&str> = content.lines().skip(idx).take(15).collect();

                // Check if there's division that could round to zero
                let has_unsafe_div = func_body.iter().any(|l| {
                    l.contains("/ totalSupply")
                        || l.contains("/ totalAssets")
                        || l.contains("/ supply")
                        || l.contains("/ assets")
                });

                let has_zero_check = func_body.iter().any(|l| {
                    l.contains("supply == 0")
                        || l.contains("totalSupply() == 0")
                        || l.contains("supply > 0")
                });

                if has_unsafe_div && has_zero_check && !has_virtual_offset {
                    vulnerabilities.push(Vulnerability::high_confidence(
                        VulnerabilitySeverity::Critical,
                        VulnerabilityCategory::LogicError,
                        "ERC4626 Zero Supply Edge Case".to_string(),
                        "Special case for zero supply can be exploited via donation attack"
                            .to_string(),
                        idx + 1,
                        line.to_string(),
                        "Use virtual shares offset instead of special-casing zero supply"
                            .to_string(),
                    ));
                }
            }
        }

        vulnerabilities
    }

    // Read-Only Reentrancy (Critical)
    // Exploits view functions during callback to get stale state
    fn detect_read_only_reentrancy(&self, content: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        // Check for external calls that can trigger callbacks
        let callback_triggers = [
            "safeTransferFrom",
            "safeTransfer",
            "_safeMint",
            ".call{",
            "IUniswapV3Pool",
            "ICurvePool",
        ];

        let has_callback_trigger = callback_triggers.iter().any(|t| content.contains(t));
        if !has_callback_trigger {
            return vulnerabilities;
        }

        // Check for view functions that read state
        let view_pattern = re!(r"function\s+(\w+)\s*\([^)]*\)\s+.*view");
        let mut view_functions: HashSet<String> = HashSet::new();

        for captures in view_pattern.captures_iter(content) {
            if let Some(name) = captures.get(1) {
                view_functions.insert(name.as_str().to_string());
            }
        }

        // Dangerous view functions that read pool state
        let dangerous_views = [
            "getPrice",
            "getRate",
            "get_virtual_price",
            "totalSupply",
            "balanceOf",
            "getReserves",
            "slot0",
            "liquidity",
            "convertToAssets",
            "convertToShares",
            "exchangeRate",
        ];

        // Check if contract has ReentrancyGuard
        let has_reentrancy_guard =
            content.contains("ReentrancyGuard") || content.contains("nonReentrant");

        // Look for state-reading patterns that could be exploited
        let lines: Vec<&str> = content.lines().collect();

        for (idx, line) in lines.iter().enumerate() {
            // Check for external calls
            if callback_triggers.iter().any(|t| line.contains(t)) {
                // Look for view function calls near this line (before or after)
                let context_start = idx.saturating_sub(10);
                let context_end = (idx + 10).min(lines.len());

                for &check_line in &lines[context_start..context_end] {

                    // Check if dangerous view functions are called
                    for view_fn in &dangerous_views {
                        if check_line.contains(view_fn) && check_line.contains("(") {
                            // Check if there's a lock mechanism
                            if !has_reentrancy_guard && !content.contains("_locked") {
                                vulnerabilities.push(Vulnerability::high_confidence(
                                    VulnerabilitySeverity::Critical,
                                    VulnerabilityCategory::Reentrancy,
                                    "CRITICAL: Read-Only Reentrancy (Curve Pattern)".to_string(),
                                    format!(
                                        "{}() can return stale state during {} callback. Attacker can exploit price/rate discrepancy during reentrancy window.",
                                        view_fn,
                                        callback_triggers.iter().find(|t| line.contains(*t)).unwrap_or(&"callback")
                                    ),
                                    idx + 1,
                                    line.to_string(),
                                    "Add reentrancy lock that also protects view functions, or use 'staticcall' pattern to prevent callbacks".to_string(),
                                ));
                                break;
                            }
                        }
                    }
                }
            }
        }

        // Specific Curve read-only reentrancy pattern
        if content.contains("get_virtual_price") || content.contains("ICurvePool") {
            for (idx, line) in content.lines().enumerate() {
                if line.contains("get_virtual_price") {
                    vulnerabilities.push(Vulnerability::new(
                        VulnerabilitySeverity::High,
                        VulnerabilityCategory::Reentrancy,
                        "Curve Read-Only Reentrancy Risk".to_string(),
                        "get_virtual_price() is vulnerable to manipulation during remove_liquidity callback".to_string(),
                        idx + 1,
                        line.to_string(),
                        "Use Curve's reentrancy lock or query price before/after liquidity operations".to_string(),
                    ));
                }
            }
        }

        vulnerabilities
    }

    // Permit2 Integration Risks (High)
    // Uniswap's Permit2 has unique security considerations
    fn detect_permit2_risks(&self, content: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        // Check if Permit2 is used
        if !content.contains("Permit2")
            && !content.contains("ISignatureTransfer")
            && !content.contains("IAllowanceTransfer")
            && !content.contains("permit2")
        {
            return vulnerabilities;
        }

        // Check for signature-based transfers
        let permit_transfer_pattern =
            re!(r"(permitTransferFrom|permitWitnessTransferFrom|permit\s*\()");

        for (idx, line) in content.lines().enumerate() {
            if permit_transfer_pattern.is_match(line) {
                let func_body: Vec<&str> = content.lines().skip(idx).take(15).collect();

                // Check for deadline validation
                let has_deadline_check = func_body.iter().any(|l| {
                    l.contains("deadline")
                        && (l.contains("require") || l.contains("if") || l.contains("<="))
                });

                // Check for nonce validation
                let has_nonce_check = func_body
                    .iter()
                    .any(|l| l.contains("nonce") && (l.contains("++") || l.contains("invalidate")));

                if !has_deadline_check {
                    vulnerabilities.push(Vulnerability::new(
                        VulnerabilitySeverity::High,
                        VulnerabilityCategory::SignatureReplay,
                        "Permit2 Missing Deadline Check".to_string(),
                        "Permit2 signature without deadline validation enables indefinite replay"
                            .to_string(),
                        idx + 1,
                        line.to_string(),
                        "Verify permit.deadline >= block.timestamp before processing".to_string(),
                    ));
                }

                if !has_nonce_check && line.contains("permitTransferFrom") {
                    vulnerabilities.push(Vulnerability::new(
                        VulnerabilitySeverity::High,
                        VulnerabilityCategory::SignatureReplay,
                        "Permit2 Nonce Not Invalidated".to_string(),
                        "SignatureTransfer nonce may allow replay if not properly tracked"
                            .to_string(),
                        idx + 1,
                        line.to_string(),
                        "Use unique nonces and verify they're consumed".to_string(),
                    ));
                }
            }
        }

        // Check for AllowanceTransfer approval patterns
        if content.contains("IAllowanceTransfer") || content.contains("allowance") {
            let approve_pattern = re!(r"approve\s*\([^)]*Permit2");

            for (idx, line) in content.lines().enumerate() {
                if approve_pattern.is_match(line)
                    || (line.contains("approve") && content.contains("Permit2"))
                {
                    // Check for amount validation
                    if line.contains("type(uint160).max") || line.contains("type(uint256).max") {
                        vulnerabilities.push(Vulnerability::new(
                            VulnerabilitySeverity::Medium,
                            VulnerabilityCategory::AccessControl,
                            "Unlimited Permit2 Approval".to_string(),
                            "Max approval to Permit2 enables unlimited token transfers if signature is leaked".to_string(),
                            idx + 1,
                            line.to_string(),
                            "Consider limited approvals with specific amounts and deadlines".to_string(),
                        ));
                    }
                }
            }
        }

        vulnerabilities
    }

    // LayerZero Message Validation (High)
    // Cross-chain messaging security patterns
    fn detect_layerzero_validation(&self, content: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        // Check if LayerZero is used
        if !content.contains("LayerZero")
            && !content.contains("lzReceive")
            && !content.contains("LzApp")
            && !content.contains("ILayerZeroEndpoint")
        {
            return vulnerabilities;
        }

        // Check _lzReceive implementation
        let lz_receive_pattern =
            re!(r"function\s+(_lzReceive|lzReceive|_nonblockingLzReceive)\s*\(");

        for (idx, line) in content.lines().enumerate() {
            if lz_receive_pattern.is_match(line) {
                let func_body: Vec<&str> = content.lines().skip(idx).take(30).collect();

                // Check for source chain ID validation
                let has_chain_id_check = func_body.iter().any(|l| {
                    l.contains("_srcChainId")
                        && (l.contains("require")
                            || l.contains("if")
                            || l.contains("trustedRemote"))
                });

                // Check for source address validation
                let has_source_check = func_body.iter().any(|l| {
                    l.contains("trustedRemoteLookup")
                        || l.contains("trustedRemote[")
                        || (l.contains("_srcAddress") && l.contains("require"))
                });

                // Check for payload length validation
                let has_payload_check = func_body.iter().any(|l| {
                    l.contains("_payload.length") && (l.contains("require") || l.contains(">="))
                });

                if !has_chain_id_check {
                    vulnerabilities.push(Vulnerability::high_confidence(
                        VulnerabilitySeverity::Critical,
                        VulnerabilityCategory::BridgeVulnerability,
                        "LayerZero Missing Chain ID Validation".to_string(),
                        "lzReceive doesn't validate source chain ID - accepts messages from any chain".to_string(),
                        idx + 1,
                        line.to_string(),
                        "Add: require(trustedRemoteLookup[_srcChainId].length > 0)".to_string(),
                    ));
                }

                if !has_source_check {
                    vulnerabilities.push(Vulnerability::high_confidence(
                        VulnerabilitySeverity::Critical,
                        VulnerabilityCategory::BridgeVulnerability,
                        "LayerZero Missing Source Address Validation".to_string(),
                        "lzReceive doesn't validate source address - accepts messages from any contract".to_string(),
                        idx + 1,
                        line.to_string(),
                        "Validate _srcAddress matches trustedRemoteLookup[_srcChainId]".to_string(),
                    ));
                }

                if !has_payload_check {
                    vulnerabilities.push(Vulnerability::new(
                        VulnerabilitySeverity::Medium,
                        VulnerabilityCategory::InputValidationFailure,
                        "LayerZero Missing Payload Validation".to_string(),
                        "Cross-chain payload not validated before decoding".to_string(),
                        idx + 1,
                        line.to_string(),
                        "Validate payload length before abi.decode to prevent out-of-bounds"
                            .to_string(),
                    ));
                }
            }
        }

        // Check for setTrustedRemote access control
        let set_trusted_pattern = re!(r"function\s+setTrustedRemote\w*\s*\(");

        for (idx, line) in content.lines().enumerate() {
            if set_trusted_pattern.is_match(line) {
                let func_body: Vec<&str> = content.lines().skip(idx).take(5).collect();

                let has_access_control = func_body.iter().any(|l| {
                    l.contains("onlyOwner") || l.contains("onlyRole") || l.contains("onlyAdmin")
                });

                if !has_access_control {
                    vulnerabilities.push(Vulnerability::high_confidence(
                        VulnerabilitySeverity::Critical,
                        VulnerabilityCategory::AccessControl,
                        "Unprotected setTrustedRemote".to_string(),
                        "Anyone can change trusted remote addresses, enabling cross-chain attack"
                            .to_string(),
                        idx + 1,
                        line.to_string(),
                        "Add onlyOwner or appropriate access control modifier".to_string(),
                    ));
                }
            }
        }

        vulnerabilities
    }

    // EIP-4337 Account Abstraction Vulnerabilities (High)
    // Smart account security patterns
    fn detect_eip4337_vulnerabilities(&self, content: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        // Check if this is an EIP-4337 related contract
        if !content.contains("UserOperation")
            && !content.contains("IAccount")
            && !content.contains("IEntryPoint")
            && !content.contains("validateUserOp")
            && !content.contains("IPaymaster")
        {
            return vulnerabilities;
        }

        // Check validateUserOp implementation
        let validate_pattern = re!(r"function\s+validateUserOp\s*\(");

        for (idx, line) in content.lines().enumerate() {
            if validate_pattern.is_match(line) {
                let func_body: Vec<&str> = content.lines().skip(idx).take(30).collect();

                // Check for signature validation
                let has_sig_check = func_body.iter().any(|l| {
                    l.contains("ecrecover")
                        || l.contains("ECDSA")
                        || l.contains("isValidSignature")
                        || l.contains("SignatureChecker")
                });

                // Check for nonce validation
                let has_nonce_check = func_body
                    .iter()
                    .any(|l| l.contains("userOp.nonce") || l.contains("nonce"));

                // Check for gas validation
                let has_gas_check = func_body.iter().any(|l| {
                    l.contains("prefund")
                        || l.contains("missingAccountFunds")
                        || l.contains("validationData")
                });

                if !has_sig_check {
                    vulnerabilities.push(Vulnerability::high_confidence(
                        VulnerabilitySeverity::Critical,
                        VulnerabilityCategory::AccessControl,
                        "EIP-4337: Missing Signature Validation".to_string(),
                        "validateUserOp doesn't verify signature - anyone can execute operations"
                            .to_string(),
                        idx + 1,
                        line.to_string(),
                        "Add ECDSA signature verification against owner".to_string(),
                    ));
                }

                if !has_nonce_check {
                    vulnerabilities.push(Vulnerability::new(
                        VulnerabilitySeverity::High,
                        VulnerabilityCategory::SignatureReplay,
                        "EIP-4337: Nonce Not Validated".to_string(),
                        "UserOperation nonce not checked - enables replay attacks".to_string(),
                        idx + 1,
                        line.to_string(),
                        "Validate and increment nonce from UserOperation".to_string(),
                    ));
                }

                if !has_gas_check {
                    vulnerabilities.push(Vulnerability::new(
                        VulnerabilitySeverity::Medium,
                        VulnerabilityCategory::DoSAttacks,
                        "EIP-4337: Missing Prefund Validation".to_string(),
                        "Account doesn't properly handle gas prefunding".to_string(),
                        idx + 1,
                        line.to_string(),
                        "Return proper validationData and handle missingAccountFunds".to_string(),
                    ));
                }
            }
        }

        // Check paymaster validation
        let paymaster_pattern = re!(r"function\s+validatePaymasterUserOp\s*\(");

        for (idx, line) in content.lines().enumerate() {
            if paymaster_pattern.is_match(line) {
                let func_body: Vec<&str> = content.lines().skip(idx).take(25).collect();

                // Check for proper return value
                let _has_context = func_body
                    .iter()
                    .any(|l| l.contains("context") && l.contains("return"));

                // Check for sender validation
                let has_sender_check = func_body.iter().any(|l| {
                    l.contains("userOp.sender") && (l.contains("require") || l.contains("if"))
                });

                if !has_sender_check {
                    vulnerabilities.push(Vulnerability::new(
                        VulnerabilitySeverity::High,
                        VulnerabilityCategory::AccessControl,
                        "EIP-4337: Paymaster Missing Sender Validation".to_string(),
                        "Paymaster doesn't validate which accounts it sponsors".to_string(),
                        idx + 1,
                        line.to_string(),
                        "Add allowlist or other validation for sponsored accounts".to_string(),
                    ));
                }
            }
        }

        vulnerabilities
    }

    // Transient Storage (TSTORE/TLOAD) Issues (Medium)
    // EIP-1153 transient storage security patterns
    fn detect_transient_storage_issues(&self, content: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        // Check if transient storage is used
        if !content.contains("tstore")
            && !content.contains("tload")
            && !content.contains("TSTORE")
            && !content.contains("TLOAD")
            && !content.contains("transient")
        {
            return vulnerabilities;
        }

        // Check for transient storage in assembly blocks
        let assembly_pattern = re!(r"assembly\s*\{");

        for (idx, line) in content.lines().enumerate() {
            if assembly_pattern.is_match(line) {
                let asm_body: Vec<&str> = content.lines().skip(idx).take(20).collect();

                let has_tstore = asm_body.iter().any(|l| l.contains("tstore"));
                let has_tload = asm_body.iter().any(|l| l.contains("tload"));

                if has_tstore && !has_tload {
                    // TSTORE without TLOAD might indicate forgotten cleanup
                    vulnerabilities.push(Vulnerability::new(
                        VulnerabilitySeverity::Low,
                        VulnerabilityCategory::StateVariable,
                        "Transient Storage Write Without Read".to_string(),
                        "TSTORE used but TLOAD not found - verify transient value is consumed"
                            .to_string(),
                        idx + 1,
                        line.to_string(),
                        "Ensure transient storage is read within same transaction".to_string(),
                    ));
                }

                // Check for slot collision risk
                if has_tstore || has_tload {
                    let uses_dynamic_slot = asm_body.iter().any(
                        |l| (l.contains("tstore") || l.contains("tload")) && !l.contains("0x"), // Not a constant slot
                    );

                    if uses_dynamic_slot {
                        vulnerabilities.push(Vulnerability::new(
                            VulnerabilitySeverity::Medium,
                            VulnerabilityCategory::StateVariable,
                            "Dynamic Transient Storage Slot".to_string(),
                            "Transient storage with dynamic slot may collide with other uses"
                                .to_string(),
                            idx + 1,
                            line.to_string(),
                            "Use constant slots or namespaced keys to prevent collision"
                                .to_string(),
                        ));
                    }
                }
            }
        }

        // Check for reentrancy lock using transient storage
        if content.contains("transient") && content.contains("lock") {
            // This is actually a good pattern, but warn about proper reset
            let lock_pattern = re!(r"(LOCK|lock|_locked).*transient");

            for (idx, line) in content.lines().enumerate() {
                if lock_pattern.is_match(line) || line.contains("tstore") {
                    // Look for matching reset
                    let func_body: Vec<&str> = content.lines().skip(idx).take(30).collect();

                    let has_reset = func_body
                        .iter()
                        .any(|l| l.contains("tstore") && (l.contains("0") || l.contains("false")));

                    if !has_reset {
                        vulnerabilities.push(Vulnerability::new(
                            VulnerabilitySeverity::Medium,
                            VulnerabilityCategory::Reentrancy,
                            "Transient Lock Not Reset".to_string(),
                            "Transient reentrancy lock may not be reset on all paths".to_string(),
                            idx + 1,
                            line.to_string(),
                            "Ensure lock is reset in finally/cleanup block".to_string(),
                        ));
                    }
                }
            }
        }

        vulnerabilities
    }

    // Create2 Address Collision (Medium)
    // Metamorphic contract and address collision attacks
    fn detect_create2_collision(&self, content: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        // Check if CREATE2 is used
        if !content.contains("create2")
            && !content.contains("CREATE2")
            && !content.contains("Create2")
        {
            return vulnerabilities;
        }

        let create2_pattern = re!(r"(create2|CREATE2)\s*\(");

        for (idx, line) in content.lines().enumerate() {
            if create2_pattern.is_match(line) || line.contains("Create2.deploy") {
                // Check if salt is user-controlled
                let func_context: Vec<&str> = content
                    .lines()
                    .skip(idx.saturating_sub(15))
                    .take(30)
                    .collect();

                let salt_from_param = func_context.iter().any(|l| {
                    l.contains("bytes32 salt")
                        || l.contains("_salt")
                        || (l.contains("salt") && l.contains("calldata"))
                });

                if salt_from_param {
                    vulnerabilities.push(Vulnerability::new(
                        VulnerabilitySeverity::Medium,
                        VulnerabilityCategory::LogicError,
                        "User-Controlled CREATE2 Salt".to_string(),
                        "User-controlled salt enables address prediction and potential griefing"
                            .to_string(),
                        idx + 1,
                        line.to_string(),
                        "Include msg.sender in salt computation to prevent address squatting"
                            .to_string(),
                    ));
                }

                // Check for metamorphic pattern (selfdestruct + create2 reuse)
                if content.contains("selfdestruct") || content.contains("SELFDESTRUCT") {
                    vulnerabilities.push(Vulnerability::high_confidence(
                        VulnerabilitySeverity::Critical,
                        VulnerabilityCategory::LogicError,
                        "CRITICAL: Metamorphic Contract Pattern".to_string(),
                        "CREATE2 with selfdestruct enables metamorphic contracts - code can change at same address".to_string(),
                        idx + 1,
                        line.to_string(),
                        "Verify contract code hash before interacting, avoid selfdestruct in CREATE2 contracts".to_string(),
                    ));
                }
            }
        }

        // Check for address collision in proxy patterns
        if content.contains("implementation") && content.contains("create2") {
            for (idx, line) in content.lines().enumerate() {
                if line.contains("implementation") && line.contains("=") {
                    let func_body: Vec<&str> = content.lines().skip(idx).take(10).collect();

                    let has_code_check = func_body.iter().any(|l| {
                        l.contains("extcodesize")
                            || l.contains("code.length")
                            || l.contains("isContract")
                    });

                    if !has_code_check {
                        vulnerabilities.push(Vulnerability::new(
                            VulnerabilitySeverity::Medium,
                            VulnerabilityCategory::LogicError,
                            "Implementation Without Code Verification".to_string(),
                            "Implementation address set without verifying code exists".to_string(),
                            idx + 1,
                            line.to_string(),
                            "Verify implementation has code: require(impl.code.length > 0)"
                                .to_string(),
                        ));
                    }
                }
            }
        }

        vulnerabilities
    }

    // Merkle Tree Vulnerabilities (Medium)
    // Merkle proof verification security patterns
    fn detect_merkle_tree_vulnerabilities(&self, content: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        // Check if Merkle proofs are used
        if !content.contains("merkle")
            && !content.contains("Merkle")
            && !content.contains("proof")
            && !content.contains("MerkleProof")
        {
            return vulnerabilities;
        }

        // Check for Merkle proof verification
        let verify_pattern = re!(r"(verify|processProof)\s*\(");

        for (idx, line) in content.lines().enumerate() {
            if verify_pattern.is_match(line)
                && (line.contains("merkle") || line.contains("Merkle") || line.contains("proof"))
            {
                let func_body: Vec<&str> = content
                    .lines()
                    .skip(idx.saturating_sub(10))
                    .take(25)
                    .collect();

                // Check for leaf construction with multiple values
                let leaf_construction = func_body
                    .iter()
                    .any(|l| l.contains("keccak256") && l.contains("abi.encode"));

                // Check if leaf includes sender/claimer
                let includes_sender = func_body.iter().any(|l| {
                    l.contains("msg.sender")
                        || l.contains("_claimer")
                        || l.contains("_account")
                        || l.contains("_user")
                });

                if leaf_construction && !includes_sender {
                    vulnerabilities.push(Vulnerability::high_confidence(
                        VulnerabilitySeverity::Critical,
                        VulnerabilityCategory::AccessControl,
                        "CRITICAL: Merkle Proof Without Address Binding".to_string(),
                        "Merkle leaf doesn't include msg.sender - proofs can be stolen/replayed"
                            .to_string(),
                        idx + 1,
                        line.to_string(),
                        "Include msg.sender in leaf: keccak256(abi.encode(msg.sender, amount))"
                            .to_string(),
                    ));
                }

                // Check for second preimage attack (leaf vs node)
                let has_leaf_encoding = func_body
                    .iter()
                    .any(|l| l.contains("abi.encodePacked") && l.contains("keccak256"));

                let has_double_hash = func_body.iter().any(|l| {
                    l.contains("keccak256(keccak256")
                        || (l.contains("keccak256") && l.contains("bytes32"))
                });

                if has_leaf_encoding && !has_double_hash {
                    // Check if using abi.encodePacked with multiple dynamic values
                    let packed_dynamic = func_body.iter().any(|l| {
                        l.contains("abi.encodePacked")
                            && (l.matches("string").count()
                                + l.matches("bytes ").count()
                                + l.matches("bytes,").count())
                                > 1
                    });

                    if packed_dynamic {
                        vulnerabilities.push(Vulnerability::new(
                            VulnerabilitySeverity::High,
                            VulnerabilityCategory::AccessControl,
                            "Merkle Tree Hash Collision Risk".to_string(),
                            "abi.encodePacked with multiple dynamic types enables hash collision"
                                .to_string(),
                            idx + 1,
                            line.to_string(),
                            "Use abi.encode instead of abi.encodePacked for leaf hashing"
                                .to_string(),
                        ));
                    }
                }
            }
        }

        // Check for claimed/used tracking
        if content.contains("merkle") || content.contains("Merkle") {
            let claim_pattern = re!(r"function\s+\w*(claim|mint|redeem)\w*\s*\(");

            for (idx, line) in content.lines().enumerate() {
                if claim_pattern.is_match(line) {
                    let func_body: Vec<&str> = content.lines().skip(idx).take(20).collect();

                    let has_claimed_check = func_body.iter().any(|l| {
                        l.contains("claimed[")
                            || l.contains("hasClaimed[")
                            || l.contains("used[")
                            || l.contains("redeemed[")
                    });

                    let has_claimed_update = func_body.iter().any(|l| {
                        (l.contains("claimed[") || l.contains("hasClaimed["))
                            && l.contains("= true")
                    });

                    if !has_claimed_check || !has_claimed_update {
                        vulnerabilities.push(Vulnerability::high_confidence(
                            VulnerabilitySeverity::Critical,
                            VulnerabilityCategory::AccessControl,
                            "Merkle Claim Without Replay Protection".to_string(),
                            "Merkle-based claim lacks tracking - same proof can be used multiple times".to_string(),
                            idx + 1,
                            line.to_string(),
                            "Track claimed proofs: require(!claimed[leaf]); claimed[leaf] = true;".to_string(),
                        ));
                    }
                }
            }
        }

        vulnerabilities
    }

    // ============================================================================
    // L2/BASE CHAIN SPECIFIC PATTERNS (v0.4.0)
    // Enhanced detection for L2 chains including Base, Optimism, Arbitrum
    // ============================================================================

    /// Analyze L2/Base chain specific vulnerability patterns
    pub fn analyze_l2_patterns(&self, content: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_l2_sequencer_patterns(content));
        vulnerabilities.extend(self.detect_l2_gas_oracle_patterns(content));
        vulnerabilities.extend(self.detect_base_bridge_patterns(content));
        vulnerabilities.extend(self.detect_push0_compatibility(content));
        vulnerabilities.extend(self.detect_uniswap_v4_hook_patterns(content));
        vulnerabilities.extend(self.detect_ccip_patterns(content));
        vulnerabilities.extend(self.detect_eigenlayer_patterns(content));

        vulnerabilities
    }

    // L2 Sequencer Downtime Detection
    // Critical for Chainlink price feeds on L2s
    fn detect_l2_sequencer_patterns(&self, content: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        // Check if using Chainlink on L2
        let uses_chainlink = content.contains("AggregatorV3Interface")
            || content.contains("latestRoundData")
            || content.contains("priceFeed");

        let is_l2_aware = content.contains("sequencer")
            || content.contains("Sequencer")
            || content.contains("L2_SEQUENCER");

        if uses_chainlink && !is_l2_aware {
            // Look for price feed usage without sequencer check
            let price_pattern = re!(r"latestRoundData\s*\(\s*\)");

            for (idx, line) in content.lines().enumerate() {
                if price_pattern.is_match(line) {
                    vulnerabilities.push(Vulnerability::high_confidence(
                        VulnerabilitySeverity::Critical,
                        VulnerabilityCategory::L2SequencerDowntime,
                        "CRITICAL: L2 Sequencer Uptime Not Checked".to_string(),
                        "Chainlink price feed used without L2 sequencer uptime check. During sequencer downtime, stale prices can be exploited for liquidations.".to_string(),
                        idx + 1,
                        line.to_string(),
                        "Add sequencer uptime feed check: require(block.timestamp - startedAt > GRACE_PERIOD)".to_string(),
                    ));
                }
            }
        }

        // Check for grace period after sequencer recovery
        if is_l2_aware {
            let has_grace_period = content.contains("GRACE_PERIOD")
                || content.contains("gracePeriod")
                || content.contains("3600"); // 1 hour is common

            if !has_grace_period {
                for (idx, line) in content.lines().enumerate() {
                    if line.contains("sequencer")
                        && (line.contains("isSequencerUp") || line.contains("answer"))
                    {
                        vulnerabilities.push(Vulnerability::new(
                            VulnerabilitySeverity::High,
                            VulnerabilityCategory::L2SequencerDowntime,
                            "L2 Sequencer Check Missing Grace Period".to_string(),
                            "Sequencer uptime checked but no grace period after recovery"
                                .to_string(),
                            idx + 1,
                            line.to_string(),
                            "Add grace period: require(block.timestamp - startedAt > GRACE_PERIOD)"
                                .to_string(),
                        ));
                        break;
                    }
                }
            }
        }

        vulnerabilities
    }

    // L2 Gas Oracle Manipulation Detection
    fn detect_l2_gas_oracle_patterns(&self, content: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        // Check for L1 gas price dependencies
        let uses_l1_gas = content.contains("l1GasPrice")
            || content.contains("L1_GAS")
            || content.contains("getL1Fee")
            || content.contains("OVM_GasPriceOracle");

        if uses_l1_gas {
            let oracle_pattern = re!(r"(l1GasPrice|getL1Fee|L1_GAS)\s*\(?\s*\)?");

            for (idx, line) in content.lines().enumerate() {
                if oracle_pattern.is_match(line) {
                    // Check for manipulation protection
                    let func_body: Vec<&str> = content
                        .lines()
                        .skip(idx.saturating_sub(5))
                        .take(15)
                        .collect();

                    let has_bounds_check = func_body.iter().any(|l| {
                        l.contains("maxL1Gas")
                            || l.contains("MAX_L1")
                            || l.contains("< ")
                            || l.contains("> ")
                            || l.contains("require(") && l.contains("gas")
                    });

                    if !has_bounds_check {
                        vulnerabilities.push(Vulnerability::new(
                            VulnerabilitySeverity::Medium,
                            VulnerabilityCategory::L2GasOracle,
                            "L2 Gas Oracle Without Bounds Check".to_string(),
                            "L1 gas price used without bounds - can be manipulated during gas spikes".to_string(),
                            idx + 1,
                            line.to_string(),
                            "Add bounds: require(l1GasPrice <= MAX_L1_GAS_PRICE)".to_string(),
                        ));
                    }
                }
            }
        }

        // Check for block.basefee usage on L2
        if content.contains("block.basefee") {
            for (idx, line) in content.lines().enumerate() {
                if line.contains("block.basefee") {
                    vulnerabilities.push(Vulnerability::new(
                        VulnerabilitySeverity::Low,
                        VulnerabilityCategory::L2GasOracle,
                        "block.basefee on L2".to_string(),
                        "block.basefee behaves differently on L2 - may not reflect true gas costs"
                            .to_string(),
                        idx + 1,
                        line.to_string(),
                        "Consider using L2-specific gas oracle for accurate fee estimation"
                            .to_string(),
                    ));
                }
            }
        }

        vulnerabilities
    }

    // Base Chain Bridge Security Patterns
    fn detect_base_bridge_patterns(&self, content: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        // Check for Base/Optimism bridge patterns
        let is_bridge_related = content.contains("CrossDomainMessenger")
            || content.contains("L1StandardBridge")
            || content.contains("L2StandardBridge")
            || content.contains("OptimismPortal");

        if !is_bridge_related {
            return vulnerabilities;
        }

        // Check for xDomainMessageSender validation
        let message_pattern =
            re!(r"function\s+\w+\s*\([^)]*\)\s+(external|public)");

        for (idx, line) in content.lines().enumerate() {
            if message_pattern.is_match(line) {
                let func_body: Vec<&str> = content.lines().skip(idx).take(15).collect();

                let uses_cross_domain = func_body.iter().any(|l| {
                    l.contains("xDomainMessageSender") || l.contains("CrossDomainMessenger")
                });

                if uses_cross_domain {
                    let has_sender_check = func_body
                        .iter()
                        .any(|l| l.contains("require(") && l.contains("xDomainMessageSender"));

                    let has_messenger_check = func_body
                        .iter()
                        .any(|l| l.contains("msg.sender") && l.contains("messenger"));

                    if !has_sender_check || !has_messenger_check {
                        vulnerabilities.push(Vulnerability::high_confidence(
                            VulnerabilitySeverity::Critical,
                            VulnerabilityCategory::BaseBridgeSecurity,
                            "Base/Optimism Bridge Message Not Validated".to_string(),
                            "Cross-domain message handler lacks proper sender validation".to_string(),
                            idx + 1,
                            line.to_string(),
                            "Validate: require(msg.sender == messenger && messenger.xDomainMessageSender() == expectedSender)".to_string(),
                        ));
                    }
                }
            }
        }

        // Check for finalization period awareness
        if content.contains("finalize") || content.contains("Finalize") {
            let has_delay_check = content.contains("FINALIZATION_PERIOD")
                || content.contains("finalizationPeriod")
                || content.contains("7 days");

            if !has_delay_check {
                for (idx, line) in content.lines().enumerate() {
                    if line.contains("finalize") && !line.contains("//") {
                        vulnerabilities.push(Vulnerability::new(
                            VulnerabilitySeverity::Medium,
                            VulnerabilityCategory::BaseBridgeSecurity,
                            "Bridge Finalization Period Not Enforced".to_string(),
                            "Optimistic rollup requires 7-day finalization for withdrawals"
                                .to_string(),
                            idx + 1,
                            line.to_string(),
                            "Enforce finalization period before processing withdrawals".to_string(),
                        ));
                        break;
                    }
                }
            }
        }

        vulnerabilities
    }

    // FN-6: PUSH0 Opcode Compatibility Detection - warn for ALL 0.8.20+ contracts
    fn detect_push0_compatibility(&self, content: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        // Check pragma version for PUSH0 compatibility
        let pragma_pattern = re!(r"pragma\s+solidity\s*[\^>=<\s]*(\d+\.\d+\.\d+)");

        for (idx, line) in content.lines().enumerate() {
            if let Some(captures) = pragma_pattern.captures(line) {
                if let Some(version) = captures.get(1) {
                    let version_str = version.as_str();

                    // PUSH0 was introduced in 0.8.20
                    if version_str.starts_with("0.8.") {
                        if let Ok(minor) =
                            version_str.split('.').nth(2).unwrap_or("0").parse::<u32>()
                        {
                            if minor >= 20 {
                                // Only suppress if contract explicitly mentions Shanghai-compatible deployment
                                let explicitly_shanghai = content
                                    .contains("// evm-version: shanghai")
                                    || content.contains("// shanghai")
                                    || content.contains("evm_version = \"shanghai\"");

                                if !explicitly_shanghai {
                                    // Info, not Medium: by 2026 nearly all major chains
                                    // support Shanghai/PUSH0. This is a deployment note,
                                    // not a vulnerability in the contract itself.
                                    vulnerabilities.push(Vulnerability::new(
                                        VulnerabilitySeverity::Info,
                                        VulnerabilityCategory::Push0Compatibility,
                                        "PUSH0 Opcode Compatibility Risk".to_string(),
                                        format!(
                                            "Solidity {version_str} uses PUSH0 opcode which is not supported on chains that haven't activated Shanghai (Arbitrum, older BSC, some L2s)"
                                        ),
                                        idx + 1,
                                        line.to_string(),
                                        "Use --evm-version paris to avoid PUSH0, or verify all target chains support Shanghai".to_string(),
                                    ));
                                }
                            }
                        }
                    }
                }
            }
        }

        vulnerabilities
    }

    // Uniswap V4 Hook Exploitation Patterns
    fn detect_uniswap_v4_hook_patterns(&self, content: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        // Check if this is a Uniswap V4 hook
        if !content.contains("IHooks")
            && !content.contains("BaseHook")
            && !content.contains("beforeSwap")
            && !content.contains("afterSwap")
        {
            return vulnerabilities;
        }

        // Check hook implementations
        let hook_pattern =
            re!(r"function\s+(before|after)(Swap|AddLiquidity|RemoveLiquidity|Donate)\s*\(");

        for (idx, line) in content.lines().enumerate() {
            if hook_pattern.is_match(line) {
                let func_body: Vec<&str> = content.lines().skip(idx).take(25).collect();

                // Check for reentrancy protection
                let has_lock = func_body.iter().any(|l| {
                    l.contains("nonReentrant") || l.contains("lock") || l.contains("_lock")
                });

                // Check for caller validation
                let has_caller_check = func_body.iter().any(|l| {
                    l.contains("PoolManager")
                        || l.contains("poolManager")
                        || l.contains("msg.sender") && l.contains("require")
                });

                if !has_caller_check {
                    vulnerabilities.push(Vulnerability::high_confidence(
                        VulnerabilitySeverity::Critical,
                        VulnerabilityCategory::UniswapV4HookExploit,
                        "Uniswap V4 Hook Missing Caller Validation".to_string(),
                        "Hook function can be called by any contract, not just PoolManager"
                            .to_string(),
                        idx + 1,
                        line.to_string(),
                        "Validate: require(msg.sender == address(poolManager))".to_string(),
                    ));
                }

                if !has_lock && line.contains("beforeSwap") {
                    vulnerabilities.push(Vulnerability::new(
                        VulnerabilitySeverity::High,
                        VulnerabilityCategory::UniswapV4HookExploit,
                        "V4 Hook Reentrancy Risk".to_string(),
                        "beforeSwap hook without reentrancy protection".to_string(),
                        idx + 1,
                        line.to_string(),
                        "Add reentrancy protection to prevent callback attacks".to_string(),
                    ));
                }

                // Check for state modifications in view hooks
                if line.contains("view")
                    && func_body
                        .iter()
                        .any(|l| l.contains("=") && !l.contains("=="))
                {
                    vulnerabilities.push(Vulnerability::new(
                        VulnerabilitySeverity::Medium,
                        VulnerabilityCategory::UniswapV4HookExploit,
                        "V4 Hook State in View Function".to_string(),
                        "View hook appears to modify state which will revert".to_string(),
                        idx + 1,
                        line.to_string(),
                        "Remove view modifier or remove state modifications".to_string(),
                    ));
                }
            }
        }

        vulnerabilities
    }

    // Chainlink CCIP Cross-Chain Patterns
    fn detect_ccip_patterns(&self, content: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        // Check if CCIP is used
        if !content.contains("ccipReceive")
            && !content.contains("CCIPReceiver")
            && !content.contains("IRouterClient")
        {
            return vulnerabilities;
        }

        // Check ccipReceive implementation
        let receive_pattern = re!(r"function\s+_ccipReceive\s*\(");

        for (idx, line) in content.lines().enumerate() {
            if receive_pattern.is_match(line) || line.contains("ccipReceive") {
                let func_body: Vec<&str> = content.lines().skip(idx).take(25).collect();

                // Check for source chain validation
                let has_chain_check = func_body.iter().any(|l| {
                    l.contains("sourceChainSelector") && (l.contains("require") || l.contains("if"))
                });

                // Check for sender validation
                let has_sender_check = func_body.iter().any(|l| {
                    l.contains("allowlistedSender")
                        || l.contains("trustedSender")
                        || (l.contains("sender") && l.contains("require"))
                });

                if !has_chain_check {
                    vulnerabilities.push(Vulnerability::high_confidence(
                        VulnerabilitySeverity::Critical,
                        VulnerabilityCategory::CrossChainMessageReplay,
                        "CCIP Missing Source Chain Validation".to_string(),
                        "CCIP receiver doesn't validate source chain selector".to_string(),
                        idx + 1,
                        line.to_string(),
                        "Validate: require(allowlistedChains[sourceChainSelector])".to_string(),
                    ));
                }

                if !has_sender_check {
                    vulnerabilities.push(Vulnerability::high_confidence(
                        VulnerabilitySeverity::Critical,
                        VulnerabilityCategory::CrossChainMessageReplay,
                        "CCIP Missing Sender Validation".to_string(),
                        "CCIP receiver doesn't validate message sender".to_string(),
                        idx + 1,
                        line.to_string(),
                        "Validate sender is allowlisted for the source chain".to_string(),
                    ));
                }
            }
        }

        vulnerabilities
    }

    // EigenLayer Restaking Patterns
    fn detect_eigenlayer_patterns(&self, content: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        // Check if EigenLayer related
        if !content.contains("EigenLayer")
            && !content.contains("restake")
            && !content.contains("AVS")
            && !content.contains("StrategyManager")
        {
            return vulnerabilities;
        }

        // Check for slashing conditions
        let stake_pattern = re!(r"function\s+(stake|deposit|restake)\w*\s*\(");

        for (idx, line) in content.lines().enumerate() {
            if stake_pattern.is_match(line) {
                let func_body: Vec<&str> = content.lines().skip(idx).take(20).collect();

                // Check for withdrawal delay
                let has_delay = func_body.iter().any(|l| {
                    l.contains("withdrawalDelay")
                        || l.contains("WITHDRAWAL_DELAY")
                        || l.contains("minWithdrawalDelay")
                });

                // Check for slashing protection
                let has_slashing_check = content.contains("slashingCondition")
                    || content.contains("canSlash")
                    || content.contains("isSlashed");

                if !has_delay {
                    vulnerabilities.push(Vulnerability::new(
                        VulnerabilitySeverity::Medium,
                        VulnerabilityCategory::AccessControl,
                        "EigenLayer Missing Withdrawal Delay".to_string(),
                        "Restaking without withdrawal delay enables rapid unstaking".to_string(),
                        idx + 1,
                        line.to_string(),
                        "Implement withdrawal delay to prevent flash loan attacks".to_string(),
                    ));
                }

                if !has_slashing_check {
                    vulnerabilities.push(Vulnerability::new(
                        VulnerabilitySeverity::Low,
                        VulnerabilityCategory::AccessControl,
                        "EigenLayer Slashing Not Implemented".to_string(),
                        "Restaking contract doesn't implement slashing conditions".to_string(),
                        idx + 1,
                        line.to_string(),
                        "Implement slashing for AVS operators".to_string(),
                    ));
                }
            }
        }

        vulnerabilities
    }

    // ============================================================================
    // RESEARCH PAPER VULNERABILITIES
    // From: "Security Analysis of DeFi" (arXiv:2205.09524v1)
    // ============================================================================

    /// Analyze vulnerabilities from the DeFi security research paper
    pub fn analyze_defi_paper_vulnerabilities(&self, content: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        // ERC-777 Callback Reentrancy (dForce $24M)
        vulnerabilities.extend(self.detect_erc777_reentrancy(content));

        // Greedy Contract (Locked ETH)
        vulnerabilities.extend(self.detect_greedy_contract(content));

        // Double Claiming Attack (Popsicle Finance $25M)
        vulnerabilities.extend(self.detect_double_claiming_pattern(content));

        // Missing Emergency Stop
        vulnerabilities.extend(self.detect_missing_emergency_stop(content));

        // Signature Verification Bypass (Wormhole $326M)
        vulnerabilities.extend(self.detect_signature_bypass_patterns(content));

        vulnerabilities
    }

    /// Detect ERC-777 callback reentrancy (dForce $24M attack pattern)
    /// ERC-777 tokens have hooks (tokensReceived/tokensToSend) that can enable reentrancy
    fn detect_erc777_reentrancy(&self, content: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        // Check for ERC-777 usage
        let has_erc777 = content.contains("IERC777")
            || content.contains("ERC777")
            || content.contains("tokensReceived")
            || content.contains("tokensToSend")
            || content.contains("ERC777TokensSender")
            || content.contains("ERC777TokensRecipient");

        if !has_erc777 {
            return vulnerabilities;
        }

        // Check for reentrancy protection
        let has_protection = content.contains("ReentrancyGuard")
            || content.contains("nonReentrant")
            || content.contains("_status");

        if !has_protection {
            // Find where ERC-777 is used
            let erc777_pattern = re!(r"IERC777|ERC777|tokensReceived|tokensToSend");

            for (idx, line) in content.lines().enumerate() {
                if erc777_pattern.is_match(line) {
                    vulnerabilities.push(Vulnerability::high_confidence(
                        VulnerabilitySeverity::Critical,
                        VulnerabilityCategory::ERC777CallbackReentrancy,
                        "ERC-777 Token Without Reentrancy Guard (dForce Pattern)".to_string(),
                        "ERC-777 token interaction without ReentrancyGuard - $24M dForce exploit pattern".to_string(),
                        idx + 1,
                        line.to_string(),
                        "Add ReentrancyGuard to all functions that interact with ERC-777 tokens".to_string(),
                    ));
                    break; // Only report once
                }
            }
        }

        // Also check for state changes after ERC-777 transfers
        let lines: Vec<&str> = content.lines().collect();
        for (idx, line) in lines.iter().enumerate() {
            if line.contains(".send(") || line.contains("IERC777(") {
                // Look for state changes after the transfer
                for &future_line in lines.iter().skip(idx + 1).take(9) {
                    if (future_line.contains("=") && !future_line.contains("=="))
                        && (future_line.contains("balance")
                            || future_line.contains("total")
                            || future_line.contains("amount")
                            || future_line.contains("debt"))
                        && !has_protection {
                            vulnerabilities.push(Vulnerability::high_confidence(
                                VulnerabilitySeverity::Critical,
                                VulnerabilityCategory::ERC777CallbackReentrancy,
                                "State Change After ERC-777 Transfer".to_string(),
                                "State modification after ERC-777 token transfer enables callback reentrancy".to_string(),
                                idx + 1,
                                line.to_string(),
                                "Move all state changes before ERC-777 transfers or use ReentrancyGuard".to_string(),
                            ));
                            break;
                        }
                }
            }
        }

        vulnerabilities
    }

    /// Detect greedy contracts that can receive but not withdraw ETH
    /// Table I from paper: "Greedy Contracts - Receive but not withdraw Ethers"
    fn detect_greedy_contract(&self, content: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        // Check for receive/fallback payable
        let can_receive = content.contains("receive()") && content.contains("payable")
            || content.contains("fallback()") && content.contains("payable")
            || re!(r"function\s+\w+\([^)]*\)\s+(external|public)\s+payable")
                .is_match(content);

        if !can_receive {
            return vulnerabilities;
        }

        // Check for withdrawal mechanism (including indirect ones: contracts that can
        // make arbitrary/value-bearing calls — executors, wallets, proxies — can always
        // move ETH out, so their ETH is not locked).
        let has_withdraw = content.contains("withdraw")
            || content.contains("transfer(")
            || content.contains(".send(")
            || content.contains(".call{value:")
            || content.contains("payable(")
            || content.contains("selfdestruct")
            || content.contains("functionCallWithValue")
            || content.contains("sendValue")
            || content.contains("delegatecall")
            || content.contains("LowLevelCall")
            || content.contains("execute");

        if !has_withdraw {
            // Find the payable function
            let payable_pattern = re!(r"(receive|fallback)\s*\(\s*\)\s*(external\s+)?payable|function\s+\w+\([^)]*\)\s+(external|public)\s+payable");

            for (idx, line) in content.lines().enumerate() {
                if payable_pattern.is_match(line) {
                    vulnerabilities.push(Vulnerability::high_confidence(
                        VulnerabilitySeverity::High,
                        VulnerabilityCategory::GreedyContract,
                        "Greedy Contract - ETH Can Be Locked Forever".to_string(),
                        "Contract can receive ETH but has no withdrawal mechanism - funds may be locked forever".to_string(),
                        idx + 1,
                        line.to_string(),
                        "Add a withdraw function to allow ETH extraction".to_string(),
                    ));
                    break;
                }
            }
        }

        vulnerabilities
    }

    /// Detect double-claiming attack patterns (Popsicle Finance $25M)
    /// LP tokens can be transferred between addresses to claim rewards multiple times
    fn detect_double_claiming_pattern(&self, content: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        // Check if this is a rewards/staking contract
        let is_rewards_contract = content.contains("reward")
            || content.contains("Reward")
            || content.contains("stake")
            || content.contains("Stake")
            || content.contains("farm")
            || content.contains("Farm");

        if !is_rewards_contract {
            return vulnerabilities;
        }

        // Look for claiming functions
        let claim_pattern = re!(r"function\s+(claim|harvest|getReward|collectFee|collectReward)\w*\s*\([^)]*\)");

        for (idx, line) in content.lines().enumerate() {
            if claim_pattern.is_match(line) {
                // Look at function body
                let func_body: Vec<&str> = content.lines().skip(idx).take(30).collect();

                // Check for reward debt pattern (proper protection)
                let has_debt_tracking = func_body.iter().any(|l| {
                    l.contains("rewardDebt")
                        || l.contains("claimedAmount")
                        || l.contains("userRewardPaid")
                        || l.contains("_rewardPaid")
                });

                // Check for balance-based reward calculation (vulnerable)
                let uses_balance_for_reward = func_body.iter().any(|l| {
                    (l.contains("balanceOf") || l.contains("_balances["))
                        && (l.contains("reward") || l.contains("*"))
                });

                // Check for transfer hooks that reset claims
                let has_transfer_hook = content.contains("_beforeTokenTransfer")
                    || content.contains("_afterTokenTransfer")
                    || content.contains("_transfer");

                if uses_balance_for_reward && !has_debt_tracking {
                    vulnerabilities.push(Vulnerability::high_confidence(
                        VulnerabilitySeverity::High,
                        VulnerabilityCategory::DoubleClaiming,
                        "Double-Claiming Vulnerability (Popsicle Finance Pattern)".to_string(),
                        "Reward calculation based on balance without debt tracking - $25M Popsicle Finance exploit".to_string(),
                        idx + 1,
                        line.to_string(),
                        "Use rewardDebt pattern: track total rewards and subtract already claimed amount".to_string(),
                    ));
                }

                if uses_balance_for_reward && !has_transfer_hook {
                    vulnerabilities.push(Vulnerability::new(
                        VulnerabilitySeverity::Medium,
                        VulnerabilityCategory::DoubleClaiming,
                        "Missing Transfer Hook for Reward Reset".to_string(),
                        "LP tokens can be transferred without resetting reward claims".to_string(),
                        idx + 1,
                        line.to_string(),
                        "Implement _beforeTokenTransfer to claim/reset rewards before LP transfers"
                            .to_string(),
                    ));
                }
            }
        }

        vulnerabilities
    }

    /// Detect missing emergency stop / circuit breaker (Table I: "Missing Interrupter")
    /// DeFi contracts need pause mechanisms for incident response
    fn detect_missing_emergency_stop(&self, content: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        // Check if this is a DeFi contract with critical operations
        let defi_operations = ["swap",
            "deposit",
            "withdraw",
            "stake",
            "unstake",
            "borrow",
            "repay",
            "liquidate"];
        let is_defi = defi_operations
            .iter()
            .any(|op| content.to_lowercase().contains(op));

        if !is_defi {
            return vulnerabilities;
        }

        // Check for pausable pattern
        let has_pausable = content.contains("Pausable")
            || content.contains("whenNotPaused")
            || content.contains("paused()")
            || content.contains("_pause")
            || content.contains("isPaused");

        if !has_pausable {
            // Find critical DeFi functions without pause
            let critical_pattern = re!(r"function\s+(swap|deposit|withdraw|stake|unstake|borrow|repay|liquidate)\w*\s*\([^)]*\)\s+(external|public)");

            for (idx, line) in content.lines().enumerate() {
                if critical_pattern.is_match(line) {
                    vulnerabilities.push(Vulnerability::new(
                        VulnerabilitySeverity::Medium,
                        VulnerabilityCategory::MissingEmergencyStop,
                        "DeFi Contract Missing Emergency Stop".to_string(),
                        "Critical DeFi function without pause mechanism - no circuit breaker for incident response".to_string(),
                        idx + 1,
                        line.to_string(),
                        "Implement Pausable pattern: add whenNotPaused modifier to critical functions".to_string(),
                    ));
                    break; // Report once per contract
                }
            }
        }

        vulnerabilities
    }

    /// Detect signature verification bypass patterns (Wormhole $326M)
    /// Incomplete signature verification allows message forgery
    fn detect_signature_bypass_patterns(&self, content: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        // Check for signature verification code
        let has_sig_verification = content.contains("ecrecover")
            || content.contains("ECDSA.recover")
            || content.contains("SignatureChecker")
            || content.contains("verifySignature")
            || content.contains("verify_signature");

        if !has_sig_verification {
            return vulnerabilities;
        }

        // Look for custom verification functions (higher risk)
        let custom_verify_pattern =
            re!(r"function\s+verify\w*[Ss]ignature\w*\s*\([^)]*\)");

        for (idx, line) in content.lines().enumerate() {
            if custom_verify_pattern.is_match(line) {
                let func_body: Vec<&str> = content.lines().skip(idx).take(30).collect();

                // Check for proper account validation
                let has_account_validation = func_body.iter().any(|l| {
                    (l.contains("require") || l.contains("if"))
                        && (l.contains("account")
                            || l.contains("signer")
                            || l.contains("address(0)"))
                });

                // Check for message hash validation
                let has_message_validation = func_body
                    .iter()
                    .any(|l| l.contains("keccak256") || l.contains("hash") || l.contains("digest"));

                if !has_account_validation {
                    vulnerabilities.push(Vulnerability::high_confidence(
                        VulnerabilitySeverity::Critical,
                        VulnerabilityCategory::SignatureVerificationBypass,
                        "Signature Verification Without Account Validation (Wormhole Pattern)".to_string(),
                        "Custom signature verification without proper account validation - $326M Wormhole exploit pattern".to_string(),
                        idx + 1,
                        line.to_string(),
                        "Validate recovered address: require(signer != address(0) && signer == expected)".to_string(),
                    ));
                }

                if !has_message_validation {
                    vulnerabilities.push(Vulnerability::new(
                        VulnerabilitySeverity::High,
                        VulnerabilityCategory::SignatureVerificationBypass,
                        "Signature Verification Missing Message Hash".to_string(),
                        "Signature verification without message hash validation can be exploited"
                            .to_string(),
                        idx + 1,
                        line.to_string(),
                        "Use structured message hashing (EIP-712) with domain separator"
                            .to_string(),
                    ));
                }
            }
        }

        // Check ecrecover usage specifically
        for (idx, line) in content.lines().enumerate() {
            if line.contains("ecrecover(") {
                // Check wider context (15 lines before and after) for address(0) validation
                let start = idx.saturating_sub(15);
                let surrounding: Vec<&str> = content.lines().skip(start).take(30).collect();

                // Check if result is validated (recoveredAddress != address(0), etc.)
                let has_zero_check = surrounding.iter().any(|l| {
                    (l.contains("address(0)")
                        && (l.contains("!=") || l.contains("require") || l.contains("if")))
                        || l.contains("!= 0")
                        || l.contains("> 0")
                        || l.contains("recoveredAddress != address(0)")
                        || l.contains("recovered != address(0)")
                        || l.contains("signer != address(0)")
                });

                if !has_zero_check {
                    vulnerabilities.push(Vulnerability::high_confidence(
                        VulnerabilitySeverity::Critical,
                        VulnerabilityCategory::SignatureVerificationBypass,
                        "ecrecover Result Not Validated".to_string(),
                        "ecrecover returns address(0) for invalid signatures - must be checked"
                            .to_string(),
                        idx + 1,
                        line.to_string(),
                        "Add: require(recovered != address(0), 'Invalid signature')".to_string(),
                    ));
                }

                // FN-7: Check for s-value malleability protection
                let uses_ecdsa_lib =
                    content.contains("ECDSA.recover") || content.contains("ECDSA.tryRecover");
                if !uses_ecdsa_lib {
                    let surrounding: Vec<&str> = content
                        .lines()
                        .skip(idx.saturating_sub(20))
                        .take(40)
                        .collect();
                    let context = surrounding.join("\n");
                    let has_s_check = context.contains("0x7FFFFFFF")
                        || context.contains("secp256k1n")
                        || context.contains("s <= ")
                        || context.contains("s < ")
                        || context.contains("malleab");
                    if !has_s_check {
                        vulnerabilities.push(Vulnerability::new(
                            VulnerabilitySeverity::Medium,
                            VulnerabilityCategory::SignatureVulnerabilities,
                            "Signature Malleability - Missing s-value Check".to_string(),
                            "ecrecover without s-value bounds checking allows signature malleability (same hash, different valid signature)".to_string(),
                            idx + 1,
                            line.to_string(),
                            "Use OpenZeppelin ECDSA library, or add: require(uint256(s) <= 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0)".to_string(),
                        ));
                    }
                }
            }
        }

        vulnerabilities
    }

    // ============================================================================
    // SECURITY HARDENING PATTERNS (v0.6.0)
    // New detection functions for common security pitfalls
    // ============================================================================

    /// Main entry point for v0.6.0 security hardening analysis.
    /// Covers storage gaps, timelocks, downcasting, deprecated opcodes, and more.
    pub fn analyze_security_hardening(&self, content: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_storage_collision_proxy(content));
        vulnerabilities.extend(self.detect_missing_timelock(content));
        vulnerabilities.extend(self.detect_unsafe_downcast_patterns(content));
        vulnerabilities.extend(self.detect_missing_erc165(content));
        vulnerabilities.extend(self.detect_unprotected_initialize(content));
        vulnerabilities.extend(self.detect_missing_gap_in_base(content));

        vulnerabilities
    }

    /// Detect storage collision risk in upgradeable contracts.
    /// Checks for contracts that inherit Upgradeable patterns but don't declare
    /// a storage gap (__gap), which prevents safe future state variable additions.
    fn detect_storage_collision_proxy(&self, content: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        // Only apply to upgradeable contracts
        if !content.contains("Upgradeable") && !content.contains("Initializable") {
            return vulnerabilities;
        }

        // Already has storage gap - safe
        if content.contains("__gap") {
            return vulnerabilities;
        }

        // ERC-7201 namespaced storage (OZ v5 style) replaces storage gaps entirely
        if content.contains("@custom:storage-location") {
            return vulnerabilities;
        }

        // Check if this contract could be inherited (has state variables)
        let state_var_pattern =
            re!(r"^\s+(uint\d*|int\d*|address|bool|bytes\d*|string|mapping)\s+");

        let has_state_vars = content.lines().any(|line| state_var_pattern.is_match(line));

        if has_state_vars {
            let contract_pattern = re!(r"contract\s+(\w+)\s+is");
            for (idx, line) in content.lines().enumerate() {
                let trimmed = line.trim_start();
                if trimmed.starts_with("//") || trimmed.starts_with('*') || trimmed.starts_with("/*")
                {
                    continue;
                }
                if let Some(caps) = contract_pattern.captures(line) {
                    let name = caps.get(1).map_or("Unknown", |m| m.as_str());
                    // Proxies and beacons hold no implementation state to gap; the
                    // "Upgradeable" in their NAME does not make them upgradeable bases.
                    if name.ends_with("Proxy") || name.ends_with("Beacon") {
                        continue;
                    }
                    if line.contains("Upgradeable") || line.contains("Initializable") {
                        vulnerabilities.push(Vulnerability::new(
                            VulnerabilitySeverity::High,
                            VulnerabilityCategory::MissingStorageGap,
                            format!("Missing Storage Gap in {name}"),
                            "Upgradeable contract with state variables but no __gap. Adding new variables in future upgrades will shift storage slots of child contracts, corrupting their data.".to_string(),
                            idx + 1,
                            line.trim().to_string(),
                            "Add `uint256[50] private __gap;` after all state variable declarations.".to_string(),
                        ));
                        break;
                    }
                }
            }
        }

        vulnerabilities
    }

    /// Detect admin/privileged functions that lack a timelock delay.
    /// Critical operations (ownership transfer, parameter changes, withdrawals) should
    /// have a time delay to allow users to react before changes take effect.
    fn detect_missing_timelock(&self, content: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        // Skip if contract already uses a timelock
        if content.contains("TimelockController")
            || content.contains("Timelock")
            || content.contains("timelock")
            || content.contains("delay") && content.contains("queue")
        {
            return vulnerabilities;
        }

        // Look for critical admin functions
        let admin_fn_pattern = re!(r"function\s+(setFee|updateFee|changeFee|setOracle|updateOracle|setAdmin|changeAdmin|setReward|updateReward|setTreasury|setReceiver|setPauser|setMinter|changeOwner)\s*\([^)]*\)\s+(?:external|public)");

        for (idx, line) in content.lines().enumerate() {
            if admin_fn_pattern.is_match(line) {
                // Check if there's a delay mechanism in the next 20 lines
                let end = (idx + 20).min(content.lines().count());
                let func_body: String = content
                    .lines()
                    .skip(idx)
                    .take(end - idx)
                    .collect::<Vec<_>>()
                    .join("\n");

                let has_delay = func_body.contains("delay")
                    || func_body.contains("pending")
                    || func_body.contains("queue")
                    || func_body.contains("timelock")
                    || func_body.contains("block.timestamp +")
                    || func_body.contains("block.timestamp >=");

                if !has_delay {
                    vulnerabilities.push(Vulnerability::new(
                        VulnerabilitySeverity::Medium,
                        VulnerabilityCategory::MissingTimelock,
                        "Missing Timelock on Admin Function".to_string(),
                        "Critical parameter change function executes immediately without time delay. Users cannot react to malicious or accidental parameter changes.".to_string(),
                        idx + 1,
                        line.trim().to_string(),
                        "Implement a timelock pattern: queue the change, wait for a delay period, then execute. Consider OpenZeppelin's TimelockController.".to_string(),
                    ));
                }
            }
        }

        vulnerabilities
    }

    /// Detect unsafe integer downcasting patterns that could silently truncate values.
    /// In Solidity, casting from a larger type to a smaller type (e.g., uint256 → uint128)
    /// silently truncates, potentially leading to loss of funds.
    fn detect_unsafe_downcast_patterns(&self, content: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        // Skip if SafeCast is used
        if content.contains("SafeCast") || content.contains("safeCast") {
            return vulnerabilities;
        }

        // Detect explicit downcasts of non-constant expressions in financial contexts
        let downcast_pattern = re!(r"\b(uint(?:8|16|32|48|64|96|128)|int(?:8|16|32|48|64|96|128))\s*\(\s*(\w+(?:\.\w+|\[\w+\])*)\s*\)");

        let financial_vars = [
            "amount",
            "balance",
            "supply",
            "reserve",
            "liquidity",
            "price",
            "fee",
            "reward",
            "deposit",
            "value",
            "totalSupply",
        ];

        for (idx, line) in content.lines().enumerate() {
            if line.trim().starts_with("//") || line.trim().starts_with("*") {
                continue;
            }
            if let Some(caps) = downcast_pattern.captures(line) {
                let var_name = caps.get(2).map_or("", |m| m.as_str());
                // Only flag if it's a financial-looking variable
                if financial_vars
                    .iter()
                    .any(|fv| var_name.to_lowercase().contains(fv))
                {
                    vulnerabilities.push(Vulnerability::new(
                        VulnerabilitySeverity::Medium,
                        VulnerabilityCategory::UnsafeDowncast,
                        "Unsafe Downcast of Financial Value".to_string(),
                        format!(
                            "Casting `{}` to `{}` will silently truncate if the value exceeds the target type's maximum, potentially causing incorrect financial calculations.",
                            var_name, caps.get(1).map_or("", |m| m.as_str())
                        ),
                        idx + 1,
                        line.trim().to_string(),
                        "Use OpenZeppelin SafeCast (e.g., `amount.toUint128()`) which reverts on overflow.".to_string(),
                    ));
                }
            }
        }

        vulnerabilities
    }

    /// Detect contracts implementing ERC-721/1155 without ERC-165 supportsInterface.
    /// Missing ERC-165 breaks composability since other contracts can't detect
    /// which interfaces are supported.
    fn detect_missing_erc165(&self, content: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        // Check if contract implements NFT interfaces (NOT ERC-20 — ERC-20 doesn't need ERC-165)
        // _mint( was removed because ERC-20 also uses _mint(). tokenURI is NFT-specific.
        let is_nft = content.contains("ERC721")
            || content.contains("ERC1155")
            || content.contains("onERC721Received")
            || content.contains("onERC1155Received")
            || content.contains("tokenURI")
            || content.contains("safeTransferFrom(address,address,uint256,bytes");

        if !is_nft {
            return vulnerabilities;
        }

        // Check if supportsInterface is implemented
        let has_erc165 = content.contains("supportsInterface")
            || content.contains("ERC165")
            || content.contains("IERC165");

        // Contracts inheriting an ERC-721/1155 base (or receiver interface) get
        // supportsInterface from the base implementation — extensions don't redeclare it.
        let inherits_nft_base = re!(r"contract\s+\w+\s+is\s+[^{]*(ERC721|ERC1155)").is_match(content);

        if !has_erc165 && !inherits_nft_base {
            // Find the contract declaration line (skip comments/prose like
            // "the token contract is proxied", and abstract bases which inherit
            // supportsInterface from their concrete parents elsewhere)
            let contract_pattern = re!(r"^\s*contract\s+(\w+)");
            for (idx, line) in content.lines().enumerate() {
                if let Some(caps) = contract_pattern.captures(line) {
                    {
                        let name = caps.get(1).map_or("Unknown", |m| m.as_str());
                        vulnerabilities.push(Vulnerability::new(
                            VulnerabilitySeverity::Low,
                            VulnerabilityCategory::MissingERC165,
                            format!("Missing ERC-165 in NFT Contract {name}"),
                            "Token contract does not implement ERC-165 supportsInterface(). This breaks composability as other contracts cannot detect supported interfaces.".to_string(),
                            idx + 1,
                            line.trim().to_string(),
                            "Implement ERC-165 by adding `function supportsInterface(bytes4 interfaceId) public view returns (bool)` and returning true for supported interfaces.".to_string(),
                        ));
                        break;
                    }
                }
            }
        }

        vulnerabilities
    }

    /// Detect initialize() functions without proper protection against re-initialization.
    /// Implementation contracts behind proxies must prevent direct initialization.
    fn detect_unprotected_initialize(&self, content: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        // Check for initialize function
        let init_pattern =
            re!(r"function\s+initialize\s*\([^)]*\)\s+(?:external|public)");

        let lines: Vec<&str> = content.lines().collect();
        for (idx, line) in lines.iter().enumerate() {
            if init_pattern.is_match(line) {
                // Check if initializer modifier is present
                if !line.contains("initializer") && !line.contains("reinitializer") {
                    // Check if _disableInitializers is in constructor
                    if !content.contains("_disableInitializers") {
                        // Check the full function signature (may span multiple lines)
                        let full_sig: String = lines[idx..(idx + 5).min(lines.len())]
                            .iter()
                            .take_while(|l| !l.contains('{') || l == &line)
                            .copied()
                            .chain(std::iter::once(*line))
                            .collect::<Vec<_>>()
                            .join(" ");

                        // Skip if function has access control modifier AND re-init guards
                        let has_access_control = full_sig.contains("onlyOwner")
                            || full_sig.contains("onlyGov")
                            || full_sig.contains("onlyAdmin")
                            || full_sig.contains("onlyRole")
                            || full_sig.contains("auth")
                            || re!(r"\bonly\w+").is_match(&full_sig);

                        // Check function body for re-init guard (require(x == 0))
                        let func_end = (idx + 15).min(lines.len());
                        let func_body: String = lines[idx..func_end].join("\n");
                        let has_reinit_guard = func_body.contains("require(")
                            && func_body.contains("== 0")
                            || func_body.contains("initialized");

                        if has_access_control && has_reinit_guard {
                            continue; // Protected by access control + re-init guard
                        }

                        vulnerabilities.push(Vulnerability::high_confidence(
                            VulnerabilitySeverity::Critical,
                            VulnerabilityCategory::DoubleInitialization,
                            "Unprotected Initializer Function".to_string(),
                            "initialize() function lacks the `initializer` modifier and no _disableInitializers() in constructor. This allows re-initialization which can reset contract state and potentially steal funds.".to_string(),
                            idx + 1,
                            line.trim().to_string(),
                            "Add the `initializer` modifier from OpenZeppelin's Initializable contract, and call `_disableInitializers()` in the constructor.".to_string(),
                        ));
                    }
                }
            }
        }

        vulnerabilities
    }

    /// Detect upgradeable base contracts that are missing storage gap reservations.
    /// When a base contract adds new state variables, it shifts storage slots for all
    /// derived contracts, corrupting their data.
    fn detect_missing_gap_in_base(&self, content: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        // Check if this is an abstract/base upgradeable contract
        let is_abstract_upgradeable = content.contains("abstract contract")
            && (content.contains("Upgradeable") || content.contains("Initializable"));

        if !is_abstract_upgradeable {
            return vulnerabilities;
        }

        if content.contains("__gap") {
            return vulnerabilities;
        }

        // Check for state variables
        let has_state = re!(r"^\s+(?:uint|int|address|bool|bytes|string|mapping)\w*\s+(?:public|private|internal)")
        .is_match(content);

        if has_state {
            for (idx, line) in content.lines().enumerate() {
                if line.contains("abstract contract") {
                    vulnerabilities.push(Vulnerability::new(
                        VulnerabilitySeverity::High,
                        VulnerabilityCategory::MissingStorageGap,
                        "Abstract Upgradeable Contract Missing __gap".to_string(),
                        "This abstract upgradeable contract has state variables but no __gap reservation. Child contracts will have corrupted storage if state variables are added here in future upgrades.".to_string(),
                        idx + 1,
                        line.trim().to_string(),
                        "Add `uint256[50] private __gap;` as the last state variable.".to_string(),
                    ));
                    break;
                }
            }
        }

        vulnerabilities
    }

    // ========================================================================
    // 2025-2026 EXPLOIT PATTERN ANALYSIS (v0.7.0)
    // Detects 18 new vulnerability categories based on $400M+ real-world
    // exploits: Abracadabra, Yearn, Cetus, Balancer, GMX, Atlas, zkSync,
    // Thirdweb, and Ethereum Pectra upgrade (EIP-7702) patterns.
    // ========================================================================

    /// Top-level entry point for 2025-2026 exploit pattern detection.
    /// Called from `scanner.rs` in the advanced analysis phase.
    pub fn analyze_2025_exploit_patterns(&self, content: &str) -> Vec<Vulnerability> {
        let mut vulns = Vec::new();

        vulns.extend(self.detect_multicall_state_reset(content));
        vulns.extend(self.detect_inconsistent_state_reset(content));
        vulns.extend(self.detect_eip7702_txorigin_bypass(content));
        vulns.extend(self.detect_transient_storage_gas_reentrancy(content));
        vulns.extend(self.detect_read_only_reentrancy_view(content));
        vulns.extend(self.detect_erc2771_multicall_spoofing(content));
        vulns.extend(self.detect_multicall_msg_value_reuse(content));
        vulns.extend(self.detect_fee_on_transfer(content));
        vulns.extend(self.detect_unprotected_admin_sweep(content));
        vulns.extend(self.detect_unvalidated_crosschain_receiver(content));
        vulns.extend(self.detect_avs_slashing_risk(content));
        vulns.extend(self.detect_erc4626_slash_liability_drift(content));
        vulns.extend(self.detect_clmm_math_overflow(content));
        vulns.extend(self.detect_inconsistent_rounding(content));
        vulns.extend(self.detect_donation_attack(content));
        vulns.extend(self.detect_missing_slippage(content));
        vulns.extend(self.detect_arbitrary_receiver_callback(content));
        vulns.extend(self.detect_iscontract_post_pectra(content));
        vulns.extend(self.detect_unsafe_multicall_delegatecall(content));

        vulns
    }

    /// Classic, timeless vulnerability patterns (SWC registry) that complement the
    /// modern-exploit detectors. Kept precise (each requires an authorization/transfer
    /// context) so they add signal without reintroducing false positives.
    pub fn analyze_classic_patterns(&self, content: &str) -> Vec<Vulnerability> {
        let mut vulns = Vec::new();
        vulns.extend(self.detect_tx_origin_auth(content));
        vulns.extend(self.detect_value_transfer_in_loop(content));
        vulns.extend(self.detect_unlimited_approval_to_param(content));
        vulns
    }

    /// SWC-115: `tx.origin` used for authorization. `tx.origin == owner` (or `!=`) lets a
    /// malicious intermediary contract phish an authorized user into calling it, which
    /// then calls the victim contract with the user still as `tx.origin`. Only the auth
    /// comparison is flagged; the `tx.origin == msg.sender` EOA-check is a different
    /// (EIP-7702) issue handled by detect_eip7702_txorigin_bypass.
    fn detect_tx_origin_auth(&self, content: &str) -> Vec<Vulnerability> {
        let mut vulns = Vec::new();
        // tx.origin compared to something OTHER than msg.sender inside a guard.
        let auth_re = re!(r"(require|assert|if)\s*\(.*tx\.origin\s*(==|!=)");
        for (idx, line) in content.lines().enumerate() {
            let trimmed = line.trim_start();
            if trimmed.starts_with("//") || trimmed.starts_with('*') || trimmed.starts_with("/*") {
                continue;
            }
            if auth_re.is_match(line) && !line.contains("tx.origin == msg.sender")
                && !line.contains("tx.origin != msg.sender")
            {
                vulns.push(Vulnerability::high_confidence(
                    VulnerabilitySeverity::High,
                    VulnerabilityCategory::TxOriginAuth,
                    "tx.origin Used for Authorization".to_string(),
                    "Authorization is based on tx.origin, which is the original external \
                     account of the whole transaction. A malicious contract the victim is \
                     tricked into calling can forward the call to this contract while \
                     tx.origin still resolves to the victim, bypassing the check (phishing)."
                        .to_string(),
                    idx + 1,
                    line.trim().to_string(),
                    "Use msg.sender for authorization instead of tx.origin.".to_string(),
                ));
            }
        }
        vulns
    }

    /// SWC-113: an unbounded loop that performs a value transfer or external call to a
    /// per-iteration recipient (push-payment). A single recipient that reverts (or a
    /// contract with a costly fallback) bricks the whole batch, freezing everyone's funds.
    fn detect_value_transfer_in_loop(&self, content: &str) -> Vec<Vulnerability> {
        let mut vulns = Vec::new();
        let loop_re = re!(r"\b(for|while)\s*\(");
        let transfer_re = re!(r"\.(transfer|send)\s*\(|\.call\{\s*value");
        let lines: Vec<&str> = content.lines().collect();

        for (idx, line) in lines.iter().enumerate() {
            let trimmed = line.trim_start();
            if trimmed.starts_with("//") || trimmed.starts_with('*') {
                continue;
            }
            if !loop_re.is_match(line) {
                continue;
            }
            // Walk the loop body by brace depth (bounded) and look for a value transfer.
            let mut depth: i32 = 0;
            let mut started = false;
            let mut reported = false;
            for probe in lines.iter().skip(idx).take(25) {
                depth += probe.matches('{').count() as i32;
                if probe.contains('{') {
                    started = true;
                }
                if started && transfer_re.is_match(probe) {
                    vulns.push(Vulnerability::new(
                        VulnerabilitySeverity::Medium,
                        VulnerabilityCategory::DoSAttacks,
                        "Value Transfer Inside Loop (Push-Payment DoS)".to_string(),
                        "A loop sends ETH (via .transfer/.send/.call{value}) to a recipient on \
                         each iteration. If any single recipient reverts or is a contract with \
                         an expensive fallback, the entire loop reverts and no one is paid, \
                         freezing funds for all participants."
                            .to_string(),
                        idx + 1,
                        line.trim().to_string(),
                        "Use the pull-payment pattern: record amounts owed and let each \
                         recipient withdraw individually, isolating a failing transfer."
                            .to_string(),
                    ));
                    reported = true;
                    break;
                }
                depth -= probe.matches('}').count() as i32;
                if started && depth <= 0 {
                    break;
                }
            }
            let _ = reported;
        }
        vulns
    }

    /// Unlimited (`type(uint256).max`) ERC-20 approval granted to a spender that is a
    /// function parameter — i.e. an address the caller chooses. This lets an attacker
    /// pass their own address and receive unlimited allowance over the contract's tokens.
    fn detect_unlimited_approval_to_param(&self, content: &str) -> Vec<Vulnerability> {
        let mut vulns = Vec::new();
        let func_re = re!(r"function\s+\w+\s*\(([^)]*)\)");
        let approve_re =
            re!(r"\.\s*(approve|safeApprove|forceApprove)\s*\(\s*(\w+)\s*,\s*type\s*\(\s*uint256\s*\)\s*\.\s*max");
        let lines: Vec<&str> = content.lines().collect();

        for (idx, line) in lines.iter().enumerate() {
            let trimmed = line.trim_start();
            if trimmed.starts_with("//") || trimmed.starts_with('*') {
                continue;
            }
            let caps = match approve_re.captures(line) {
                Some(c) => c,
                None => continue,
            };
            let spender = caps.get(2).map_or("", |m| m.as_str());
            // Look back for the enclosing function signature and check whether `spender`
            // is one of its address parameters (caller-controlled).
            let start = idx.saturating_sub(25);
            let mut param_controlled = false;
            for prev in lines[start..=idx].iter().rev() {
                if let Some(fc) = func_re.captures(prev) {
                    let params = fc.get(1).map_or("", |m| m.as_str());
                    if params.contains(&format!("address {spender}"))
                        || params.contains(&format!("address {spender},"))
                        || params.contains(&format!("address {spender})"))
                    {
                        param_controlled = true;
                    }
                    break;
                }
            }
            if param_controlled {
                vulns.push(Vulnerability::high_confidence(
                    VulnerabilitySeverity::High,
                    VulnerabilityCategory::LogicError,
                    "Unlimited Approval to Caller-Controlled Spender".to_string(),
                    "The contract grants an unlimited (type(uint256).max) token approval to a \
                     spender address taken directly from a function parameter. A caller can \
                     pass their own address and gain unlimited allowance over the contract's \
                     token balance."
                        .to_string(),
                    idx + 1,
                    line.trim().to_string(),
                    "Approve only a trusted, hardcoded/immutable spender, and grant the exact \
                     amount needed rather than an unlimited allowance."
                        .to_string(),
                ));
            }
        }
        vulns
    }

    fn detect_multicall_state_reset(&self, content: &str) -> Vec<Vulnerability> {
        let mut vulns = Vec::new();
        let multicall_re =
            re!(r"(?i)function\s+(cook|multicall|batch|multiCall|batchCall)\s*\(");
        let flag_reset_re = re!(r"(solvent|accrue|status|_status|locked)\s*=\s*(true|false|0|1|_NOT_ENTERED)");

        for (idx, line) in content.lines().enumerate() {
            if multicall_re.is_match(line) {
                let end = (idx + 40).min(content.lines().count());
                let body: String = content
                    .lines()
                    .skip(idx)
                    .take(end - idx)
                    .collect::<Vec<_>>()
                    .join("\n");
                if flag_reset_re.is_match(&body) && (body.contains("for") || body.contains("while"))
                {
                    vulns.push(Vulnerability::high_confidence(
                        VulnerabilitySeverity::Critical,
                        VulnerabilityCategory::MulticallStateReset,
                        "Multicall Resets State Flag Between Sub-Calls".to_string(),
                        "Batch/multicall function resets a status flag (solvency, lock, accrue) inside a loop. \
                         Each sub-call sees a clean flag, bypassing cumulative checks. \
                         Real-world: Abracadabra $14.7M exploit.".to_string(),
                        idx + 1,
                        line.trim().to_string(),
                        "Move solvency/invariant checks AFTER the entire batch completes, not inside the loop. \
                         Use a deferred check pattern: set dirty flag in loop, validate after.".to_string(),
                    ));
                }
            }
        }
        vulns
    }

    fn detect_inconsistent_state_reset(&self, content: &str) -> Vec<Vulnerability> {
        let mut vulns = Vec::new();
        let total_reset_re =
            re!(r"totalSupply\s*=\s*0|_totalSupply\s*=\s*0|totalShares\s*=\s*0");

        for (idx, line) in content.lines().enumerate() {
            if total_reset_re.is_match(line) {
                let start = idx.saturating_sub(5);
                let end = (idx + 20).min(content.lines().count());
                let context: String = content
                    .lines()
                    .skip(start)
                    .take(end - start)
                    .collect::<Vec<_>>()
                    .join("\n");

                let clears_balances = context.contains("delete balances")
                    || context.contains("balances[") && context.contains("= 0")
                    || context.contains("_balances[") && context.contains("= 0")
                    || context.contains("delete _balances");

                if !clears_balances {
                    vulns.push(Vulnerability::high_confidence(
                        VulnerabilitySeverity::Critical,
                        VulnerabilityCategory::InconsistentStateReset,
                        "totalSupply Reset Without Clearing Balances".to_string(),
                        "totalSupply/totalShares is set to 0 but individual balance mappings are not cleared. \
                         Users can withdraw based on stale cached balances. \
                         Real-world: Yearn $9M exploit.".to_string(),
                        idx + 1,
                        line.trim().to_string(),
                        "When resetting totalSupply, also clear all individual balance entries, or use a \
                         snapshot mechanism that invalidates old balances.".to_string(),
                    ));
                }
            }
        }
        vulns
    }

    fn detect_eip7702_txorigin_bypass(&self, content: &str) -> Vec<Vulnerability> {
        let mut vulns = Vec::new();
        let txorigin_check_re =
            re!(r"(require|assert|if)\s*\(.*tx\.origin\s*==\s*msg\.sender");

        for (idx, line) in content.lines().enumerate() {
            if line.trim().starts_with("//") || line.trim().starts_with("*") {
                continue;
            }
            if txorigin_check_re.is_match(line) {
                vulns.push(Vulnerability::new(
                    VulnerabilitySeverity::High,
                    VulnerabilityCategory::EIP7702TxOriginBypass,
                    "tx.origin == msg.sender EOA Check Broken Post-Pectra".to_string(),
                    "tx.origin == msg.sender is used to verify the caller is an EOA. Post-Pectra \
                     (EIP-7702), EOAs can delegate execution to smart contract code, making this \
                     check unreliable. Attackers can phish users into delegating to malicious code.".to_string(),
                    idx + 1,
                    line.trim().to_string(),
                    "Remove the tx.origin == msg.sender check. Use ERC-4337 account abstraction or \
                     EIP-1271 isValidSignature for contract-compatible authentication.".to_string(),
                ));
            }
        }
        vulns
    }

    fn detect_transient_storage_gas_reentrancy(&self, content: &str) -> Vec<Vulnerability> {
        let mut vulns = Vec::new();
        let has_transient = content.contains("tstore")
            || content.contains("tload")
            || content.contains("TSTORE")
            || content.contains("TLOAD")
            || content.contains("transient");
        if !has_transient {
            return vulns;
        }

        let transfer_send_re = re!(r"\.(transfer|send)\s*\(");
        for (idx, line) in content.lines().enumerate() {
            if line.trim().starts_with("//") {
                continue;
            }
            if transfer_send_re.is_match(line) {
                vulns.push(Vulnerability::new(
                    VulnerabilitySeverity::High,
                    VulnerabilityCategory::TransientStorageGasReentrancy,
                    ".transfer()/.send() Unsafe With Transient Storage".to_string(),
                    "Contract uses transient storage (TSTORE/TLOAD) alongside .transfer()/.send(). \
                     The 2300 gas stipend is insufficient when transient storage operations are involved \
                     in the recipient's receive/fallback function, enabling reentrancy.".to_string(),
                    idx + 1,
                    line.trim().to_string(),
                    "Replace .transfer()/.send() with .call{value: amount}(\"\") and use a \
                     reentrancy guard (nonReentrant modifier).".to_string(),
                ));
            }
        }
        vulns
    }

    fn detect_read_only_reentrancy_view(&self, content: &str) -> Vec<Vulnerability> {
        let mut vulns = Vec::new();
        if content.contains("ReentrancyGuard") || content.contains("nonReentrant") {
            return vulns;
        }

        let view_fn_re = re!(r"(?i)function\s+(\w*(?:price|rate|share|value|balance|total|getRate|getPrice|convertToAssets|convertToShares)\w*)\s*\([^)]*\)\s*(?:external|public)\s+view");
        let external_call_re =
            re!(r"\.(call|transfer|send)\s*[\({]|\.safeTransfer\(|\.withdraw\(");

        if !external_call_re.is_match(content) {
            return vulns;
        }

        for (idx, line) in content.lines().enumerate() {
            if view_fn_re.is_match(line) {
                vulns.push(Vulnerability::new(
                    VulnerabilitySeverity::High,
                    VulnerabilityCategory::ReadOnlyReentrancy,
                    "Read-Only Reentrancy Risk in View Function".to_string(),
                    "Public view function reads state (price/rate/balance/shares) that can be stale \
                     during an external call's callback. An attacker can re-enter via the callback \
                     and read manipulated values from this view function.".to_string(),
                    idx + 1,
                    line.trim().to_string(),
                    "Apply nonReentrant modifier to state-changing functions that call external contracts, \
                     or use a read-only reentrancy guard on view functions.".to_string(),
                ));
            }
        }
        vulns
    }

    fn detect_erc2771_multicall_spoofing(&self, content: &str) -> Vec<Vulnerability> {
        let mut vulns = Vec::new();
        let has_erc2771 = content.contains("ERC2771")
            || content.contains("_msgSender") && content.contains("trustedForwarder");
        let has_multicall = content.contains("Multicall") || content.contains("multicall");
        if !has_erc2771 || !has_multicall {
            return vulns;
        }

        let contract_re = re!(r"contract\s+(\w+)\s+is\s+([^{]+)");
        for (idx, line) in content.lines().enumerate() {
            if let Some(caps) = contract_re.captures(line) {
                let inheritance = caps.get(2).map_or("", |m| m.as_str());
                if (inheritance.contains("ERC2771") || inheritance.contains("Context"))
                    && inheritance.contains("Multicall")
                {
                    vulns.push(Vulnerability::high_confidence(
                        VulnerabilitySeverity::Critical,
                        VulnerabilityCategory::ERC2771MulticallSpoofing,
                        "ERC2771 + Multicall _msgSender() Spoofing".to_string(),
                        "Contract inherits both ERC2771Context and Multicall. An attacker can craft \
                         a multicall payload that appends a spoofed sender address to sub-call calldata, \
                         causing _msgSender() to return an arbitrary address. \
                         Real-world: Thirdweb exploit affecting millions of contracts.".to_string(),
                        idx + 1,
                        line.trim().to_string(),
                        "Use OpenZeppelin's ERC2771Forwarder v4.9+ which includes the fix, or override \
                         multicall() to strip/validate the ERC2771 suffix in each sub-call.".to_string(),
                    ));
                }
            }
        }
        vulns
    }

    fn detect_multicall_msg_value_reuse(&self, content: &str) -> Vec<Vulnerability> {
        let mut vulns = Vec::new();
        let multicall_re = re!(r"(?i)function\s+(multicall|batch|aggregate)\s*\(");

        for (idx, line) in content.lines().enumerate() {
            if multicall_re.is_match(line) {
                let end = (idx + 30).min(content.lines().count());
                let body: String = content
                    .lines()
                    .skip(idx)
                    .take(end - idx)
                    .collect::<Vec<_>>()
                    .join("\n");
                let has_delegatecall = body.contains("delegatecall");
                let has_payable = line.contains("payable") || body.contains("msg.value");
                if has_delegatecall && has_payable {
                    vulns.push(Vulnerability::high_confidence(
                        VulnerabilitySeverity::Critical,
                        VulnerabilityCategory::MulticallMsgValueReuse,
                        "msg.value Reused Across Multicall delegatecall Sub-Calls".to_string(),
                        "Payable multicall uses delegatecall to execute sub-calls. msg.value persists \
                         across all delegatecall invocations, so the same ETH can be spent multiple \
                         times in different sub-calls.".to_string(),
                        idx + 1,
                        line.trim().to_string(),
                        "Track consumed msg.value with a local variable and revert if total exceeds \
                         msg.value, or avoid delegatecall in payable multicall functions.".to_string(),
                    ));
                }
            }
        }
        vulns
    }

    fn detect_fee_on_transfer(&self, content: &str) -> Vec<Vulnerability> {
        let mut vulns = Vec::new();
        let transfer_from_re =
            re!(r"\.transferFrom\s*\([^,]+,\s*[^,]+,\s*(\w+)\s*\)");

        for (idx, line) in content.lines().enumerate() {
            if line.trim().starts_with("//") {
                continue;
            }
            if let Some(caps) = transfer_from_re.captures(line) {
                let amount_var = caps.get(1).map_or("", |m| m.as_str());
                let start = idx.saturating_sub(5);
                let end = (idx + 8).min(content.lines().count());
                let context: String = content
                    .lines()
                    .skip(start)
                    .take(end - start)
                    .collect::<Vec<_>>()
                    .join("\n");
                let has_balance_diff = context.contains("balanceBefore")
                    || context.contains("balanceOf") && context.contains("- ")
                    || context.contains("_before")
                    || context.contains("received =");
                if !has_balance_diff && !amount_var.is_empty() {
                    let after: String = content
                        .lines()
                        .skip(idx + 1)
                        .take(5)
                        .collect::<Vec<_>>()
                        .join("\n");
                    let uses_amount_directly = after.contains(amount_var)
                        && (after.contains("+=")
                            || after.contains("alances[")
                            || after.contains("mint")
                            || after.contains("shares")
                            || after.contains("deposit")
                            || after.contains("credit")
                            || after.contains("supply"));
                    if uses_amount_directly {
                        vulns.push(Vulnerability::new(
                            VulnerabilitySeverity::Medium,
                            VulnerabilityCategory::FeeOnTransferAssumption,
                            "Fee-on-Transfer Token Amount Assumption".to_string(),
                            format!(
                                "transferFrom credits `{amount_var}` directly without checking actual received \
                                 amount. Fee-on-transfer tokens (USDT, PAXG, deflationary tokens) deliver less \
                                 than the specified amount, causing accounting errors."
                            ),
                            idx + 1,
                            line.trim().to_string(),
                            "Measure actual received amount: uint256 before = token.balanceOf(address(this)); \
                             token.transferFrom(...); uint256 received = token.balanceOf(address(this)) - before;".to_string(),
                        ));
                    }
                }
            }
        }
        vulns
    }

    fn detect_unprotected_admin_sweep(&self, content: &str) -> Vec<Vulnerability> {
        let mut vulns = Vec::new();
        if content.contains("TimelockController")
            || content.contains("Timelock")
            || (content.contains("delay")
                && content.contains("queue")
                && content.contains("execute"))
        {
            return vulns;
        }

        let sweep_re = re!(r"function\s+(sweep|recover|rescue|emergencyWithdraw|drain|withdrawAll|withdrawToken|recoverToken|recoverERC20)\s*\(");
        let admin_mod_re =
            re!(r"(onlyOwner|onlyAdmin|onlyRole|onlyGovernance|auth)");

        for (idx, line) in content.lines().enumerate() {
            if sweep_re.is_match(line) {
                let end = (idx + 5).min(content.lines().count());
                let func_header: String = content
                    .lines()
                    .skip(idx)
                    .take(end - idx)
                    .collect::<Vec<_>>()
                    .join(" ");
                if admin_mod_re.is_match(&func_header) {
                    vulns.push(Vulnerability::new(
                        VulnerabilitySeverity::High,
                        VulnerabilityCategory::UnprotectedAdminSweep,
                        "Admin Sweep Function Without Timelock".to_string(),
                        "Admin-protected sweep/recover function can withdraw funds instantly without \
                         a timelock delay. A compromised admin key can drain all funds immediately. \
                         Real-world: zkSync $5M exploit via admin sweep.".to_string(),
                        idx + 1,
                        line.trim().to_string(),
                        "Add a timelock (e.g., 48h delay) to sweep functions, or use a multi-sig \
                         with a time-delayed execution pattern.".to_string(),
                    ));
                }
            }
        }
        vulns
    }

    fn detect_unvalidated_crosschain_receiver(&self, content: &str) -> Vec<Vulnerability> {
        let mut vulns = Vec::new();
        let receiver_re = re!(r"function\s+(_?(?:receive|execute|handle|process)(?:Message|Payload|CrossChain|FromChain)?|_nonblockingLzReceive|_ccipReceive|onMessageReceived)\s*\(");

        for (idx, line) in content.lines().enumerate() {
            if line.trim().starts_with("//") {
                continue;
            }
            if receiver_re.is_match(line) {
                let end = (idx + 20).min(content.lines().count());
                let body: String = content
                    .lines()
                    .skip(idx)
                    .take(end - idx)
                    .collect::<Vec<_>>()
                    .join("\n");
                let body_lower = body.to_lowercase();
                let line_lower = line.to_lowercase();

                let has_crosschain_context = line.contains("_nonblockingLzReceive")
                    || line.contains("_ccipReceive")
                    || line.contains("CrossChain")
                    || line.contains("FromChain")
                    || body_lower.contains("sourcechain")
                    || body_lower.contains("srcchain")
                    || body_lower.contains("trustedremote")
                    || body_lower.contains("bridge")
                    || body_lower.contains("layerzero")
                    || body_lower.contains("wormhole")
                    || body_lower.contains("ccip")
                    || body_lower.contains("endpoint")
                    || body_lower.contains("router")
                    || body_lower.contains("remote")
                    || body_lower.contains("_srcaddress")
                    || body_lower.contains("_origin")
                    || body_lower.contains("origin.sender")
                    || line_lower.contains("message")
                        && (body_lower.contains("bridge")
                            || body_lower.contains("router")
                            || body_lower.contains("remote"));

                if !has_crosschain_context {
                    continue;
                }

                let has_validation = body_lower.contains("sourcechain")
                    || body_lower.contains("srcchainid")
                    || body_lower.contains("trustedremote")
                    || body_lower.contains("allowedsender")
                    || body_lower.contains("onlyrelayer")
                    || body_lower.contains("onlybridge")
                    || body_lower.contains("onlyrouter")
                    || body_lower.contains("trusted sender")
                    || body_lower.contains("trusted_sender")
                    || body_lower.contains("require")
                        && (body_lower.contains("sender")
                            || body_lower.contains("source")
                            || body_lower.contains("remote"));
                if !has_validation {
                    vulns.push(Vulnerability::high_confidence(
                        VulnerabilitySeverity::Critical,
                        VulnerabilityCategory::UnvalidatedCrossChainReceiver,
                        "Cross-Chain Receiver Without Source Validation".to_string(),
                        "Cross-chain message handler does not validate the source chain or sender. \
                         Any chain/contract can send malicious messages to this receiver. \
                         Real-world: Atlas $112M, CrossCurve $3M exploits.".to_string(),
                        idx + 1,
                        line.trim().to_string(),
                        "Validate source chain ID and sender address against a whitelist: \
                         require(trustedRemote[srcChainId] == sender). Use LayerZero's lzReceive \
                         or CCIP's onlyRouter pattern.".to_string(),
                    ));
                }
            }
        }
        vulns
    }

    fn detect_avs_slashing_risk(&self, content: &str) -> Vec<Vulnerability> {
        let mut vulns = Vec::new();
        if !content.contains("slash") && !content.contains("Slash") {
            return vulns;
        }

        let slash_re =
            re!(r"(?i)^(slash|freezeOperator|penalize|slashOperator|slashStaker)$");
        let delay_re =
            re!(r"(?i)\b(delay|timelock|dispute|cooldown|veto(?:able)?|queue)\b");

        for function in self
            .extract_functions(content)
            .into_iter()
            .filter(|function| slash_re.is_match(&function.name))
        {
            let code_body = self.strip_comment_lines(&function.body);
            let has_delay = delay_re.is_match(&code_body);
            if !has_delay {
                vulns.push(Vulnerability::new(
                    VulnerabilitySeverity::High,
                    VulnerabilityCategory::AVSSlashingRisk,
                    "AVS Slash Without Timelock or Dispute Window".to_string(),
                    "Slash/freeze function executes immediately without a dispute window or \
                     timelock delay. A malicious or compromised slasher can instantly confiscate \
                     staked funds without recourse."
                        .to_string(),
                    function.start_line,
                    function.signature.clone(),
                    "Add a dispute/veto period (e.g., 7 days) before slash execution. Use a \
                     two-step process: propose slash -> wait for dispute window -> execute."
                        .to_string(),
                ));
            }
        }
        vulns
    }

    fn detect_erc4626_slash_liability_drift(&self, content: &str) -> Vec<Vulnerability> {
        let mut vulns = Vec::new();
        let content_lower = content.to_lowercase();
        let has_loss_hook = content_lower.contains("slash")
            || content_lower.contains("penal")
            || content_lower.contains("seize")
            || content_lower.contains("loss");
        if !content.contains("totalAssets") || !has_loss_hook {
            return vulns;
        }

        let functions = self.extract_functions(content);
        let Some(total_assets_fn) = functions.iter().find(|func| func.name == "totalAssets") else {
            return vulns;
        };

        let balance_expr_re = re!(r"(?:\w+\s*\.\s*)?balanceOf\s*\(\s*address\s*\(\s*this\s*\)\s*\)|address\s*\(\s*this\s*\)\s*\.\s*balance");
        if !balance_expr_re.is_match(&total_assets_fn.body) {
            return vulns;
        }

        let state_vars = self.extract_state_variable_names(content);
        let liability_name_re = re!(r"(?i)(revenue|liabil|debt|pending|accru|fee|fees|reserve|owed|obligation|claim|escrow|buffer)");
        let alias_assign_re = re!(r"(?:\w+\s+)?([A-Za-z_]\w*)\s*=\s*.+");
        let subtraction_re = re!(r"-\s*([A-Za-z_]\w*)");
        let mut balance_aliases: HashSet<String> = HashSet::new();
        let mut liability_vars: HashSet<String> = HashSet::new();

        for line in total_assets_fn.body.lines() {
            if balance_expr_re.is_match(line) {
                if let Some(caps) = alias_assign_re.captures(line) {
                    if let Some(alias) = caps.get(1) {
                        balance_aliases.insert(alias.as_str().to_string());
                    }
                }
            }
        }

        for line in total_assets_fn.body.lines() {
            let line_trimmed = line.trim();
            let references_balance = balance_expr_re.is_match(line_trimmed)
                || balance_aliases.iter().any(|alias| {
                    line_trimmed.contains(&format!("{alias} -"))
                        || line_trimmed.contains(&format!("{alias}-"))
                });
            if !references_balance {
                continue;
            }

            for caps in subtraction_re.captures_iter(line_trimmed) {
                if let Some(candidate) = caps.get(1) {
                    let candidate = candidate.as_str().to_string();
                    if state_vars.contains(&candidate) {
                        liability_vars.insert(candidate);
                    }
                }
            }
        }

        if liability_vars.is_empty() {
            return vulns;
        }

        let slash_like_re = re!(r"(?i)(slash|penali[sz]e|confiscat|seize|socializeLoss|reportLoss|handleLoss)");
        let asset_loss_re = re!(r"\.(?:safeTransfer|transfer|burn|safeTransferFrom)\s*\(|\b(?:_?burn|withdraw|redeem)\s*\(");
        let writer_hint_re =
            re!(r"(?i)(buy|accru|collect|deposit|mint|harvest|fee)");

        for slash_fn in functions
            .iter()
            .filter(|func| slash_like_re.is_match(&func.name))
        {
            if !asset_loss_re.is_match(&slash_fn.body) {
                continue;
            }

            for liability_var in &liability_vars {
                if slash_fn.body.contains(liability_var) {
                    continue;
                }

                let escaped_var = regex::escape(liability_var);
                let write_re = Regex::new(&format!(r"\b{escaped_var}\b\s*(?:\+=|-=|=)")).unwrap();
                let has_liability_writer = functions.iter().any(|func| {
                    if func.name == "totalAssets" || func.name == slash_fn.name {
                        return false;
                    }
                    let is_view =
                        func.signature.contains(" view") || func.signature.contains(" pure");
                    !is_view && func.body.contains(liability_var) && write_re.is_match(&func.body)
                });

                let name_looks_like_liability = liability_name_re.is_match(liability_var)
                    || functions.iter().any(|func| {
                        func.name != "totalAssets"
                            && func.name != slash_fn.name
                            && func.body.contains(liability_var)
                            && writer_hint_re.is_match(&func.name)
                    });

                if !has_liability_writer || !name_looks_like_liability {
                    continue;
                }

                vulns.push(Vulnerability::high_confidence(
                    VulnerabilitySeverity::Critical,
                    VulnerabilityCategory::LogicError,
                    "ERC4626 Liability Drift After Slash".to_string(),
                    format!(
                        "slash-like function reduces real vault assets, but totalAssets() still subtracts the liability variable `{}`. If `{}` is left unchanged after slashing, totalAssets() can underflow/revert once liabilities exceed the post-slash balance, bricking share accounting.",
                        liability_var, liability_var
                    ),
                    slash_fn.start_line,
                    slash_fn.signature.clone(),
                    format!(
                        "Update `{}` whenever slashing reduces backing assets, or clamp totalAssets() so liabilities cannot exceed live assets.",
                        liability_var
                    ),
                ));
                break;
            }
        }

        vulns
    }

    fn detect_clmm_math_overflow(&self, content: &str) -> Vec<Vulnerability> {
        let mut vulns = Vec::new();
        let has_clmm_context = content.contains("sqrtPrice")
            || content.contains("liquidity")
            || content.contains("tickMath")
            || content.contains("TickMath")
            || content.contains("SqrtPrice")
            || content.contains("concentrated");
        if !has_clmm_context {
            return vulns;
        }

        let clmm_shift_re = re!(r"(?i)((sqrt|price|liquidity|tick|ratio|amount)\w*.*(<<|>>)\s*\d+|(<<|>>)\s*\d+.*(sqrt|price|liquidity|tick|ratio|amount)\w*)");
        for (idx, line) in content.lines().enumerate() {
            if line.trim().starts_with("//") {
                continue;
            }
            if clmm_shift_re.is_match(line) {
                let is_in_unchecked = {
                    let before: String =
                        content.lines().take(idx + 1).collect::<Vec<_>>().join("\n");
                    before.matches("unchecked {").count() + before.matches("unchecked{").count() > 0
                };
                let line_lower = line.to_lowercase();
                let is_math_context = line_lower.contains("sqrt")
                    || line_lower.contains("price")
                    || line_lower.contains("liquidity")
                    || line_lower.contains("tick")
                    || line_lower.contains("amount")
                    || line_lower.contains("ratio");
                if is_math_context && (is_in_unchecked || !content.contains("SafeMath")) {
                    vulns.push(Vulnerability::high_confidence(
                        VulnerabilitySeverity::Critical,
                        VulnerabilityCategory::CLMMMathOverflow,
                        "Unchecked Arithmetic in CLMM Tick/Price Math".to_string(),
                        "Bit-shift operation on price/liquidity/tick math without overflow validation. \
                         Bit-shifts bypass Solidity 0.8+ overflow checks. An attacker can pass extreme \
                         values causing silent overflow. Real-world: Cetus $223M exploit.".to_string(),
                        idx + 1,
                        line.trim().to_string(),
                        "Add explicit bounds checking before bit-shift operations: \
                         require(value <= type(uint128).max) before shifting. Use OpenZeppelin's \
                         Math.mulDiv for safe fixed-point math.".to_string(),
                    ));
                }
            }
        }
        vulns
    }

    fn detect_inconsistent_rounding(&self, content: &str) -> Vec<Vulnerability> {
        let mut vulns = Vec::new();
        let lines: Vec<&str> = content.lines().collect();
        let fn_re = re!(r"function\s+\w+");
        let mut func_start = 0;
        let mut brace_depth: i32 = 0;
        let mut in_function = false;

        for (idx, line) in lines.iter().enumerate() {
            if fn_re.is_match(line) {
                func_start = idx;
                in_function = true;
                brace_depth = 0;
            }
            if in_function {
                brace_depth += line.matches('{').count() as i32;
                brace_depth -= line.matches('}').count() as i32;
                if brace_depth <= 0 && idx > func_start {
                    let func_body: String = lines[func_start..=idx].join("\n");
                    let has_mul_down =
                        func_body.contains("mulDown") || func_body.contains("mulDivDown");
                    let has_div_up = func_body.contains("divUp") || func_body.contains("mulDivUp");
                    let has_mul_up = func_body.contains("mulUp") || func_body.contains("mulDivUp");
                    let has_div_down =
                        func_body.contains("divDown") || func_body.contains("mulDivDown");
                    if (has_mul_down && has_div_up) || (has_mul_up && has_div_down) {
                        vulns.push(Vulnerability::high_confidence(
                            VulnerabilitySeverity::Critical,
                            VulnerabilityCategory::InconsistentRounding,
                            "Inconsistent Rounding Direction in Same Function".to_string(),
                            "Function mixes rounding directions (mulDown with divUp, or mulUp with divDown). \
                             This creates an exploitable rounding error that compounds on each operation. \
                             Real-world: Balancer $128M exploit.".to_string(),
                            func_start + 1,
                            lines[func_start].trim().to_string(),
                            "Use consistent rounding direction: round DOWN for amounts leaving the protocol \
                             (user receives) and round UP for amounts entering (user pays). Never mix.".to_string(),
                        ));
                    }
                    in_function = false;
                }
            }
        }
        vulns
    }

    fn detect_donation_attack(&self, content: &str) -> Vec<Vulnerability> {
        let mut vulns = Vec::new();
        let balance_of_this_re =
            re!(r"balanceOf\s*\(\s*address\s*\(\s*this\s*\)\s*\)");

        for (idx, line) in content.lines().enumerate() {
            if line.trim().starts_with("//") {
                continue;
            }
            if balance_of_this_re.is_match(line) {
                let start = idx.saturating_sub(3);
                let end = (idx + 4).min(content.lines().count());
                let context: String = content
                    .lines()
                    .skip(start)
                    .take(end - start)
                    .collect::<Vec<_>>()
                    .join("\n");
                let ctx_lower = context.to_lowercase();
                let is_price_context = ctx_lower.contains("price")
                    || ctx_lower.contains("rate")
                    || ctx_lower.contains("share")
                    || ctx_lower.contains("exchange")
                    || ctx_lower.contains("convert")
                    || ctx_lower.contains("per")
                    || ctx_lower.contains(" / total")
                    || ctx_lower.contains("/ _total");
                if is_price_context {
                    let has_offset = context.contains("+ 1")
                        || context.contains("+1")
                        || context.contains("virtualAssets")
                        || context.contains("_decimalsOffset")
                        || context.contains("OFFSET")
                        || context.contains("INITIAL_DEPOSIT");
                    if !has_offset {
                        vulns.push(Vulnerability::new(
                            VulnerabilitySeverity::High,
                            VulnerabilityCategory::DonationAttackVector,
                            "Donation Attack: balanceOf(this) in Share Price Without Offset".to_string(),
                            "Share price or exchange rate uses balanceOf(address(this)) which can be \
                             manipulated via direct token transfer (donation). An attacker can inflate \
                             the price to steal funds from subsequent depositors.".to_string(),
                            idx + 1,
                            line.trim().to_string(),
                            "Use a virtual offset: add 1 to both numerator and denominator (ERC-4626 \
                             virtual shares pattern), or track internal accounting separate from actual balance.".to_string(),
                        ));
                    }
                }
            }
        }
        vulns
    }

    fn detect_missing_slippage(&self, content: &str) -> Vec<Vulnerability> {
        let mut vulns = Vec::new();
        // Only flag swap/liquidity operations that actually involve price-sensitive exchanges.
        // Plain deposit() and stake() functions just transfer tokens at 1:1, no slippage risk.
        let swap_fn_re =
            re!(r"function\s+(swap|addLiquidity|removeLiquidity|zap)\s*\(([^)]*)\)");

        for (idx, line) in content.lines().enumerate() {
            if line.trim().starts_with("//") {
                continue;
            }
            if let Some(caps) = swap_fn_re.captures(line) {
                let fn_name = caps.get(1).map_or("", |m| m.as_str());
                let params = caps.get(2).map_or("", |m| m.as_str()).to_lowercase();
                let has_slippage = params.contains("min")
                    || params.contains("slippage")
                    || params.contains("deadline")
                    || params.contains("amountoutmin")
                    || params.contains("minout")
                    || params.contains("minamount");
                let end = (idx + 3).min(content.lines().count());
                let header: String = content
                    .lines()
                    .skip(idx)
                    .take(end - idx)
                    .collect::<Vec<_>>()
                    .join(" ");
                if header.contains("internal") || header.contains("private") {
                    continue;
                }
                if !has_slippage {
                    vulns.push(Vulnerability::new(
                        VulnerabilitySeverity::Medium,
                        VulnerabilityCategory::MissingSlippageProtection,
                        format!("Missing Slippage Protection in {fn_name}()"),
                        format!(
                            "Function {fn_name}() performs a swap/deposit without a minimum output amount \
                             parameter. Users cannot protect themselves against sandwich attacks or \
                             unfavorable price movements."
                        ),
                        idx + 1,
                        line.trim().to_string(),
                        "Add a `uint256 minAmountOut` parameter and revert if output is below it: \
                         require(amountOut >= minAmountOut, \"slippage\").".to_string(),
                    ));
                }
            }
        }
        vulns
    }

    fn detect_arbitrary_receiver_callback(&self, content: &str) -> Vec<Vulnerability> {
        let mut vulns = Vec::new();
        let lines: Vec<&str> = content.lines().collect();
        let callback_re = re!(r"\.(onFlashLoan|onERC721Received|onERC1155Received|tokensReceived|afterExecution|callback|notify)\s*\(");

        for (idx, line) in lines.iter().enumerate() {
            if line.trim().starts_with("//") {
                continue;
            }
            if callback_re.is_match(line) {
                let end = (idx + 10).min(lines.len());
                let after_callback: String = lines[(idx + 1)..end].join("\n");
                let state_mod_re = re!(r"(\w+\s*[\[.]\s*\w+\s*\]\s*=|\w+\s*=\s*[^=]|\w+\s*\+=|\w+\s*-=|totalSupply|_mint|_burn)");
                if state_mod_re.is_match(&after_callback) {
                    vulns.push(Vulnerability::new(
                        VulnerabilitySeverity::High,
                        VulnerabilityCategory::ArbitraryReceiverCallback,
                        "Callback to User-Supplied Receiver Before State Update".to_string(),
                        "External callback is made to a user-supplied address before internal state \
                         is finalized. The receiver can re-enter or observe inconsistent state. \
                         Real-world: GMX $42M exploit.".to_string(),
                        idx + 1,
                        line.trim().to_string(),
                        "Follow CEI (Checks-Effects-Interactions): complete ALL state updates \
                         before making callbacks to external addresses.".to_string(),
                    ));
                }
            }
        }
        vulns
    }

    fn detect_iscontract_post_pectra(&self, content: &str) -> Vec<Vulnerability> {
        let mut vulns = Vec::new();
        let iscontract_re = re!(r"(extcodesize|isContract|\.code\.length)\s*");
        let auth_like_patterns = [
            "function onlyeoa",
            "function onlyhuman",
            "function onlyexternallyowned",
            "function requireeoa",
            "function allowedeoa",
            "function authorizedcaller",
            "function isauthorized",
            "function isallowed",
            "function validatecaller",
            "modifier onlyeoa",
        ];

        for (idx, line) in content.lines().enumerate() {
            if line.trim().starts_with("//") || line.trim().starts_with("*") {
                continue;
            }
            if iscontract_re.is_match(line) {
                let start = idx.saturating_sub(2);
                let end = (idx + 3).min(content.lines().count());
                let context: String = content
                    .lines()
                    .skip(start)
                    .take(end - start)
                    .collect::<Vec<_>>()
                    .join("\n");
                let context_lower = context.to_lowercase();
                let is_access_control = context.contains("require")
                    || context.contains("if")
                    || context.contains("revert")
                    || context.contains("assert")
                    || auth_like_patterns
                        .iter()
                        .any(|pattern| context_lower.contains(pattern));
                if line.contains("function isContract") {
                    continue;
                }
                if is_access_control {
                    vulns.push(Vulnerability::new(
                        VulnerabilitySeverity::Medium,
                        VulnerabilityCategory::IsContractPostPectra,
                        "extcodesize/isContract Unreliable Post-EIP-7702".to_string(),
                        "extcodesize or isContract() is used for access control. Post-Pectra (EIP-7702), \
                         EOAs can delegate to code, making extcodesize > 0 for regular wallets. \
                         Also unreliable during constructor execution.".to_string(),
                        idx + 1,
                        line.trim().to_string(),
                        "Do not use extcodesize/isContract for access control. Use EIP-1271 for \
                         signature verification, or implement account-type-agnostic logic.".to_string(),
                    ));
                }
            }
        }
        vulns
    }

    fn detect_unsafe_multicall_delegatecall(&self, content: &str) -> Vec<Vulnerability> {
        let mut vulns = Vec::new();
        let multicall_re = re!(r"(?i)function\s+(multicall|batch|aggregate)\s*\(");

        for (idx, line) in content.lines().enumerate() {
            if multicall_re.is_match(line) {
                let end = (idx + 30).min(content.lines().count());
                let body: String = content
                    .lines()
                    .skip(idx)
                    .take(end - idx)
                    .collect::<Vec<_>>()
                    .join("\n");
                if body.contains("delegatecall") {
                    let has_value_tracking = body.contains("remainingValue")
                        || body.contains("valueConsumed")
                        || body.contains("msg.value -")
                        || body.contains("ethUsed")
                        || body.contains("_refund");
                    if !has_value_tracking && !body.contains("payable") {
                        vulns.push(Vulnerability::new(
                            VulnerabilitySeverity::High,
                            VulnerabilityCategory::UnsafeMulticallDelegatecall,
                            "Multicall Uses delegatecall Without Value Isolation".to_string(),
                            "Multicall function uses delegatecall to forward calls. If any sub-call \
                             reads msg.value, it will see the full value on every iteration, enabling \
                             double-spending of ETH.".to_string(),
                            idx + 1,
                            line.trim().to_string(),
                            "Use address(this).call instead of delegatecall for multicall, or track \
                             consumed value and revert if total exceeds msg.value.".to_string(),
                        ));
                    }
                }
            }
        }
        vulns
    }

    fn extract_functions(&self, content: &str) -> Vec<ExtractedFunction> {
        let lines: Vec<&str> = content.lines().collect();
        let fn_re = re!(r"^\s*function\s+([A-Za-z_]\w*)\b");
        let mut functions = Vec::new();
        let mut idx = 0;

        while idx < lines.len() {
            let line = lines[idx];
            let Some(caps) = fn_re.captures(line) else {
                idx += 1;
                continue;
            };

            let name = caps.get(1).map_or("", |m| m.as_str()).to_string();
            let start_line = idx + 1;
            let mut signature_lines = vec![line.trim().to_string()];
            let mut body = String::new();
            let mut brace_depth: i32 = 0;
            let mut saw_open_brace = false;
            let mut saw_signature_terminator = line.contains(';');
            let mut end_idx = idx;

            for (scan_idx, scan_line) in lines.iter().enumerate().skip(idx) {
                if scan_idx > idx && !saw_open_brace {
                    signature_lines.push(scan_line.trim().to_string());
                }
                body.push_str(scan_line);
                body.push('\n');
                brace_depth += scan_line.matches('{').count() as i32;
                if scan_line.contains('{') {
                    saw_open_brace = true;
                }
                if scan_line.contains(';') {
                    saw_signature_terminator = true;
                }
                brace_depth -= scan_line.matches('}').count() as i32;
                end_idx = scan_idx;

                if !saw_open_brace && saw_signature_terminator {
                    body.clear();
                    break;
                }

                if saw_open_brace && brace_depth <= 0 {
                    break;
                }
            }

            functions.push(ExtractedFunction {
                name,
                start_line,
                signature: signature_lines.join(" "),
                body,
            });
            idx = end_idx + 1;
        }

        functions
    }

    /// Collect the names of *contract-level* state variables.
    ///
    /// Depth-aware on purpose: a flat line scan also picks up locals such as
    /// `uint256 tokenId = totalSupply();`, and callers that use this set to decide
    /// "is this a storage write?" would then treat local assignments as state
    /// changes. Only declarations at brace depth 1 (directly inside a contract,
    /// library, or interface body) count. Array declarations (`address[] public
    /// players;`) are included -- they are the storage that array-index writes
    /// like `players[i] = address(0)` target.
    fn extract_state_variable_names(&self, content: &str) -> HashSet<String> {
        let mut vars = HashSet::new();
        let var_re = re!(r"^\s*(?:mapping\s*\(.+\)|address|uint\d*|int\d*|bool|bytes\d*|string|bytes)(?:\s*\[[^\]]*\])*\s+(?:(?:public|private|internal|constant|immutable|override)\s+)*([A-Za-z_]\w*)\s*(?:=|;)");
        let container_re = re!(r"^\s*(?:abstract\s+)?(?:contract|library|interface)\s+\w+");

        let mut depth: i32 = 0;
        let mut in_container = false;

        for line in content.lines() {
            let trimmed = line.trim();
            if !in_container && container_re.is_match(line) {
                in_container = true;
            }

            // Declarations sit at depth 1: inside the container body, outside any
            // function body. Measure before applying this line's own braces so a
            // one-line `contract C { ... }` does not shift the frame.
            if in_container && depth == 1 && !trimmed.starts_with("//") {
                if let Some(caps) = var_re.captures(line) {
                    if let Some(name) = caps.get(1) {
                        vars.insert(name.as_str().to_string());
                    }
                }
            }

            depth += line.matches('{').count() as i32;
            depth -= line.matches('}').count() as i32;
            if depth <= 0 {
                depth = 0;
                in_container = false;
            }
        }

        vars
    }
}

#[cfg(test)]
mod tests {
    use super::AdvancedAnalyzer;

    #[test]
    fn extract_functions_skips_interface_prototypes() {
        let analyzer = AdvancedAnalyzer::new();
        let content = r#"
interface IERC20Like {
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
}

contract ExampleVault {
    uint256 public weeklyRevenue;

    function buyDbr(uint256 amount) external {
        weeklyRevenue += amount;
    }

    function slash(address receiver, uint256 amount) external {
        receiver;
        amount;
    }
}
"#;

        let functions = analyzer.extract_functions(content);
        let names: Vec<&str> = functions.iter().map(|function| function.name.as_str()).collect();

        assert_eq!(names, vec!["balanceOf", "transfer", "buyDbr", "slash"]);
        assert!(functions[0].body.is_empty(), "interface prototype should not absorb the rest of the file");
        assert!(functions[1].body.is_empty(), "interface prototype should not absorb the rest of the file");
        assert!(functions[2].body.contains("weeklyRevenue += amount;"));
        assert!(functions[3].body.contains("receiver;"));
    }

    #[test]
    fn detects_erc4626_liability_drift_after_interface_declarations() {
        let analyzer = AdvancedAnalyzer::new();
        let content = r#"// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20Like {
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
}

contract ERC4626SlashLiabilityDrift {
    IERC20Like public asset;
    uint256 public totalSupply;
    uint256 public weeklyRevenue;

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
"#;

        let findings = analyzer.analyze_2025_exploit_patterns(content);

        assert!(findings.iter().any(|finding| finding.title == "ERC4626 Liability Drift After Slash"));
    }
}

#[cfg(test)]
mod legacy_arith_tests {
    use super::AdvancedAnalyzer;

    #[test]
    fn flags_narrow_state_accumulator() {
        let a = AdvancedAnalyzer::new();
        let src = r#"
contract A {
    uint64 public totalFees = 0;
    uint256 public counter;

    function bump(uint256 fee) external {
        totalFees = totalFees + uint64(fee);
        counter += fee;
    }
}
"#;
        let types = a.extract_state_variable_types(src);
        println!("TYPES {:?}", types);
        let v = a.detect_legacy_unchecked_arithmetic(src);
        for x in &v {
            println!("FOUND {} @{}", x.title, x.line_number);
        }
        assert!(!v.is_empty());
    }
}
