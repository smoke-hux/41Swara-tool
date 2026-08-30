# Corpus Gap Analysis

Mining sixteen public security corpora for detections 41Swara is missing. One section per
batch, appended as each batch completes. Driving spec: `docs/RESEARCH_MINING_PROMPT.md`.

Scope is EVM/Solidity only. Non-EVM (Solana, Move, Cairo, CosmWasm, Substrate, Sui, TON) and
off-chain infrastructure entries are dropped at intake without analysis, and never translated
into Solidity rules by analogy.

- **Branch:** `corpus-mining-batch1`
- **Scanner:** 41Swara v0.11.0, release build
- **Status:** Batch 1 complete — analysis only, nothing implemented. Awaiting review.

---

## Rule inventory at time of mining

Every rule ID maps 1:1 to a `VulnerabilityCategory` variant via `SwcId::new` in
`src/vulnerabilities.rs`.

| | Count | Range |
|---|---|---|
| Native `41S-NNN` | 82 | `41S-001` … `41S-092` |
| Registry `SWC-NNN` | 20 | 101, 102, 103, 104, 105, 106, 107, 109, 111, 112, 114, 115, 116, 117, 119, 120, 121, 128, 132 |
| Analyzer functions | 122 | `advanced_analysis`, `logic_analyzer`, `reachability_analyzer`, `eip_analyzer`, `inheritance`, `abi_scanner` |

**Highest `41S-NNN` in use: `41S-092`. Next free: `41S-093`.**
Unused gaps, reusable only deliberately: `41S-019`, `41S-032`–`041`, `41S-049`.

Two registry IDs are *listed* in the inventory but proved **inert** in testing — no rule fires
for them (see Batch 1 rows #24 and #32):

| ID | Category | Status |
|---|---|---|
| `SWC-119` | `ShadowingIssues` | Category exists; no rule matched any shadowing fixture |
| `SWC-109` | `UninitializedVariables` | Category exists; no rule matched an uninitialized storage pointer |

---

## Quality-gate baselines

Both gates required a "before" number; neither existed on this branch. Measured, not assumed.

### Gate 1 — OpenZeppelin false-positive baseline
`openzeppelin-contracts` v5.4.0, `contracts/` only, 319 files, `41swara -f json`.

> **Corrected 2026-08-30.** An earlier revision of this file reported 574 findings / 256
> Critical+High. That measurement was taken with a stale binary that predated the branch HEAD,
> so it was not a baseline for any commit. The numbers below are rebuilt from the actual
> commits and are deterministic across repeated runs.

| | `8bb29dc` (before) | `d8e60bf` (proxy-layout fix) |
|---|---|---|
| Critical | 58 | 58 |
| High | 202 | 26 |
| Medium | 45 | 45 |
| Low | 277 | 277 |
| **Total** | **655** | **479** |
| **Critical + High — the gate** | **260** | **84** |

The sole category delta between the two commits is `ProxyAdminVulnerability` **176 → 0**; every
other category is byte-identical. The proxy-collision detector was responsible for 68% of all
Critical+High findings on unmodified, audited OpenZeppelin code.

**Current gate: 84 Critical+High.** Any increase above that from new rules is a blocking
regression.

Remaining concentrations on clean OZ: `PragmaIssues` 255, `GasOptimization` 61,
`AccessControl` 23, `LogicError` 17, `StateVariable` 12, `CompilerBug` 13.

> One structural note found while measuring: `detect_proxy_storage_collisions` is invoked in the
> `enrichment` block *after* `false_positive_filter.filter(...)` runs, so proxy findings bypass
> the false-positive filter, dedup, and confidence scoring entirely. That is why 176 of them
> reached the report unchallenged. Worth revisiting if this detector is extended.

### Gate 4 — runtime baseline
`test_contracts/` (11 files), three runs: 1.81 s / 2.81 s / 2.41 s → **median ~2.4 s**, high
run-to-run variance. Dominant phases per `SCAN_PROFILE=1`: `version_rules`, `general_rules`,
`ast_bridge`, `logic_analyzer`, `analyze_2025_exploit_patterns`. New rules must compile once
into the master-rules cache, never per file.

---

# Batch 1 — code-bearing corpora

Three repos, mined in parallel. Every COVERED / PARTIAL / MISSING row below was produced by
running the scanner and reading its actual output; UNDETECTABLE rows are argued, not tested.

## Correction to the task premise: the ToB EVM corpus has moved

`crytic/building-secure-contracts` HEAD contains **zero `.sol` files** under
`not-so-smart-contracts/`. That directory now holds only `algorand cairo cosmos solana
substrate sui ton`. Unshallowing the clone (919 commits) confirms an `evm/` subdirectory never
existed there.

The EVM "Not So Smart Contracts" corpus — the one the task describes, vulnerable and fixed
Solidity side by side — lives in the separate upstream repo **`crytic/not-so-smart-contracts`**.
That repo was cloned and used instead, supplemented by Solidity under
`building-secure-contracts/program-analysis/` (Echidna/Manticore exercises) and `learn_evm/`.

## Intake

| Repo | Enumerated | Dropped at intake | Classified |
|---|---|---|---|
| `crytic/building-secure-contracts` + `crytic/not-so-smart-contracts` | 87 | **64** (55 non-EVM bug classes: algorand 11, cairo 6, cosmos 9, solana 6, substrate 7, sui 6, ton 10; + 9 prose-only `development-guidelines/*.md` with zero Solidity blocks) | 23 |
| `kadenzipfel/smart-contract-vulnerabilities` | 38 | **0** non-EVM (repo is 100% Solidity); 1 empty stub | 37 |
| `SunWeb3Sec/DeFiHackLabs` | 865 incidents | **0 non-EVM** (every PoC pins an EVM fork); 1 off-chain (Bybit phishing) + `academy/move/` tutorials | 16 root-cause groups, from 18 PoCs read in full |

**Total dropped at intake as non-EVM or prose-only: 64** — all from the ToB corpus. DeFiHackLabs
contributed zero non-EVM drops: chain distribution across 865 PoCs is bsc 379, mainnet 351,
arbitrum 41, base 40, polygon 24, avalanche 13, optimism 12, other EVM 16.

## Class totals (all three repos)

| Class | building-secure-contracts | smart-contract-vulnerabilities | DeFiHackLabs |
|---|---|---|---|
| COVERED | 5 | 14 | 8 |
| PARTIAL | 3 | 9 | 3 |
| MISSING | 9 | 8 | 4 |
| UNDETECTABLE | 4 | 6 | 2 |
| OBSOLETE / dropped | 2 | 1 | — |

The high COVERED rate in the taxonomy repo is the expected and desired outcome: reentrancy,
tx.origin, delegatecall, SWC-128 loop DoS, SWC-114, SWC-116, SWC-117, SWC-121, floating and
outdated pragma, incorrect constructor, `msg.value`-in-loop, and code-size assertion (41S-076)
all fire with a quoted finding line.

---

## The headline result: precision, not coverage

Both agents independently concluded that the highest-value work in Batch 1 is **removing false
positives, not adding rules** — and the task's own rules of engagement say precision beats
coverage. The following are reproduced in the main thread, not taken on report.

### FP-1 — Textbook CEI pull-payment draws two CRITICALs

```solidity
function withdraw() external {
    uint256 amount = credits[msg.sender];
    require(amount > 0, "nothing to withdraw");
    credits[msg.sender] = 0;                          // effect BEFORE interaction
    (bool ok, ) = msg.sender.call{value: amount}("");
    require(ok, "transfer failed");
}
```
```
🚨 ● Unprotected Critical Function: withdraw [Line 6]
   Severity: CRITICAL | CVSS: 9.1  | Confidence: High | Priority: P1
🚨 ● Potential Reentrancy Attack   [Line 10]
   Severity: CRITICAL | CVSS: 10.0 | Confidence: High | Priority: P1
```

This is the single most common correct pattern in DeFi, and the mitigation the ToB corpus
itself prescribes. The same two Criticals fire on that corpus's own **fixed** contracts —
`SecureAuction.withdraw` and `CrowdFundPull.withdraw`.

- The reentrancy finding is unambiguously wrong: state is zeroed before the call.
- The access-control finding is defensible in the abstract (a `public withdraw` with no
  modifier) but wrong in substance: the rule cannot distinguish "anyone can drain the contract"
  from "each caller withdraws only their own credited balance." Verified separately that the
  rule *does* correctly suppress on `onlyOwner`, so the guard detection works — it is the
  per-caller accounting case that is unhandled.

**Suppression layer:** the reentrancy half is a multi-line/CFG finding → belongs in
`multiline_category_suppressed(Reentrancy, raw)`. The access-control half is layer 1.

### FP-2 — The `abi.encodePacked` hash-collision rule is blind to most real uses

Two rules exist. One is unmatchable; the other is gutted by borrowed suppression:

| Location | Regex | Problem |
|---|---|---|
| `src/vulnerabilities.rs:2036` | `abi\.encodePacked\([^)]*\)[^)]*keccak256` | **Operand order is inverted.** Requires `encodePacked` to appear *before* `keccak256` on the line. Real Solidity is `keccak256(abi.encodePacked(...))`. Effectively unmatchable. |
| `src/vulnerabilities.rs:4178` | `(keccak256\|sha256)\s*\(\s*abi\.encodePacked\s*\([^)]*,\s*[^)]*\)` | Regex is correct, but the rule is categorised `UnsafeExternalCalls` and so inherits that category's layer-1 suppression at `src/scanner.rs:2045`: `if line.contains("(bool") \|\| line.contains("= ") \|\| line.contains("require(") { return false; }` — which discards the assignment and `require` forms. |

Verified form matrix on `0.8.20` (count of `Hash Collision Attack Risk` findings):

| Form | Fires? |
|---|---|
| `return keccak256(abi.encodePacked(a, b));` | yes |
| `emit E(keccak256(abi.encodePacked(a, b)));` | yes |
| `s = keccak256(abi.encodePacked(a, b));` | **no** — line contains `= ` |
| `bytes32 v = keccak256(abi.encodePacked(a, b));` | **no** — line contains `= ` |
| `require(keccak256(abi.encodePacked(a, b)) != 0);` | **no** — line contains `require(` |

The failing forms are exactly those matching the layer-1 guard, which confirms the diagnosis:
the rule works, and the suppression borrowed from `UnsafeExternalCalls` removes the assignment
and `require` forms — i.e. most real uses, including the corpus's own exploit shape
`bytes32 hash = keccak256(abi.encodePacked(admins, regularUsers));`.

The root cause is **category mis-assignment**. "Don't report if the return value is captured" is
correct for `.call()` and meaningless for a hash-collision rule, where capturing the hash is the
entire point. The fix is to give this rule its own category rather than to widen the regex.

The taxonomy agent additionally reports the rule mis-firing on OZ `MerkleProof._hashPair(bytes32,
bytes32)` — fixed-size args cannot collide — so a type gate removes a real FP at the same time.

### FP-3 — 41S-076 fires on the documented mitigation

`require(to.code.length > 0)` is the corpus's prescribed fix for calling a possibly-nonexistent
contract, and it draws `41S-076 IsContractPostPectra`. Flagging the mitigation trains users to
ignore the rule.

### FP-4 — Severity is inverted on several fixture pairs

On `unchecked-send`, `selfbalance-includes-msgvalue`, and the Popsicle Broken/Fixed pair, the
**safe** file scores at or above the vulnerable one. `PopsicleFixed` produces *more* findings
than `PopsicleBroken`. This is a signal-quality problem independent of any single rule.

### Unconfirmed FP claims

Two reported items did **not** reproduce on minimal fixtures in the main thread, and are
recorded as unconfirmed rather than repeated as fact:
- "Public Oracle Update — Frontrunnable (CRITICAL) on an `onlyOwner` setter" — the guarded
  fixture yielded only `Oracle Update Without Deviation Check` at **Medium**.
- "`CFG-Confirmed: State Change After External Call` on `.transfer()`" — the `.transfer()`
  fixture yielded only `Low Gas Stipend with .transfer()` at Low.

Both may depend on fixture specifics in the agents' larger files. They need a second look before
any fix is written against them.

### Adjacent quirk observed while verifying

`Nested External Calls: withdraw -> withdraw` reports `Severity: MEDIUM | CVSS: 10.0 |
Priority: P1`. Medium severity carrying a 10.0 vector is the known "mapped categories force the
category vector regardless of per-instance severity" behaviour recorded in project memory. Noting
it because it recurred, not proposing a change.

---

## DeFiHackLabs — root causes, with money attached

865 incidents enumerated (121 × 2026, 161 × 2025, 189 × 2024, 394 × 2021–23). Grouped by **root
cause**, not per incident, because most PoCs share one. 471 in-window titles read; **18 PoCs read
in full at source level; ~845 of 865 were not opened**. Frequency counts for groups G2, G6 and G7
lean on title keywords and are estimates.

| Group | Root cause | Class | Rule | $ in corpus | Incidents |
|---|---|---|---|---|---|
| G1 | Arbitrary external call where target+calldata come from a **struct field** or a `call{value:}` form | **PARTIAL** | 41S-005 | **≈$26.6M** | 22 |
| G2 | AMM spot price from `balanceOf(pair)` ratio rather than `getReserves()` | **PARTIAL** | 41S-001 | ~$1M in-window, long tail | ~70 |
| G3 | ERC-20 `transferFrom` with absent or wrong-key allowance check | **MISSING** | — | 2.02 ETH + 3 unquantified | 4 |
| G4 | ERC-4626 `withdraw`/`redeem` override missing the allowance spend | **MISSING** | — | ~$399K | 1 + adjacent |
| G5 | Self-transfer balance doubling (both balances cached before either write) | **MISSING** | — | 1 flash-loan drain + 2 | 3 |
| G6 | Token mutates the pair's own balance, then calls `pair.sync()` | **PARTIAL** | 41S-013 | ≈$570K+ | 25 |
| G7 | Duplicate IDs in a caller-supplied array; accrue in loop, commit after | **MISSING** | — | 6.21 ETH + 4 | 5 |
| G8 | `ecrecover` result never compared against `address(0)` | **PARTIAL** | SWC-117 | ~$85.5K + 4 | 5 |
| G9–G16 | Flash-loan callback validation, fake flash-swap callback, vault donation inflation, unprotected `initialize()`, classic reentrancy, weak randomness, zero slippage, `tx.origin` | **COVERED** | 41S-002, 41S-004, 41S-020/073, 41S-053/059, SWC-107, SWC-120, 41S-074/084, SWC-115 | — | — |

### G1 is the batch's single best finding — verified in the main thread

41S-005 fires on a plain `address` parameter and misses the two forms every router and
aggregator actually uses:

```solidity
function execA(address target, bytes calldata data) external            // fires
{ (bool ok,) = target.call(data); }

function execB(Call calldata c) external                                 // SILENT
{ (bool ok,) = c.callTo.call(c.callData); }

function execC(address target, bytes calldata data) external payable     // SILENT
{ (bool ok,) = target.call{value: msg.value}(data); }
```
```
🚨 ● Arbitrary External Call to User Address [Lines 6-7]     <- execA only
🚨 ● Arbitrary Calldata Execution [Line 7]                   <- execA only
⚠️  ● State Check After External Call in execB [Line 11]      <- not an arbitrary-call finding
⚡ ● Push Payment to Arbitrary Recipient in execC [Line 17]   <- not an arbitrary-call finding
```

Attribution: Li.Fi ($10M), Seneca ($6M), Squid ($3.98M), Socket ($3.3M), Unizen ($2M) — **22
incidents, ≈$26.6M**, the largest single group in the corpus. The struct-member form *is* the
Li.Fi/Socket/Squid shape. Two regex edits.

**Flags caveat resolved for this group:** re-run with `--defi-analysis`, `--advanced-detectors`
and `--project-analysis` in every combination yields the identical result — 2 arbitrary-call
findings, both on `execA`. The gap is not hidden behind an opt-in mode.

### Additional precision defects

- **OZ `ERC20Burnable.burn(uint256)` draws a CRITICAL** `Missing Access Control on
  State-Changing Function` — reproduced in the main thread. Burning your own balance needs no
  guard, and OZ ships this contract, so it feeds the OZ baseline's 23 `AccessControl` hits.
- **Correct OZ `transferFrom` draws a CRITICAL** from the same catch-all — which is why G3 has
  zero discriminating power today: the vulnerable and correct versions produce the same finding.
- **Access-control findings land on `interface` declaration lines**, which have no body to guard.
- *Unconfirmed:* `Flash Loan Callback Missing Pool Validation` reported as firing despite
  `require(msg.sender == pool)`. A minimal correctly-guarded Aave `executeOperation` fixture came
  back **clean** in the main thread, so this needs the agent's larger fixture before anyone acts
  on it.

### Honest UNDETECTABLE calls from this corpus

- **Cross-chain attestation semantics** (Allbridge CCTP; also Verus $11.58M, Adshares $628K).
  Circle's `sendMessage` attests *submission*, not *value movement*. Catching this needs the
  semantic guarantee of a third-party contract on another chain; any regex would fire on every
  correct bridge.
- **Dividend/payout-ledger accounting** (Bankroll family, SWAPPStaking, SorStaking, LPMine,
  Revamp — 28 in-window titles). The PoCs call deployed bytecode with **no victim source in
  repo**, so there is nothing to ground a rule on beyond a README line. Correctly refused. This
  is the largest recoverable group left unexamined and the obvious first target for a follow-up
  that pulls verified sources from the explorers the PoCs link.
- **Economic/insolvency invariants** (SharwaFinance, MIMSpell3, AjnaFinance, SummerFi) — need
  cross-contract state and price paths.
- **Rug pulls and key compromise** (~11 titles) — the code works as its author intended; a
  "malicious owner" detector is a different product.
- **Governance-timeout takeovers** (PantherBase, StrongBlock) — turn on on-chain governance
  state, not code shape. 41S-083/41S-012 already cover the statically visible half.

### Methodological caveat carried forward

Every DeFiHackLabs run used default flags. I resolved this for G1 above; **G2–G8 were not
re-tested across the opt-in modes** and should be before any of them is implemented.


---

## Convergent gaps — found independently by more than one corpus

Independent agreement across corpora is the strongest signal in this batch.

| Gap | ToB corpus | smart-contract-vulnerabilities | Verified |
|---|---|---|---|
| `.send()` return value discarded | P-5 (King of the Ether) | P-10 | Yes — `winner.send(amt);` yields only a taint-flow note, nothing about the dropped bool |
| Weak-randomness sources too narrow | P-8 (`blockhash`, `coinbase`, `gaslimit` silent) | P-15 (multi-line form yields zero findings) | Yes |
| Shadowing (SWC-119 inert) | P-6 | P-8 | Yes — vulnerable and safe versions produce identical output |
| Narrowing/sign casts beyond 41S-054 | P-4 (uint→int in a bound check) | P-6 (4 of 5 syntactic forms missed) | Yes |
| `unchecked { }` arithmetic on 0.8+ | P-3 | P-7 | Yes — 41S-017 is legacy-pragma-gated only |

---

## Ranked candidate list — Batch 1, all three repos reporting

Ranked by (real-world $ impact × detectability), FP fixes included as first-class items because
the task's rules of engagement rank precision above coverage.

| # | Item | Source | Class | $ impact | Detectability | Note |
|---|---|---|---|---|---|---|
| 1 | **G1** Arbitrary external call: struct-member target + `call{value:}` | DHL | PARTIAL (41S-005) | **≈$26.6M / 22 incidents** | **High** | Two regex edits. Verified across all opt-in flags. Biggest $ in the batch, smallest fix. |
| 2 | **FP-1** CEI pull-payment → 2 CRITICALs | ToB | FP fix | — | Very high | Most common correct DeFi pattern; fires on the corpus's own prescribed fixes |
| 3 | **FP-2** `abi.encodePacked` blind to assignment/`require` forms, mis-fires on fixed-size args | SCV | FP fix + FN fix | High (auth bypass) | High | One category change fixes both halves |
| 4 | **G2** `balanceOf(pair)` ratio pricing | DHL | PARTIAL (41S-001) | ~$1M in-window, long tail | Medium-high | Corpus's #1 root cause by frequency (~70). Extension of an existing rule. |
| 5 | Unprotected privileged setter | ToB | MISSING | Very high (Parity class) | High | Unguarded and `onlyOwner` versions byte-identical today; twin of FP-1 |
| 6 | **G4** ERC-4626 `withdraw`/`redeem` missing allowance spend | DHL | MISSING | ~$399K | **High** | Signature-anchored, OZ negative silent. Best precision-per-effort. |
| 7 | **G6** pair-balance write + `pair.sync()` | DHL | PARTIAL (41S-013) | ≈$570K / 25 | High | Promoting the compound shape *raises* precision vs today's generic HIGH |
| 8 | **G3** `transferFrom` allowance absent/wrong key | DHL | MISSING | 2.02 ETH + 3 | High | Also fixes the correct-OZ-`transferFrom` FP |
| 9 | `.send()` discarded return | ToB + SCV | MISSING | Medium-high (King of the Ether) | **Very high** | One regex, near-zero FP |
| 10 | Weak randomness widening | ToB + SCV | PARTIAL | Medium-high | **Very high** | One-line alternation + a multi-line span rule (layer 2) |
| 11 | 41S-054 downcast form coverage | SCV | PARTIAL | High | High | Rule is trusted; only its anchor is wrong |
| 12 | `ecrecover` unchecked vs `address(0)` | SCV + DHL (G8) | MISSING / PARTIAL | High; ~$85.5K enumerated | High | A finding already lands on the right line with the wrong story |
| 13 | Reward accounting not settled on transfer | ToB | MISSING | High (Popsicle $20.7M) | Medium | ToB's flagship modern example; structural |
| 14 | **FP-3** 41S-076 on `to.code.length > 0` | SCV | FP fix | — | Very high | Flags the documented mitigation |
| 15 | **G5** self-transfer balance doubling | DHL | MISSING | Small | **High** | Zero current output; OZ never caches the recipient balance |
| 16 | `unchecked { }` block without guard (0.8+) | ToB + SCV | MISSING | High | Medium-high | **Highest FP danger on this list** — gate carefully |
| 17 | **G7** duplicate array IDs, accrue-then-commit | DHL | MISSING | 6.21 ETH + 4 | Medium | Larger analyzer job |
| 18 | Unsigned→signed cast in a bound check | ToB | MISSING | Medium-high | High | Attribution needs sourcing before ship |
| 19 | Unbounded return-data copy | SCV | MISSING | Medium | Medium | Griefing only |
| 20 | Relayer gas griefing | SCV | MISSING | Medium | Medium | OZ and Gnosis ship the mitigation → clean negative |
| 21 | Off-by-one `i < length - 1` | SCV | MISSING | Medium | Medium | Ship only with a successor-access body check |
| 22 | TOD consumer side | ToB | PARTIAL | High in aggregate (MEV) | Medium | The paired FP fix is worth more than the coverage |
| 23 | `msg.value` vs `address(this).balance` | ToB | MISSING | Low-medium | Very high | Narrow and cheap |
| 24 | Division before multiplication | SCV | PARTIAL | Medium | Medium | The 2026-07 pass removed a broader version — reintroduce only gated |
| 25 | Deprecated functions (7 more keywords) | SCV | PARTIAL | Low (legacy) | Very high | Only `callcode` fires today |
| 26 | Default visibility | SCV | MISSING | Low (legacy) | Very high | Pragma-gated to <0.5.0 |
| 27 | Wrong constructor name | ToB | PARTIAL | Low (legacy) | High | Value is the FP fix, not the coverage |

Sources: **ToB** = `crytic/not-so-smart-contracts` + `building-secure-contracts`,
**SCV** = `kadenzipfel/smart-contract-vulnerabilities`, **DHL** = `SunWeb3Sec/DeFiHackLabs`.

**Suggested first slice:** items 1–3. G1 is the largest dollar gap in the corpus and costs two
regex edits; FP-1 and FP-2 are the two precision defects that most undermine trust in the
output. Shipping them together also keeps the OZ gate honest — FP-1 and the `ERC20Burnable.burn`
defect both *reduce* the Critical+High count, so a new-rule increase would otherwise be masked.

### Recommended against shipping

- **Dirty upper bits in inline assembly** — unattributed, low detectability, speculative.
- **Unencrypted private data on-chain (SWC-136)** in general form — name-heuristic only
  (`secretKey`, `password`); would fire on every `private` state variable with a suggestive name.

---

## Honest UNDETECTABLE calls

Recorded so nobody re-opens them, and so no rule is shipped that pretends to catch them.

| Entry | Why a static per-file pass cannot reach it |
|---|---|
| `incorrect_interface` | Interface declaration and implementation are in different files by construction. `--project-analysis` produced no cross-file selector comparison. |
| `honeypots/GiftBox` | The trap is an Etherscan UI rendering artefact (0-value internal txs), not a source property. |
| `honeypots/PrivateBank` | The trap is deployed bytecode differing from published source. Not a source property. |
| `arbitrary-storage-location` | Needs storage-slot arithmetic modelling. |
| `assert-violation`, `requirement-violation` | "Is this condition the right one?" is a specification question, not a syntactic one. |
| `incorrect-inheritance-order` | Needs the full multi-file C3 linearisation graph. |
| `inadherence-to-standards` | Non-standard reverts on 0-value/0x0 transfers need cross-contract semantics. |

### Obsolete — real bugs, dead syntax

`honeypots/Lottery` (uninitialized struct storage pointer) and `honeypots/VarLoop` (`var` →
`uint8` narrowing) are **compile errors** on Solidity ≥ 0.5. Inherited state shadowing was
compiled against solc 0.8.17 and is likewise a hard error; only the local/parameter variant is
live. `uninitialized-storage-pointer` is legacy-audit-only for the same reason.

---

## Sub-report artifacts

Full per-repo reports, every repro `.sol`, and every negative fixture live in the session
scratchpad (`reports/batch1-*.md`, `repro/`). They are not committed; the tables above carry the
conclusions and the quoted evidence.

## Operational note

The scanner writes `reports/41swara_report_<name>_<ts>.md` into its **current working
directory**. A research loop run from the project tree will litter it (the path is gitignored,
so `git status` stays clean and the litter is easy to miss). Run the binary from a scratch
directory. The project tree was verified clean after this batch.

---

## Follow-up: edge cases in the `d8e60bf` review fixes

Found and fixed while re-measuring the baseline (both verified by running the binary, both
covered by new regression tests; `cargo test` 162 passed, `clippy -D warnings` and
`fmt --check` clean; OZ gate unchanged at 84 Critical+High).

| # | Edge case | Was | Now |
|---|---|---|---|
| 1 | One oversized file aborted the entire `--project-analysis` run — `scan_project` propagated the new `Err` with `?`, so a single 10 MB file suppressed every finding in the repo and exited 1 | exit 1, zero output | logs the file, skips it, finishes the scan, exit 0 |
| 2 | The proxy-collision gate still paired **unrelated** contracts: any file containing a `delegatecall` plus any contract named `*Proxy*` produced a High `Storage Slot Collision` against every other storage-bearing contract | `Alpha` vs `SomeProxy` reported | requires a shared name stem (`VaultProxy`/`VaultImplementation` → `vault`); unrelated stems skipped |

Edge case 1 was a regression introduced by making oversized files an error: the four scan paths
disagreed on what to do with one. `--audit` and plain directory scans logged and continued,
`--project-analysis` aborted, single-file scans errored. They now agree except for the
single-file case, where erroring is correct.

Edge case 2 is the gap the original tests missed: the existing negative fixture has no
`delegatecall`, so it passed on the first gate and never exercised the name check.

## Batch 1 status

- [x] Inventory
- [x] Quality-gate baselines measured
- [x] `crytic/building-secure-contracts` (+ upstream `crytic/not-so-smart-contracts`)
- [x] `kadenzipfel/smart-contract-vulnerabilities`
- [x] `SunWeb3Sec/DeFiHackLabs`
- [x] Batch 1 complete — 3 of 3 repos
- [ ] **Review gate — no implementation until Batch 1 is signed off**
- [ ] Batch 2 (attack-vector catalogs) — not started

