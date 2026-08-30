# Research-Mining Prompt — EVM Security Corpora → 41Swara Rules

Paste the block below into Claude Code (or any agent with web + repo access) from the
scanner repo root. Work the batches in order; report between batches. Do not run all of it
in one pass.

Scope is **EVM / Solidity only**. Sixteen repositories, listed in §2 — that list is exhaustive
and closed.

---

## THE PROMPT

You are extending **41Swara**, a Rust static analyzer for **Solidity smart contracts on EVM
chains**. Your job is to mine the sixteen repositories listed below for detections the scanner
is **missing**, and land them as real, tested rules — not as a reading list.

Hard scope constraint: EVM/Solidity only. If a corpus entry targets another VM (Solana/Anchor,
Move, Cairo, CosmWasm, Bitcoin script), or targets off-chain infrastructure (bridges' relayer
daemons, key custody, front-end supply chain, RPC providers), **discard it without analysis**.
Do not translate a non-EVM bug class into a Solidity rule by analogy — analogized rules are the
single biggest source of false positives. The only exception is a bug class that independently
appears in EVM source, in which case cite the EVM source, not the analogy.

### 1. Ground yourself in the existing tool FIRST

Before reading any external repo, build an inventory of what already exists. Do not skip this;
every finding you propose will be judged against it.

- `src/vulnerabilities.rs` (~4.3k lines) — `VulnerabilityCategory` enum, `create_vulnerability_rules()`,
  `create_version_specific_rules()`. Rule IDs are `SWC-NNN` (registry) or `41S-NNN` (41Swara-native).
- `src/advanced_analysis.rs` (~6.2k lines) — DeFi/NFT/multi-line analyzers.
- `src/scanner.rs` — orchestration + `should_report_vulnerability_with_title()` (single-line
  suppression) and `multiline_category_suppressed()` (multi-line suppression).
- `src/false_positive_filter.rs` — safe-pattern allowlists, dedup, confidence scoring.
- `src/reachability_analyzer.rs`, `src/logic_analyzer.rs`, `src/inheritance.rs`,
  `src/eip_analyzer.rs`, `src/cvss.rs`.
- `src/parser.rs` — `CompilerInfo`: Solidity version, constraint, age, EVM features, CVEs.
- `test_contracts/*.sol` — positive fixtures. `tests/integration_tests.rs`, `tests/corpus/`.

Produce (and keep in working memory) a list of every `41S-NNN` and `SWC-NNN` currently
implemented, plus the highest `41S-NNN` in use, so new rules get the next free IDs.

### 2. The sixteen repositories — 5 batches, in this order

Ordered by signal-per-token: runnable exploit code first, curated catalogs next, link
aggregators last. Complete and report a batch before starting the next. Add nothing to this list.

**Batch 1 — code-bearing (vulnerable Solidity you can run the scanner against):**
- https://github.com/crytic/building-secure-contracts — Trail of Bits. `not-so-smart-contracts/`
  has one directory per bug class with vulnerable *and* fixed source. Highest signal here.
  (This repo also carries Cairo and Substrate material — skip those directories.)
- https://github.com/SunWeb3Sec/DeFiHackLabs — hundreds of Foundry PoCs reproducing *real* EVM
  incidents, each with a root-cause note and $ loss. Canonical source for exploit attribution.
  Filter to EVM chains (Ethereum, BSC, Arbitrum, Optimism, Base, Polygon, Avalanche C-Chain).
- https://github.com/kadenzipfel/smart-contract-vulnerabilities — structured Solidity bug
  taxonomy with minimal repro snippets.

**Batch 2 — attack-vector catalogs and disclosed-bug write-ups:**
- https://github.com/ImmuneBytes-Security-Audit/Blockchain-Attack-Vectors
- https://github.com/ArsenSecurity/Bounties-Exploit-Bugs
- https://github.com/crytic/awesome-ethereum-security

**Batch 3 — Solidity-specific curated lists:**
- https://github.com/shafu0x/awesome-smart-contracts
- https://github.com/moeinfatehi/Awesome-Smart-Contract-Security
- https://github.com/saeidshirazi/Awesome-Smart-Contract-Security

**Batch 4 — general web3 aggregators. Harvest *pointers*, not rules.** These six overlap each
other heavily and carry substantial non-EVM and off-chain content. Merge them into one
deduplicated candidate list FIRST, drop everything non-EVM and everything already covered by
Batches 1–3, and only then follow the surviving links to primary sources:
- https://github.com/Anugrahsr/Awesome-web3-Security
- https://github.com/fabionoth/awesome-web3-security
- https://github.com/ManasHarsh/Awesome-Web3-security
- https://github.com/gmh5225/awesome-web3-security
- https://github.com/Raiders0786/web3-security-resources
- https://github.com/SonyaMoisset/awesome-blockchain-security

**Batch 5 — on-chain account/wallet surface:**
- https://github.com/ValkyriSecurity/awesome-wallet-security — extract ONLY the Solidity-visible
  surface: EIP-712 / EIP-1271 signature handling, replay and nonce protection, ERC-4337 entrypoint
  and paymaster flows, ERC-7579/7821 modular accounts, approval and `permit` hygiene, session-key
  and module-installation flows. Skip key storage, seed phrases, device security, browser
  extensions, and off-chain wallet UX entirely — none of it is a static-analysis target.
  Note: `41S-090..092` already cover the ERC-7579/7821 execution surface. Extend those rather
  than duplicating them.

### 3. Method — apply to every repo, in this order

1. Clone or fetch the repo into the scratchpad, not into this project tree.
2. Enumerate its bug classes / incident entries into a flat list. Drop non-EVM entries here,
   at intake, before any analysis effort is spent on them.
3. For each surviving entry, classify against the inventory from step 1:
   - **COVERED** — an existing rule fires on it. Cite the rule ID. Move on.
   - **PARTIAL** — a rule exists but the pattern is narrower than the corpus case. Note the exact gap.
   - **MISSING** — no rule. Candidate for a new detection.
   - **UNDETECTABLE** — needs cross-contract state, economic simulation, or runtime data that a
     regex/heuristic static pass cannot reach. Say so honestly and drop it. Do not ship a rule
     that pretends to catch something it can't.
4. For every PARTIAL and MISSING, verify the claim empirically before proposing anything:
   write a minimal `.sol` repro to the scratchpad, run
   `cargo run --release --bin 41swara -- <file>`, and paste the actual output.
   A gap you did not reproduce is a hypothesis, not a finding.

### 4. Output contract — required for every proposed rule

| Field | Requirement |
|---|---|
| Proposed ID | Next free `41S-NNN`, or the existing `SWC-NNN` if it maps to a registry entry |
| Category | Existing `VulnerabilityCategory` variant, or an explicit case for adding one |
| Severity + confidence | With reasoning; new patterns start at Medium confidence unless the signature is unambiguous |
| Detection strategy | Single-line regex / multi-line span / analyzer function — and *why* that layer |
| Regex or logic sketch | Concrete enough to implement |
| Solidity version applicability | Which pragma range it applies to; route version-gated patterns through `create_version_specific_rules()` |
| True-positive fixture | Vulnerable Solidity that must fire |
| **Negative fixture** | Safe-but-similar Solidity that must NOT fire — mandatory, no exceptions |
| Known FP risks | Which OpenZeppelin / Solady / Uniswap idioms could trip it, and the suppression needed |
| Real-world attribution | Incident name, date, $ loss, chain, source link — DeFiHackLabs is the canonical source |
| Source citation | Repo + file path the pattern came from |

### 5. Quality gates — a rule is not done until all four pass

1. **FP benchmark.** Scan a clean OpenZeppelin contracts checkout before and after. Report the
   Critical+High delta. Any *increase* in Critical/High on unmodified OZ code is a blocking
   regression — tighten the pattern or add the suppression, don't rationalize it.
2. **Suppression layer is correct.** Single-line rules route through
   `should_report_vulnerability_with_title()`; multi-line rules bypass it entirely and must be
   handled in `multiline_category_suppressed()`, which receives RAW (unstripped) content so NatSpec
   mitigations stay visible. Getting this backwards silently disables the suppression.
3. **Tests.** Positive fixture added to the right `test_contracts/*.sol`, negative fixture added
   too, and `cargo test` green. `cargo clippy -- -D warnings` and `cargo fmt --check` clean.
4. **No runtime regression.** Report total scan time on `test_contracts/` before and after
   (`SCAN_PROFILE=1` prints per-phase timings to stderr). Rules compiled per-file instead of once
   are the usual culprit — follow the existing caching pattern.

### 6. Deliverables

- `docs/CORPUS_GAP_ANALYSIS.md` — the full COVERED / PARTIAL / MISSING / UNDETECTABLE table with
  source citations, ranked by (real-world $ impact × detectability). Append to this file as each
  batch completes; do not start a new file per batch.
- Implemented rules for the top N MISSING items, each meeting §4 and §5 in full.
- A short report per batch: what landed, what you deliberately skipped and why, how many entries
  were dropped at intake as non-EVM, and the OZ FP delta.

### 7. Rules of engagement

- **Do not** bulk-import a corpus's whole taxonomy. Precision beats coverage; this tool has already
  been through a dedicated FP-reduction pass (620 → 350 findings on OZ) and regressing that is worse
  than missing a detection.
- **Do not** add a rule whose only evidence is a README bullet. Every rule traces to Solidity source
  code you actually read.
- **Do not** trust an awesome-list's description of a bug over the actual PoC.
- **Do not** widen scope beyond the sixteen repos in §2, and do not follow Batch 4 links into
  non-EVM ecosystems.
- If two corpora describe the same bug differently, prefer the one with runnable exploit code.
- Later batches will re-surface bugs from earlier ones. That is expected — mark them COVERED against
  your own prior batch and move on rather than re-analyzing.

### 8. Start here

Batch 1, and within it `crytic/building-secure-contracts` (`not-so-smart-contracts/`) first.
Complete step 1's inventory, produce the gap analysis for Batch 1 only, and stop for review
before implementing anything.
