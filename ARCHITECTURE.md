# 41Swara Smart Contract Scanner &mdash; Architecture

**Version:** 0.8.0 &nbsp;|&nbsp; **Language:** Rust &nbsp;|&nbsp; **Total Source:** ~27,600 lines across 34 modules

---

## High-Level Overview

```
┌──────────────────────────────────────────────────────────────────────────┐
│                          CLI  (main.rs)                                  │
│   clap parsing · thread pool · watch mode · git diff · output routing   │
└────────────────────────────────┬─────────────────────────────────────────┘
                                 │
                    ┌────────────▼────────────┐
                    │   Scanner Orchestrator  │
                    │      (scanner.rs)       │
                    │  config · context detect│
                    │  should_report filter   │
                    │  multi-line sig parsing │
                    └─────┬────────┬──────────┘
                          │        │
            ┌─────────────┘        └──────────────┐
            ▼                                      ▼
┌───────────────────────┐              ┌───────────────────────┐
│   Pattern Matching    │              │   Advanced Analysis   │
│  (vulnerabilities.rs) │              │                       │
│  200+ regex rules     │              │  ┌─────────────────┐  │
│  SWC/CWE mapping      │              │  │ DeFi Analyzers  │  │
│  severity + confidence│              │  │  amm · lending  │  │
└──────────┬────────────┘              │  │  oracle · mev   │  │
           │                           │  └─────────────────┘  │
           │                           │  ┌─────────────────┐  │
           │                           │  │ AST Engine      │  │
           │                           │  │  parser · cfg   │  │
           │                           │  │  dataflow/taint │  │
           │                           │  │  interprocedural│  │
           │                           │  └─────────────────┘  │
           │                           │  ┌─────────────────┐  │
           │                           │  │ Logic & Reach.  │  │
           │                           │  │  logic_analyzer │  │
           │                           │  │  reachability   │  │
           │                           │  └─────────────────┘  │
           │                           │  ┌─────────────────┐  │
           │                           │  │ EIP Analyzer    │  │
           │                           │  │  30+ EIP rules  │  │
           │                           │  └─────────────────┘  │
           │                           │  ┌─────────────────┐  │
           │                           │  │ Threat Model    │  │
           │                           │  │  STRIDE gen     │  │
           │                           │  └─────────────────┘  │
           │                           └───────────┬───────────┘
           │                                       │
           └────────────┬──────────────────────────┘
                        ▼
           ┌────────────────────────┐
           │  False Positive Filter │
           │ (false_positive_filter)│
           │  3-layer reduction     │
           │  6 dedup groups        │
           │  function-scope merge  │
           │  ~90% FP removal       │
           └────────────┬───────────┘
                        ▼
           ┌────────────────────────┐
           │  Finding Enrichment    │
           │                        │
           │  cvss.rs    (CVSS 3.1) │
           │  exploit_db (53 refs)  │
           │  attack_path (20+ cat) │
           └────────────┬───────────┘
                        ▼
           ┌────────────────────────┐
           │    Output Generation   │
           │                        │
           │  reporter (terminal)   │
           │  professional_reporter │
           │  sarif (GitHub/CI)     │
           │  JSON (pipelines)      │
           │  Markdown (auto-save)  │
           └────────────────────────┘
```

---

## Project Structure

```
smart-contract-scanner/
├── src/
│   ├── main.rs                  (1,880 lines)  CLI entry, orchestration, watch/git modes
│   ├── scanner.rs               (1,366 lines)  Core scanning engine, context detection
│   ├── vulnerabilities.rs       (3,189 lines)  200+ vulnerability rules, SWC/CWE maps
│   ├── advanced_analysis.rs     (4,526 lines)  DeFi/NFT/L2/exploit pattern analyzers
│   ├── false_positive_filter.rs (1,327 lines)  Multi-pass false positive reduction
│   ├── logic_analyzer.rs        (1,300 lines)  Business logic bug detection
│   ├── reachability_analyzer.rs   (841 lines)  Code path reachability analysis
│   ├── eip_analyzer.rs            (848 lines)  EIP/ERC standard vulnerability checks
│   ├── threat_model.rs          (1,177 lines)  STRIDE threat model auto-generation
│   ├── dependency_analyzer.rs     (583 lines)  Import/dependency CVE analysis
│   ├── abi_scanner.rs             (725 lines)  ABI JSON security analysis
│   ├── parser.rs                  (372 lines)  Solidity source parsing
│   ├── cache.rs                   (362 lines)  Incremental scanning cache (blake3)
│   ├── config.rs                  (190 lines)  TOML config loading and rule overrides
│   │
│   ├── cvss.rs                    (344 lines)  CVSS 3.1 base score calculator    [v0.8.0]
│   ├── exploit_db.rs              (192 lines)  Real-world exploit reference DB    [v0.8.0]
│   ├── attack_path.rs             (245 lines)  Attack narrative generator         [v0.8.0]
│   │
│   ├── ast/                                    AST-Based Analysis Engine
│   │   ├── mod.rs                  (18 lines)
│   │   ├── parser.rs            (1,030 lines)  tree-sitter Solidity parsing
│   │   ├── cfg.rs                 (833 lines)  Control flow graph construction
│   │   ├── dataflow.rs            (723 lines)  Taint analysis + interprocedural propagation
│   │   └── bridge.rs              (134 lines)  AST-to-Vulnerability bridge
│   │
│   ├── defi/                                   DeFi-Specific Analyzers
│   │   ├── mod.rs                 (113 lines)
│   │   ├── amm_analyzer.rs        (456 lines)  Uniswap V2/V3/V4, Curve, slippage
│   │   ├── lending_analyzer.rs    (464 lines)  Aave/Compound, liquidation, flash loans
│   │   ├── oracle_analyzer.rs     (413 lines)  Chainlink, TWAP, L2 sequencer
│   │   └── mev_analyzer.rs        (576 lines)  Sandwich, frontrunning, commit-reveal
│   │
│   ├── integrations/                           External Tool Integration
│   │   ├── mod.rs                  (11 lines)
│   │   ├── slither.rs             (567 lines)  Slither JSON correlation
│   │   └── foundry.rs             (575 lines)  Foundry PoC test generation
│   │
│   ├── reporter.rs                (531 lines)  Terminal + markdown output formatting
│   ├── professional_reporter.rs   (845 lines)  Audit report generation (exec summary, priority matrix)
│   ├── sarif.rs                   (340 lines)  SARIF 2.1.0 output (GitHub/CI)
│   └── project_scanner.rs         (503 lines)  Cross-file project analysis
│
├── tests/
│   ├── integration_tests.rs       (371 lines)  20 integration tests
│   └── contracts/                              13 test Solidity contracts
│       ├── reentrancy/                         Classic + safe reentrancy
│       ├── access_control/                     Unprotected + Ownable-safe
│       ├── defi/                               Vulnerable vault
│       ├── false_positives/                    5 FP regression contracts      [v0.8.0]
│       └── v07_exploits/                       Multicall + cross-chain
│
├── test_contracts/                             Sample vulnerable Solidity files
├── scripts/                                    Build/deploy utilities
├── man/                                        Unix man pages (41.1, 41swara.1)
├── dist/                                       Distribution packaging
├── Cargo.toml                                  Dependencies & build config
├── Makefile                                    Install targets (global/user-local)
└── *.md                                        Documentation files
```

---

## Core Components

### 1. CLI Entry Point &mdash; `main.rs`

Handles argument parsing (clap derive), thread pool setup, and routing to the correct scan mode.

| Mode | Flag | Description |
|------|------|-------------|
| Default scan | `41 .` | Full analysis on directory or file |
| Fast mode | `--fast` | Regex-only, skip advanced analyzers |
| Watch mode | `--watch` | Continuous monitoring, rescan on change |
| Git diff | `--git-diff` | Scan only modified `.sol` files |
| Audit report | `--audit` | Professional security audit output |
| ABI analysis | `--abi` | Scan ABI JSON for interface-level issues |
| Project analysis | `--project-analysis` | Cross-file vulnerability detection |

**v0.8.0 default changes:**
- FP filter and EIP analysis are now **on by default** (opt out with `--no-fp-filter` / `--no-eip-analysis`)
- Threat model findings hidden by default (show with `--show-threat-model`)

### 2. Scanner Orchestrator &mdash; `scanner.rs`

The core engine that coordinates all analysis passes for each file.

**Pipeline per file:**
```
Source code
  → Parse (version, imports, pragmas)
  → Context detection (SafeMath, ReentrancyGuard, access control, SafeERC20)
  → Pattern matching (vulnerabilities.rs — 200+ rules)
  → Advanced analysis (DeFi, NFT, L2, EIP, logic, reachability)
  → Context-aware filtering (should_report_vulnerability)
  → False positive filter (false_positive_filter.rs)
  → CVSS 3.1 enrichment (cvss.rs)                                    [v0.8.0]
  → Exploit reference lookup (exploit_db.rs)                          [v0.8.0]
  → Attack path generation (attack_path.rs)                           [v0.8.0]
  → Final vulnerability list (sorted by line number)
```

**Context Detection:**
```
Contract Context
├── Solidity version (affects which rules apply)
├── SafeMath usage (filters arithmetic warnings)
├── ReentrancyGuard (filters reentrancy warnings)
├── Access control modifiers (onlyOwner, onlyRole, etc.)
├── Multi-line function signature parsing                              [v0.8.0]
│   └── Catches modifiers split across lines (function X()\n  onlyOwner)
├── Inheritance-aware modifier resolution                              [v0.8.0]
│   ├── Ownable → onlyOwner
│   ├── ReentrancyGuard → nonReentrant
│   ├── Pausable → whenNotPaused, whenPaused
│   ├── AccessControl → onlyRole
│   └── Initializable → initializer, reinitializer
├── SafeERC20 usage (filters unchecked return warnings)
├── OpenZeppelin/Solmate/Solady imports
└── Comment/annotation detection (@audit, @security, // SAFE)
```

### 3. Vulnerability Rules &mdash; `vulnerabilities.rs`

Contains 200+ regex-based rules, each with:
- Category (one of 77 `VulnerabilityCategory` variants)
- Severity, confidence
- SWC ID (SWC-100 to SWC-136) or custom ID (41S-001 to 41S-077)
- CWE mapping (MITRE Common Weakness Enumeration)
- Title, description, recommendation

**Severity Levels:**

| Level | Exit Code | Meaning |
|-------|-----------|---------|
| Critical | 1 | Immediate fund loss, contract takeover |
| High | 1 | Significant security impact, likely exploitable |
| Medium | 2 | Conditional risk, specific circumstances needed |
| Low | 3 | Best practice violation, minor risk |
| Info | 3 | Informational, code quality |

**Category Coverage (selected):**

| Category | SWC/ID | Count | Examples |
|----------|--------|-------|---------|
| Reentrancy | SWC-107 | 8+ | CEI violations, cross-function, read-only |
| Access Control | SWC-105 | 6+ | Unprotected functions, missing modifiers |
| Oracle Manipulation | 41S-001 | 5+ | Stale price, missing TWAP, no fallback |
| Flash Loan | 41S-002 | 4+ | Governance, oracle, callback attacks |
| Proxy/Upgrade | 41S-003 | 5+ | Uninitialized impl, storage collision |
| Signature | SWC-121 | 4+ | Replay, malleability, missing nonce |
| DoS | SWC-128 | 4+ | Unbounded loops, gas griefing |
| L2/Cross-chain | 41S-029+ | 6+ | Sequencer, bridge, PUSH0, gas oracle |
| Math/Precision | 41S-054+ | 6+ | Unsafe downcast, rounding, CLMM overflow |
| 2025&ndash;2026 Exploits | 41S-060+ | 18 | Cetus, Balancer, Atlas, GMX, Abracadabra |

### 4. Advanced Analysis &mdash; `advanced_analysis.rs`

The largest module (4,526 lines). Deep analysis for protocol-specific patterns.

```
advanced_analysis.rs
├── DeFi vulnerability detection
│   ├── Price oracle manipulation (balanceOf, missing TWAP, Chainlink)
│   ├── Flash loan attack vectors
│   ├── Slippage/MEV protection gaps
│   ├── Liquidity pool vulnerabilities
│   └── Yield farming precision errors
├── NFT vulnerability detection
│   ├── Supply cap validation
│   ├── Unsafe transferFrom
│   ├── Mutable metadata
│   └── Royalty (EIP-2981) issues
├── L2/Cross-chain patterns
│   ├── Sequencer uptime checks
│   ├── PUSH0 opcode compatibility (0.8.20+)
│   ├── Bridge message validation
│   └── Gas oracle manipulation
├── Modern protocol patterns (2024-2026)
│   ├── ERC-4626 inflation attack
│   ├── Permit2 signature reuse
│   ├── LayerZero V2 trusted remote
│   ├── Uniswap V4 hook exploitation
│   ├── Chainlink CCIP validation
│   └── Transient storage reentrancy (EIP-1153)
├── v0.6.0 security hardening
│   ├── Missing storage gap (upgradeable)
│   ├── Missing timelock (admin functions)
│   ├── selfdestruct deprecation (EIP-6780)
│   ├── Uninitialized implementation
│   ├── Unsafe downcast (uint256→uint128)
│   └── Double initialization
└── v0.7.0 2025-2026 exploit patterns
    ├── Multicall state reset (Abracadabra $14.7M)
    ├── Inconsistent state reset (Yearn $9M)
    ├── CLMM math overflow (Cetus $223M)
    ├── Inconsistent rounding (Balancer $128M)
    ├── Unvalidated cross-chain receiver (Atlas $112M)
    ├── Arbitrary receiver callback (GMX $42M)
    ├── ERC-2771 multicall spoofing (Thirdweb)
    ├── Multicall msg.value reuse
    ├── EIP-7702 tx.origin bypass
    └── Donation attack vector
```

### 5. AST Engine &mdash; `ast/`

Regex-based Solidity AST extraction with control flow and taint analysis.

```
ast/
├── parser.rs    — Solidity AST extraction (contracts, functions, variables)
├── cfg.rs       — Control flow graph construction per function
├── dataflow.rs  — Taint analysis: track user input → dangerous sinks
│                  + Inter-procedural propagation (fixed-point, max 10 rounds)  [v0.8.0]
│                  + Function summaries (taint sources/sinks per function)      [v0.8.0]
└── bridge.rs    — AST analysis → Vulnerability finding converter
```

**Inter-procedural taint propagation (v0.8.0):**
The `InterproceduralAnalyzer` builds a call graph across all functions in a contract, then iterates (up to 10 rounds) to propagate taint summaries through internal function calls. When a callee returns tainted data or has dangerous sinks, the caller inherits those properties.

### 6. DeFi Analyzers &mdash; `defi/`

Protocol-aware analyzers that understand DeFi primitives.

| Analyzer | Lines | Detects |
|----------|-------|---------|
| `amm_analyzer.rs` | 456 | Uniswap V2/V3/V4 reentrancy, Curve read-only reentrancy, slippage, sandwich |
| `lending_analyzer.rs` | 464 | Oracle manipulation, flash loan governance, liquidation frontrunning |
| `oracle_analyzer.rs` | 413 | Chainlink staleness, L2 sequencer, TWAP, multi-oracle fallback |
| `mev_analyzer.rs` | 576 | Sandwich attacks, frontrunning, commit-reveal, deadline enforcement |

### 7. EIP Analyzer &mdash; `eip_analyzer.rs`

Automatic EIP standard detection and EIP-specific vulnerability patterns.

**Detected Standards:**
ERC-20, ERC-721, ERC-777, ERC-1155, ERC-4626, ERC-2612, ERC-2771, ERC-4337, ERC-1967, ERC-1822, EIP-1153, EIP-4844, EIP-712

**EIP-Specific Vulnerabilities (30+):**

| EIP | Vulnerability | Severity |
|-----|---------------|----------|
| ERC-20 | Approval race condition, missing return value | High |
| ERC-721 | onERC721Received reentrancy, zero address mint | Critical |
| ERC-777 | tokensReceived/tokensToSend reentrancy (dForce $24M) | Critical |
| ERC-1155 | Batch transfer reentrancy | Critical |
| ERC-4626 | First depositor inflation, share/asset rounding | Critical |
| ERC-2612 | Permit signature replay, front-running | High |
| ERC-2771 | Trusted forwarder bypass (KiloEx $7.4M) | Critical |
| ERC-4337 | UserOp validation bypass, execution reentrancy | Critical |
| ERC-1967 | Unprotected proxy upgrade | Critical |
| EIP-3156 | Flash loan callback reentrancy | High |

### 8. False Positive Reduction &mdash; 3 Layers

The scanner applies three filtering layers to achieve ~90% false positive reduction:

```
Layer 1: scanner.rs::should_report_vulnerability()
  → Per-category context filtering
  → Solidity version awareness (0.8+ skips overflow)
  → Library/modifier detection (ReentrancyGuard, SafeMath)
  → Multi-line function signature parsing                              [v0.8.0]
  → Inheritance-aware modifier resolution                              [v0.8.0]
  → .transfer()/.send() excluded from reentrancy                      [v0.8.0]
  → onlyOwner functions excluded from reentrancy                      [v0.8.0]
  → Comment/annotation filtering

Layer 2: false_positive_filter.rs
  → Safe pattern matching (OpenZeppelin, Solmate, Solady)
  → Deduplication across 6 category groups:                            [v0.8.0]
     1. Reentrancy (Reentrancy, ReadOnly, TransientStorage, Callback, ...)
     2. Access Control (AccessControl, ProxyUpgrade, AdminSweep, ...)
     3. Oracle/Flash Loan (OracleManipulation, DonationAttack, Liquidity, ...)
     4. Compiler/Pragma (CompilerBug, PragmaIssues, Push0Compatibility)
     5. Signature (Replay, Malleability, VerificationBypass)
     6. Math/Precision (Arithmetic, PrecisionLoss, CLMM, Downcast, Rounding)
  → Function-scope merge (30-line window)                              [v0.8.0]
  → Threat model suppression when specific detections exist            [v0.8.0]
  → Confidence score adjustment
  → Safe library recognition

Layer 3: Structural analysis
  → Reachability analysis (skip unreachable code paths)
  → Logic analyzer (skip intentional patterns)
  → Threat model context
```

### 9. CVSS 3.1 Scoring &mdash; `cvss.rs` [v0.8.0]

Implements the official CVSS 3.1 base scoring formula:

- **ISS** = 1 &minus; [(1 &minus; C) &times; (1 &minus; I) &times; (1 &minus; A)]
- **Exploitability** = 8.22 &times; AV &times; AC &times; PR &times; UI
- **Impact (Scope Changed)** = 7.52 &times; [ISS &minus; 0.029] &minus; 3.25 &times; [ISS &times; 0.9731 &minus; 0.02]^13
- **Impact (Scope Unchanged)** = 6.42 &times; ISS
- **Base** = Roundup(min(1.08 &times; (Impact + Exploitability), 10)) if scope changed

Smart contract context:
- **AV** = Network always (public blockchain)
- **C** = None usually (on-chain data is public)
- **I** and **A** = primary impact axes (state integrity, fund availability)

Static mapping from each of the 77 `VulnerabilityCategory` variants to a default CVSS vector. Scores range from 0.0 (GasOptimization) to 10.0 (Reentrancy with scope change).

### 10. Exploit Reference Database &mdash; `exploit_db.rs` [v0.8.0]

53 real-world exploit references mapped to vulnerability categories:

| Category | Notable Exploits |
|----------|-----------------|
| Reentrancy | The DAO ($60M), Curve ($62M), Fei Protocol ($80M) |
| Oracle Manipulation | Mango Markets ($100M), Harvest Finance ($24M) |
| Access Control | Parity Wallet ($30M), Poly Network ($611M) |
| Flash Loan | bZx ($8M), Pancake Bunny ($45M) |
| Bridge/Cross-chain | Ronin ($624M), Wormhole ($326M), Nomad ($190M) |
| Proxy/Upgrade | Euler Finance ($197M) |
| CLMM Math | Cetus DEX ($223M) |
| Rounding | Balancer ($128M) |
| Cross-chain Receiver | Atlas Chain ($112M) |
| Callback Reentrancy | GMX ($42M) |

Each reference includes: name, date, loss amount, chain, and description.

### 11. Attack Path Generator &mdash; `attack_path.rs` [v0.8.0]

Generates step-by-step attack narratives for 20+ vulnerability categories, using actual function and contract names extracted from the source code:

```
1. Attacker deploys malicious contract with fallback function
2. Attacker calls VulnerableVault.withdraw() with valid balance
3. External call via .call{value:} triggers attacker's fallback
4. Fallback re-enters withdraw() before state is updated
5. Attacker drains all funds from the contract
```

### 12. Logic & Reachability &mdash; `logic_analyzer.rs` + `reachability_analyzer.rs`

| Module | Lines | Purpose |
|--------|-------|---------|
| `logic_analyzer.rs` | 1,300 | Business logic bugs: state machine violations, race conditions, invariant breaks, CEI violations |
| `reachability_analyzer.rs` | 841 | Code path analysis: skip findings in unreachable code, dead branches |

### 13. Threat Model &mdash; `threat_model.rs`

Auto-generates a STRIDE threat model per contract:
- **S**poofing &mdash; identity-based attacks
- **T**ampering &mdash; data modification risks
- **R**epudiation &mdash; action deniability
- **I**nformation disclosure &mdash; data leaks
- **D**enial of service &mdash; availability attacks
- **E**levation of privilege &mdash; access escalation

Threat model findings are hidden by default in v0.8.0 (show with `--show-threat-model`). When specific vulnerability detections exist for the same category group, the corresponding threat model finding is suppressed to avoid noise.

### 14. Output Formats

| Format | Module | Use Case |
|--------|--------|----------|
| Terminal (text) | `reporter.rs` | Color-coded, CVSS scores, priority labels, exploit references |
| JSON | `main.rs` (inline) | CI/CD pipelines with `cvss_score`, `cvss_vector`, `exploit_references`, `attack_path` |
| SARIF 2.1.0 | `sarif.rs` | GitHub Code Scanning with actual CVSS `security-severity` |
| Audit report | `professional_reporter.rs` | Executive summary, priority matrix, exploit reference boxes |
| Markdown | `reporter.rs` | Auto-saved report for every scan |

### 15. Tool Integrations &mdash; `integrations/`

| Integration | Module | Description |
|-------------|--------|-------------|
| Slither | `slither.rs` | Correlate 41Swara findings with Slither JSON, merge reports, boost confidence |
| Foundry | `foundry.rs` | Generate Foundry PoC test cases for critical findings |

### 16. Configuration &mdash; `config.rs` [v0.8.0]

TOML-based configuration loaded from `.41swara.toml`:
- Custom regex-based vulnerability rules
- Severity overrides for built-in rules (by SWC/41S ID)
- Rule disabling (skip specific detectors)
- Scan settings (confidence threshold, library trust, file exclusion)

### 17. Supporting Modules

| Module | Lines | Purpose |
|--------|-------|---------|
| `parser.rs` | 372 | Solidity source parsing &mdash; line splitting, version extraction, pragma detection |
| `abi_scanner.rs` | 725 | ABI JSON analysis &mdash; 22 vulnerability categories, 12 contract types |
| `project_scanner.rs` | 503 | Cross-file analysis &mdash; inter-contract call chains, shared state |
| `dependency_analyzer.rs` | 583 | Import graph analysis, known CVE detection in dependencies |
| `cache.rs` | 362 | blake3 file hashing, incremental scan cache for CI/CD |

---

## Data Flow &mdash; Complete Pipeline

```
                          ┌──────────────┐
                          │    Input     │
                          │  .sol / .json│
                          │  / directory │
                          └──────┬───────┘
                                 │
                 ┌───────────────┼───────────────┐
                 ▼               ▼               ▼
          ┌──────────┐    ┌──────────┐    ┌───────────┐
          │  Single  │    │   ABI    │    │ Directory │
          │ .sol file│    │  .json   │    │  walk     │
          └────┬─────┘    └────┬─────┘    └─────┬─────┘
               │               │                │
               │               ▼          ┌─────▼──────┐
               │         ┌──────────┐     │  Parallel  │
               │         │   ABI    │     │   rayon    │
               │         │ Scanner  │     │  per-file  │
               │         └────┬─────┘     └─────┬──────┘
               │              │                 │
               ▼              │                 ▼
        ┌─────────────┐       │         ┌──────────────┐
        │   Parser    │       │         │  Per-file    │
        │  (version,  │       │         │  pipeline    │──────┐
        │   imports)  │       │         └──────────────┘      │
        └──────┬──────┘       │                               │
               │              │                               │
               ▼              │                               │
        ┌─────────────┐       │                               │
        │  Context    │       │                               │
        │  Detection  │       │                               │
        │ (SafeMath,  │       │                               │
        │  Guards,    │       │                               │
        │  version,   │       │                               │
        │  modifiers) │       │                               │
        └──────┬──────┘       │                               │
               │              │                               │
               ▼              │                               │
     ┌──────────────────┐     │                               │
     │  Pattern Match   │     │                               │
     │  200+ rules      │     │                               │
     └────────┬─────────┘     │                               │
              │               │                               │
              ▼               │                               │
     ┌──────────────────┐     │     ┌─────────────────────┐   │
     │  Advanced        │     │     │  AST Analysis       │   │
     │  Analysis        │◄────┼─────│  CFG · Taint        │   │
     │  DeFi · NFT      │     │     │  Interprocedural    │   │
     │  L2 · EIP        │     │     └─────────────────────┘   │
     │  Logic · Reach.  │     │                               │
     └────────┬─────────┘     │                               │
              │               │                               │
              ▼               │                               │
     ┌──────────────────┐     │                               │
     │  FP Filter       │     │                               │
     │  Layer 1: context│     │                               │
     │  Layer 2: dedup  │     │                               │
     │  Layer 3: struct │     │                               │
     │  (~90% removal)  │     │                               │
     └────────┬─────────┘     │                               │
              │               │                               │
              ▼               │                               │
     ┌──────────────────┐     │                               │
     │  Enrichment      │     │                               │
     │  CVSS 3.1 score  │     │                               │
     │  Exploit refs    │     │                               │
     │  Attack paths    │     │                               │
     └────────┬─────────┘     │                               │
              │               │                               │
              ▼               ▼                               │
     ┌─────────────────────────────────────┐                  │
     │         Output Generation           │◄─────────────────┘
     │                                     │
     │  Text · JSON · SARIF · Audit · MD   │
     └─────────────────────────────────────┘
```

---

## Finding Data Model (v0.8.0)

Each finding produced by the scanner includes:

```rust
pub struct Vulnerability {
    pub severity: VulnerabilitySeverity,     // Critical/High/Medium/Low/Info
    pub category: VulnerabilityCategory,     // One of 77 categories
    pub title: String,                       // Human-readable title
    pub description: String,                 // Detailed explanation
    pub line_number: usize,                  // Source line
    pub code_snippet: String,                // Matched code
    pub recommendation: String,              // Fix guidance
    pub confidence: VulnerabilityConfidence, // High (95%), Medium (70%), Low (40%)
    pub context_before: Vec<String>,         // Lines before the finding
    pub context_after: Vec<String>,          // Lines after the finding
    // v0.8.0 enrichment fields:
    pub cvss_score: Option<f64>,             // CVSS 3.1 base score (0.0–10.0)
    pub cvss_vector: Option<String>,         // "CVSS:3.1/AV:N/AC:L/PR:N/..."
    pub exploit_references: Vec<String>,     // "Cetus DEX ($223M, 2025-05)"
    pub attack_path: Option<String>,         // Step-by-step exploitation narrative
}
```

---

## ABI Scanner &mdash; Contract Type Detection

The ABI scanner identifies 12 contract types and 10 behavioral patterns from the JSON ABI alone.

**Contract Types:** Unknown, ERC20, ERC721, ERC1155, ERC4626, Proxy, Governor, Timelock, DEX, Lending, Bridge, FlashLoan

**Behavioral Patterns:** FlashLoanCapable, OracleDependent, DEXInteraction, AccessControlled, Pausable, Upgradeable, CallbackEnabled, CrossChainCapable, MEVExposed, PermitEnabled

**Security Score (0&ndash;100):**
```
Base: 100
  − Critical finding: −15 each
  − High finding:     −8 each
  − Medium finding:   −4 each
  − Low finding:      −1 each
  = min 0

80–100  Good security posture
60–79   Moderate concerns
40–59   Significant issues
0–39    Critical vulnerabilities
```

---

## Performance Architecture

| Feature | Implementation |
|---------|---------------|
| Parallel scanning | `rayon` thread pool, configurable with `-j N` |
| Lazy regex compilation | `once_cell::Lazy` &mdash; compile each regex exactly once |
| Incremental cache | `blake3` file hash → skip unchanged files |
| File size limit | 10 MB default (prevents DoS on large generated files) |
| Streaming | Process files individually, don't load entire project into memory |
| Progress tracking | `indicatif` progress bars for large scans |

**Benchmarks:**

| Project Size | Files | 1 Thread | 8 Threads | Speedup |
|--------------|-------|----------|-----------|---------|
| Small | 5 | 0.5s | 0.2s | 2.5x |
| Medium | 25 | 2.8s | 0.6s | 4.7x |
| Large | 100 | 12.5s | 1.8s | 6.9x |
| Very Large | 500 | 68s | 7.2s | 9.4x |
| Enterprise | 1000+ | 150s | 15s | 10x |

---

## Test Suite

| Category | Count | Description |
|----------|-------|-------------|
| Unit tests | 42 | CVSS formula, exploit DB, attack paths, parser, AST, filter, scanner, SARIF |
| Integration tests | 20 | End-to-end scanning of test contracts via JSON output |
| FP regression tests | 5 | ReentrancyGuard, Ownable, SafeMath 0.8+, view/pure, transfer 2300 gas |
| Test contracts | 13 | Vulnerable and safe Solidity files covering all major categories |

All tests pass with zero compiler warnings.

---

## Dependencies

All local-only &mdash; zero network required at runtime.

```toml
# Core
regex = "1.10"              # Pattern matching (no lookahead)
clap = "4.4"                # CLI parsing (derive macros)
colored = "2.1"             # Terminal colors
walkdir = "2.4"             # Recursive directory traversal
serde = "1.0"               # Serialization framework
serde_json = "1.0"          # JSON handling
chrono = "0.4"              # Timestamps for reports
toml = "0.8"                # Config file parsing

# Performance
rayon = "1.8"               # Parallel scanning (4-10x speedup)
once_cell = "1.19"          # Lazy static regex compilation
dashmap = "5.5"             # Concurrent hashmap for parallel access
indicatif = "0.17"          # Progress bars

# AST Analysis
tree-sitter = "0.20"        # Incremental parsing framework
petgraph = "0.6"            # Graph structures (CFG, call graph)

# Caching
blake3 = "1.5"              # Fast file hashing
glob = "0.3"                # Pattern matching for file exclusion
uuid = "1.6"                # Unique IDs for findings

# Git Integration
git2 = "0.18"               # Local git operations (diff mode)

# File Watching
notify = "6.1"              # File system events (watch mode)
```

**Build optimizations (`Cargo.toml`):**
```toml
[profile.release]
lto = true           # Link-time optimization
codegen-units = 1    # Better optimization
strip = true         # Smaller binary
```

---

## Known Exploit Pattern Coverage

Based on real-world losses tracked via rekt.news ($3.5B+):

| Exploit Type | Loss | Detection Pattern |
|--------------|------|-------------------|
| Reentrancy | $60M&ndash;$62M | The DAO, Curve &mdash; CEI violations, cross-function, read-only |
| Bridge Exploits | $624M+ | Ronin, Wormhole, Nomad &mdash; missing sender/source validation |
| CLMM Math Overflow | $223M | Cetus &mdash; bit-shift overflow in concentrated liquidity |
| Flash Loan Governance | $182M | Beanstalk &mdash; borrow → vote → repay in same tx |
| Oracle Manipulation | $100M+ | Mango Markets, Harvest &mdash; spot price manipulation |
| Rounding Errors | $128M | Balancer &mdash; mulDown + divUp mismatch |
| Cross-chain Receiver | $112M | Atlas &mdash; unvalidated source chain/sender |
| Arbitrary Calls | $611M | Poly Network &mdash; user-controlled delegatecall target |
| ERC-777 Reentrancy | $24M | dForce &mdash; tokensReceived/tokensToSend callbacks |
| ERC-4626 Inflation | $182M | Beanstalk &mdash; first depositor share manipulation |
| Trusted Forwarder | $7.4M | KiloEx &mdash; ERC-2771 _msgSender confusion |
| MEV/Sandwich | $675M+ | Missing deadline and slippage params |
| Signature Replay | Multiple | ecrecover without nonce/chainId |
| Receiver Callback | $42M | GMX &mdash; callback before state update |
| Multicall State Reset | $14.7M | Abracadabra &mdash; batch cook() resets solvency |
| Admin Sweep | $5M | zkSync &mdash; unprotected sweep without timelock |
| Unprotected Upgrade | $197M | Euler &mdash; missing access control on upgrade |

---

## Limitations

This scanner is a **static analysis tool**. It does not replace:

- Professional manual security audit
- Formal verification (Certora, Halmos)
- Symbolic execution (Mythril, Manticore)
- Fuzz testing (Echidna, Foundry fuzz)
- Runtime monitoring and incident response
- Economic/game-theoretic modeling

Use 41Swara as the **first pass** in a layered security workflow.

---

*Last Updated: March 2026*
*Version: 0.8.0 &mdash; Security Researcher Edition*
