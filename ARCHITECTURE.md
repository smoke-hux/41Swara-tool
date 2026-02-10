# 41Swara Smart Contract Scanner — Architecture

**Version:** 0.6.0 &nbsp;|&nbsp; **Language:** Rust &nbsp;|&nbsp; **Total Source:** ~24,400 lines across 29 modules

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
                    └─────┬────────┬──────────┘
                          │        │
            ┌─────────────┘        └──────────────┐
            ▼                                      ▼
┌───────────────────────┐              ┌───────────────────────┐
│   Pattern Matching    │              │   Advanced Analysis   │
│  (vulnerabilities.rs) │              │                       │
│  150+ regex rules     │              │  ┌─────────────────┐  │
│  SWC/CWE mapping      │              │  │ DeFi Analyzers  │  │
│  severity + confidence│              │  │  amm · lending  │  │
└──────────┬────────────┘              │  │  oracle · mev   │  │
           │                           │  └─────────────────┘  │
           │                           │  ┌─────────────────┐  │
           │                           │  │ AST Engine      │  │
           │                           │  │  parser · cfg   │  │
           │                           │  │  dataflow/taint │  │
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
           │  ~90% FP removal       │
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
│   ├── main.rs                  (1,451 lines)  CLI entry, orchestration, watch/git modes
│   ├── scanner.rs               (1,153 lines)  Core scanning engine, context detection
│   ├── vulnerabilities.rs       (3,096 lines)  150+ vulnerability rules, SWC/CWE maps
│   ├── advanced_analysis.rs     (3,777 lines)  DeFi/NFT/L2/exploit pattern analyzers
│   ├── false_positive_filter.rs (1,124 lines)  Multi-pass false positive reduction
│   ├── logic_analyzer.rs        (1,299 lines)  Business logic bug detection
│   ├── reachability_analyzer.rs   (841 lines)  Code path reachability analysis
│   ├── eip_analyzer.rs            (848 lines)  EIP/ERC standard vulnerability checks
│   ├── threat_model.rs          (1,175 lines)  STRIDE threat model auto-generation
│   ├── dependency_analyzer.rs     (583 lines)  Import/dependency CVE analysis
│   ├── abi_scanner.rs             (725 lines)  ABI JSON security analysis
│   ├── parser.rs                  (322 lines)  Solidity source parsing
│   ├── cache.rs                   (362 lines)  Incremental scanning cache (blake3)
│   │
│   ├── ast/                                    AST-Based Analysis Engine
│   │   ├── mod.rs                  (11 lines)
│   │   ├── parser.rs            (1,030 lines)  tree-sitter Solidity parsing
│   │   ├── cfg.rs                 (833 lines)  Control flow graph construction
│   │   └── dataflow.rs            (590 lines)  Taint analysis, data flow tracking
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
│   │   ├── slither.rs             (563 lines)  Slither JSON correlation
│   │   └── foundry.rs             (575 lines)  Foundry PoC test generation
│   │
│   ├── reporter.rs                (483 lines)  Terminal output formatting
│   ├── professional_reporter.rs   (697 lines)  Audit report generation
│   ├── sarif.rs                   (340 lines)  SARIF 2.1.0 output (GitHub/CI)
│   └── project_scanner.rs         (503 lines)  Cross-file project analysis
│
├── test_contracts/                             Sample vulnerable Solidity files
├── test_versions/                              Version-specific test cases
├── scripts/                                    Build/deploy utilities
├── man/                                        Unix man pages (41.1, 41swara.1)
├── dist/                                       Distribution packaging
├── Cargo.toml                                  Dependencies & build config
├── Makefile                                    Install targets (global/user-local)
└── *.md                                        Documentation files
```

---

## Core Components

### 1. CLI Entry Point — `main.rs`

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

### 2. Scanner Orchestrator — `scanner.rs`

The core engine that coordinates all analysis passes for each file.

**Pipeline per file:**
```
Source code
  → Parse (version, imports, pragmas)
  → Context detection (SafeMath, ReentrancyGuard, access control, SafeERC20)
  → Pattern matching (vulnerabilities.rs — 150+ rules)
  → Advanced analysis (DeFi, NFT, L2, EIP, logic, reachability)
  → Context-aware filtering (should_report_vulnerability)
  → False positive filter (false_positive_filter.rs)
  → Final vulnerability list
```

**Context Detection:**
```
Contract Context
├── Solidity version (affects which rules apply)
├── SafeMath usage (filters arithmetic warnings)
├── ReentrancyGuard (filters reentrancy warnings)
├── Access control modifiers (onlyOwner, onlyRole, etc.)
├── SafeERC20 usage (filters unchecked return warnings)
├── OpenZeppelin/Solmate/Solady imports
└── Comment/annotation detection (@audit, @security, // SAFE)
```

### 3. Vulnerability Rules — `vulnerabilities.rs`

Contains 150+ regex-based rules, each with:
- Category, severity, confidence
- SWC ID (SWC-100 to SWC-136) or custom ID (41S-001 to 41S-059)
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

### 4. Advanced Analysis — `advanced_analysis.rs`

The largest module. Deep analysis for protocol-specific patterns.

```
advanced_analysis.rs (3,777 lines)
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
├── Modern protocol patterns (2024-2025)
│   ├── ERC-4626 inflation attack
│   ├── Permit2 signature reuse
│   ├── LayerZero V2 trusted remote
│   ├── Uniswap V4 hook exploitation
│   ├── Chainlink CCIP validation
│   └── Transient storage reentrancy (EIP-1153)
└── v0.6.0 security hardening
    ├── Missing storage gap (upgradeable)
    ├── Missing timelock (admin functions)
    ├── selfdestruct deprecation (EIP-6780)
    ├── Uninitialized implementation
    ├── Unsafe downcast (uint256→uint128)
    ├── Missing ERC-165 (supportsInterface)
    ├── Missing swap deadline
    ├── Hardcoded gas amount
    ├── Unsafe .transfer() gas stipend
    ├── Double initialization
    └── Missing events on state changes
```

### 5. AST Engine — `ast/`

Tree-sitter-based parsing for structural analysis beyond regex.

```
ast/
├── parser.rs   — tree-sitter-solidity integration, AST node extraction
├── cfg.rs      — Control flow graph construction per function
└── dataflow.rs — Taint analysis: track user input → dangerous sinks
```

### 6. DeFi Analyzers — `defi/`

Protocol-aware analyzers that understand DeFi primitives.

| Analyzer | Lines | Detects |
|----------|-------|---------|
| `amm_analyzer.rs` | 456 | Uniswap V2/V3/V4 reentrancy, Curve read-only reentrancy, slippage, sandwich |
| `lending_analyzer.rs` | 464 | Oracle manipulation, flash loan governance, liquidation frontrunning |
| `oracle_analyzer.rs` | 413 | Chainlink staleness, L2 sequencer, TWAP, multi-oracle fallback |
| `mev_analyzer.rs` | 576 | Sandwich attacks, frontrunning, commit-reveal, deadline enforcement |

### 7. EIP Analyzer — `eip_analyzer.rs`

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

### 8. False Positive Reduction — 3 Layers

The scanner applies three filtering layers to achieve ~90% false positive reduction:

```
Layer 1: scanner.rs::should_report_vulnerability()
  → Per-category context filtering
  → Solidity version awareness (0.8+ skips overflow)
  → Library/modifier detection (ReentrancyGuard, SafeMath)
  → Comment/annotation filtering

Layer 2: false_positive_filter.rs::should_keep()
  → Safe pattern matching (OpenZeppelin, Solmate, Solady)
  → Deduplication across overlapping rules
  → Confidence score adjustment
  → Safe library recognition

Layer 3: Structural analysis
  → Reachability analysis (skip unreachable code paths)
  → Logic analyzer (skip intentional patterns)
  → Threat model context
```

### 9. Logic & Reachability — `logic_analyzer.rs` + `reachability_analyzer.rs`

| Module | Lines | Purpose |
|--------|-------|---------|
| `logic_analyzer.rs` | 1,299 | Business logic bugs: state machine violations, race conditions, invariant breaks |
| `reachability_analyzer.rs` | 841 | Code path analysis: skip findings in unreachable code, dead branches |

### 10. Threat Model — `threat_model.rs`

Auto-generates a STRIDE threat model per contract:
- **S**poofing — identity-based attacks
- **T**ampering — data modification risks
- **R**epudiation — action deniability
- **I**nformation disclosure — data leaks
- **D**enial of service — availability attacks
- **E**levation of privilege — access escalation

### 11. Output Formats

| Format | Module | Use Case |
|--------|--------|----------|
| Terminal (text) | `reporter.rs` | Color-coded, severity indicators, context snippets |
| JSON | `main.rs` (inline) | CI/CD pipelines, scripting, data processing |
| SARIF 2.1.0 | `sarif.rs` | GitHub Code Scanning, VS Code, IDE integration |
| Audit report | `professional_reporter.rs` | Client-facing security audit documents |
| Markdown | `reporter.rs` | Auto-saved report for every scan |

### 12. Tool Integrations — `integrations/`

| Integration | Module | Description |
|-------------|--------|-------------|
| Slither | `slither.rs` | Correlate 41Swara findings with Slither JSON, merge reports, boost confidence |
| Foundry | `foundry.rs` | Generate Foundry PoC test cases for critical findings |

### 13. Supporting Modules

| Module | Lines | Purpose |
|--------|-------|---------|
| `parser.rs` | 322 | Solidity source parsing — line splitting, version extraction |
| `abi_scanner.rs` | 725 | ABI JSON analysis — 22 vulnerability categories, 12 contract types |
| `project_scanner.rs` | 503 | Cross-file analysis — inter-contract call chains, shared state |
| `dependency_analyzer.rs` | 583 | Import graph analysis, known CVE detection in dependencies |
| `cache.rs` | 362 | blake3 file hashing, incremental scan cache for CI/CD |

---

## Data Flow — Complete Pipeline

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
        │  version)   │       │                               │
        └──────┬──────┘       │                               │
               │              │                               │
               ▼              │                               │
     ┌──────────────────┐     │                               │
     │  Pattern Match   │     │                               │
     │  150+ rules      │     │                               │
     └────────┬─────────┘     │                               │
              │               │                               │
              ▼               │                               │
     ┌──────────────────┐     │     ┌─────────────────────┐   │
     │  Advanced        │     │     │  AST Analysis       │   │
     │  Analysis        │◄────┼─────│  (tree-sitter)      │   │
     │  DeFi · NFT      │     │     │  CFG · Taint        │   │
     │  L2 · EIP        │     │     └─────────────────────┘   │
     │  Logic · Reach.  │     │                               │
     └────────┬─────────┘     │                               │
              │               │                               │
              ▼               │                               │
     ┌──────────────────┐     │                               │
     │  FP Filter       │     │                               │
     │  Layer 1: context│     │                               │
     │  Layer 2: pattern│     │                               │
     │  Layer 3: struct │     │                               │
     │  (~90% removal)  │     │                               │
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

## ABI Scanner — Contract Type Detection

The ABI scanner identifies 12 contract types and 10 behavioral patterns from the JSON ABI alone.

**Contract Types:** Unknown, ERC20, ERC721, ERC1155, ERC4626, Proxy, Governor, Timelock, DEX, Lending, Bridge, FlashLoan

**Behavioral Patterns:** FlashLoanCapable, OracleDependent, DEXInteraction, AccessControlled, Pausable, Upgradeable, CallbackEnabled, CrossChainCapable, MEVExposed, PermitEnabled

**Security Score (0–100):**
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
| Lazy regex compilation | `once_cell::Lazy` — compile each regex exactly once |
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

## Dependencies

All local-only — zero network required at runtime.

```toml
# Core
regex = "1.10"              # Pattern matching (no lookahead)
clap = "4.4"                # CLI parsing (derive macros)
colored = "2.1"             # Terminal colors
walkdir = "2.4"             # Recursive directory traversal
serde = "1.0"               # Serialization framework
serde_json = "1.0"          # JSON handling
chrono = "0.4"              # Timestamps for reports

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

Based on real-world losses tracked via rekt.news ($3.1B+):

| Exploit Type | Loss | Detection Pattern |
|--------------|------|-------------------|
| ERC-777 Reentrancy | $24M (dForce) | tokensReceived/tokensToSend callbacks |
| ERC-4626 Inflation | $182M (Beanstalk) | First depositor share manipulation |
| Trusted Forwarder | $7.4M (KiloEx) | ERC-2771 _msgSender confusion |
| Oracle Manipulation | $69M+ | Unsafe balanceOf as price, missing TWAP |
| MEV/Sandwich | $675M+ | Missing deadline and slippage params |
| Arbitrary Calls | $21M | User-controlled delegatecall target |
| Signature Replay | Multiple | ecrecover without nonce/chainId |
| Bridge Exploits | $600M+ | Missing cross-domain sender validation |
| Unprotected Upgrade | $2.7M (Aevo) | transferOwnership without 2-step |
| Flash Loan Governance | $182M | Borrow → vote → repay in same tx |

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

*Last Updated: February 2026*
*Version: 0.6.0 — Security Researcher Edition*
