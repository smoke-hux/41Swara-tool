<p align="center">
  <strong>41Swara</strong><br>
  Smart Contract Security Scanner
</p>

<p align="center">
  <em>Production-grade static analysis for Solidity &mdash; built in Rust</em>
</p>

<p align="center">
  <a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License: MIT"></a>
  <a href="https://www.rust-lang.org/"><img src="https://img.shields.io/badge/rust-1.70%2B-orange.svg" alt="Rust"></a>
  <img src="https://img.shields.io/badge/version-0.6.0-blue.svg" alt="Version">
  <img src="https://img.shields.io/badge/offline-100%25-green.svg" alt="Offline">
  <img src="https://img.shields.io/badge/parallel-4--10x_faster-brightgreen.svg" alt="Performance">
  <img src="https://img.shields.io/badge/false_positives-90%25_reduced-success.svg" alt="FP Reduction">
</p>

---

## What is 41Swara?

A fully offline, Rust-based static analysis tool that scans Solidity smart contracts for security vulnerabilities. Designed for bug bounty hunters, audit contest participants, and professional security researchers.

**Key numbers:**
- **150+** vulnerability patterns with SWC/CWE mapping
- **30+** EIP-specific detectors (ERC-20 through ERC-4337)
- **90%+** false positive reduction through 3-layer filtering
- **4-10x** faster than single-threaded with parallel scanning
- **24,400** lines of Rust across 29 modules
- **$3.1B+** in real-world DeFi exploit patterns covered
- **Zero** network dependencies &mdash; runs in air-gapped environments

---

## Quick Start

```bash
# Install
git clone https://github.com/41swara/smart-contract-scanner
cd smart-contract-scanner
cargo install --path .

# Scan (two equivalent commands)
41 contracts/
41swara contracts/

# Full analysis with all features
41 contracts/ -v --stats
```

> Both `41` and `41swara` are installed as binaries. Use whichever you prefer.

---

## Usage

### Basic Scanning

```bash
41                                    # Scan current directory
41 MyContract.sol                     # Scan single file
41 contracts/                         # Scan directory
41 contracts/ -v --stats              # Verbose with performance stats
```

### Filtering

```bash
41 . --min-severity high              # Only critical + high findings
41 . --confidence-threshold 70        # Only 70%+ confidence
41 . --include-swc SWC-107,SWC-105    # Only specific SWC IDs
41 . --exclude-swc SWC-103            # Skip floating pragma
41 . --exclude-pattern "**/test/**"   # Skip test files
41 . --max-file-size 5                # Skip files > 5 MB
```

### DeFi & EIP Analysis

```bash
41 . --defi-analysis                  # AMM, lending, oracle, MEV analyzers
41 . --advanced-detectors             # ERC-4626, Permit2, LayerZero, L2
41 . --eip-analysis                   # EIP-specific vulnerability checks
41 . --strict-filter                  # Enhanced false positive filtering
```

### Output Formats

```bash
41 . -f text                          # Colored terminal (default)
41 . -f json                          # Structured JSON
41 . -f sarif -o results.sarif        # SARIF for GitHub Code Scanning
41 . --audit --project "MyDApp"       # Professional audit report
41 . --report                         # Clean markdown report
```

### Git & CI/CD Integration

```bash
41 . --git-diff                       # Scan only modified .sol files
41 . --git-diff --git-branch main     # Compare against main branch
41 . --fail-on high -q                # Exit code 1 if high/critical found
41 . --export-baseline base.json      # Save current results as baseline
41 . --baseline base.json             # Show only new findings
41 . --cache                          # Skip unchanged files (incremental)
```

### Watch Mode

```bash
41 contracts/ --watch                 # Rescan on file changes
41 contracts/ --watch --min-severity high
```

### Tool Integration

```bash
slither . --json slither.json         # Run Slither first
41 . --slither-json slither.json      # Correlate findings

41 . --generate-poc                   # Generate Foundry PoC tests
41 . --foundry-correlate              # Correlate with Foundry results
```

### Performance Tuning

```bash
41 . -j 8                             # Use 8 threads
41 . --fast                           # Regex-only, skip advanced analysis
41 . --stats                          # Show timing/thread stats
```

---

## Example Output

```
41Swara Smart Contract Scanner v0.6.0
Security Researcher Edition
High-performance security analysis for Ethereum & Base
=======================================================

Scanning directory: contracts/
Found 15 Solidity files

SCAN RESULTS FOR contracts/Vault.sol
--------------------------------------------------------------------

Access Control [SWC-105]

  !! Unprotected Critical Function: withdrawAll [Line 21]
     SWC: SWC-105 | CWE: CWE-284
     Severity: CRITICAL | Confidence: 90%
     Recommendation: Add appropriate access control modifiers

Reentrancy [SWC-107]

  !! Critical: State Change After External Call [Line 16]
     SWC: SWC-107 | CWE: CWE-841
     Severity: CRITICAL | Confidence: 95%
     Recommendation: Move all state changes before external calls

--------------------------------------------------------------------

VULNERABILITY SCAN SUMMARY
  Files scanned: 15
  Total issues found: 42

  SEVERITY BREAKDOWN
    !! CRITICAL: 5
    !  HIGH: 8
    *  MEDIUM: 18
    -  LOW: 11
```

### Confidence Indicators

| Symbol | Confidence | Meaning |
|--------|-----------|---------|
| **&#9679;** | 80-100% | Very likely a real vulnerability |
| **&#9684;** | 50-79% | Likely issue, review recommended |
| **&#9675;** | 0-49% | Possible issue, may be false positive |

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | No findings |
| 1 | Critical or High findings detected |
| 2 | Medium findings only |
| 3 | Low/Info findings only |
| 10 | Scanner error |

---

## What It Detects

### Vulnerability Categories

<details>
<summary><strong>Critical Severity</strong></summary>

| Category | SWC/ID | CWE | Description |
|----------|--------|-----|-------------|
| Reentrancy | SWC-107 | CWE-841 | CEI violations, cross-function, read-only |
| Access Control | SWC-105 | CWE-284 | Unprotected functions, missing modifiers |
| Proxy Admin | 41S-003 | CWE-284 | Unprotected upgrade/admin functions |
| Arbitrary Calls | 41S-005 | CWE-749 | Unchecked external calls with user input |
| ERC-4626 Inflation | 41S-020 | CWE-682 | First depositor share manipulation |
| Flash Loan | 41S-002 | CWE-807 | Governance manipulation, oracle attacks |
| L2 Sequencer | 41S-029 | CWE-703 | Missing sequencer uptime check |
| Bridge Security | 41S-014 | CWE-345 | Cross-chain message validation |
| Uninitialized Impl | 41S-053 | CWE-665 | Proxy impl without `_disableInitializers()` |
| Double Init | 41S-059 | CWE-665 | `initialize()` without initializer modifier |
| msg.value in Loop | 41S-040 | CWE-682 | Reused msg.value across iterations |

</details>

<details>
<summary><strong>High Severity</strong></summary>

| Category | SWC/ID | CWE | Description |
|----------|--------|-----|-------------|
| Oracle Manipulation | 41S-001 | CWE-807 | Price feed vulnerabilities |
| Signature Replay | SWC-121 | CWE-294 | Missing nonces, replay attacks |
| DoS Attacks | SWC-128 | CWE-400 | Unbounded loops, gas griefing |
| MEV/Front-Running | SWC-114 | CWE-362 | Missing slippage/deadline |
| Permit2 Risks | 41S-021 | CWE-294 | Signature reuse, deadline bypass |
| LayerZero | 41S-022 | CWE-284 | Trusted remote manipulation |
| Uniswap V4 Hooks | 41S-027 | CWE-94 | Hook exploitation vectors |
| Missing Storage Gap | 41S-050 | CWE-665 | Upgradeable contracts without `__gap` |
| selfdestruct | 41S-052 | CWE-749 | Deprecated post EIP-6780/Dencun |

</details>

<details>
<summary><strong>Medium Severity</strong></summary>

| Category | SWC/ID | CWE | Description |
|----------|--------|-----|-------------|
| Precision Loss | SWC-101 | CWE-190 | Division before multiplication |
| Time Manipulation | SWC-116 | CWE-829 | Block.timestamp dependencies |
| Unchecked Returns | SWC-104 | CWE-252 | External call failures |
| Missing Timelock | 41S-051 | CWE-284 | Admin functions without delay |
| Unsafe Downcast | 41S-054 | CWE-190 | uint256 to uint128 without SafeCast |
| Missing Deadline | 41S-056 | CWE-362 | Swap functions without deadline |
| Hardcoded Gas | 41S-057 | CWE-1104 | `.call{gas: 2300}` hardcoded values |
| PUSH0 Compat | 41S-025 | CWE-1104 | Opcode compatibility issues |

</details>

<details>
<summary><strong>Low / Info</strong></summary>

| Category | SWC/ID | Description |
|----------|--------|-------------|
| Floating Pragma | SWC-103 | Version inconsistencies |
| Deprecated | SWC-111 | Deprecated functions |
| Missing ERC-165 | 41S-055 | NFT without supportsInterface |
| Missing Events | 41S-060 | State changes without emit |
| Gas Optimization | - | Inefficient patterns |

</details>

### EIP-Specific Detectors

The scanner auto-detects which EIPs a contract implements and runs targeted checks:

| EIP | Vulnerabilities Detected |
|-----|-------------------------|
| ERC-20 | Approval race condition, missing return value, double-spend |
| ERC-721 | `onERC721Received` reentrancy, zero address mint |
| ERC-777 | `tokensReceived`/`tokensToSend` reentrancy (dForce $24M) |
| ERC-1155 | Batch transfer reentrancy |
| ERC-4626 | First depositor inflation, share/asset rounding |
| ERC-2612 | Permit signature replay, front-running |
| ERC-2771 | Trusted forwarder bypass (KiloEx $7.4M) |
| ERC-4337 | UserOp validation bypass, execution reentrancy |
| ERC-1967 | Unprotected proxy upgrade |
| EIP-3156 | Flash loan callback reentrancy |

### DeFi Protocol Analyzers

| Analyzer | Detects |
|----------|---------|
| **AMM/DEX** | Uniswap V2/V3/V4 reentrancy, Curve read-only reentrancy, slippage, sandwich |
| **Lending** | Oracle manipulation, flash loan governance, liquidation frontrunning |
| **Oracle** | Chainlink staleness, L2 sequencer uptime, TWAP validation, multi-oracle fallback |
| **MEV** | Sandwich attacks, frontrunning, commit-reveal, deadline enforcement |

### L2 & Cross-Chain

| Pattern | Severity | Description |
|---------|----------|-------------|
| Sequencer Uptime | Critical | Chainlink feeds without L2 sequencer check |
| Bridge Messages | Critical | Cross-domain messenger validation |
| Grace Period | High | Missing grace period after sequencer recovery |
| Gas Oracle | Medium | L1 gas price manipulation on L2 |
| PUSH0 Compatibility | Medium | Solidity 0.8.20+ opcode on legacy chains |

---

## False Positive Reduction

Three filtering layers achieve ~90% false positive reduction:

| Layer | Location | What It Does |
|-------|----------|--------------|
| **1. Context** | `scanner.rs` | Version-aware (0.8+ skips overflow), modifier detection, comment filtering |
| **2. Pattern** | `false_positive_filter.rs` | Safe library recognition (OZ, Solmate, Solady), dedup, confidence adjustment |
| **3. Structural** | `reachability_analyzer.rs` | Skip unreachable code paths, dead branches, intentional patterns |

**Always active:**

| Context | Action |
|---------|--------|
| SafeMath detected | Skip arithmetic overflow warnings |
| ReentrancyGuard | Skip reentrancy alerts |
| Solidity 0.8+ | Skip overflow (built-in) |
| View/Pure functions | Skip reentrancy for read-only |
| Interface files | Skip entirely |
| Commented code | Ignore |

**With `--strict-filter`:**

| Context | Action |
|---------|--------|
| SafeERC20 usage | Skip unchecked return warnings |
| OpenZeppelin imports | Trust audited implementations |
| Solmate/Solady libs | Recognize safe patterns |
| `ECDSA.recover` | Skip signature malleability |
| Audit annotations | Respect `@audit`, `@security`, `// SAFE` |

---

## CI/CD Integration

### GitHub Actions

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install Rust
        uses: dtolnay/rust-toolchain@stable

      - name: Install 41Swara
        run: cargo install --git https://github.com/41swara/smart-contract-scanner

      - name: Run Scan
        run: |
          41 contracts/ \
            --fail-on high \
            --format sarif \
            --cache \
            -o results.sarif

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

### GitLab CI

```yaml
security-scan:
  stage: test
  script:
    - cargo install --git https://github.com/41swara/smart-contract-scanner
    - 41 contracts/ --fail-on critical --format json --cache
```

### With Baseline (Only New Findings)

```yaml
security-scan:
  script:
    - aws s3 cp s3://bucket/baseline.json baseline.json || true
    - 41 contracts/ --baseline baseline.json --fail-on high
    - 41 contracts/ --export-baseline new-baseline.json
    - aws s3 cp new-baseline.json s3://bucket/baseline.json
```

---

## Installation

### Global Install (Recommended)

```bash
git clone https://github.com/41swara/smart-contract-scanner
cd smart-contract-scanner
cargo install --path .
```

Installs `41` and `41swara` to `~/.cargo/bin/`. Make sure it's in your PATH:
```bash
export PATH="$HOME/.cargo/bin:$PATH"
```

### System-Wide Install (with man pages)

```bash
sudo make install
```

### User-Local Install (no sudo)

```bash
make install-user
export PATH="$HOME/.local/bin:$PATH"
```

### Man Pages

```bash
man 41
man 41swara
```

---

## Architecture

See [ARCHITECTURE.md](ARCHITECTURE.md) for detailed internals.

```
src/
├── main.rs                   CLI entry point, orchestration
├── scanner.rs                Core scanning engine
├── vulnerabilities.rs        150+ rules with SWC/CWE mapping
├── advanced_analysis.rs      DeFi/NFT/L2/exploit analyzers
├── false_positive_filter.rs  3-layer FP reduction
├── logic_analyzer.rs         Business logic bug detection
├── reachability_analyzer.rs  Code path analysis
├── eip_analyzer.rs           EIP standard vulnerability checks
├── threat_model.rs           STRIDE threat model generation
├── dependency_analyzer.rs    Import/dependency CVE analysis
├── ast/                      tree-sitter parsing, CFG, taint analysis
├── defi/                     AMM, lending, oracle, MEV analyzers
├── integrations/             Slither + Foundry integration
├── abi_scanner.rs            ABI JSON security analysis
├── reporter.rs               Terminal output
├── professional_reporter.rs  Audit report generation
├── sarif.rs                  SARIF 2.1.0 output
├── project_scanner.rs        Cross-file analysis
├── cache.rs                  Incremental scanning cache
└── parser.rs                 Solidity source parsing
```

**Total: ~24,400 lines across 29 modules**

---

## Multi-Tool Workflow

For comprehensive security, combine 41Swara with other tools:

```bash
# 1. Fast static analysis
41 . --min-severity high -j 8

# 2. Correlate with Slither
slither . --json slither.json
41 . --slither-json slither.json

# 3. Generate PoC tests
41 . --generate-poc

# 4. Validate with Foundry
forge test

# 5. Symbolic execution (slow, thorough)
mythril analyze flagged-contract.sol
```

### Comparison

| Feature | 41Swara | Slither | Mythril |
|---------|---------|---------|---------|
| Speed | Fast (parallel) | Medium | Slow |
| DeFi Detectors | Advanced | Basic | None |
| L2 Patterns | Yes | No | No |
| EIP Analysis | 30+ patterns | No | No |
| FP Reduction | 90%+ | Moderate | N/A |
| CWE/SWC Mapping | Full | Partial | No |
| Taint Analysis | Yes | Yes | Yes |
| Offline | 100% | Yes | Yes |
| PoC Generation | Yes | No | No |
| CI/CD Ready | Yes | Yes | No |

---

## Performance

| Project Size | Files | 1 Thread | 8 Threads | Speedup |
|--------------|-------|----------|-----------|---------|
| Small | 5 | 0.5s | 0.2s | 2.5x |
| Medium | 25 | 2.8s | 0.6s | 4.7x |
| Large | 100 | 12.5s | 1.8s | 6.9x |
| Very Large | 500 | 68s | 7.2s | 9.4x |
| Enterprise | 1000+ | 150s | 15s | 10x |

With caching enabled, unchanged file rescan: ~0.1s

---

## Complete CLI Reference

```
USAGE:
    41 [PATH] [OPTIONS]

ARGUMENTS:
    [PATH]                            Path to scan (default: current directory)

BASIC OPTIONS:
    -f, --format <text|json|sarif>    Output format (default: text)
    --min-severity <LEVEL>            Filter: critical|high|medium|low|info
    -v, --verbose                     Detailed analysis output
    -j, --threads <N>                 Parallel threads (0 = auto-detect)
    -q, --quiet                       Only show summary
    -o, --output <FILE>               Save output to file
    --stats                           Show performance statistics
    --fail-on <SEVERITY>              Exit code 1 if findings above threshold
    --no-color                        Disable colored output
    --fast                            Regex-only, skip advanced analyzers

CONFIDENCE & SWC FILTERING:
    --confidence-threshold <0-100>    Only findings above confidence %
    --include-swc <IDS>               Only specific SWC IDs (comma-separated)
    --exclude-swc <IDS>               Skip specific SWC IDs

FILE FILTERING:
    --exclude-pattern <GLOB>          Exclude files matching pattern
    --max-file-size <MB>              Skip files larger than size (default: 10)

ANALYSIS:
    --defi-analysis                   DeFi analyzers (AMM, lending, oracle, MEV)
    --advanced-detectors              ERC-4626, Permit2, LayerZero, L2, etc.
    --eip-analysis                    EIP-specific vulnerability checks
    --strict-filter                   Enhanced false positive filtering
    --no-logic-analysis               Skip business logic detection
    --no-reachability-analysis        Skip reachability filtering
    --no-dependency-analysis          Skip dependency checks
    --no-threat-model                 Skip threat model generation
    --show-fixes                      Show detailed fix suggestions

BASELINE:
    --baseline <FILE>                 Compare against baseline results
    --export-baseline <FILE>          Export current results as baseline

TOOL INTEGRATION:
    --slither-json <PATH>             Combine with Slither JSON output
    --generate-poc                    Generate Foundry PoC tests
    --foundry-correlate               Correlate with Foundry test results

CACHING:
    --cache                           Enable incremental scanning cache
    --cache-dir <DIR>                 Cache directory (default: .41swara_cache)

ABI ANALYSIS:
    --abi                             Scan ABI JSON files

GIT INTEGRATION:
    --git-diff                        Scan only modified .sol files
    --git-branch <BRANCH>             Branch to compare (default: HEAD)

CONTINUOUS MONITORING:
    --watch                           Watch mode - rescan on file changes

PROFESSIONAL:
    --audit                           Professional audit report
    --project <NAME>                  Project name (requires --audit)
    --sponsor <NAME>                  Sponsor name (requires --audit)
    --project-analysis                Cross-file vulnerability analysis
    --report                          Clean markdown report

INFO:
    --version                         Print version
    --version-full                    Full version with build details
    --about                           Tool overview for new users
    --examples                        Show usage examples
    --help                            Print help
```

---

## Contributing

### Adding a Vulnerability Rule

```rust
// src/vulnerabilities.rs
rules.push(VulnerabilityRule::new(
    VulnerabilityCategory::YourCategory,
    VulnerabilitySeverity::Critical,
    r"your_regex_pattern",
    "Vulnerability Title".to_string(),
    "Description of the issue".to_string(),
    "Recommendation for fix".to_string(),
    false, // multiline
).unwrap());
```

### Development Setup

```bash
git clone https://github.com/41swara/smart-contract-scanner
cd smart-contract-scanner
cargo build
cargo test
cargo run -- test_contracts/ -v --stats
```

---

## Resources

- [SWC Registry](https://swcregistry.io/)
- [MITRE CWE](https://cwe.mitre.org/)
- [Rekt News](https://rekt.news/)
- [Solidity Docs](https://docs.soliditylang.org/)
- [Consensys Best Practices](https://consensys.github.io/smart-contract-best-practices/)
- [Chainlink L2 Sequencer Feeds](https://docs.chain.link/data-feeds/l2-sequencer-feeds)

---

## License

MIT License &mdash; see [LICENSE](LICENSE) for details.

---

Built by **41Swara Security Team**

Vulnerability patterns sourced from **rekt.news**, **SWC Registry**, **Immunefi**, **Sherlock**, and **Code4rena** findings. Inspired by **Trail of Bits' Slither** and **ConsenSys' Mythril**.

---

**v0.6.0 &mdash; Security Researcher Edition** &nbsp;|&nbsp; **150+ Patterns** &nbsp;|&nbsp; **30+ EIP Detectors** &nbsp;|&nbsp; **90% FP Reduction** &nbsp;|&nbsp; **Fully Offline**
