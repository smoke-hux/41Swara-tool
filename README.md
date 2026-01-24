# 41Swara Smart Contract Security Scanner v0.4.0

**Security Researcher Edition - Production-grade vulnerability scanner for Ethereum Foundation and blockchain security researchers**

A fully offline, API-independent Rust-based static analysis tool designed for bug bounty hunting (Immunefi, HackerOne), audit contests (Sherlock, CodeHawks, Code4rena), and professional security audits. Features **AST-based analysis**, **DeFi-specific detectors**, **CWE/SWC ID mapping**, **L2 chain patterns**, **Slither/Foundry integration**, and **150+ vulnerability patterns** including real-world exploit patterns from $3.1B+ in DeFi losses.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Rust](https://img.shields.io/badge/rust-1.70%2B-orange.svg)](https://www.rust-lang.org/)
[![Version](https://img.shields.io/badge/version-0.4.0-blue.svg)]()
[![Offline](https://img.shields.io/badge/offline-100%25-green.svg)]()
[![Performance](https://img.shields.io/badge/parallel-4--10x_faster-brightgreen.svg)]()

---

## What's New in v0.4.0

### Security Researcher Edition
- **CWE/SWC ID Mapping** - Full compliance with SWC Registry (SWC-100 to SWC-136) and custom DeFi IDs (41S-001 to 41S-050)
- **Confidence Scoring** - Percentage-based confidence (0-100%) with context-aware detection
- **L2 Chain Patterns** - Sequencer uptime, gas oracle manipulation, optimistic rollup bridge security
- **Modern Solidity 0.8.20+** - PUSH0 opcode compatibility, transient storage (EIP-1153), blob data handling (EIP-4844)
- **2024-2025 Exploit Patterns** - ERC-4626 inflation, Permit2, LayerZero V2, Uniswap V4 hooks, CCIP, EigenLayer
- **Enhanced SARIF Output** - CWE IDs in results for GitHub Code Scanning integration
- **New CLI Options** - `--confidence-threshold`, `--include-swc`, `--exclude-swc`, `--baseline`, `--no-color`
- **Exit Codes** - Semantic exit codes (0=clean, 1=critical/high, 2=medium, 3=low, 10=error)

---

## Key Features

### Fully Offline & API-Independent
- **Zero network dependencies** - works in air-gapped environments
- **No API keys required** - all analysis runs locally
- **No external services** - complete privacy for your audits
- **Git integration** via local `git2` library
- **Tool integration** via local process execution

### CWE/SWC Compliance
- **SWC Registry** - Full coverage of SWC-100 to SWC-136
- **CWE Mapping** - Each vulnerability mapped to MITRE CWE
- **Custom DeFi IDs** - 41S-001 to 41S-050 for DeFi-specific patterns
- **SARIF Integration** - CWE/SWC IDs in output for compliance tooling

### AST-Based Analysis Engine
- **tree-sitter-solidity** for proper Solidity parsing
- **Control Flow Graphs (CFG)** for each function
- **Taint Analysis** - track user input to dangerous sinks
- **Inter-procedural analysis** for cross-function vulnerabilities

### DeFi-Specific Analyzers
- **AMM/DEX Analyzer** - Uniswap V2/V3/V4 reentrancy, Curve read-only reentrancy, slippage/deadline protection
- **Lending Analyzer** - Price oracle manipulation, flash loan governance, liquidation frontrunning
- **Oracle Analyzer** - Chainlink staleness, L2 sequencer uptime, TWAP validation
- **MEV Analyzer** - Sandwich attacks, frontrunning, commit-reveal patterns
- **Bridge Analyzer** - Cross-chain message validation, replay protection, trusted remote verification

### L2 Chain Security Patterns
| Pattern | Description | Severity |
|---------|-------------|----------|
| Sequencer Uptime | Chainlink feeds without L2 sequencer check | Critical |
| Grace Period | Missing grace period after sequencer recovery | High |
| Gas Oracle | L1 gas price manipulation on L2 | Medium |
| Bridge Messages | Cross-domain messenger validation | Critical |
| Finalization | Optimistic rollup withdrawal delays | Medium |
| PUSH0 Compatibility | Solidity 0.8.20+ opcode on legacy chains | Medium |

### Modern Protocol Patterns (2024-2025)
| Detector | Category | Priority |
|----------|----------|----------|
| ERC4626 Inflation Attack | Logic Error | Critical |
| Permit2 Signature Reuse | Access Control | Critical |
| LayerZero V2 Trusted Remote | Bridge Security | Critical |
| Uniswap V4 Hook Exploitation | Callback Security | Critical |
| Chainlink CCIP Validation | Cross-Chain | Critical |
| EigenLayer Restaking | Access Control | High |
| Transient Storage Reentrancy | EIP-1153 | High |
| Create2/Create3 Collision | Logic Error | Medium |
| Blob Data Handling | EIP-4844 | Medium |

### Tool Integration
- **Slither Integration** - Correlate findings, merge reports, boost confidence
- **Foundry Integration** - Generate PoC tests, correlate with test results
- **Incremental Caching** - Skip unchanged files, persist cache for CI/CD

### Performance Optimizations
- **Parallel Scanning** - 4-10x faster with rayon multithreading
- **Incremental Analysis** - Cache by file hash, skip unchanged files
- **Memory Efficient** - Streaming for large projects (1000+ files)
- **Progress Indicators** - Track scanning progress

---

## Installation

### Global Installation (Recommended)

```bash
# Clone the repository
git clone https://github.com/41swara/smart-contract-scanner
cd smart-contract-scanner

# Install globally
cargo install --path .
```

This installs two commands:
- `41` - Short command (quick to type)
- `41swara` - Full project name

**Note**: Ensure `~/.cargo/bin` is in your PATH:
```bash
export PATH="$HOME/.cargo/bin:$PATH"
```

### Build from Source
```bash
git clone https://github.com/41swara/smart-contract-scanner
cd smart-contract-scanner
cargo build --release
./target/release/41 --help
```

---

## Quick Start

### Basic Scanning
```bash
# Scan current directory (default)
41

# Scan a single contract
41 MyContract.sol

# Scan entire project
41 contracts/

# Verbose with stats
41 contracts/ -v --stats
```

### Severity & Confidence Filtering
```bash
# Only critical/high findings
41 contracts/ --min-severity high

# High confidence only (70%+)
41 contracts/ --confidence-threshold 70

# Combine filters
41 contracts/ --min-severity high --confidence-threshold 80
```

### SWC/CWE ID Filtering
```bash
# Only check reentrancy (SWC-107)
41 contracts/ --include-swc SWC-107

# Multiple SWCs
41 contracts/ --include-swc SWC-107,SWC-105,SWC-114

# Exclude floating pragma warnings
41 contracts/ --exclude-swc SWC-103
```

### File Exclusion
```bash
# Exclude test files
41 contracts/ --exclude-pattern "**/test/**"

# Exclude mocks
41 contracts/ --exclude-pattern "**/*Mock*"

# Skip large files (>5MB)
41 contracts/ --max-file-size 5
```

### DeFi-Specific Analysis
```bash
# Enable DeFi analyzers (AMM, Lending, Oracle, MEV)
41 . --defi-analysis

# Enable advanced detectors (ERC4626, Permit2, LayerZero, L2, etc.)
41 . --advanced-detectors

# Full analysis
41 . --defi-analysis --advanced-detectors -v
```

### Baseline Comparison
```bash
# Export current results as baseline
41 contracts/ --export-baseline baseline.json

# Compare against baseline (only show new findings)
41 contracts/ --baseline baseline.json
```

### Slither Integration
```bash
# Run Slither first
slither . --json slither-output.json

# Correlate with 41Swara findings
41 . --slither-json slither-output.json
```

### Foundry Integration
```bash
# Generate PoC tests for findings
41 . --generate-poc

# Correlate with Foundry test results
41 . --foundry-correlate
```

---

## Example Output

```
41Swara Smart Contract Scanner v0.4.0
Security Researcher Edition
High-performance security analysis for Ethereum & L2
=======================================================

Scanning directory: contracts/
Found 15 Solidity files

SCAN RESULTS FOR contracts/Vault.sol
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Access Control [SWC-105]

  !! ● Unprotected Critical Function: withdrawAll [Line 21]
     Description: Critical function lacks access control modifiers
     SWC: SWC-105 | CWE: CWE-284
     Context:
         19 |
         20 |     // Vulnerable: External call without reentrancy guard
     Vulnerable Code:
         21 | function withdrawAll() external {
         22 |         uint256 balance = deposits[msg.sender];
     Recommendation: Add appropriate access control modifiers
     Severity: CRITICAL | Confidence: 90%

Reentrancy [SWC-107]

  !! ● Critical: State Change After External Call [Line 16]
     Description: State modification after external call - violates CEI pattern
     SWC: SWC-107 | CWE: CWE-841
     Vulnerable Code:
         16 |         token.transfer(address(this), amount);
     Recommendation: Move all state changes before external calls
     Severity: CRITICAL | Confidence: 95%

L2 Sequencer Downtime [41S-029]

  !! ● CRITICAL: L2 Sequencer Uptime Not Checked [Line 45]
     Description: Chainlink price feed used without L2 sequencer uptime check
     SWC: 41S-029 | CWE: CWE-703
     Vulnerable Code:
         45 |     (, int256 price,,,) = priceFeed.latestRoundData();
     Recommendation: Add sequencer uptime feed check with grace period
     Severity: CRITICAL | Confidence: 92%

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

VULNERABILITY SCAN SUMMARY
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Files scanned: 15
Total issues found: 42

SEVERITY BREAKDOWN
  !! CRITICAL: 5
  !  HIGH: 8
  *  MEDIUM: 18
  -  LOW: 11

SWC BREAKDOWN
  SWC-107 (Reentrancy): 3
  SWC-105 (Access Control): 2
  41S-029 (L2 Sequencer): 2
  ...
```

### Confidence Indicators
- **●** High (80-100%) - Very likely a real vulnerability
- **◐** Medium (50-79%) - Likely a vulnerability, review recommended
- **○** Low (0-49%) - Possible issue, may be false positive

### Exit Codes
| Code | Meaning |
|------|---------|
| 0 | No findings |
| 1 | Critical/High findings detected |
| 2 | Medium findings only |
| 3 | Low/Info findings only |
| 10 | Scanner error |

---

## Complete CLI Reference

```
USAGE:
    41 [PATH] [OPTIONS]
    41swara [PATH] [OPTIONS]

ARGUMENTS:
    [PATH]                            Path to scan (default: current directory)

BASIC OPTIONS:
    -f, --format <text|json|sarif>    Output format (default: text)
    --min-severity <LEVEL>            Filter by severity
                                      [critical|high|medium|low|info]
    -v, --verbose                     Detailed analysis output
    -j, --threads <N>                 Parallel threads (0 = auto-detect)
    -q, --quiet                       Only show summary
    --stats                           Show performance statistics
    --fail-on <SEVERITY>              Exit code 1 if issues above threshold
    -o, --output <FILE>               Save output to file
    --no-color                        Disable colored output

CONFIDENCE & SWC FILTERING:
    --confidence-threshold <0-100>    Only show findings above confidence %
    --include-swc <IDS>               Only check specific SWC IDs (comma-separated)
    --exclude-swc <IDS>               Skip specific SWC IDs (comma-separated)

FILE FILTERING:
    --exclude-pattern <GLOB>          Exclude files matching pattern
    --max-file-size <MB>              Skip files larger than size (default: 10)

BASELINE:
    --baseline <FILE>                 Compare against baseline results
    --export-baseline <FILE>          Export current results as baseline

DEFI ANALYSIS:
    --defi-analysis                   Enable DeFi-specific analyzers
                                      (AMM, Lending, Oracle, MEV)
    --advanced-detectors              Enable advanced detectors
                                      (ERC4626, Permit2, LayerZero, L2, etc.)

TOOL INTEGRATION:
    --slither-json <PATH>             Combine with Slither JSON output
    --generate-poc                    Generate Foundry PoC tests
    --foundry-correlate               Correlate with Foundry test results

CACHING:
    --cache                           Enable incremental scanning cache
    --cache-dir <DIR>                 Cache directory (default: .41swara_cache)

ABI ANALYSIS:
    --abi                             Enable ABI security analysis mode

GIT INTEGRATION:
    --git-diff                        Scan only modified .sol files
    --git-branch <BRANCH>             Branch to compare (default: HEAD)

CONTINUOUS MONITORING:
    --watch                           Watch mode - rescan on file changes

PROFESSIONAL FEATURES:
    --audit                           Generate professional audit report
    --project <NAME>                  Project name (requires --audit)
    --sponsor <NAME>                  Sponsor name (requires --audit)
    --project-analysis                Cross-file vulnerability analysis
    --report                          Clean markdown report

VERSION INFO:
    --version                         Print version
    --version-full                    Show full version with build details
    --examples                        Show usage examples
    --help                            Print help information
```

---

## Vulnerability Categories

### Critical Severity
| Category | SWC/ID | CWE | Description |
|----------|--------|-----|-------------|
| Reentrancy | SWC-107 | CWE-841 | CEI violations, cross-function, read-only |
| Access Control | SWC-105 | CWE-284 | Unprotected functions, missing modifiers |
| Proxy Admin | 41S-003 | CWE-284 | Unprotected upgrade/admin functions |
| Arbitrary Calls | 41S-005 | CWE-749 | Unchecked external calls with user input |
| ERC4626 Inflation | 41S-020 | CWE-682 | First depositor share manipulation |
| Flash Loan | 41S-002 | CWE-807 | Governance manipulation, oracle attacks |
| L2 Sequencer | 41S-029 | CWE-703 | Missing sequencer uptime check |
| Bridge Security | 41S-014 | CWE-345 | Cross-chain message validation |

### High Severity
| Category | SWC/ID | CWE | Description |
|----------|--------|-----|-------------|
| Oracle Manipulation | 41S-001 | CWE-807 | Price feed vulnerabilities |
| Signature Replay | SWC-121 | CWE-294 | Missing nonces, replay attacks |
| DoS Attacks | SWC-128 | CWE-400 | Unbounded loops, gas griefing |
| MEV/Front-Running | SWC-114 | CWE-362 | Missing slippage/deadline |
| Permit2 Risks | 41S-021 | CWE-294 | Signature reuse, deadline bypass |
| LayerZero | 41S-022 | CWE-284 | Trusted remote manipulation |
| Uniswap V4 Hooks | 41S-027 | CWE-94 | Hook exploitation vectors |
| CCIP Validation | 41S-028 | CWE-294 | Cross-chain message replay |

### Medium Severity
| Category | SWC/ID | CWE | Description |
|----------|--------|-----|-------------|
| Precision Loss | SWC-101 | CWE-190 | Division before multiplication |
| Time Manipulation | SWC-116 | CWE-829 | Block.timestamp dependencies |
| Unchecked Returns | SWC-104 | CWE-252 | External call failures |
| Transient Storage | 41S-024 | CWE-841 | TSTORE/TLOAD reentrancy |
| Create2 Collision | 41S-023 | CWE-327 | Address collision attacks |
| L2 Gas Oracle | 41S-030 | CWE-807 | Gas price manipulation |
| PUSH0 Compat | 41S-025 | CWE-1104 | Opcode compatibility issues |

### Low/Info
| Category | SWC/ID | Description |
|----------|--------|-------------|
| Floating Pragma | SWC-103 | Version inconsistencies |
| Deprecated | SWC-111 | Deprecated functions |
| Gas Optimization | - | Inefficient patterns |
| Code Quality | - | Best practices |

---

## L2 & Cross-Chain Security

### L2 Sequencer Uptime Detection
The scanner detects missing L2 sequencer uptime checks for Chainlink price feeds:

```solidity
// VULNERABLE: No sequencer check on L2
(, int256 price,,,) = priceFeed.latestRoundData();

// SAFE: With sequencer uptime check
(, int256 answer, uint256 startedAt,,) = sequencerFeed.latestRoundData();
require(answer == 0, "Sequencer down");
require(block.timestamp - startedAt > GRACE_PERIOD, "Grace period");
(, int256 price,,,) = priceFeed.latestRoundData();
```

### Optimistic Rollup Bridge Security
Detects missing validations in cross-domain message handlers:

```solidity
// VULNERABLE: No sender validation
function handleMessage(bytes calldata data) external {
    // Process without checking xDomainMessageSender
}

// SAFE: Proper validation
function handleMessage(bytes calldata data) external {
    require(msg.sender == messenger, "Only messenger");
    require(
        ICrossDomainMessenger(messenger).xDomainMessageSender() == trustedSender,
        "Invalid sender"
    );
}
```

### LayerZero V2 Patterns
Detects missing trusted remote validation:

```solidity
// VULNERABLE: No source validation
function lzReceive(uint16 _srcChainId, bytes memory _srcAddress, ...) {
    // Process without checking trustedRemote
}

// SAFE: With validation
function lzReceive(uint16 _srcChainId, bytes memory _srcAddress, ...) {
    require(trustedRemoteLookup[_srcChainId].length > 0);
    require(keccak256(_srcAddress) == keccak256(trustedRemoteLookup[_srcChainId]));
}
```

---

## DeFi Protocol Detection

The scanner automatically detects protocol types and applies specialized analysis:

### AMM/DEX Detection
```solidity
// Detected patterns: getReserves, swapExact*, addLiquidity, removeLiquidity
// Checks for: Uniswap V2/V3/V4 callback reentrancy, Curve read-only reentrancy,
//             missing slippage protection, sandwich attack surfaces
```

### Lending Detection
```solidity
// Detected patterns: borrow, repay, liquidate, collateral, healthFactor
// Checks for: Oracle manipulation, flash loan governance, liquidation
//             frontrunning, interest rate manipulation
```

### Oracle Detection
```solidity
// Checks for: Chainlink staleness (roundId, answeredInRound, updatedAt),
//             L2 sequencer uptime, TWAP window validation,
//             multi-oracle fallback patterns
```

### ERC4626 Vault Detection
```solidity
// Checks for: First depositor inflation attack, share/asset rounding,
//             virtual offset protection, minimum deposit requirements
```

---

## Smart False Positive Reduction

The scanner uses intelligent context-aware filtering (~60% reduction):

| Check | Action |
|-------|--------|
| SafeMath detected | Skip arithmetic overflow warnings |
| ReentrancyGuard detected | Skip reentrancy alerts |
| OpenZeppelin Ownable | Trust access control patterns |
| Solidity 0.8+ | Skip overflow warnings (built-in) |
| View/Pure functions | Skip reentrancy for read-only |
| Interface files | Skip entirely (no implementation) |
| Test/Mock contracts | Relaxed security checks |
| Commented code | Ignore vulnerabilities in comments |
| @audit/@security | Recognize intentional patterns |

---

## CI/CD Integration

### GitHub Actions with SARIF
```yaml
name: Security Scan

on: [push, pull_request]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Install Rust
        uses: actions-rs/toolchain@v1
        with:
          toolchain: stable

      - name: Install Scanner
        run: cargo install --git https://github.com/41swara/smart-contract-scanner

      - name: Run Security Scan
        run: |
          41 contracts/ \
            --defi-analysis \
            --advanced-detectors \
            --fail-on high \
            --format sarif \
            --cache \
            -o results.sarif

      - name: Upload SARIF to GitHub
        uses: github/codeql-action/upload-sarif@v2
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
  artifacts:
    reports:
      junit: security-report.json
```

### With Baseline (Only New Findings)
```yaml
security-scan:
  script:
    # Download baseline from previous run
    - aws s3 cp s3://bucket/baseline.json baseline.json || true
    # Scan with baseline comparison
    - 41 contracts/ --baseline baseline.json --fail-on high
    # Export new baseline
    - 41 contracts/ --export-baseline new-baseline.json
    - aws s3 cp new-baseline.json s3://bucket/baseline.json
```

### With Slither Correlation
```yaml
security-scan:
  script:
    - pip install slither-analyzer
    - slither . --json slither.json || true
    - 41 . --slither-json slither.json --fail-on high
```

---

## Performance Benchmarks

| Project Size | Files | Threads=1 | Threads=8 | Speedup |
|--------------|-------|-----------|-----------|---------|
| Small        | 5     | 0.5s      | 0.2s      | 2.5x    |
| Medium       | 25    | 2.8s      | 0.6s      | 4.7x    |
| Large        | 100   | 12.5s     | 1.8s      | 6.9x    |
| Very Large   | 500   | 68s       | 7.2s      | 9.4x    |
| Enterprise   | 1000+ | 150s      | 15s       | 10x     |

*With caching enabled, rescan of unchanged files: ~0.1s*

---

## Project Structure

```
src/
├── main.rs                 # CLI entry point
├── scanner.rs              # Core scanning engine
├── vulnerabilities.rs      # Vulnerability rules (150+) with SWC/CWE mapping
├── advanced_analysis.rs    # Phase 6 detectors + L2 patterns
├── ast/                    # AST-Based Analysis
│   ├── parser.rs           # tree-sitter integration
│   ├── cfg.rs              # Control flow graphs
│   └── dataflow.rs         # Taint analysis
├── defi/                   # DeFi Analyzers
│   ├── amm_analyzer.rs     # AMM/DEX vulnerabilities
│   ├── lending_analyzer.rs # Lending protocol issues
│   ├── oracle_analyzer.rs  # Oracle security
│   └── mev_analyzer.rs     # MEV/frontrunning
├── integrations/           # Tool Integration
│   ├── foundry.rs          # Foundry PoC generation
│   └── slither.rs          # Slither correlation
├── cache.rs                # Incremental scanning cache
├── abi_scanner.rs          # ABI security analysis
├── professional_reporter.rs# Audit report generation
├── project_scanner.rs      # Cross-file analysis
├── reporter.rs             # Output formatting
└── sarif.rs                # SARIF 2.1.0 output with CWE
```

---

## Dependencies

All dependencies are local-only (no network required):

```toml
# Core
regex = "1.10"              # Pattern matching
clap = "4.4"                # CLI parsing
colored = "2.1"             # Terminal colors
walkdir = "2.4"             # Directory traversal
serde = "1.0"               # Serialization
serde_json = "1.0"          # JSON handling

# Performance
rayon = "1.8"               # Parallel scanning
once_cell = "1.19"          # Lazy static regex
dashmap = "5.5"             # Concurrent hashmap
indicatif = "0.17"          # Progress bars

# AST Analysis
tree-sitter = "0.20"        # Incremental parsing
petgraph = "0.6"            # Graph structures (CFG)

# Caching & Filtering
blake3 = "1.5"              # Fast hashing
glob = "0.3"                # Pattern matching

# Git Integration
git2 = "0.18"               # Local git operations

# File Watching
notify = "6.1"              # File system events
```

---

## Multi-Tool Workflow

For comprehensive security analysis, combine 41Swara with other tools:

```bash
# 1. Fast static analysis with DeFi + L2 focus
41 . --defi-analysis --advanced-detectors -j 8 --min-severity high

# 2. Correlate with Slither
slither . --json slither.json
41 . --slither-json slither.json

# 3. Generate PoC tests for critical findings
41 . --generate-poc

# 4. Run Foundry tests to validate
forge test

# 5. Symbolic execution for confirmed issues (slow)
mythril analyze flagged-contract.sol
```

### Tool Comparison
| Feature | 41Swara | Slither | Mythril |
|---------|---------|---------|---------|
| Speed | Fast | Medium | Slow |
| Parallel | Yes | No | No |
| DeFi Detectors | Advanced | Basic | No |
| L2 Patterns | Yes | No | No |
| CWE/SWC Mapping | Yes | Partial | No |
| AST Analysis | Yes | Yes | No |
| Taint Analysis | Yes | Yes | Yes |
| Offline | 100% | Yes | Yes |
| Slither Integration | Yes | N/A | No |
| PoC Generation | Yes | No | No |
| CI/CD Ready | Yes | Yes | No |

---

## Contributing

### Adding New Vulnerability Patterns
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

### Adding L2/Cross-Chain Detectors
```rust
// src/advanced_analysis.rs
fn detect_your_l2_pattern(&self, content: &str) -> Vec<Vulnerability> {
    let mut vulnerabilities = Vec::new();
    // Your detection logic
    vulnerabilities
}
```

### Development Setup
```bash
git clone https://github.com/41swara/smart-contract-scanner
cd smart-contract-scanner
cargo build
cargo test

# Test on sample contracts
cargo run -- contracts/ -v --defi-analysis --advanced-detectors
```

---

## Resources

- **SWC Registry**: https://swcregistry.io/
- **MITRE CWE**: https://cwe.mitre.org/
- **Rekt News**: https://rekt.news/
- **DeFi Security**: https://consensys.github.io/smart-contract-best-practices/
- **Solidity Docs**: https://docs.soliditylang.org/
- **Secureum**: https://secureum.substack.com/
- **Trail of Bits Blog**: https://blog.trailofbits.com/
- **Chainlink L2 Sequencer**: https://docs.chain.link/data-feeds/l2-sequencer-feeds

---

## License

MIT License - see [LICENSE](LICENSE) for details

---

## Acknowledgments

- Built by **41Swara Security Team**
- Vulnerability patterns from **rekt.news** and **SWC registry**
- Inspired by **Trail of Bits' Slither** and **ConsenSys' Mythril**
- DeFi patterns from **Immunefi**, **Sherlock**, and **Code4rena** findings
- L2 patterns from **Optimism**, **Arbitrum**, and cross-chain security research

---

**Built for speed. Designed for security. Made for researchers.**

*Detect vulnerabilities before attackers do. Protect billions in DeFi assets.*

**Version 0.4.0 - Security Researcher Edition** | **Updated: January 2026** | **150+ Vulnerability Patterns** | **CWE/SWC Compliant** | **Fully Offline**
