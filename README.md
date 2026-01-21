# 41Swara Smart Contract Security Scanner v0.3.0

**Professional-grade vulnerability scanner for blockchain security researchers**

A fully offline, API-independent Rust-based static analysis tool designed for bug bounty hunting (Immunefi, HackerOne), audit contests (Sherlock, CodeHawks, Code4rena), and professional security audits. Features **AST-based analysis**, **DeFi-specific detectors**, **Slither/Foundry integration**, and **100+ vulnerability patterns** including real-world exploit patterns from $3.1B+ in DeFi losses.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Rust](https://img.shields.io/badge/rust-1.70%2B-orange.svg)](https://www.rust-lang.org/)
[![Offline](https://img.shields.io/badge/offline-100%25-green.svg)]()
[![Performance](https://img.shields.io/badge/parallel-4--10x_faster-brightgreen.svg)]()

---

## Key Features

### Fully Offline & API-Independent
- **Zero network dependencies** - works in air-gapped environments
- **No API keys required** - all analysis runs locally
- **No external services** - complete privacy for your audits
- **Git integration** via local `git2` library
- **Tool integration** via local process execution

### AST-Based Analysis Engine
- **tree-sitter-solidity** for proper Solidity parsing
- **Control Flow Graphs (CFG)** for each function
- **Taint Analysis** - track user input to dangerous sinks
- **Inter-procedural analysis** for cross-function vulnerabilities

### DeFi-Specific Analyzers
- **AMM/DEX Analyzer** - Uniswap V2/V3 reentrancy, Curve read-only reentrancy, slippage/deadline protection
- **Lending Analyzer** - Price oracle manipulation, flash loan governance, liquidation frontrunning
- **Oracle Analyzer** - Chainlink staleness, sequencer uptime (L2), TWAP validation
- **MEV Analyzer** - Sandwich attacks, frontrunning, commit-reveal patterns

### Advanced Detection (Phase 6)
| Detector | Category | Priority |
|----------|----------|----------|
| ERC4626 Inflation Attack | Logic Error | Critical |
| Read-Only Reentrancy | Reentrancy | Critical |
| Permit2 Integration Risks | Access Control | High |
| LayerZero Message Validation | Bridge Security | High |
| EIP-4337 Account Abstraction | Access Control | High |
| Transient Storage (TSTORE) | Storage | Medium |
| Create2 Address Collision | Logic Error | Medium |
| Merkle Tree Vulnerabilities | Access Control | Medium |

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
# Scan a single contract
41 -p MyContract.sol

# Scan entire project
41 -p contracts/

# Verbose with stats
41 -p contracts/ -v --stats
```

### DeFi-Specific Analysis
```bash
# Enable DeFi analyzers (AMM, Lending, Oracle, MEV)
41 -p . --defi-analysis

# Enable advanced Phase 6 detectors
41 -p . --advanced-detectors

# Full analysis
41 -p . --defi-analysis --advanced-detectors -v
```

### Slither Integration
```bash
# Run Slither first
slither . --json slither-output.json

# Correlate with 41Swara findings
41 -p . --slither-json slither-output.json
```

### Foundry Integration
```bash
# Generate PoC tests for findings
41 -p . --generate-poc

# Correlate with Foundry test results
41 -p . --foundry-correlate
```

### Caching for CI/CD
```bash
# Enable caching (faster rescans)
41 -p . --cache

# Custom cache directory
41 -p . --cache --cache-dir .my_cache
```

---

## Example Output

```
41Swara Smart Contract Scanner v0.3.0
High-performance security analysis for blockchain
=======================================================

Scanning directory: contracts/
Found 15 Solidity files

SCAN RESULTS FOR contracts/Vault.sol
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Access Control

  !! Unprotected Critical Function: withdrawAll [Line 21]
     Description: Critical function lacks access control modifiers
     Context:
         19 |
         20 |     // Vulnerable: External call without reentrancy guard
     Vulnerable Code:
         21 | function withdrawAll() external {
         22 |         uint256 balance = deposits[msg.sender];
     Recommendation: Add appropriate access control modifiers
     Severity: CRITICAL | Confidence: High

Reentrancy

  !! Critical: State Change After External Call [Line 16]
     Description: State modification after external call - violates CEI pattern
     Vulnerable Code:
         16 |         token.transfer(address(this), amount);
     Recommendation: Move all state changes before external calls
     Severity: CRITICAL | Confidence: High

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
```

### Confidence Indicators
- **!!** (Critical) - Immediate action required
- **!** (High) - Very likely a real vulnerability
- **\*** (Medium) - Likely a vulnerability, review recommended
- **-** (Low) - Possible issue, may be false positive

---

## Complete CLI Reference

```
USAGE:
    41 [OPTIONS] --path <FILE_OR_DIR>
    41swara [OPTIONS] --path <FILE_OR_DIR>

BASIC OPTIONS:
    -p, --path <FILE_OR_DIR>          Path to scan (required)
    -f, --format <text|json|sarif>    Output format (default: text)
    --min-severity <LEVEL>            Filter by severity
                                      [critical|high|medium|low|info]
    -v, --verbose                     Detailed analysis output
    -j, --threads <N>                 Parallel threads (0 = auto-detect)
    -q, --quiet                       Only show summary
    --stats                           Show performance statistics
    --fail-on <SEVERITY>              Exit code 1 if issues above threshold
    -o, --output <FILE>               Save output to file

DEFI ANALYSIS:
    --defi-analysis                   Enable DeFi-specific analyzers
                                      (AMM, Lending, Oracle, MEV)
    --advanced-detectors              Enable Phase 6 advanced detectors
                                      (ERC4626, Permit2, LayerZero, etc.)

TOOL INTEGRATION:
    --slither-json <PATH>             Combine with Slither JSON output
    --generate-poc                    Generate Foundry PoC tests
    --foundry-correlate               Correlate with Foundry test results

CACHING:
    --cache                           Enable incremental scanning cache
    --cache-dir <DIR>                 Cache directory (default: .41swara_cache)

ABI ANALYSIS:
    --abi                             Enable ABI security analysis mode
                                      Detects: contract types, DeFi patterns,
                                      security scores, 22+ ABI vulnerabilities

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

HELP:
    --examples                        Show usage examples
    --help                            Print help information
    --version                         Print version
```

---

## Vulnerability Categories

### Critical Severity
- **Reentrancy** (SWC-107) - CEI violations, cross-function, read-only
- **Access Control** (SWC-105) - Unprotected functions, missing modifiers
- **Proxy Admin** - Unprotected upgrade/admin functions
- **Arbitrary Calls** - Unchecked external calls with user input
- **ERC4626 Inflation** - First depositor share manipulation
- **Flash Loan Attacks** - Governance manipulation, oracle attacks

### High Severity
- **Oracle Manipulation** (SWC-201) - Price feed vulnerabilities
- **Signature Issues** (SWC-117, SWC-121) - Replay attacks, missing nonces
- **DoS Attacks** (SWC-128) - Unbounded loops, gas griefing
- **MEV/Front-Running** (SWC-114) - Missing slippage/deadline
- **Permit2 Risks** - Integration vulnerabilities
- **LayerZero/Bridge** - Cross-chain message validation

### Medium Severity
- **Precision Loss** (SWC-101) - Division before multiplication
- **Time Manipulation** (SWC-116) - Block.timestamp dependencies
- **Unchecked Returns** (SWC-104) - External call failures
- **Transient Storage** - TSTORE/TLOAD misuse
- **Merkle Trees** - Second preimage, leaf validation

### Low/Info
- **Floating Pragma** (SWC-103) - Version inconsistencies
- **Gas Optimization** - Inefficient patterns
- **Code Quality** - Best practices

---

## DeFi Protocol Detection

The scanner automatically detects protocol types and applies specialized analysis:

### AMM/DEX Detection
```solidity
// Detected patterns: getReserves, swapExact*, addLiquidity, removeLiquidity
// Checks for: Uniswap V2/V3 callback reentrancy, Curve read-only reentrancy,
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

---

## CI/CD Integration

### GitHub Actions
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
          41 -p contracts/ \
            --defi-analysis \
            --fail-on high \
            --format sarif \
            --cache \
            -o results.sarif

      - name: Upload SARIF
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
    - 41 -p contracts/ --fail-on critical --format json --cache
  artifacts:
    reports:
      junit: security-report.json
```

### With Slither Correlation
```yaml
security-scan:
  script:
    - pip install slither-analyzer
    - slither . --json slither.json || true
    - 41 -p . --slither-json slither.json --fail-on high
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
├── vulnerabilities.rs      # Vulnerability rules (100+)
├── advanced_analysis.rs    # Phase 6 detectors
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
└── sarif.rs                # SARIF output format
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
dashmap = "5.5"             # Concurrent hashmap
indicatif = "0.17"          # Progress bars

# AST Analysis
tree-sitter = "0.20"        # Incremental parsing
petgraph = "0.6"            # Graph structures (CFG)

# Caching
blake3 = "1.5"              # Fast hashing

# Git Integration
git2 = "0.18"               # Local git operations

# File Watching
notify = "6.1"              # File system events
```

---

## Multi-Tool Workflow

For comprehensive security analysis, combine 41Swara with other tools:

```bash
# 1. Fast static analysis with DeFi focus
41 -p . --defi-analysis --advanced-detectors -j 8 --min-severity high

# 2. Correlate with Slither
slither . --json slither.json
41 -p . --slither-json slither.json

# 3. Generate PoC tests for critical findings
41 -p . --generate-poc

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

### Adding DeFi-Specific Detectors
```rust
// src/defi/your_analyzer.rs
pub struct YourAnalyzer { /* ... */ }

impl YourAnalyzer {
    pub fn analyze(&self, content: &str) -> Vec<Vulnerability> {
        // Your detection logic
    }
}
```

### Development Setup
```bash
git clone https://github.com/41swara/smart-contract-scanner
cd smart-contract-scanner
cargo build
cargo test

# Test on sample contracts
cargo run -- -p test_contracts/ -v --defi-analysis
```

---

## Resources

- **SWC Registry**: https://swcregistry.io/
- **Rekt News**: https://rekt.news/
- **DeFi Security**: https://consensys.github.io/smart-contract-best-practices/
- **Solidity Docs**: https://docs.soliditylang.org/
- **Secureum**: https://secureum.substack.com/
- **Trail of Bits Blog**: https://blog.trailofbits.com/

---

## License

MIT License - see [LICENSE](LICENSE) for details

---

## Acknowledgments

- Built by **41Swara Security Team**
- Vulnerability patterns from **rekt.news** and **SWC registry**
- Inspired by **Trail of Bits' Slither** and **ConsenSys' Mythril**
- DeFi patterns from **Immunefi**, **Sherlock**, and **Code4rena** findings

---

**Built for speed. Designed for security. Made for researchers.**

*Detect vulnerabilities before attackers do. Protect billions in DeFi assets.*

**Version 0.3.0** | **Updated: January 2026** | **100+ Vulnerability Patterns** | **Fully Offline**
