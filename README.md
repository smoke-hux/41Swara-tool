<p align="center">
  <strong>41Swara</strong><br>
  Smart Contract Security Scanner
</p>

<p align="center">
  <a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License: MIT"></a>
  <a href="https://www.rust-lang.org/"><img src="https://img.shields.io/badge/rust-1.70%2B-orange.svg" alt="Rust"></a>
  <img src="https://img.shields.io/badge/version-0.8.1-blue.svg" alt="Version">
  <img src="https://img.shields.io/badge/offline-100%25-green.svg" alt="Offline">
  <img src="https://img.shields.io/badge/CVSS_3.1-scoring-blueviolet.svg" alt="CVSS 3.1">
</p>

---

Static analysis for Solidity smart contracts, built for bug bounty hunters, audit contestants, and security researchers. Every finding comes with a CVSS 3.1 score, real-world exploit references, and an attack path narrative.

- **200+** vulnerability detection patterns across 77 categories
- **CVSS 3.1** base scoring on every finding (official formula)
- **53 real-world exploit references** &mdash; The DAO, Ronin, Wormhole, Cetus, Balancer, and more ($3.5B+ total)
- **Attack path narratives** &mdash; step-by-step exploitation descriptions per finding
- **30+ EIP-specific** detectors (ERC-20 through ERC-4337, EIP-7702 Pectra readiness)
- **DeFi-aware** &mdash; AMM, lending, oracle, MEV, vault, and multicall analysis
- **L2 & cross-chain** &mdash; sequencer uptime, bridge validation, PUSH0 compatibility
- **90%+ false positive reduction** &mdash; 3-layer filtering, version-aware, recognizes OpenZeppelin/Solmate/Solady
- **Priority-based triage** &mdash; P1/P2/P3 remediation priorities (CVSS &times; confidence)
- **Fully offline** &mdash; no network dependencies, no API keys

---

## Install

```bash
git clone https://github.com/41swara/smart-contract-scanner
cd smart-contract-scanner
cargo install --path .
```

This installs both `41` and `41swara` to `~/.cargo/bin/`.

To update:

```bash
git pull origin main && cargo install --path . --force
```

---

## Quick Start

```bash
# Scan a contract
41 MyContract.sol

# Scan a directory
41 contracts/

# Only critical and high severity
41 . --min-severity high

# Professional audit report with executive summary and priority matrix
41 . --audit --project "MyDApp"

# JSON output with CVSS scores, exploit references, and attack paths
41 . -f json -o results.json

# SARIF for GitHub Code Scanning
41 . -f sarif -o results.sarif

# CI gate: fail if high/critical found
41 . --fail-on high -q
```

---

## What's New in v0.8.1

### False Positive Reduction

29 false positives removed across 7 distinct patterns (207 &rarr; 178 findings on test suite, &minus;14%):

| FP Pattern | Root Cause | Fix |
|-----------|------------|-----|
| **"Calldata Parameter Detected"** (Critical) | Flagged every `calldata` param | Removed &mdash; standard param location, not a vuln |
| **"DeFi Function Without Pause Check"** (&times;15) | Regex rule fired per-function | Removed duplicate &mdash; advanced analyzer already reports once per contract |
| **"Missing Slippage on deposit()"** | `deposit`/`stake` matched swap pattern | Restricted to `swap`, `addLiquidity`, `removeLiquidity`, `zap` |
| **"Insufficient Balance Validation"** on `withdraw` | Flagged all withdraw functions | Restricted to `removeLiquidity` &mdash; Solidity 0.8+ underflow protects |
| **CFG reentrancy at wrong lines** | `parse_statements` hardcoded `base_line=0` | Pass actual file-level line offset |
| **"State Check After External Call"** | Included safe `.transfer()`/`.send()`, never reset | Only `.call()`; skip `require(success`; break after first |
| **Calldata in advanced analyzer** | Flagged any `calldata` without validation | Only flag `bytes calldata` (arbitrary raw data) |

### Reports Directory

Scan reports are now saved to `reports/` by default (gitignored). Previously they accumulated in the project root.

---

## What's New in v0.8.0

### Professional-Grade Output

Every finding now includes:

| Field | Description |
|-------|-------------|
| **CVSS 3.1 Score** | Official base score (0.0&ndash;10.0) with full vector string |
| **Exploit References** | Real-world incidents with loss amounts (e.g., "Cetus DEX, $223M, 2025") |
| **Attack Path** | 5-step narrative showing how the vulnerability can be exploited |
| **Priority** | P1 (immediate), P2 (short-term), P3 (monitor) based on CVSS &times; confidence |

### Audit Report Enhancements

The `--audit` report now generates:
- **Executive Summary** with overall risk rating and average CVSS
- **Remediation Priority Matrix** sorted by CVSS &times; confidence
- **Exploit Reference Boxes** linking findings to real losses
- **Attack Path Sections** with step-by-step exploitation details

### Credibility Fixes

- **FP filter and EIP analysis enabled by default** (opt out with `--no-fp-filter` / `--no-eip-analysis`)
- **Compiler findings consolidated** &mdash; 11 CVEs per version &rarr; 1 finding per file
- **Function-scope deduplication** across 6 category groups (reentrancy, access control, oracle, compiler, signature, math)
- **Threat model suppression** &mdash; architectural findings hidden by default (show with `--show-threat-model`)
- **Multi-line signature parsing** &mdash; detects `nonReentrant`, `onlyOwner`, `whenNotPaused` across line breaks
- **Inheritance-aware modifiers** &mdash; resolves Ownable, ReentrancyGuard, Pausable, AccessControl
- **.transfer()/.send() excluded from reentrancy** &mdash; 2300 gas stipend is safe
- **Inter-procedural taint analysis** &mdash; tracks taint propagation across internal function calls

### v0.7.0 &mdash; 2025&ndash;2026 Exploit Patterns

18 new detections from $400M+ in real-world exploits:

| Exploit | Loss | What it catches |
|---------|------|-----------------|
| Cetus CLMM | $223M | Bit-shift overflow in concentrated liquidity math |
| Balancer | $128M | Inconsistent rounding (mulDown + divUp mismatch) |
| Atlas Chain | $112M | Unvalidated cross-chain receiver |
| GMX | $42M | Receiver callback before state update |
| Abracadabra | $14.7M | Multicall batch resets solvency flag |
| Yearn | $9M | Inconsistent state reset |
| zkSync | $5M | Unprotected admin sweep |
| Thirdweb | &mdash; | ERC-2771 `_msgSender()` spoofed via multicall |
| EigenLayer | &mdash; | AVS slashing without dispute period |

**Ethereum Pectra (EIP-7702) readiness:**
- `tx.origin == msg.sender` no longer reliable for EOA checks
- `extcodesize` / `isContract()` unreliable for smart wallets
- `.transfer()` / `.send()` gas assumptions changed by transient storage

---

## Usage Reference

```bash
41 contracts/                         # Scan a directory
41 MyContract.sol                     # Scan a single file
41 . -v --stats                       # Verbose with performance stats
41 . --min-severity high              # Only critical + high
41 . --confidence-threshold 70        # Only 70%+ confidence
41 . --defi-analysis                  # Enable DeFi analyzers
41 . --git-diff                       # Scan only modified files
41 . --watch                          # Rescan on file changes
41 . -f json -o results.json          # JSON output with CVSS
41 . -f sarif -o results.sarif        # SARIF for GitHub Code Scanning
41 . --audit --project "MyDApp"       # Professional audit report
41 . --fail-on high -q                # Exit 1 if high/critical found (CI)
41 . -j 8 --fast                      # 8 threads, regex-only (fastest)
41 . --show-threat-model              # Include STRIDE threat model findings
41 . --no-fp-filter                   # Disable false positive filtering
41 . --no-eip-analysis                # Disable EIP-specific checks
41 . --config rules.toml              # Load custom rules from TOML
41 . --baseline prev.json             # Diff against previous scan
```

Run `41 --help` for the full CLI reference.

---

## Output Formats

### Terminal (default)

```
[Critical] CVSS 10.0 (P1) — State Change After External Call
  Line 15: (bool success,) = msg.sender.call{value: balance}("");
  Exploits: The DAO ($60M, 2016), Curve ($62M, 2023)
  Recommendation: Move all state changes before external calls
```

### JSON

```json
{
  "version": "0.8.1",
  "results": [{
    "vulnerabilities": [{
      "severity": "Critical",
      "category": "Reentrancy",
      "title": "State Change After External Call",
      "cvss_score": 10.0,
      "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:H/A:H",
      "exploit_references": ["The DAO ($60M, 2016-06)", "Curve ($62M, 2023-07)"],
      "attack_path": "1. Attacker deploys malicious contract...",
      "line_number": 15,
      "confidence": 95
    }]
  }]
}
```

### SARIF 2.1.0

Includes CVSS scores in the `security-severity` property for GitHub Code Scanning severity mapping.

### Audit Report (`--audit`)

Professional security audit document with executive summary, priority matrix, per-finding CVSS badges, exploit reference boxes, attack path narratives, and remediation guidance.

---

## Custom Rules

Create a `.41swara.toml` in your project root:

```toml
[[rules]]
id = "PROJ-001"
title = "Hardcoded Admin Address"
description = "Admin address should not be hardcoded"
severity = "High"
pattern = "address\\s+admin\\s*=\\s*0x[0-9a-fA-F]{40}"
recommendation = "Use constructor parameter or upgradeable pattern"

[[overrides]]
rule_id = "SWC-107"
severity = "Medium"      # Downgrade reentrancy for this project

[[overrides]]
rule_id = "41S-058"
enabled = false           # Disable .transfer() gas warning
```

---

## CI/CD

### GitHub Actions

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - run: cargo install --git https://github.com/41swara/smart-contract-scanner
      - run: 41 contracts/ --fail-on high -f sarif --cache -o results.sarif
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

### GitLab CI

```yaml
security-scan:
  stage: test
  script:
    - cargo install --git https://github.com/41swara/smart-contract-scanner
    - 41 contracts/ --fail-on critical -f json --cache
```

---

## Contributing

```bash
git clone https://github.com/41swara/smart-contract-scanner
cd smart-contract-scanner
cargo build && cargo test --all
cargo run -- test_contracts/ -v --stats
```

See [ARCHITECTURE.md](ARCHITECTURE.md) for internals.

---

## License

MIT &mdash; see [LICENSE](LICENSE).

Built by **41Swara Security Team**.
