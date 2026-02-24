<p align="center">
  <strong>41Swara</strong><br>
  Smart Contract Security Scanner
</p>

<p align="center">
  <a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License: MIT"></a>
  <a href="https://www.rust-lang.org/"><img src="https://img.shields.io/badge/rust-1.70%2B-orange.svg" alt="Rust"></a>
  <img src="https://img.shields.io/badge/version-0.7.0-blue.svg" alt="Version">
  <img src="https://img.shields.io/badge/offline-100%25-green.svg" alt="Offline">
</p>

---

Scans Solidity smart contracts for security vulnerabilities. Built for bug bounty hunters, audit contestants, and security researchers.

- **176+** vulnerability patterns (reentrancy, access control, flash loans, oracle manipulation, and more)
- **30+** EIP-specific detectors (ERC-20 through ERC-4337, EIP-7702)
- **DeFi-aware** &mdash; AMM, lending, oracle, MEV, vault, and multicall analysis
- **L2 & cross-chain** &mdash; sequencer uptime, bridge validation, PUSH0 compatibility
- **90%+ false positive reduction** &mdash; version-aware, recognizes OpenZeppelin/Solmate/Solady
- **$3.5B+** in real-world exploit patterns covered
- **Fully offline** &mdash; no network dependencies

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

## Usage

```bash
41 contracts/                         # Scan a directory
41 MyContract.sol                     # Scan a single file
41 . -v --stats                       # Verbose with performance stats
41 . --min-severity high              # Only critical + high
41 . --confidence-threshold 70        # Only 70%+ confidence
41 . --defi-analysis                  # Enable DeFi analyzers
41 . --eip-analysis                   # EIP-specific checks
41 . --strict-filter                  # Enhanced false positive filtering
41 . --git-diff                       # Scan only modified files
41 . --watch                          # Rescan on file changes
41 . -f json -o results.json          # JSON output
41 . -f sarif -o results.sarif        # SARIF for GitHub Code Scanning
41 . --audit --project "MyDApp"       # Professional audit report
41 . --fail-on high -q                # Exit 1 if high/critical found (CI)
41 . -j 8 --fast                      # 8 threads, regex-only (fastest)
```

Run `41 --help` for the full CLI reference.

---

## What's New in v0.7.0

**18 new detections** from **$400M+** in 2025&ndash;2026 exploits:

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
cargo build && cargo test
cargo run -- test_contracts/ -v --stats
```

See [ARCHITECTURE.md](ARCHITECTURE.md) for internals.

---

## License

MIT &mdash; see [LICENSE](LICENSE).

Built by **41Swara Security Team**. Patterns sourced from **rekt.news**, **SWC Registry**, **Immunefi**, **Sherlock**, and **Code4rena**.
