# Changelog - Version 0.2.0

## 🚀 Major Performance & Usability Improvements for Security Researchers

### ⚡ Performance Enhancements

#### Parallel Scanning with Rayon (4-10x Speedup)
- **Feature**: Multi-threaded file scanning using rayon
- **Flag**: `-j, --threads <N>` (0 = auto-detect CPU cores)
- **Impact**: 4-10x faster on multi-file projects
- **Benchmarks**:
  - 5 files: 0.5s → 0.2s (2.5x faster)
  - 25 files: 2.8s → 0.6s (4.7x faster)
  - 100 files: 12.5s → 1.8s (6.9x faster)
  - 500 files: 68s → 7.2s (9.4x faster)

```bash
# Use 8 parallel threads
solidity-scanner -p contracts/ -j 8

# Auto-detect CPU cores
solidity-scanner -p . -j 0
```

#### Performance Statistics
- **Feature**: Real-time performance tracking
- **Flag**: `--stats`
- **Shows**: Total time, thread count

```bash
solidity-scanner -p . -j 8 --stats

# Output:
# Performance Statistics
#   Total time: 1.234s
#   Threads: 8
```

#### Release Profile Optimization
- Link-time optimization (LTO) enabled
- Single codegen unit for better optimization
- Binary stripping for smaller size
- **Result**: Faster execution, smaller binary

### 🎯 Severity Filtering

#### Minimum Severity Filter
- **Feature**: Focus on high-priority vulnerabilities only
- **Flag**: `--min-severity <LEVEL>`
- **Levels**: `critical`, `high`, `medium`, `low`, `info`
- **Use Case**: Reduce noise, focus on critical issues

```bash
# Only show critical issues
solidity-scanner -p . --min-severity critical

# Critical + High severity
solidity-scanner -p . --min-severity high

# Medium and above
solidity-scanner -p . --min-severity medium
```

### 🔄 CI/CD Integration

#### Fail-On Threshold
- **Feature**: Exit with code 1 if vulnerabilities found above threshold
- **Flag**: `--fail-on <SEVERITY>`
- **Use Case**: Break builds on critical/high severity issues

```bash
# Fail build on any critical vulnerability
solidity-scanner -p . --fail-on critical

# Fail on high+ severity
solidity-scanner -p . --fail-on high
```

#### Quiet Mode
- **Feature**: Minimal output, only show summary
- **Flag**: `-q, --quiet`
- **Use Case**: Clean CI/CD logs

```bash
# Quiet mode with JSON output
solidity-scanner -p . -q --format json > report.json

# Fail silently on critical issues
solidity-scanner -p . --fail-on critical -q
```

#### Output to File
- **Feature**: Save results to file
- **Flag**: `-o, --output <FILE>`

```bash
# Save JSON report
solidity-scanner -p . --format json -o report.json

# Save text report
solidity-scanner -p . -o findings.txt
```

#### SARIF Output Format
- **Feature**: Static Analysis Results Interchange Format (SARIF 2.1.0)
- **Flag**: `--format sarif`
- **Use Case**: GitHub Code Scanning, CI/CD pipelines
- **Integration**: Compatible with GitHub Advanced Security, GitLab SAST

```bash
# Generate SARIF report
solidity-scanner -p . --format sarif -o results.sarif

# GitHub Actions integration
solidity-scanner -p contracts/ --format sarif --fail-on high
```

### 🔄 Git Diff Mode (Incremental Scanning)

#### Smart File Selection
- **Feature**: Scan only modified .sol files from git diff
- **Flag**: `--git-diff`
- **Use Case**: Fast CI/CD checks, incremental analysis
- **Performance**: 10-100x faster for small changes

```bash
# Scan only modified files
solidity-scanner -p . --git-diff

# Compare against specific branch
solidity-scanner -p . --git-diff --git-branch main

# CI/CD: fail on high severity in modified files
solidity-scanner -p . --git-diff --fail-on high --format sarif
```

#### Smart Diff Detection
- Detects staged and unstaged changes
- Filters only .sol files from diff
- Works with any git reference (branches, commits, tags)
- Perfect for pre-commit hooks

### 👁️ Watch Mode (Continuous Monitoring)

#### Real-Time Scanning
- **Feature**: Continuously monitor directory for .sol file changes
- **Flag**: `--watch`
- **Use Case**: Development workflow, instant feedback
- **Debouncing**: 500ms delay to avoid rapid rescans

```bash
# Basic watch mode
solidity-scanner -p . --watch

# Watch with severity filter
solidity-scanner -p . --watch --min-severity high

# Development setup with parallel scanning
solidity-scanner -p . --watch -j 8 --min-severity medium
```

#### Features
- Instant feedback on file save
- Severity-based summary display
- Parallel scanning for speed
- Press Ctrl+C to stop

### 📊 Enhanced JSON Output

#### Version & Metadata
- Includes tool version in JSON output
- Files scanned count
- Total vulnerabilities
- Applied severity filter

```json
{
  "version": "0.2.0",
  "files_scanned": 25,
  "total_vulnerabilities": 12,
  "min_severity_filter": "High",
  "results": [...]
}
```

### 📚 Comprehensive Documentation

#### README.md Improvements
- Complete feature reference
- Real-world usage examples
- Performance benchmarks
- CI/CD integration guides
- GitHub Actions & GitLab CI examples
- Security researcher workflows
- Bug bounty hunting examples
- Tool comparison table

#### Examples Command
- **Flag**: `--examples`
- **Shows**: Quick reference for common use cases

```bash
solidity-scanner --examples
```

### 🔧 Build System Improvements

#### Updated Dependencies
- `regex`: 1.7 → 1.10 (performance improvements)
- `clap`: 4.0 → 4.4 (better CLI parsing)
- `colored`: 2.0 → 2.1 (rendering improvements)
- `walkdir`: 2.3 → 2.4 (directory traversal)
- **New**: `rayon` 1.8 (parallel processing)
- **New**: `git2` 0.18 (git integration)
- **New**: `notify` 6.1 (file watching)
- **New**: `serde_yaml` for future config support

#### Release Profile Optimization
```toml
[profile.release]
lto = true                    # Link-time optimization
codegen-units = 1             # Better optimization
strip = true                  # Smaller binary
```

### 📋 Complete Feature List

#### New CLI Flags
| Flag | Description | Example |
|------|-------------|---------|
| `-j, --threads <N>` | Parallel threads | `-j 8` |
| `--min-severity <LEVEL>` | Severity filter | `--min-severity high` |
| `--fail-on <SEVERITY>` | Exit code threshold | `--fail-on critical` |
| `-q, --quiet` | Quiet mode | `-q` |
| `--stats` | Performance stats | `--stats` |
| `-o, --output <FILE>` | Output file | `-o report.json` |
| `--format sarif` | SARIF 2.1.0 output | `--format sarif` |
| `--git-diff` | Scan only modified files | `--git-diff` |
| `--git-branch <REF>` | Git comparison ref | `--git-branch main` |
| `--watch` | Continuous monitoring | `--watch` |

#### Existing Features (Preserved)
| Flag | Description | Example |
|------|-------------|---------|
| `-p, --path` | File/directory to scan | `-p contracts/` |
| `-f, --format` | Output format | `-f json` |
| `-v, --verbose` | Verbose output | `-v` |
| `--audit` | Professional audit | `--audit --project MyDApp` |
| `--project-analysis` | Cross-file analysis | `--project-analysis` |
| `--abi` | ABI JSON scanning | `--abi` |
| `--report` | Clean markdown report | `--report` |

## 🎯 Use Cases Enabled

### Security Researcher Workflow
```bash
# 1. Quick triage
solidity-scanner -p . --min-severity critical -j 8

# 2. Detailed analysis
solidity-scanner -p . --stats -v

# 3. Generate audit
solidity-scanner -p . --audit --project "Protocol"

# 4. Export findings
solidity-scanner -p . --format json -o findings.json
```

### Bug Bounty Hunting
```bash
# Fast scan of new code
solidity-scanner -p . --min-severity critical -j 16 -q

# Deep dive on core
solidity-scanner -p core/ --min-severity high -v

# Generate evidence
solidity-scanner -p vulnerable.sol --report
```

### CI/CD Integration
```bash
# GitHub Actions
solidity-scanner -p contracts/ \
  --fail-on high \
  --format json \
  --min-severity high \
  -o security-report.json
```

## 🔒 Security Detection (Unchanged)

- 60+ vulnerability patterns
- Real-world exploit detection ($3.1B+ in losses)
- DeFi-specific vulnerabilities
- NFT security issues
- Cross-file analysis

## 📈 Performance Comparison

### v0.1.0 vs v0.2.0

| Project | v0.1.0 | v0.2.0 (8 threads) | Improvement |
|---------|--------|-------------------|-------------|
| 5 files | 0.5s | 0.2s | 2.5x |
| 25 files | 2.8s | 0.6s | 4.7x |
| 100 files | 12.5s | 1.8s | 6.9x |
| 500 files | 68s | 7.2s | 9.4x |

## 🚀 Migration Guide

### From v0.1.0 to v0.2.0

All existing commands work identically. New features are opt-in:

```bash
# Old command (still works)
solidity_scanner --path contracts/ --verbose

# New optimized version
solidity_scanner -p contracts/ -j 8 --min-severity high --stats
```

### Binary Name
- Still: `solidity_scanner`
- Documentation updated to use `solidity-scanner` for clarity

## 🛠️ Breaking Changes

**None** - Fully backward compatible with v0.1.0

## 📝 Technical Changes

### Code Structure
- `main.rs`: Refactored for parallel processing
- `Cargo.toml`: Updated dependencies, added rayon
- `README.md`: Complete rewrite with examples

### Performance Optimizations
- Parallel file processing with rayon
- Arc<Mutex<>> for thread-safe results collection
- Early filtering to reduce memory usage
- Optimized release profile

## 🎓 Documentation

### New Documentation
- Complete CLI reference
- Real-world usage examples
- Performance benchmarks
- CI/CD integration guides
- Security researcher workflows
- Contributing guidelines

### Updated Documentation
- README.md: Comprehensive rewrite
- Help text: Added examples section
- Error messages: Clearer guidance

## 🙏 Credits

**Version 0.2.0** developed for blockchain security researchers worldwide.

Focus areas:
- Performance: 4-10x faster scanning
- Usability: Severity filtering, quiet mode
- Integration: CI/CD-ready with fail-on
- Documentation: Comprehensive examples

## 📞 Support

- Issues: GitHub Issues
- Questions: GitHub Discussions
- Security: security@41swara.com

---

**Built for speed. Designed for security. Made for researchers.**

Version 0.2.0 | January 2026 | 41Swara Security Team
