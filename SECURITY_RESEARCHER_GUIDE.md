# 41Swara Smart Contract Scanner - Security Researcher Guide

> A deep-dive reference for security researchers, auditors, and bug bounty hunters who want to understand how 41Swara works under the hood, interpret its output correctly, tune it for their workflows, and troubleshoot issues.

**Version**: 0.6.0 | **Last Updated**: February 2026

---

## Table of Contents

1. [Architecture Overview](#1-architecture-overview)
2. [Scanning Pipeline (Step by Step)](#2-scanning-pipeline-step-by-step)
3. [Vulnerability Detection Engine](#3-vulnerability-detection-engine)
4. [False Positive Filtering (3-Layer System)](#4-false-positive-filtering-3-layer-system)
5. [Confidence Scoring System](#5-confidence-scoring-system)
6. [Interpreting Scan Results](#6-interpreting-scan-results)
7. [Tuning the Scanner for Your Workflow](#7-tuning-the-scanner-for-your-workflow)
8. [Common Workflows](#8-common-workflows)
9. [Troubleshooting & Known Issues](#9-troubleshooting--known-issues)
10. [Adding Custom Rules](#10-adding-custom-rules)
11. [Understanding the Threat Model Generator](#11-understanding-the-threat-model-generator)
12. [Integration with Other Tools](#12-integration-with-other-tools)
13. [Vulnerability ID Reference](#13-vulnerability-id-reference)
14. [FAQ](#14-faq)

---

## 1. Architecture Overview

### Core Components

The scanner is built as a layered pipeline in Rust. Each layer handles a distinct responsibility:

```
                    ┌──────────────┐
                    │   main.rs    │  CLI entry point, argument parsing, output formatting
                    └──────┬───────┘
                           │
                    ┌──────▼───────┐
                    │  scanner.rs  │  Orchestration: creates analyzers, runs pipeline, filters
                    └──────┬───────┘
                           │
          ┌────────────────┼────────────────────┐
          │                │                    │
   ┌──────▼──────┐  ┌─────▼──────┐  ┌──────────▼──────────┐
   │vulnerabilit │  │  advanced   │  │   logic_analyzer.rs  │
   │  ies.rs     │  │ _analysis.rs│  │  (business logic)    │
   │ (150+ regex │  │ (DeFi/NFT/  │  └──────────┬───────────┘
   │  rules)     │  │  L2/exploit)│             │
   └──────┬──────┘  └─────┬──────┘             │
          │                │                    │
          └────────────────┼────────────────────┘
                           │
          ┌────────────────┼────────────────────┐
          │                │                    │
   ┌──────▼──────┐  ┌─────▼──────┐  ┌──────────▼───────────┐
   │reachability │  │false_posit │  │   threat_model.rs     │
   │_analyzer.rs │  │ive_filter  │  │  (STRIDE generation)  │
   │(call graph) │  │    .rs     │  └───────────────────────┘
   └─────────────┘  └────────────┘
```

### File Responsibilities

| File | Role | What It Does |
|------|------|-------------|
| `main.rs` | Entry point | Parses CLI args, dispatches to scanner, formats output (text/JSON/SARIF) |
| `scanner.rs` | Orchestrator | Creates all sub-analyzers, runs the 9-phase pipeline, coordinates filtering |
| `vulnerabilities.rs` | Rule engine | Defines 150+ regex-based detection rules with SWC/CWE mapping |
| `advanced_analysis.rs` | Advanced detectors | DeFi, NFT, L2, known exploits, OWASP patterns, rekt.news patterns |
| `logic_analyzer.rs` | Logic analysis | State machine validation, invariants, race conditions, protocol-specific bugs |
| `reachability_analyzer.rs` | Call graph | Builds function call graph, filters findings in unreachable code |
| `false_positive_filter.rs` | FP reduction | 3-layer filtering: safe patterns, dedup, confidence adjustment |
| `threat_model.rs` | Threat modeling | Auto-detects contract type, generates STRIDE-based threat model |

### Key Data Structures

**`Vulnerability`** - the core finding type that flows through the entire pipeline:
```
Vulnerability {
    severity:           Critical | High | Medium | Low | Info
    category:           VulnerabilityCategory enum (80+ variants)
    title:              Human-readable title
    description:        Detailed explanation
    line_number:        Source line (1-indexed)
    code_snippet:       The vulnerable code
    recommendation:     How to fix
    confidence:         High | Medium | Low
    confidence_percent: 0-100 (numeric)
    swc_id:             SWC-XXX or 41S-XXX identifier
    fix_suggestion:     Optional code fix
}
```

**`ScannerConfig`** - controls which analysis passes are enabled:
```
ScannerConfig {
    enable_logic_analysis:        true   (business logic bugs)
    enable_reachability_analysis: true   (dead code filtering)
    enable_dependency_analysis:   true   (import CVE checks)
    enable_threat_model:          true   (STRIDE model)
    enable_eip_analysis:          true   (EIP-specific vulns)
    enable_strict_filter:         true   (enhanced FP filtering)
}
```

---

## 2. Scanning Pipeline (Step by Step)

When you run `41swara contracts/Vault.sol`, the following 9 phases execute in order:

### Phase 1: Parse Source
- Reads the `.sol` file
- Enforces the 10 MB file size limit (prevents DoS on the scanner itself)
- Splits into lines for line-by-line rule matching
- Extracts the Solidity version from `pragma solidity`

### Phase 2: Regex-Based Rules (vulnerabilities.rs)
- Applies 150+ compiled regex patterns against the source
- Each rule is either **single-line** (matched per line) or **multiline** (matched against full file content)
- Rules are pre-compiled with `once_cell::Lazy` for performance
- Each match produces a `Vulnerability` with line number, severity, SWC ID, etc.

### Phase 3: Advanced Analyzers (advanced_analysis.rs)
Runs a series of specialized analysis functions:
1. **Control flow analysis** - reentrancy, flash loan vectors, sandwich attacks
2. **Complexity analysis** - cyclomatic complexity per function (threshold: 10)
3. **Access control analysis** - unprotected critical functions
4. **Storage layout analysis** - missing `__gap` in upgradeable contracts
5. **Gas optimization** - storage reads in loops, batching opportunities
6. **DeFi vulnerabilities** - oracle manipulation, slippage, liquidity (if `--defi-analysis`)
7. **NFT vulnerabilities** - minting caps, unsafe transfers, metadata
8. **Known exploit patterns** - DAO hack, Parity wallet, integer overflow
9. **Rekt news patterns** - real-world exploits from $3.1B+ in losses
10. **OWASP 2025 patterns** - flash loan callbacks, meta-transactions
11. **Research paper patterns** - ERC-777 reentrancy, greedy contracts, double claiming
12. **L2 patterns** - sequencer downtime, PUSH0 compatibility, gas oracle
13. **Security hardening** - storage gaps, timelocks, unsafe downcasts

### Phase 4: Logic Analysis (logic_analyzer.rs)
Ten structural analysis passes:
1. State machine transition validation
2. Balance/supply invariant checks
3. Logic bypass detection (asymmetric access control)
4. Inconsistent state update detection
5. Missing condition checks (division by zero, bounds)
6. Authorization flow analysis
7. Race condition window detection
8. Asymmetric behavior in paired operations (deposit/withdraw)
9. Unreachable logic detection (code after top-level return)
10. Protocol-specific bugs (ERC4626, AMM, lending, staking)

### Phase 5: Dependency Analysis
- Scans `import` statements for known vulnerable packages
- Checks for outdated OpenZeppelin versions with known CVEs

### Phase 6: Threat Model Generation (threat_model.rs)
- Auto-classifies the contract type (ERC20, DEX, Lending, Proxy, etc.)
- Generates STRIDE-based threats with attack vectors and mitigations
- Identifies trust boundaries, data flows, and assets

### Phase 7: Reachability Filtering (reachability_analyzer.rs)
- Builds a function call graph from the source
- Identifies entry points (external/public functions, constructor, fallback, receive)
- Uses BFS from entry points to determine which internal functions are reachable
- **Filters out findings in unreachable code** (dead code)
- **Contract-level findings** (pragma, state variables) are always kept
- Adjusts confidence based on reachability depth

### Phase 8: EIP-Specific Analysis
- Detects which EIPs/ERCs the contract implements
- Applies 30+ EIP-specific vulnerability patterns
- Covers ERC-20, ERC-721, ERC-777, ERC-1155, ERC-4626, ERC-2612, ERC-2771, ERC-4337, ERC-1967, EIP-3156

### Phase 9: False Positive Filtering (false_positive_filter.rs)
- The final cleanup pass (see Section 4 for the full 3-layer breakdown)
- Removes safe patterns, deduplicates, adjusts confidence
- Typically removes 25-90% of raw findings depending on mode

### Final Output
- Sorts remaining findings by line number
- Formats as text (colored), JSON, or SARIF 2.1.0
- Returns exit code: 0 (clean), 1 (critical/high), 2 (medium), 3 (low/info), 10 (error)

---

## 3. Vulnerability Detection Engine

### How Rules Work

Each rule in `vulnerabilities.rs` is defined as a `VulnerabilityRule`:

```
VulnerabilityRule {
    category:       VulnerabilityCategory
    severity:       Critical | High | Medium | Low | Info
    pattern:        Compiled Regex
    title:          "Human-readable title"
    description:    "What the issue is"
    recommendation: "How to fix it"
    multiline:      true | false
}
```

- **Single-line rules** (`multiline: false`): The regex is tested against each line individually. This is fast and gives precise line numbers.
- **Multiline rules** (`multiline: true`): The regex is tested against the entire file content. Used for patterns that span multiple lines (e.g., state change after external call).

### Contextual Filtering in scanner.rs

Before a finding is emitted, `should_report_vulnerability()` in `scanner.rs` applies context-aware filtering per category. Examples:

| Category | Filter Logic |
|----------|-------------|
| Reentrancy | Skip if `nonReentrant` modifier present on the function |
| ArithmeticIssues | Skip if Solidity >= 0.8.0 (built-in overflow checks) |
| AccessControl | Skip if function has `onlyOwner`, `onlyRole`, or custom `only*` modifier |
| OracleManipulation | Skip if `getReserves` is used without price computation |
| UncheckedReturn | Skip if `SafeERC20` is imported |
| DelegateCalls | Skip if inside a known proxy pattern (ERC-1967/UUPS) |
| Reentrancy (.send/.transfer) | Always skip - 2300 gas limit makes reentrancy impractical |

This is the **first** filtering layer and runs before any other post-processing.

### Severity Levels

| Level | Meaning | Typical Examples |
|-------|---------|-----------------|
| **Critical** | Immediate fund loss, full contract compromise | Reentrancy with state after call, unprotected `selfdestruct`, proxy admin exposure |
| **High** | Significant risk, likely exploitable | Oracle manipulation, missing access control, signature replay |
| **Medium** | Conditional risk, requires specific circumstances | Precision loss, timestamp dependence, missing deadline |
| **Low** | Best practice violations, minor risk | Floating pragma, missing events, gas inefficiency |
| **Info** | Informational, no direct security impact | Code quality suggestions, documentation gaps |

---

## 4. False Positive Filtering (3-Layer System)

The scanner uses 3 independent filtering layers to achieve 90%+ false positive reduction. Understanding these layers is crucial for interpreting results.

### Layer 1: Context-Aware Pre-Filter (`scanner.rs::should_report_vulnerability`)

This runs **at detection time**, before the finding even enters the results list. It checks the surrounding code context for safe patterns:

- **ReentrancyGuard/nonReentrant** detected → reentrancy findings suppressed
- **SafeMath imported** → arithmetic overflow findings suppressed
- **Solidity 0.8+** → overflow/underflow findings suppressed
- **SafeERC20 imported** → unchecked return value findings suppressed
- **Ownable/AccessControl** → unprotected function findings suppressed
- **Ownable2Step** → transferOwnership risk suppressed
- **View/pure functions** → reentrancy suppressed (no state changes possible)
- **Interface files** → all findings suppressed (no implementation)
- **Comments/strings** → findings in comments suppressed

### Layer 2: Safe Pattern Matching (`false_positive_filter.rs::should_keep`)

This runs **after all analyzers** complete. It builds a `ContractContext` that understands the contract's imports, modifiers, version, and audit annotations:

**What it detects:**
- OpenZeppelin, Solmate, Solady library usage
- Custom modifier names (anything starting with `only*`)
- Inline access checks (`require(msg.sender == owner)`, `_checkOwner()`)
- Audit annotations (`@audit`, `@security`, `// SAFE`, `// slither-disable`)
- Solidity version for version-aware filtering
- Inheritance chain for library trust

**Confidence adjustments applied:**
| Condition | Adjustment |
|-----------|-----------|
| Test/mock contract detected | -30% |
| No safety libraries used | +10% |
| Audit annotations present | -15% |
| Reentrancy without ReentrancyGuard | +15% |
| Pre-0.8 without SafeMath | +20% |

**Deduplication:**
- Removes exact duplicates (same category + same line number)
- Keeps the finding with the highest confidence when duplicates exist

### Layer 3: Structural Analysis (Reachability + Logic Analyzers)

- **Reachability analyzer** removes findings in dead code paths
- **Logic analyzer** validates structural correctness

**Confidence adjustments from reachability:**
| Reachability | Adjustment |
|-------------|-----------|
| Contract-level (pragma, state vars) | 0 (always kept) |
| Direct entry point (external/public) | +20% |
| Reachable via >3 call paths | +15% |
| Reachable via 1-3 call paths | +10% |
| Unreachable (dead code) | -25% |

### How the Layers Interact

```
Raw findings from regex + analyzers (e.g., 200 findings)
        │
        ▼
Layer 1: should_report_vulnerability()
        │  Removes ~30-40% (safe library detection)
        ▼
Layer 2: FalsePositiveFilter::should_keep()
        │  Removes ~20-30% (pattern matching, dedup, confidence)
        ▼
Layer 3: Reachability filtering
        │  Removes ~10-20% (dead code)
        ▼
Final output (e.g., 40-60 findings)
```

---

## 5. Confidence Scoring System

Every finding has a confidence score from 0-100%:

### Confidence Categories
| Range | Label | Visual Indicator | Meaning |
|-------|-------|-----------------|---------|
| 80-100% | High | `●` (filled circle) | Very likely a real vulnerability |
| 50-79% | Medium | `◐` (half circle) | Likely real, manual review recommended |
| 0-49% | Low | `○` (empty circle) | Possible issue, may be false positive |

### What Affects Confidence

**Base confidence** is set by the rule definition (each rule has a default confidence).

**Upward adjustments (+):**
- No safety library for this category: +10%
- Reentrancy pattern without guard: +15%
- Arithmetic issue in pre-0.8 without SafeMath: +20%
- Multiple entry points reach the vulnerable code: +15-20%

**Downward adjustments (-):**
- Test/mock contract: -30%
- Audit annotations present: -15%
- Unreachable code: -25%
- Safe library covers this category: varies

### Using Confidence Threshold

```bash
# Only show high-confidence findings (recommended for first pass)
41swara contracts/ --confidence-threshold 80

# Show medium+ confidence (good balance)
41swara contracts/ --confidence-threshold 50

# Show everything (includes speculative findings)
41swara contracts/ --confidence-threshold 0
```

**Recommendation:** Start with `--confidence-threshold 70` for a clean first pass, then lower to `50` for deeper review.

---

## 6. Interpreting Scan Results

### Reading the Text Output

```
Access Control [SWC-105]

  !! ● Unprotected Critical Function: withdrawAll [Line 21]
     Description: Critical function lacks access control modifiers
     SWC: SWC-105 | CWE: CWE-284
     Vulnerable Code:
         21 | function withdrawAll() external {
     Recommendation: Add appropriate access control modifiers
     Severity: CRITICAL | Confidence: 90%
```

Breaking this down:
- **`Access Control [SWC-105]`** — the vulnerability category and SWC ID
- **`!!`** — severity indicator (`!!` = Critical, `!` = High, `*` = Medium, `-` = Low)
- **`●`** — confidence indicator (filled = High, half = Medium, empty = Low)
- **`[Line 21]`** — exact source line
- **`SWC: SWC-105 | CWE: CWE-284`** — standard identifiers for compliance
- **`Confidence: 90%`** — numeric confidence after all adjustments

### Understanding the Summary

```
VULNERABILITY SCAN SUMMARY
Files scanned: 15
Total issues found: 42

SEVERITY BREAKDOWN
  !! CRITICAL: 5
  !  HIGH: 8
  *  MEDIUM: 18
  -  LOW: 11
```

### Prioritization Strategy

For an efficient manual review:

1. **Start with Critical + High confidence (●)** — these are almost certainly real bugs
2. **Review High severity + Medium confidence (◐)** — likely real, need context check
3. **Check Medium severity for DeFi-specific findings** — oracle, slippage, flash loan patterns
4. **Low severity + Low confidence** — review last, mostly informational

### When a Finding is a False Positive

If you encounter a finding you believe is a false positive, check:

1. **Is there a safe pattern the scanner missed?** The scanner recognizes OpenZeppelin, Solmate, and Solady. Custom safety patterns may not be detected.
2. **Is the code in a test/mock contract?** Rename to include "Test" or "Mock" in the filename for automatic confidence reduction.
3. **Add audit annotations** to intentionally accepted risks:
   ```solidity
   // @audit - Accepted risk: reentrancy is safe here because...
   // @security - Reviewed, no risk
   // SAFE: checked by external audit
   ```
4. **Use SWC exclusion** to suppress specific categories:
   ```bash
   41swara contracts/ --exclude-swc SWC-103  # Skip floating pragma warnings
   ```

---

## 7. Tuning the Scanner for Your Workflow

### Scenario: Bug Bounty Hunting (Speed + Precision)

```bash
# Fast scan, high confidence only, critical/high severity
41swara contracts/ \
  --min-severity high \
  --confidence-threshold 80 \
  --strict-filter \
  --stats
```

This gives you a short, high-signal list of findings to investigate first.

### Scenario: Full Security Audit

```bash
# Everything enabled, all severities, DeFi + advanced + EIP
41swara contracts/ \
  --defi-analysis \
  --advanced-detectors \
  --eip-analysis \
  --strict-filter \
  --min-severity low \
  -v \
  --stats \
  -o audit-report.txt
```

### Scenario: DeFi Protocol Audit

```bash
# DeFi-focused with threat model
41swara contracts/ \
  --defi-analysis \
  --advanced-detectors \
  --eip-analysis \
  --strict-filter \
  -v \
  --audit \
  --project "ProtocolName" \
  --sponsor "SponsorName"
```

### Scenario: CI/CD Gate (Block on Critical)

```bash
41swara contracts/ \
  --fail-on critical \
  --confidence-threshold 70 \
  --strict-filter \
  --format sarif \
  --cache \
  -o results.sarif
```

### Scenario: Incremental Review (PR Review)

```bash
# Only scan files changed in the current branch
41swara --git-diff --min-severity medium --strict-filter
```

### Scenario: Continuous Monitoring (Watch Mode)

```bash
# Re-scan automatically when files change
41swara contracts/ --watch --min-severity high --strict-filter
```

### Scenario: L2/Cross-Chain Audit

```bash
# Advanced detectors include L2 patterns
41swara contracts/ \
  --advanced-detectors \
  --defi-analysis \
  --eip-analysis \
  --strict-filter \
  -v
```

### Scenario: Comparing Against Previous Scan

> **Note:** `--baseline` and `--export-baseline` flags are defined in the CLI but **not yet wired into the comparison logic** (as of v0.6.0). For now, export JSON output and use `diff` or `jq` to compare runs manually.

```bash
# Export scan results as JSON
41swara contracts/ -f json -o scan-run-1.json

# Later, export again and diff
41swara contracts/ -f json -o scan-run-2.json
diff scan-run-1.json scan-run-2.json
```

### Disabling Specific Analysis Passes

If a particular analysis pass produces noise for your codebase:

```bash
--no-logic-analysis        # Disable business logic detection
--no-reachability-analysis # Skip reachability filtering (keep all findings)
--no-dependency-analysis   # Skip import/dependency checks
--no-threat-model          # Skip STRIDE threat model generation
--fast                     # Disable ALL advanced features (regex rules only)
```

---

## 8. Common Workflows

### Workflow 1: Triage a New Codebase

```bash
# Step 1: Quick overview (30 seconds)
41swara contracts/ --min-severity high --confidence-threshold 80 -q

# Step 2: If interesting, full scan
41swara contracts/ --defi-analysis --advanced-detectors --eip-analysis --strict-filter -v --stats

# Step 3: Export for tracking
41swara contracts/ -f json -o findings.json
```

### Workflow 2: Validate a Specific Vulnerability Class

> **Note:** `--include-swc` and `--exclude-swc` flags are defined in the CLI but **not yet wired into the filtering logic** (as of v0.6.0). Use `--min-severity` and `--confidence-threshold` for now. SWC filtering is planned for a future release.

```bash
# Focus on high-severity findings only
41swara contracts/ --min-severity high -v

# Focus on critical findings with high confidence
41swara contracts/ --min-severity critical --confidence-threshold 80 -v
```

### Workflow 3: Multi-Tool Analysis

```bash
# Step 1: 41Swara (fast, DeFi-focused)
41swara contracts/ --defi-analysis --advanced-detectors -v -o 41swara-results.txt

# Step 2: Slither (IR-based, different detection approach)
slither . --json slither.json

# Step 3: Correlate findings
41swara contracts/ --slither-json slither.json -v

# Step 4: Generate PoC tests for critical findings
41swara contracts/ --generate-poc

# Step 5: Run Foundry tests
forge test -vv
```

### Workflow 4: Project-Wide Cross-File Analysis

```bash
# Analyze interactions between contracts
41swara contracts/ --project-analysis -v
```

### Workflow 5: Generate Professional Audit Report

```bash
41swara contracts/ \
  --audit \
  --project "MyProtocol" \
  --sponsor "AuditFirm" \
  --defi-analysis \
  --advanced-detectors \
  --eip-analysis \
  --strict-filter \
  -v
```

---

## 9. Troubleshooting & Known Issues

### Problem: Too many false positives

**Symptoms:** Scan returns hundreds of findings, many are clearly safe patterns.

**Solutions:**
1. **Enable strict filtering:**
   ```bash
   41swara contracts/ --strict-filter
   ```
2. **Raise confidence threshold:**
   ```bash
   41swara contracts/ --confidence-threshold 70
   ```
3. **Raise minimum severity:**
   ```bash
   41swara contracts/ --min-severity medium
   ```
4. **Add audit annotations** to intentionally accepted patterns in your code:
   ```solidity
   // @audit - accepted risk
   ```

### Problem: Scanner misses a known vulnerability (false negative)

**Symptoms:** You know a vulnerability exists but the scanner doesn't flag it.

**Possible causes and solutions:**
1. **Filtering is too aggressive:** Try disabling filters:
   ```bash
   41swara contracts/ --no-reachability-analysis --confidence-threshold 0
   ```
2. **The vulnerability pattern isn't covered:** Check if the pattern is in `vulnerabilities.rs`. You can add custom rules (see Section 10).
3. **The code is in a function the reachability analyzer thinks is dead:** The call graph analysis may miss indirect calls (via function pointers, delegatecall, or interfaces). Disable reachability:
   ```bash
   41swara contracts/ --no-reachability-analysis
   ```
4. **DeFi/advanced detectors are not enabled:** Some patterns require explicit opt-in:
   ```bash
   41swara contracts/ --defi-analysis --advanced-detectors
   ```
5. **The vulnerability spans multiple files:** Use project analysis:
   ```bash
   41swara contracts/ --project-analysis
   ```

### Problem: Scanner is slow on large codebases

**Solutions:**
1. **Enable caching** (skips unchanged files):
   ```bash
   41swara contracts/ --cache
   ```
2. **Increase threads:**
   ```bash
   41swara contracts/ -j 0  # auto-detect CPU count
   ```
3. **Use fast mode** (regex rules only, no advanced analysis):
   ```bash
   41swara contracts/ --fast
   ```
4. **Exclude test/mock files:**
   ```bash
   41swara contracts/ --exclude-pattern "**/test/**" --exclude-pattern "**/*Mock*"
   ```
5. **Reduce max file size** (skip very large generated files):
   ```bash
   41swara contracts/ --max-file-size 2
   ```
6. **Use git-diff mode** (only scan changed files):
   ```bash
   41swara --git-diff
   ```

### Problem: Scanner crashes or panics

**Possible causes:**
1. **Malformed Solidity file:** The regex engine may encounter pathological patterns on malformed input. Try scanning with `--fast` to isolate the issue.
2. **Very large file (>10 MB):** The scanner enforces a 10 MB limit. Files above this are automatically skipped.
3. **Out of memory on massive codebases:** Use `--cache` and `--exclude-pattern` to reduce memory usage.

**Collecting debug info:**
```bash
# Run with verbose and stats for timing info
41swara contracts/ -v --stats 2>&1 | tee debug-output.txt
```

### Problem: SARIF output isn't accepted by GitHub

**Solution:** Ensure you're using the `--format sarif` flag, which produces SARIF 2.1.0 with proper CWE/SWC IDs:
```bash
41swara contracts/ --format sarif -o results.sarif
```

The SARIF output includes:
- `ruleId` mapped to SWC/41S IDs
- `taxa` references to CWE IDs
- `level` mapped from severity (error/warning/note)
- `region` with line numbers

### Problem: Confidence scores seem wrong

**Understanding:** Confidence is adjusted by multiple layers. A finding may start at 90% but get reduced to 60% because:
- The contract is a test contract (-30%)
- Audit annotations are present (-15%)
- The code has limited reachability paths

To see the raw confidence before adjustments, disable all post-processing:
```bash
41swara contracts/ --no-reachability-analysis --fast --confidence-threshold 0
```

### Problem: Regex patterns behave unexpectedly

**Important Rust `regex` crate limitation:** The Rust regex crate does **NOT** support lookahead (`(?=...)`) or lookbehind (`(?<=...)`). All negative patterns must be handled through context filtering in `should_report_vulnerability()` instead.

If you're adding custom rules, test your regex at [regex101.com](https://regex101.com) with the "Rust" flavor selected.

### Problem: Reachability analyzer marks reachable code as unreachable

**Known limitation:** The call graph is built from regex-based function parsing, not a full AST. It can miss:
- Indirect calls via function pointers or interfaces
- Calls through `delegatecall` or `staticcall`
- Calls from inherited contracts (partial inheritance support)
- Callbacks from external contracts (e.g., Uniswap callbacks)

**Workaround:**
```bash
41swara contracts/ --no-reachability-analysis
```

### Problem: OpenZeppelin patterns not recognized

**Ensure imports are standard.** The scanner detects these patterns:
- `import "@openzeppelin/..."`
- `import "openzeppelin-contracts/..."`
- `using SafeMath for uint256`
- `using SafeERC20 for IERC20`
- `Ownable`, `AccessControl` in inheritance

If you use non-standard import paths (e.g., remapped imports), the safe pattern detection may not work. In this case, add audit annotations to suppress false positives.

### Problem: Duplicate findings

The false positive filter includes deduplication (same category + same line = remove duplicate). If you still see near-duplicates:
- They may be on **different lines** within the same function
- They may be from **different categories** that overlap (e.g., reentrancy + callback reentrancy)
- Enable strict filter for better dedup: `--strict-filter`

---

## 10. Adding Custom Rules

### Adding a New Regex Rule

In `src/vulnerabilities.rs`, add to the rule list:

```rust
rules.push(VulnerabilityRule::new(
    VulnerabilityCategory::YourCategory,     // Use existing or add new
    VulnerabilitySeverity::High,
    r"your_regex_pattern_here",              // Rust regex syntax
    "Short Title".to_string(),
    "Detailed description of what this detects".to_string(),
    "How to fix the issue".to_string(),
    false,  // true for multiline matching
).unwrap());
```

### Adding a New Vulnerability Category

In `src/vulnerabilities.rs`, extend the `VulnerabilityCategory` enum:

```rust
pub enum VulnerabilityCategory {
    // ... existing categories ...
    YourNewCategory,
}
```

Then add the SWC/CWE mapping in the `swc_id()` and display methods.

### Adding an Advanced Detector

In `src/advanced_analysis.rs`, add a new method:

```rust
fn detect_your_pattern(&self, content: &str) -> Vec<Vulnerability> {
    let mut vulnerabilities = Vec::new();
    // Your detection logic using regex or string analysis
    // Push Vulnerability structs to the vector
    vulnerabilities
}
```

Then wire it into the main `analyze()` method so it gets called during scanning.

### Adding Context Filtering

In `src/scanner.rs`, extend `should_report_vulnerability()`:

```rust
VulnerabilityCategory::YourCategory => {
    // Check for safe pattern
    if content.contains("your_safe_pattern") {
        return false;  // Don't report this finding
    }
    true  // Report it
}
```

### Testing Your Rule

```bash
# Create a test contract
echo 'pragma solidity ^0.8.0;
contract Test {
    // Add code that should trigger your rule
}' > test_contracts/YourTest.sol

# Build and test
cargo build && cargo run --bin 41swara -- test_contracts/YourTest.sol -v

# Run the test suite
cargo test
```

### Regex Tips for Solidity Patterns

| Goal | Pattern | Notes |
|------|---------|-------|
| Match function declaration | `function\s+(\w+)\s*\(` | Captures function name |
| Match state variable | `^\s+(uint256\|address\|bool\|mapping)` | Start of line |
| Match external call | `\.call\{?\s*` | Handles `.call{value: ...}` |
| Match modifier usage | `\)\s+(\w+)\s*\{` | After params, before brace |
| Match import | `import\s+["']([^"']+)["']` | Captures path |
| Avoid matching comments | Handle in `should_report_vulnerability()` | Regex can't easily skip comments |

**Critical note:** The Rust `regex` crate does not support lookahead/lookbehind. Use context filtering for negative patterns instead of `(?!...)`.

---

## 11. Understanding the Threat Model Generator

### How Contract Type Detection Works

The scanner analyzes function signatures, imports, and patterns to classify the contract:

| Contract Type | Detection Signals |
|--------------|-------------------|
| ERC20Token | `transfer`, `approve`, `totalSupply`, `balanceOf` |
| ERC721NFT | `ownerOf`, `tokenURI`, `safeMint`, ERC721 import |
| ERC1155MultiToken | `balanceOfBatch`, `safeBatchTransferFrom` |
| ERC4626Vault | `deposit`, `withdraw`, `convertToShares`, `convertToAssets` |
| DEXRouter | `swapExact`, `addLiquidity`, `removeLiquidity` |
| AMMPool | `getReserves`, `swap`, `mint`, `burn` + pair pattern |
| LendingProtocol | `borrow`, `repay`, `liquidate`, `collateral` |
| Governance | `propose`, `castVote`, `execute`, `queue` |
| Bridge | `sendMessage`, `relayMessage`, cross-domain patterns |
| Proxy | `delegatecall`, `implementation`, ERC-1967 slots |
| Staking | `stake`, `unstake`, `claimRewards`, `rewardRate` |
| Oracle | `latestRoundData`, `getPrice`, `updatePrice` |
| Multisig | `submitTransaction`, `confirmTransaction`, `executeTransaction` |

### STRIDE Threat Categories

Each classified contract type receives relevant threats based on STRIDE:

| STRIDE | Mapped Category | Example |
|--------|----------------|---------|
| **S**poofing | PrivilegeEscalation | Admin function called by non-admin |
| **T**ampering | Manipulation | Oracle price manipulation |
| **R**epudiation | Replay | Signature replay across chains |
| **I**nformation Disclosure | DataBreach | Private data in storage slots |
| **D**enial of Service | Denial | Unbounded loop gas griefing |
| **E**levation of Privilege | AssetTheft | Proxy upgrade to malicious implementation |

### Using Threat Model Output

The threat model is included in verbose text output and in JSON/audit report output. Each threat includes:
- **Attack vectors** - specific ways the threat can be exploited
- **Affected functions** - which functions are at risk
- **Mitigations** - recommended countermeasures
- **Impact** and **Likelihood** ratings

---

## 12. Integration with Other Tools

### Slither Integration

```bash
# Run Slither first (generates JSON report)
slither . --json slither.json

# Feed Slither results to 41Swara
41swara contracts/ --slither-json slither.json
```

**What happens:**
- 41Swara reads Slither findings
- Correlates them with its own findings
- Boosts confidence when both tools agree on a vulnerability
- Merges unique findings from both tools

### Foundry Integration

```bash
# Generate PoC test templates for critical findings
41swara contracts/ --generate-poc

# After writing PoC tests, correlate results
41swara contracts/ --foundry-correlate
```

**PoC generation** creates Foundry test stubs for critical/high findings, giving you a starting point for exploit validation.

### GitHub Code Scanning (SARIF)

```bash
41swara contracts/ --format sarif -o results.sarif
```

Upload `results.sarif` using the `github/codeql-action/upload-sarif@v2` action. Findings will appear as code scanning alerts with:
- CWE references (MITRE CWE taxonomy)
- SWC references (Smart Contract Weakness Classification)
- Severity levels mapped to GitHub alert levels
- Exact line numbers and code snippets

### JSON Output for Custom Processing

```bash
41swara contracts/ -f json -o results.json
```

The JSON output includes:
```json
{
  "version": "0.6.0",
  "files": [...],
  "vulnerabilities": [
    {
      "severity": "Critical",
      "category": "Reentrancy",
      "title": "...",
      "line_number": 42,
      "confidence_percent": 90,
      "swc_id": "SWC-107",
      "cwe_id": "CWE-841",
      "recommendation": "...",
      "code_snippet": "..."
    }
  ],
  "summary": {
    "total": 42,
    "critical": 5,
    "high": 8,
    "medium": 18,
    "low": 11
  },
  "threat_model": {...}
}
```

You can pipe this into `jq` for custom filtering:
```bash
# Only critical findings with >80% confidence
41swara contracts/ -f json | jq '.vulnerabilities[] | select(.severity == "Critical" and .confidence_percent > 80)'

# Group by category
41swara contracts/ -f json | jq '.vulnerabilities | group_by(.category) | map({category: .[0].category, count: length})'
```

---

## 13. Vulnerability ID Reference

### SWC Registry IDs (Implemented)

| ID | Name | Severity |
|----|------|----------|
| SWC-101 | Integer Overflow/Underflow | High |
| SWC-102 | Outdated Compiler Version | Medium |
| SWC-103 | Floating Pragma | Low |
| SWC-104 | Unchecked Call Return Value | Medium |
| SWC-105 | Unprotected Ether Withdrawal | Critical |
| SWC-106 | Unprotected SELFDESTRUCT | Critical |
| SWC-107 | Reentrancy | Critical |
| SWC-109 | Uninitialized Variables | Medium |
| SWC-111 | Use of Deprecated Functions | Low |
| SWC-112 | Delegatecall to Untrusted Callee | High |
| SWC-114 | Transaction Order Dependence | High |
| SWC-115 | Authorization Through tx.origin | High |
| SWC-116 | Block Timestamp Dependence | Medium |
| SWC-117 | Signature Malleability | High |
| SWC-119 | Shadowing State Variables | Medium |
| SWC-120 | Weak Sources of Randomness | High |
| SWC-121 | Missing Protection Against Signature Replay | High |
| SWC-128 | DoS with Block Gas Limit | High |
| SWC-132 | Unexpected Ether Balance / Strict Equality | Medium |
| SWC-136 | Unencrypted Private Data | Medium |

### 41Swara Custom IDs (DeFi/Modern)

| ID | Name | Severity |
|----|------|----------|
| 41S-001 | Oracle Manipulation | High |
| 41S-003 | Proxy Admin Vulnerability | Critical |
| 41S-004 | Callback Reentrancy | Critical |
| 41S-005 | Arbitrary External Call | Critical |
| 41S-006 | Cross-Chain Replay | High |
| 41S-007 | Input Validation Failure | Medium |
| 41S-008 | Decimal Precision Mismatch | Medium |
| 41S-009 | Unprotected Proxy Upgrade | Critical |
| 41S-010 | MEV Exploitable | High |
| 41S-011 | Callback Injection | High |
| 41S-012 | Governance Attack | High |
| 41S-013 | Liquidity Manipulation | High |
| 41S-014 | Bridge Vulnerability | Critical |
| 41S-015 | Logic Error | Varies |
| 41S-016 | Meta-Transaction Vulnerability | High |
| 41S-017 | Unchecked Math Operation | Medium |
| 41S-018 | Trusted Forwarder Bypass | Critical |
| 41S-020 | ERC4626 Inflation Attack | Critical |
| 41S-021 | Permit2 Signature Reuse | Critical |
| 41S-022 | LayerZero Trusted Remote | Critical |
| 41S-023 | Create2 Collision | Medium |
| 41S-024 | Transient Storage Reentrancy | High |
| 41S-025 | PUSH0 Compatibility | Medium |
| 41S-026 | Blob Data Handling | Medium |
| 41S-027 | Uniswap V4 Hook Exploit | Critical |
| 41S-028 | Cross-Chain Message Replay | High |
| 41S-029 | L2 Sequencer Downtime | Critical |
| 41S-030 | L2 Gas Oracle | Medium |
| 41S-031 | Base Bridge Security | Critical |
| 41S-040 | Strict Balance Equality | Medium |
| 41S-041 | Misleading Data Location | Medium |
| 41S-042 | Missing Return Value | Medium |
| 41S-043 | Greedy Contract | Medium |
| 41S-044 | Missing Emergency Stop | Medium |
| 41S-045 | ERC777 Callback Reentrancy | Critical |
| 41S-046 | Deposit-For Reentrancy | Critical |
| 41S-047 | Double Claiming | Critical |
| 41S-048 | Signature Verification Bypass | Critical |
| 41S-050 | Missing Storage Gap | High |
| 41S-051 | Missing Timelock | Medium |
| 41S-052 | Selfdestruct Deprecation | High |
| 41S-053 | Uninitialized Implementation | Critical |
| 41S-054 | Unsafe Downcast | Medium |
| 41S-055 | Missing ERC165 | Low |
| 41S-056 | Missing Swap Deadline | Medium |
| 41S-057 | Hardcoded Gas Amount | Medium |
| 41S-058 | Unsafe Transfer Gas | Low |
| 41S-059 | Double Initialization | Critical |

---

## 14. FAQ

### Q: Is this tool a replacement for manual auditing?

**No.** 41Swara is a force multiplier for manual review. It automates detection of known patterns so you can focus on business logic, economic design, and novel attack vectors. Always perform manual review on top of automated scanning.

### Q: Why do I see different results with --strict-filter vs without?

`--strict-filter` enables the enhanced false positive filter which recognizes safe library patterns (OpenZeppelin, Solmate, Solady), audit annotations, and applies stronger confidence adjustments. Without it, only basic contextual filtering (Layer 1) is applied.

### Q: Can I run this on Vyper contracts?

No. 41Swara is specifically designed for Solidity (`.sol` files). Vyper has a fundamentally different syntax and security model.

### Q: How does this compare to Slither?

41Swara and Slither take different approaches:
- **41Swara**: Regex + context analysis, DeFi-specific detectors, L2 patterns, 90% FP reduction, parallel scanning, SARIF output. Faster for large codebases.
- **Slither**: IR-based analysis (SlithIR), deeper data flow analysis, more mature inheritance resolution. Better for inter-contract analysis.

They complement each other well. Use `--slither-json` to correlate findings.

### Q: Why does confidence drop for test contracts?

Test contracts contain intentionally vulnerable code for testing purposes. The scanner detects filenames containing "Test", "Mock", "test_", etc. and reduces confidence by 30% to avoid noise. If your production code is in a file named "TestToken.sol", rename it.

### Q: Can I use this in an air-gapped environment?

Yes. 41Swara is 100% offline. Zero network calls. All analysis runs locally. The only external integration (Slither correlation) reads from a local JSON file.

### Q: What Solidity versions are supported?

All Solidity versions from 0.4.x to 0.8.x+. The scanner is version-aware:
- Pre-0.8.0: Applies arithmetic overflow/underflow checks
- 0.8.0+: Suppresses overflow checks (built-in protection)
- 0.8.20+: Checks PUSH0 opcode compatibility

### Q: How do I suppress a specific finding?

Two options:
1. **Add inline annotation**: `// @audit - accepted risk: <reason>`
2. **Filter by severity/confidence**: `--min-severity high --confidence-threshold 70`

> **Planned:** `--exclude-swc` and `--baseline` flags exist in the CLI but are not yet wired to filtering logic. They will be functional in a future release.

### Q: The scanner flagged my OpenZeppelin code. Why?

This can happen if:
- You're using a vendored/modified copy of OpenZeppelin (import path doesn't match expected pattern)
- The finding is about how you **use** OpenZeppelin, not about OZ code itself
- It's a version-specific issue (e.g., using an OZ version with a known vulnerability)

Check if the finding is about your code that interacts with OZ, not the OZ library itself.

### Q: How do I contribute a new detection rule?

See [Section 10: Adding Custom Rules](#10-adding-custom-rules). In summary:
1. Add regex rule to `src/vulnerabilities.rs`
2. Add context filtering to `src/scanner.rs` if needed
3. Create a test contract in `test_contracts/`
4. Run `cargo test` and `cargo build`
5. Submit a PR

---

## Appendix: Exit Codes

| Code | Meaning | CI/CD Action |
|------|---------|-------------|
| `0` | No findings at or above minimum severity | Pass |
| `1` | Critical or High findings detected | Fail |
| `2` | Medium findings only (no Critical/High) | Warning |
| `3` | Low or Info findings only | Pass (usually) |
| `10` | Scanner error (file not found, parse error) | Error |

Use `--fail-on <severity>` to customize which severity triggers exit code 1.

---

*This guide is maintained alongside the 41Swara codebase. For feature requests, bug reports, or new detection patterns, please open an issue on the project repository.*
