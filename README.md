# Smart Contract Vulnerability Scanner

A comprehensive Rust-based static analysis tool that scans Solidity smart contracts for security vulnerabilities and code quality issues across all major operating systems.

## Features

- **Line-by-line Analysis**: Identifies vulnerabilities with exact line numbers and context
- **Comprehensive Vulnerability Detection**: Detects 15+ vulnerability types including:
  - Reentrancy attacks
  - Access control issues  
  - Weak randomness sources
  - DoS vulnerabilities
  - Arithmetic overflow/underflow
  - Gas optimization opportunities
  - Magic numbers and constants
  - Code quality issues
- **Severity Classification**: Issues categorized as Critical, High, Medium, Low, or Info
- **Multiple Output Formats**: Text and JSON output with detailed reporting
- **Batch Processing**: Scan individual files or entire directories recursively
- **Cross-Platform**: Works on Linux, macOS, and Windows

## Prerequisites

- **Rust**: Install from [rustup.rs](https://rustup.rs/)
- **Git**: For cloning the repository

## Installation

### Option 1: Build from Source (Recommended)

```bash
# Clone the repository
git clone <repository-url>
cd smart-contract-scanner

# Build the project
cargo build --release
```

### Option 2: Quick Setup Script

**Linux/macOS:**
```bash
chmod +x 41swara-scan.sh
./41swara-scan.sh
```

**Windows (PowerShell):**
```powershell
# Build the project
cargo build --release
```

## Usage

### Basic Commands

**Linux/macOS:**
```bash
# Scan a single file
./target/release/solidity_scanner --path contract.sol

# Scan a directory
./target/release/solidity_scanner --path ./contracts/ --verbose

# JSON output
./target/release/solidity_scanner --path contract.sol --format json
```

**Windows:**
```cmd
REM Scan a single file
.\target\release\solidity_scanner.exe --path contract.sol

REM Scan a directory
.\target\release\solidity_scanner.exe --path .\contracts\ --verbose

REM JSON output
.\target\release\solidity_scanner.exe --path contract.sol --format json
```

### Command Line Options

- `--path, -p`: Path to smart contract file or directory (required)
- `--format, -f`: Output format - 'text' or 'json' (default: text)
- `--verbose, -v`: Enable verbose output with additional details and context

## Detected Vulnerabilities

### Critical Severity
- **Reentrancy Attacks**: Detects external calls that could lead to reentrancy
- **Access Control Issues**: Identifies public functions without proper access control

### High Severity  
- **Weak Randomness**: Identifies use of predictable blockchain data for randomness
- **DoS via Gas Limit**: Detects patterns that could cause denial of service
- **Integer Overflow/Underflow**: Finds arithmetic operations without proper checks

### Medium Severity
- **Floating Pragma**: Identifies contracts using floating pragma versions
- **Time Dependencies**: Detects reliance on manipulable timestamp values
- **Uninitialized Variables**: Finds potentially uninitialized state variables

### Low Severity
- **Magic Numbers**: Hard-coded values that should be constants
- **Gas Optimization**: Suggestions for gas-efficient code patterns

### Info Level
- **Unused Code**: Identifies potentially unused functions
- **Naming Issues**: Detects potential typos in code

### Advanced Usage

**Scanning with custom output directory:**
```bash
# Linux/macOS
./target/release/solidity_scanner --path ./contracts/ --format json > scan_results.json

# Windows
.\target\release\solidity_scanner.exe --path .\contracts\ --format json > scan_results.json
```

**Integration with CI/CD pipelines:**
```bash
# Exit with error code if critical vulnerabilities found
./target/release/solidity_scanner --path ./contracts/ || exit 1
```

## Example Output

```
🔍 Smart Contract Vulnerability Scanner
========================================

📁 Scanning file: contracts/MyContract.sol
🔍 Analyzing MyContract.sol (150 lines)
✅ Found 5 potential issues in MyContract.sol

🔍 SCAN RESULTS FOR contracts/MyContract.sol (Line-by-line Analysis)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

📋 Reentrancy

  🚨 Potential Reentrancy Attack [Line 45]
     Description: External call with value transfer found without reentrancy protection
     Code: (bool success,) = recipient.call{value: amount}("");
     Recommendation: Use ReentrancyGuard or follow checks-effects-interactions pattern
     Severity: CRITICAL

📊 VULNERABILITY SCAN SUMMARY
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📁 Files scanned: 1
🔍 Total issues found: 5

🎯 SEVERITY BREAKDOWN
  🚨 CRITICAL: 1
  ⚠️  HIGH: 2  
  ⚡ MEDIUM: 2
```

## Troubleshooting

### Common Issues

**Build Errors:**
```bash
# Update Rust toolchain
rustup update

# Clean and rebuild
cargo clean
cargo build --release
```

**Permission Issues (Linux/macOS):**
```bash
chmod +x target/release/solidity_scanner
```

**Path Issues (Windows):**
- Use forward slashes `/` or double backslashes `\\` in paths
- Ensure the `.exe` extension is included when running the binary

## Integration Examples

### VS Code Task
```json
{
    "label": "Scan Smart Contracts",
    "type": "shell",
    "command": "./target/release/solidity_scanner",
    "args": ["--path", "${workspaceFolder}/contracts", "--verbose"],
    "group": "build"
}
```

### GitHub Actions
```yaml
- name: Scan Smart Contracts
  run: |
    cargo build --release
    ./target/release/solidity_scanner --path ./contracts/ --format json > results.json
```

## Performance Notes

- **Single File**: ~10-50ms per contract
- **Directory Scanning**: Parallel processing for multiple files
- **Memory Usage**: ~5-20MB depending on contract size
- **Supported File Extensions**: `.sol` files

## Limitations

- Static analysis tool - may produce false positives
- Context-dependent patterns may require manual review  
- Should complement, not replace, professional security audits
- Detection rules are continuously updated

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add new vulnerability detection rules or improve existing ones
4. Submit a pull request with tests

## License

This project is open source. Please check the license file for details.