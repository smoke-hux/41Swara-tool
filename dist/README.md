# 41Swara Smart Contract Scanner

**Professional Smart Contract Vulnerability Scanner**

[![Version](https://img.shields.io/badge/version-v1.0.0-blue.svg)](https://github.com/41swara/41Swara-tool)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Linux%20|%20macOS%20|%20Windows-lightgrey.svg)](#installation)

A comprehensive Rust-based smart contract vulnerability scanner that detects 200+ security issues and generates professional audit reports.

## 🚀 Features

- **200+ Vulnerability Patterns** - Comprehensive detection of security issues
- **Professional Audit Reports** - Industry-standard security audit documentation
- **Multi-Platform Support** - Linux, macOS, and Windows executables
- **Real-Time Analysis** - Fast, accurate vulnerability detection
- **Role-Based Access Control** - Advanced permission system analysis
- **ZorpAudit Integration** - Includes patterns from real audit findings

## 🛡️ Vulnerability Detection

### Critical & High Severity
- ✅ **Reentrancy Attacks** - State manipulation vulnerabilities
- ✅ **Access Control Issues** - Missing permissions and authorization flaws
- ✅ **Delegate Call Vulnerabilities** - 7 different delegate call attack patterns
- ✅ **Storage DoS Attacks** - Unbounded operations and spam vulnerabilities
- ✅ **Precision Loss** - Integer division and financial calculation issues
- ✅ **Role-Based Access Control** - 15+ RBAC-specific vulnerability patterns

### Medium & Low Severity  
- ✅ **Gas Optimization** - Efficiency improvements
- ✅ **Pragma Issues** - Compiler version problems
- ✅ **Time Manipulation** - Timestamp dependency issues
- ✅ **Naming Conventions** - Code quality and typo detection
- ✅ **Magic Numbers** - Hard-coded value issues

## 📦 Installation

### Quick Install (Recommended)

**Linux:**
```bash
# Download and install
wget https://github.com/41swara/releases/41swara-scanner-linux
chmod +x 41swara-scanner-linux
sudo mv 41swara-scanner-linux /usr/local/bin/41swara-scanner
```

**macOS:**
```bash
# Download and install
curl -L https://github.com/41swara/releases/41swara-scanner-macos -o 41swara-scanner
chmod +x 41swara-scanner
sudo mv 41swara-scanner /usr/local/bin/
```

**Windows:**
```cmd
# Download 41swara-scanner-windows.exe
# Add to PATH or run directly
41swara-scanner-windows.exe --help
```

### Manual Installation

1. **Download the appropriate binary for your platform:**
   - Linux: `41swara-scanner-linux`
   - macOS: `41swara-scanner-macos` 
   - Windows: `41swara-scanner-windows.exe`

2. **Make executable (Linux/macOS):**
   ```bash
   chmod +x 41swara-scanner-*
   ```

3. **Add to PATH (optional):**
   ```bash
   # Linux/macOS
   sudo mv 41swara-scanner-* /usr/local/bin/41swara-scanner
   
   # Windows: Add directory to system PATH
   ```

## 🔧 Usage

### Basic Scanning
```bash
# Scan a single contract
41swara-scanner --path MyContract.sol

# Scan with verbose output
41swara-scanner --path MyContract.sol --verbose

# Scan entire directory
41swara-scanner --path contracts/ --verbose
```

### Professional Audit Reports
```bash
# Generate professional audit report
41swara-scanner --audit --project "MyProject" --sponsor "ClientName" --path Contract.sol

# Save audit report to file
41swara-scanner --audit --project "DeFi Protocol" --sponsor "Security Firm" --path Contract.sol > audit_report.md
```

### Output Formats
```bash
# JSON output for CI/CD integration
41swara-scanner --path Contract.sol --format json

# Clean report format
41swara-scanner --path Contract.sol --report
```

## 📋 Command Line Options

| Option | Description | Example |
|--------|-------------|---------|
| `--path` | File or directory to scan | `--path MyContract.sol` |
| `--verbose` | Detailed analysis output | `--verbose` |
| `--format` | Output format (text/json) | `--format json` |
| `--audit` | Generate professional audit report | `--audit` |
| `--project` | Project name for audit | `--project "TokenContract"` |
| `--sponsor` | Sponsor name for audit | `--sponsor "ClientCorp"` |
| `--report` | Clean PDF-style report | `--report` |
| `--examples` | Show usage examples | `--examples` |

## 🎯 Example Output

### Standard Scan
```
🔍 Smart Contract Vulnerability Scanner v1.0.0
=======================================================

📁 Scanning file: MyContract.sol
🔍 Analyzing MyContract.sol (156 lines)
✅ Found 12 potential issues in MyContract.sol

🚨 CRITICAL: Missing Access Control on State-Changing Function [Line 45]
   Description: Critical state-changing function without access control modifier
   Recommendation: Add access control modifiers (onlyOwner, onlyRole, etc.)

📊 VULNERABILITY SCAN SUMMARY
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📁 Files scanned: 1
🔍 Total issues found: 12

🎯 SEVERITY BREAKDOWN
  🚨 CRITICAL: 2
  ⚠️  HIGH: 4  
  ⚡ MEDIUM: 5
  💡 LOW: 1
```

### Professional Audit Report
```markdown
# MyProject - Security Audit Report

**Professional Smart Contract Security Analysis**

## Results Summary
• **Critical:** 2
• **High:** 4
• **Medium:** 5  
• **Low:** 1

# Critical Risk Findings

## C-01. Missing Access Control in MyContract::setPassword

### Summary
The MyContract contract assumes that only the owner can set the password.
The setPassword() function modifies the s_password storage variable without
access control, meaning anyone can reset the owner's password.

### Vulnerability Details
This vulnerability exists in MyContract.sol::setPassword starting on line 26.

### Proof of Concept
[Detailed attack scenario with code examples]

### Recommended Mitigation
[Complete code fixes with multiple implementation options]
```

## 🏗️ Building from Source

If you want to build from source code:

### Prerequisites
- Rust 1.70+ (`curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`)
- Git

### Build Steps
```bash
# Clone repository
git clone https://github.com/41swara/41Swara-tool
cd smart-contract-scanner

# Build release version
cargo build --release

# The executable will be in target/release/solidity_scanner
```

### Cross-Compilation
```bash
# Add targets
rustup target add x86_64-pc-windows-gnu
rustup target add x86_64-apple-darwin
rustup target add aarch64-apple-darwin

# Build for specific targets
cargo build --release --target x86_64-pc-windows-gnu    # Windows
cargo build --release --target x86_64-apple-darwin      # macOS Intel
cargo build --release --target aarch64-apple-darwin     # macOS Apple Silicon
```

## 🧪 Testing the Scanner

Create a test contract to verify installation:

```solidity
// TestContract.sol
pragma solidity ^0.8.19;

contract TestContract {
    address private owner;
    string private password;
    
    function setPassword(string memory newPassword) external {
        password = newPassword; // Missing access control!
    }
    
    function getPassword() external view returns (string memory) {
        return password; // Anyone can read!
    }
}
```

Run the scanner:
```bash
41swara-scanner --path TestContract.sol --verbose
```

Expected output: The scanner should detect critical access control vulnerabilities.

## 🔍 Vulnerability Categories Detected

| Category | Count | Severity | Examples |
|----------|-------|----------|----------|
| Access Control | 25+ | Critical/High | Missing onlyOwner, role violations |
| Reentrancy | 10+ | Critical | State manipulation attacks |
| Delegate Calls | 7+ | Critical | Arbitrary code execution |
| Role-Based Access Control | 15+ | Critical/High | RBAC violations |
| Storage DoS | 5+ | High | Unbounded operations |
| Precision Loss | 8+ | High/Medium | Integer division issues |
| Arithmetic Issues | 15+ | High/Medium | Overflow, underflow |
| Gas Optimization | 10+ | Low/Medium | Efficiency improvements |
| Code Quality | 20+ | Info/Low | Best practices |

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Add vulnerability patterns or improve detection
4. Test thoroughly
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **ZorpAudit Integration** - Real vulnerability patterns from professional audits
- **OpenZeppelin** - Access control pattern references
- **Rust Security** - Memory-safe implementation
- **Community** - Feedback and vulnerability pattern contributions

## 📞 Support

- **Issues:** [GitHub Issues](https://github.com/41swara/41Swara-tool/issues)
- **Documentation:** [Wiki](https://github.com/41swara/41Swara-tool/wiki)
- **Security:** Report vulnerabilities privately to security@41swara.com

---

**⚡ Start scanning your smart contracts for vulnerabilities today!**

```bash
41swara-scanner --path YourContract.sol --audit --project "YourProject" --sponsor "YourOrg"
```