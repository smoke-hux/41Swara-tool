# REKT.NEWS REAL-WORLD EXPLOIT PATTERNS

## Security Researcher: Ethereum Foundation Level Analysis

This document details the comprehensive integration of real-world DeFi exploit patterns from rekt.news into our smart contract scanner. Based on **$3.1 billion+ in actual losses** from 2024-2025, this represents the most critical vulnerability patterns in production DeFi systems.

---

## 📊 Industry Context (2024-2025)

### Total Losses
- **2025 H1**: $3.1B in losses (exceeding all of 2024's $2.85B)
- **2024 Total**: $1.4B - $2.9B in DeFi exploits
- **Q3 2025**: $434M across 40+ exploits
- **MEV Profits**: $675M extracted via front-running (19% YoY increase)

### Top Vulnerability Categories
1. **Input Validation Failures**: 34.6% of all exploits
2. **Access Control Issues**: #1 on OWASP SC Top 10 (2025)
3. **Flash Loan Attacks**: 83.3% of eligible exploits
4. **Callback Reentrancy**: $1.43M+ (Omni NFT)
5. **Oracle Manipulation**: $52M across 37 incidents

---

## 🔴 CRITICAL PATTERNS IMPLEMENTED

### 1. Aevo/Ribbon Finance Pattern ($2.7M - December 2025)

**Root Cause**: Unprotected proxy admin functions + Oracle manipulation

#### Vulnerabilities Detected:
- ✅ Unprotected `transferOwnership()` in proxy contracts
- ✅ Exposed `setImplementation()` functions
- ✅ Oracle configuration without access control
- ✅ Decimal precision mismatch (18 vs 8 decimals)

#### Attack Vector:
```solidity
// VULNERABLE - Aevo exact pattern
function transferOwnership(address newOwner) external {
    // Missing: onlyOwner modifier
    implementation = newOwner;  // Anyone can call!
}

function setOracle(address newOracle) external {
    // Missing: governance/timelock
    oracle = newOracle;  // Attacker modified oracle
}
```

#### Scanner Detection:
```
🚨 CRITICAL: Unprotected Proxy Admin Function (Aevo Pattern)
Description: CRITICAL: Proxy admin functions without access control -
            $2.7M Aevo exploit pattern
Recommendation: Add onlyOwner/onlyAdmin modifier - this is a known exploit pattern
```

**Real-World Impact**: Aevo attacker:
1. Exploited unprotected `transferOwnership` to gain proxy admin access
2. Modified oracle implementation to manipulate prices
3. Mixed 18-decimal and 8-decimal tokens
4. Drained $2.7M by settling options at manipulated prices

---

### 2. Omni NFT Pattern ($1.43M - 2024)

**Root Cause**: Callback reentrancy via `onERC721Received`

#### Vulnerabilities Detected:
- ✅ State changes after `safeTransferFrom()` calls
- ✅ Missing `ReentrancyGuard` on NFT operations
- ✅ ERC721/ERC1155 callback without protection
- ✅ Critical functions (borrow/lend) using safe transfers

#### Attack Vector:
```solidity
// VULNERABLE - Omni exact pattern
function borrowWithCollateral(address nft, uint256 tokenId, uint256 amount) external {
    // Transfer triggers onERC721Received callback
    IERC721(nft).safeTransferFrom(msg.sender, address(this), tokenId);

    // VULNERABLE: State changes AFTER callback
    collateral[msg.sender] += 1;  // Attacker reenters here
    balances[msg.sender] += amount;
}
```

#### Scanner Detection:
```
🚨 CRITICAL: Omni-Pattern Callback Reentrancy
Description: State changes after safeTransferFrom enable onERC721Received
            reentrancy - exact $1.43M Omni exploit pattern
Recommendation: URGENT: Add ReentrancyGuard OR move all state changes
               before safeTransferFrom
```

**Real-World Impact**: Omni attacker:
1. Called `borrowWithCollateral()` with malicious NFT contract
2. In `onERC721Received` callback, reentered `borrowWithCollateral()`
3. Received multiple loans for single NFT collateral
4. Drained $1.43M from the protocol

---

### 3. Input Validation Failures (34.6% of exploits - $69M in 2024)

**Root Cause**: #1 vulnerability in 2021, 2022, and 2024 - Missing input validation

#### Vulnerabilities Detected:
- ✅ Unchecked calldata parameters (most dangerous)
- ✅ Array parameters without length validation
- ✅ Address parameters without zero-address checks
- ✅ No maximum bounds on user inputs

#### Attack Vector:
```solidity
// VULNERABLE - Common pattern across multiple hacks
function executeWithCalldata(bytes calldata data) external {
    // Missing: calldata validation
    // Missing: function selector whitelist
    (bool success, ) = address(this).call(data);
    require(success, "Call failed");
}

function batchTransfer(address[] calldata recipients, uint256[] calldata amounts) external {
    // Missing: require(recipients.length == amounts.length)
    // Missing: require(recipients.length > 0 && recipients.length <= MAX)
    for (uint256 i = 0; i < recipients.length; i++) {
        balances[recipients[i]] += amounts[i];
    }
}
```

#### Scanner Detection:
```
🚨 CRITICAL: Unchecked Calldata in executeWithCalldata
Description: Calldata parameter without validation - #1 exploit vector
            (34.6% of hacks)
Recommendation: Decode and validate ALL calldata inputs before processing

⚠️  HIGH: Missing Array Length Validation in batchTransfer
Description: Array parameter without length validation - enables DoS
            and manipulation
```

**Real-World Impact**: Multiple protocols lost $69M in 2024 due to:
- Maliciously crafted calldata bypassing validation
- Array length manipulation causing DoS
- Unbounded loops draining gas

---

### 4. Signature Replay Attacks (Multiple cross-chain incidents)

**Root Cause**: Missing nonce tracking + missing chain ID validation

#### Vulnerabilities Detected:
- ✅ `ecrecover` without nonce tracking
- ✅ Signature verification without chain ID
- ✅ Missing deadline in permit/meta-transactions
- ✅ No replay protection across chains

#### Attack Vector:
```solidity
// VULNERABLE - Cross-chain replay pattern
function withdrawWithSignature(uint256 amount, bytes memory signature) external {
    bytes32 messageHash = keccak256(abi.encodePacked(msg.sender, amount));
    // Missing: nonce in message hash
    // Missing: chainId in message hash

    address signer = recoverSigner(messageHash, signature);
    require(signer == msg.sender, "Invalid signature");

    // Signature can be replayed indefinitely!
    // Also replayed on different chains!
    balances[msg.sender] -= amount;
}
```

#### Scanner Detection:
```
🚨 CRITICAL: Signature Replay Attack Risk
Description: Signature verification without nonce tracking allows replay attacks
Recommendation: Implement nonce mapping and increment after each signature use

🚨 CRITICAL: Cross-Chain Signature Replay Risk
Description: Signature verification without chain ID enables cross-chain replay
Recommendation: Include block.chainid in EIP-712 domain separator
```

**Real-World Impact**:
- Signatures replayed across transactions
- Cross-chain replay on L2s/sidechains
- Indefinite signature validity without deadlines

---

### 5. MEV Exploitation ($675M in 2025, 19% YoY increase)

**Root Cause**: Transactions without deadline/slippage protection

#### Vulnerabilities Detected:
- ✅ Swap functions without deadline parameter
- ✅ Missing slippage protection
- ✅ Public liquidation functions
- ✅ Oracle prices without staleness checks

#### Attack Vector:
```solidity
// VULNERABLE - MEV sandwich attack surface
function swap(uint256 amountIn, uint256 minAmountOut, address[] calldata path) external {
    // Missing: deadline parameter
    router.swapExactTokensForTokens(
        amountIn,
        minAmountOut,
        path,
        msg.sender,
        type(uint256).max  // VULNERABLE: no deadline!
    );
}

function liquidate(address user) external {
    // Public liquidation = front-running target
    // Bots will front-run profitable liquidations
}
```

#### Scanner Detection:
```
🚨 CRITICAL: MEV Sandwich Attack Vulnerability
Description: Swap without slippage+deadline protection - vulnerable to $675M
            MEV attack surface
Recommendation: Add both minAmountOut AND deadline parameters

⚠️  HIGH: Public Liquidation MEV Target
Description: Public liquidation function is prime MEV target - bots will
            front-run profitable liquidations
```

**Real-World Impact**: MEV bots in 2025:
- Extracted $675M in profits
- 19% year-over-year increase
- Front-ran 20% of DeFi protocols
- Sandwich attacks on every unprotected swap

---

### 6. Arbitrary External Calls ($21M across 18 incidents in 2024)

**Root Cause**: User-controlled call targets without validation

#### Vulnerabilities Detected:
- ✅ Functions accepting arbitrary `address target`
- ✅ Delegatecall to user-provided addresses
- ✅ No address whitelist/validation
- ✅ Arbitrary calldata execution

#### Attack Vector:
```solidity
// VULNERABLE - Arbitrary call pattern
function executeArbitraryCall(address target, bytes calldata data) external {
    // CRITICAL: No address whitelist
    // Attacker can call ANY contract
    (bool success, ) = target.call(data);
    require(success, "Call failed");
}
```

#### Scanner Detection:
```
🚨 CRITICAL: Arbitrary External Call to User Address
Description: Function allows external calls to user-controlled addresses
            ($21M in 2024)
Recommendation: Implement address whitelist and validate all external call targets
```

---

### 7. Decimal Precision Mismatch (Aevo pattern)

**Root Cause**: Mixing different token decimal standards

#### Vulnerabilities Detected:
- ✅ Mixing 1e18 and 1e8 decimals in same contract
- ✅ Token decimal operations without normalization
- ✅ Division before multiplication in pricing
- ✅ Integer division without remainder handling

#### Attack Vector:
```solidity
// VULNERABLE - Aevo decimal mismatch pattern
function mixedPrecisionCalc(uint256 amount) external pure returns (uint256) {
    uint256 value18 = amount * 1e18;  // 18 decimals
    uint256 value8 = amount * 1e8;    // 8 decimals
    return value18 + value8;  // DANGEROUS: mixing precisions
}
```

#### Scanner Detection:
```
🚨 CRITICAL: Mixed Decimal Precision (Aevo Pattern)
Description: Contract mixes 1e18 and 1e8 decimals - exact Aevo $2.7M
            exploit pattern
Recommendation: Normalize ALL values to single precision (preferably 1e18)
               before any operations
```

---

### 8. Access Control - Callback Functions (17 incidents in 2024)

**Root Cause**: Unprotected callback functions handling funds

#### Vulnerabilities Detected:
- ✅ `onERC721Received` without access control
- ✅ Flash loan callbacks without sender validation
- ✅ Unrestricted callbacks that modify state
- ✅ Missing approved contract checks

#### Attack Vector:
```solidity
// VULNERABLE - Unprotected callback pattern
function onERC721Received(address, address from, uint256, bytes memory)
    external returns (bytes4) {
    // Missing: require(approvedContracts[msg.sender])
    // Anyone can trigger this callback
    balances[from] += 1000 ether;
    return this.onERC721Received.selector;
}
```

---

## 📈 Detection Statistics

### Test Results on RektNewsPatterns.sol

```
📁 Files scanned: 1
🔍 Total issues found: 73

🎯 SEVERITY BREAKDOWN
  🚨 CRITICAL: 35
  ⚠️  HIGH: 14
  ⚡ MEDIUM: 16
  💡 LOW: 2
  ℹ️  INFO: 6

📂 TOP CATEGORIES DETECTED
  • Access Control: 14
  • Unsafe External Calls: 7
  • Input Validation Failure: 6
  • Arbitrary External Call: 4
  • Delegate Call Vulnerabilities: 4
  • Proxy Admin Vulnerability: 3
  • Callback Reentrancy: 3
```

---

## 🛡️ Advanced Detection Features

### Context-Aware Analysis

Our scanner goes beyond simple pattern matching with:

1. **Proxy Pattern Detection**: Identifies upgradeable contracts and validates admin functions
2. **NFT Contract Analysis**: Special handling for ERC721/ERC1155 callback reentrancy
3. **Signature Verification Context**: Checks entire function for nonce/chainId usage
4. **MEV Surface Analysis**: Validates slippage AND deadline protection
5. **Decimal Normalization**: Detects mixed precision across entire contract

### Multi-Layer Detection

Each exploit pattern has detection at multiple levels:

- **Pattern Rules**: Quick regex-based initial detection
- **Advanced Analyzer**: Context-aware deep analysis
- **Known Exploits**: Specific real-world attack pattern matching
- **Cross-Function Analysis**: Tracks patterns across function boundaries

---

## 📚 Sources & Research

This implementation is based on comprehensive research from:

- **[Rekt.news](https://rekt.news/)**: The leading database of DeFi hacks and exploits
- **[Halborn's Top 100 DeFi Hacks Report 2025](https://www.halborn.com/reports/top-100-defi-hacks-2025)**
- **[Three Sigma: 2024 Most Exploited DeFi Vulnerabilities](https://threesigma.xyz/blog/exploit/2024-defi-exploits-top-vulnerabilities)**
- **[The 5 Smart Contract Vulnerabilities That Cost DeFi $1.4 Billion in 2024](https://medium.com/@marcellusv2/the-5-smart-contract-vulnerabilities-that-cost-defi-1-4-billion-in-2024-and-how-to-prevent-them-db96951de930)**
- **[OWASP SC Top 10 (2025)](https://www.resonance.security/blog-posts/owasp-sc-top-10-2025-breakdown-the-most-critical-smart-contract-risks-of-2025)**
- **[Hacken: Top 10 Smart Contract Vulnerabilities in 2025](https://hacken.io/discover/smart-contract-vulnerabilities/)**
- **[DeFi Rekt Report Q3 2025](https://de.fi/blog/defi-rekt-report-q3-2025-434m-lost-across-40-exploits)**

---

## 🎯 Recommendations for Developers

### Pre-Deployment Checklist

Based on $3.1B+ in real losses, ALWAYS:

1. ✅ **Proxy Contracts**: Verify ALL admin functions have access control
2. ✅ **NFT Operations**: Use ReentrancyGuard on ALL ERC721/ERC1155 operations
3. ✅ **Input Validation**: Validate EVERY external input (calldata, arrays, addresses)
4. ✅ **Signatures**: Include nonce + chainId in ALL signature verification
5. ✅ **Swaps/DEX**: Require both deadline AND slippage protection
6. ✅ **External Calls**: Whitelist all external call targets
7. ✅ **Decimals**: Normalize to single precision before operations
8. ✅ **Callbacks**: Restrict who can trigger callbacks

### Use This Scanner

```bash
# Scan your contract BEFORE deployment
./solidity_scanner --path YourContract.sol --verbose

# Generate professional audit report
./solidity_scanner --path contracts/ --audit --project "YourDApp"

# CI/CD integration
./solidity_scanner --path contracts/ --format json > security-report.json
```

---

## 🔬 Future Enhancements

Planned additions based on emerging exploit patterns:

1. **Account Abstraction Vulnerabilities** (EIP-4337 patterns)
2. **Intent-Based Systems** (MEV in intent protocols)
3. **Cross-Chain Bridge Exploits** (inter-chain message verification)
4. **Transient Storage Attacks** (TSTORE/TLOAD in 0.8.24+)
5. **AI-Based Pattern Recognition** (ML for novel exploit detection)

---

## 💡 Conclusion

This scanner now incorporates **real-world exploit patterns** from over $3 billion in actual losses. Every detection rule is based on exploits that happened to real protocols with real money.

**This is not theoretical security** - this is battle-tested knowledge from the frontlines of DeFi security incidents.

Use it. Learn from it. Don't become the next rekt.news headline.

---

**Developed with security research standards from:**
- Ethereum Foundation Security Team methodologies
- Trail of Bits audit best practices
- OpenZeppelin security guidelines
- Real-world incident post-mortems

**Stay safe. Stay secure. 🔒**
