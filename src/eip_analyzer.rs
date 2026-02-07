//! EIP Vulnerability Analyzer
//!
//! Detects Ethereum Improvement Proposals (EIPs) used in smart contracts
//! and identifies known vulnerabilities associated with each EIP implementation.
//!
//! Covers:
//! - Token standards: ERC-20, ERC-721, ERC-777, ERC-1155, ERC-4626
//! - Meta-transactions: ERC-2771, ERC-2612 (Permit)
//! - Account abstraction: ERC-4337
//! - Proxy patterns: ERC-1967, ERC-1822 (UUPS)
//! - Access control: ERC-173 (Ownable)
//! - And many more...

#![allow(dead_code)]

use regex::Regex;
use crate::vulnerabilities::{
    Vulnerability, VulnerabilityCategory, VulnerabilitySeverity, SwcId,
};

/// Represents a detected EIP in the contract
#[derive(Debug, Clone)]
pub struct DetectedEIP {
    pub eip_number: u32,
    pub name: String,
    pub detection_line: usize,
    pub detection_method: EIPDetectionMethod,
    pub confidence: u8,
}

#[derive(Debug, Clone)]
pub enum EIPDetectionMethod {
    InterfaceImplementation,
    ImportStatement,
    FunctionSignature,
    EventSignature,
    CommentAnnotation,
    InheritancePattern,
}

/// Known EIP vulnerability patterns
#[derive(Debug, Clone)]
pub struct EIPVulnerability {
    pub eip_number: u32,
    pub vulnerability_id: String,
    pub title: String,
    pub description: String,
    pub severity: VulnerabilitySeverity,
    pub pattern: Regex,
    pub recommendation: String,
    pub cwe_id: Option<String>,
    pub real_world_exploit: Option<String>,
}

pub struct EIPAnalyzer {
    verbose: bool,
    eip_patterns: Vec<EIPPattern>,
    eip_vulnerabilities: Vec<EIPVulnerability>,
}

#[derive(Debug, Clone)]
struct EIPPattern {
    eip_number: u32,
    name: String,
    detection_patterns: Vec<Regex>,
    interface_signatures: Vec<String>,
}

impl EIPAnalyzer {
    pub fn new(verbose: bool) -> Self {
        Self {
            verbose,
            eip_patterns: Self::create_eip_patterns(),
            eip_vulnerabilities: Self::create_eip_vulnerabilities(),
        }
    }

    /// Create patterns to detect EIP implementations
    fn create_eip_patterns() -> Vec<EIPPattern> {
        vec![
            // ERC-20: Fungible Token Standard
            EIPPattern {
                eip_number: 20,
                name: "ERC-20 Fungible Token".to_string(),
                detection_patterns: vec![
                    Regex::new(r"(?i)(IERC20|ERC20|is\s+ERC20)").unwrap(),
                    Regex::new(r"function\s+transfer\s*\(\s*address[^,]*,\s*uint").unwrap(),
                    Regex::new(r"function\s+approve\s*\(\s*address[^,]*,\s*uint").unwrap(),
                    Regex::new(r"function\s+transferFrom\s*\(").unwrap(),
                ],
                interface_signatures: vec![
                    "transfer(address,uint256)".to_string(),
                    "approve(address,uint256)".to_string(),
                    "transferFrom(address,address,uint256)".to_string(),
                    "balanceOf(address)".to_string(),
                    "allowance(address,address)".to_string(),
                ],
            },
            // ERC-721: Non-Fungible Token Standard
            EIPPattern {
                eip_number: 721,
                name: "ERC-721 NFT".to_string(),
                detection_patterns: vec![
                    Regex::new(r"(?i)(IERC721|ERC721|is\s+ERC721)").unwrap(),
                    Regex::new(r"function\s+safeTransferFrom\s*\(").unwrap(),
                    Regex::new(r"function\s+ownerOf\s*\(\s*uint").unwrap(),
                    Regex::new(r"onERC721Received").unwrap(),
                ],
                interface_signatures: vec![
                    "safeTransferFrom(address,address,uint256)".to_string(),
                    "ownerOf(uint256)".to_string(),
                    "approve(address,uint256)".to_string(),
                    "setApprovalForAll(address,bool)".to_string(),
                ],
            },
            // ERC-777: Advanced Token Standard
            EIPPattern {
                eip_number: 777,
                name: "ERC-777 Token".to_string(),
                detection_patterns: vec![
                    Regex::new(r"(?i)(IERC777|ERC777|is\s+ERC777)").unwrap(),
                    Regex::new(r"tokensReceived").unwrap(),
                    Regex::new(r"tokensToSend").unwrap(),
                    Regex::new(r"function\s+send\s*\(\s*address[^,]*,\s*uint").unwrap(),
                ],
                interface_signatures: vec![
                    "send(address,uint256,bytes)".to_string(),
                    "tokensReceived(address,address,address,uint256,bytes,bytes)".to_string(),
                ],
            },
            // ERC-1155: Multi Token Standard
            EIPPattern {
                eip_number: 1155,
                name: "ERC-1155 Multi Token".to_string(),
                detection_patterns: vec![
                    Regex::new(r"(?i)(IERC1155|ERC1155|is\s+ERC1155)").unwrap(),
                    Regex::new(r"function\s+safeTransferFrom\s*\([^)]*uint256\s+id").unwrap(),
                    Regex::new(r"function\s+safeBatchTransferFrom").unwrap(),
                    Regex::new(r"onERC1155Received").unwrap(),
                ],
                interface_signatures: vec![
                    "safeTransferFrom(address,address,uint256,uint256,bytes)".to_string(),
                    "safeBatchTransferFrom(address,address,uint256[],uint256[],bytes)".to_string(),
                ],
            },
            // ERC-2612: Permit Extension for ERC-20
            EIPPattern {
                eip_number: 2612,
                name: "ERC-2612 Permit".to_string(),
                detection_patterns: vec![
                    Regex::new(r"(?i)(IERC2612|ERC20Permit|is\s+ERC20Permit)").unwrap(),
                    Regex::new(r"function\s+permit\s*\(").unwrap(),
                    Regex::new(r"DOMAIN_SEPARATOR").unwrap(),
                    Regex::new(r"nonces\s*\(").unwrap(),
                ],
                interface_signatures: vec![
                    "permit(address,address,uint256,uint256,uint8,bytes32,bytes32)".to_string(),
                    "nonces(address)".to_string(),
                    "DOMAIN_SEPARATOR()".to_string(),
                ],
            },
            // ERC-2771: Meta Transactions
            EIPPattern {
                eip_number: 2771,
                name: "ERC-2771 Meta Transactions".to_string(),
                detection_patterns: vec![
                    Regex::new(r"(?i)(ERC2771|is\s+ERC2771Context|trustedForwarder)").unwrap(),
                    Regex::new(r"_msgSender\s*\(\s*\)").unwrap(),
                    Regex::new(r"isTrustedForwarder").unwrap(),
                ],
                interface_signatures: vec![
                    "isTrustedForwarder(address)".to_string(),
                ],
            },
            // ERC-4626: Tokenized Vault Standard
            EIPPattern {
                eip_number: 4626,
                name: "ERC-4626 Tokenized Vault".to_string(),
                detection_patterns: vec![
                    Regex::new(r"(?i)(IERC4626|ERC4626|is\s+ERC4626)").unwrap(),
                    Regex::new(r"function\s+deposit\s*\(\s*uint256[^,]*,\s*address").unwrap(),
                    Regex::new(r"function\s+withdraw\s*\(\s*uint256[^,]*,\s*address[^,]*,\s*address").unwrap(),
                    Regex::new(r"function\s+convertToShares").unwrap(),
                    Regex::new(r"function\s+convertToAssets").unwrap(),
                ],
                interface_signatures: vec![
                    "deposit(uint256,address)".to_string(),
                    "withdraw(uint256,address,address)".to_string(),
                    "redeem(uint256,address,address)".to_string(),
                    "convertToShares(uint256)".to_string(),
                    "convertToAssets(uint256)".to_string(),
                ],
            },
            // ERC-4337: Account Abstraction
            EIPPattern {
                eip_number: 4337,
                name: "ERC-4337 Account Abstraction".to_string(),
                detection_patterns: vec![
                    Regex::new(r"(?i)(IAccount|UserOperation|EntryPoint|is\s+BaseAccount)").unwrap(),
                    Regex::new(r"validateUserOp").unwrap(),
                    Regex::new(r"function\s+execute\s*\(\s*address[^,]*,\s*uint256[^,]*,\s*bytes").unwrap(),
                ],
                interface_signatures: vec![
                    "validateUserOp((address,uint256,bytes,bytes,uint256,uint256,uint256,uint256,uint256,bytes,bytes),bytes32,uint256)".to_string(),
                ],
            },
            // ERC-1967: Proxy Storage Slots
            EIPPattern {
                eip_number: 1967,
                name: "ERC-1967 Proxy Storage".to_string(),
                detection_patterns: vec![
                    Regex::new(r"(?i)(ERC1967|_IMPLEMENTATION_SLOT|_ADMIN_SLOT|_BEACON_SLOT)").unwrap(),
                    Regex::new(r"0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc").unwrap(),
                ],
                interface_signatures: vec![],
            },
            // ERC-1822: UUPS Proxy
            EIPPattern {
                eip_number: 1822,
                name: "ERC-1822 UUPS Proxy".to_string(),
                detection_patterns: vec![
                    Regex::new(r"(?i)(UUPSUpgradeable|proxiableUUID|_authorizeUpgrade)").unwrap(),
                ],
                interface_signatures: vec![
                    "proxiableUUID()".to_string(),
                    "upgradeTo(address)".to_string(),
                    "upgradeToAndCall(address,bytes)".to_string(),
                ],
            },
            // ERC-173: Contract Ownership
            EIPPattern {
                eip_number: 173,
                name: "ERC-173 Ownership".to_string(),
                detection_patterns: vec![
                    Regex::new(r"(?i)(Ownable|is\s+Ownable|owner\s*\(\s*\))").unwrap(),
                    Regex::new(r"onlyOwner").unwrap(),
                    Regex::new(r"transferOwnership").unwrap(),
                ],
                interface_signatures: vec![
                    "owner()".to_string(),
                    "transferOwnership(address)".to_string(),
                ],
            },
            // EIP-1153: Transient Storage
            EIPPattern {
                eip_number: 1153,
                name: "EIP-1153 Transient Storage".to_string(),
                detection_patterns: vec![
                    Regex::new(r"(?i)(tstore|tload|transient)").unwrap(),
                    Regex::new(r"assembly\s*\{[^}]*tstore").unwrap(),
                    Regex::new(r"assembly\s*\{[^}]*tload").unwrap(),
                ],
                interface_signatures: vec![],
            },
            // EIP-4844: Blob Transactions
            EIPPattern {
                eip_number: 4844,
                name: "EIP-4844 Blob Data".to_string(),
                detection_patterns: vec![
                    Regex::new(r"(?i)(blobhash|BLOBBASEFEE|blob)").unwrap(),
                    Regex::new(r"blobhash\s*\(").unwrap(),
                ],
                interface_signatures: vec![],
            },
            // EIP-712: Typed Structured Data Hashing
            EIPPattern {
                eip_number: 712,
                name: "EIP-712 Typed Data".to_string(),
                detection_patterns: vec![
                    Regex::new(r"(?i)(EIP712|DOMAIN_SEPARATOR|_hashTypedDataV4)").unwrap(),
                    Regex::new(r"keccak256\s*\(\s*abi\.encode\s*\(").unwrap(),
                ],
                interface_signatures: vec![
                    "DOMAIN_SEPARATOR()".to_string(),
                ],
            },
            // EIP-165: Interface Detection
            EIPPattern {
                eip_number: 165,
                name: "EIP-165 Interface Detection".to_string(),
                detection_patterns: vec![
                    Regex::new(r"(?i)(IERC165|ERC165|supportsInterface)").unwrap(),
                    Regex::new(r"function\s+supportsInterface\s*\(\s*bytes4").unwrap(),
                ],
                interface_signatures: vec![
                    "supportsInterface(bytes4)".to_string(),
                ],
            },
            // EIP-2981: NFT Royalty Standard
            EIPPattern {
                eip_number: 2981,
                name: "EIP-2981 NFT Royalty".to_string(),
                detection_patterns: vec![
                    Regex::new(r"(?i)(IERC2981|ERC2981|royaltyInfo)").unwrap(),
                    Regex::new(r"function\s+royaltyInfo\s*\(").unwrap(),
                ],
                interface_signatures: vec![
                    "royaltyInfo(uint256,uint256)".to_string(),
                ],
            },
            // EIP-3156: Flash Loans
            EIPPattern {
                eip_number: 3156,
                name: "EIP-3156 Flash Loans".to_string(),
                detection_patterns: vec![
                    Regex::new(r"(?i)(IERC3156|flashLoan|flashBorrow|FlashLender|FlashBorrower)").unwrap(),
                    Regex::new(r"function\s+flashLoan\s*\(").unwrap(),
                    Regex::new(r"onFlashLoan").unwrap(),
                ],
                interface_signatures: vec![
                    "flashLoan(address,address,uint256,bytes)".to_string(),
                    "onFlashLoan(address,address,uint256,uint256,bytes)".to_string(),
                ],
            },
        ]
    }

    /// Create known EIP vulnerability patterns
    fn create_eip_vulnerabilities() -> Vec<EIPVulnerability> {
        vec![
            // ============================================
            // ERC-20 Vulnerabilities
            // ============================================
            EIPVulnerability {
                eip_number: 20,
                vulnerability_id: "EIP20-001".to_string(),
                title: "ERC-20 Approval Race Condition".to_string(),
                description: "The approve() function is vulnerable to front-running. An attacker can observe a transaction changing allowance from N to M and front-run it to spend N tokens, then spend M more after the transaction confirms.".to_string(),
                severity: VulnerabilitySeverity::High,
                pattern: Regex::new(r"function\s+approve\s*\([^)]+\)[^{]*\{[^}]*allowances?\s*\[[^\]]+\]\s*\[[^\]]+\]\s*=").unwrap(),
                recommendation: "Implement increaseAllowance() and decreaseAllowance() functions, or use permit() from ERC-2612. Consider OpenZeppelin's SafeERC20.".to_string(),
                cwe_id: Some("CWE-362".to_string()),
                real_world_exploit: Some("Multiple DeFi protocols".to_string()),
            },
            EIPVulnerability {
                eip_number: 20,
                vulnerability_id: "EIP20-002".to_string(),
                title: "Missing Return Value Check on ERC-20 Transfer".to_string(),
                description: "Some ERC-20 tokens don't return a boolean on transfer/transferFrom (e.g., USDT, BNB). Failing to handle this causes transactions to revert.".to_string(),
                severity: VulnerabilitySeverity::High,
                pattern: Regex::new(r"\.transfer\s*\([^)]+\)\s*;|\.transferFrom\s*\([^)]+\)\s*;").unwrap(),
                recommendation: "Use OpenZeppelin's SafeERC20 library with safeTransfer() and safeTransferFrom().".to_string(),
                cwe_id: Some("CWE-252".to_string()),
                real_world_exploit: Some("Multiple protocols, including early Uniswap issues".to_string()),
            },
            EIPVulnerability {
                eip_number: 20,
                vulnerability_id: "EIP20-003".to_string(),
                title: "ERC-20 Double-Spend via transferFrom".to_string(),
                description: "If allowance and transfer logic are not properly synchronized, double-spending may be possible.".to_string(),
                severity: VulnerabilitySeverity::Critical,
                pattern: Regex::new(r"function\s+transferFrom[^{]+\{").unwrap(),
                recommendation: "Ensure allowance is decremented before the transfer is executed (checks-effects-interactions pattern).".to_string(),
                cwe_id: Some("CWE-672".to_string()),
                real_world_exploit: None,
            },

            // ============================================
            // ERC-721 Vulnerabilities
            // ============================================
            EIPVulnerability {
                eip_number: 721,
                vulnerability_id: "EIP721-001".to_string(),
                title: "ERC-721 Reentrancy via onERC721Received".to_string(),
                description: "The safeTransferFrom function calls onERC721Received on the recipient, which can execute arbitrary code and re-enter the contract.".to_string(),
                severity: VulnerabilitySeverity::Critical,
                pattern: Regex::new(r"safeTransferFrom.*onERC721Received|onERC721Received").unwrap(),
                recommendation: "Follow checks-effects-interactions pattern. Update state before calling safeTransferFrom. Consider using ReentrancyGuard.".to_string(),
                cwe_id: Some("CWE-841".to_string()),
                real_world_exploit: Some("Multiple NFT marketplace exploits".to_string()),
            },
            EIPVulnerability {
                eip_number: 721,
                vulnerability_id: "EIP721-002".to_string(),
                title: "Missing Zero Address Check in ERC-721 Mint".to_string(),
                description: "Minting to address(0) will burn the token permanently with no way to recover it.".to_string(),
                severity: VulnerabilitySeverity::Medium,
                pattern: Regex::new(r"function\s+_mint\s*\([^)]*\)").unwrap(),
                recommendation: "Add require(to != address(0), 'ERC721: mint to zero address') at the start of _mint().".to_string(),
                cwe_id: Some("CWE-20".to_string()),
                real_world_exploit: None,
            },

            // ============================================
            // ERC-777 Vulnerabilities (CRITICAL)
            // ============================================
            EIPVulnerability {
                eip_number: 777,
                vulnerability_id: "EIP777-001".to_string(),
                title: "ERC-777 Reentrancy via tokensReceived Hook".to_string(),
                description: "ERC-777 tokens call tokensReceived() hook on the recipient before completing the transfer, enabling reentrancy attacks. This was exploited in the $24M dForce/Lendf.me hack.".to_string(),
                severity: VulnerabilitySeverity::Critical,
                pattern: Regex::new(r"(?i)(ERC777|tokensReceived|tokensToSend|IERC777)").unwrap(),
                recommendation: "CRITICAL: Do not integrate ERC-777 tokens without ReentrancyGuard. Always update state before external calls. Consider blocking ERC-777 tokens entirely.".to_string(),
                cwe_id: Some("CWE-841".to_string()),
                real_world_exploit: Some("dForce/Lendf.me - $24M (April 2020), imBTC on Uniswap V1".to_string()),
            },
            EIPVulnerability {
                eip_number: 777,
                vulnerability_id: "EIP777-002".to_string(),
                title: "ERC-777 tokensToSend Reentrancy".to_string(),
                description: "The tokensToSend hook is called on the sender BEFORE tokens are moved, allowing the sender to re-enter and manipulate state.".to_string(),
                severity: VulnerabilitySeverity::Critical,
                pattern: Regex::new(r"tokensToSend").unwrap(),
                recommendation: "Never trust ERC-777 tokens in DeFi protocols without proper reentrancy protection.".to_string(),
                cwe_id: Some("CWE-841".to_string()),
                real_world_exploit: Some("Multiple DeFi protocols".to_string()),
            },

            // ============================================
            // ERC-1155 Vulnerabilities
            // ============================================
            EIPVulnerability {
                eip_number: 1155,
                vulnerability_id: "EIP1155-001".to_string(),
                title: "ERC-1155 Batch Transfer Reentrancy".to_string(),
                description: "safeBatchTransferFrom calls onERC1155BatchReceived, which can re-enter the contract with manipulated state.".to_string(),
                severity: VulnerabilitySeverity::High,
                pattern: Regex::new(r"onERC1155BatchReceived|onERC1155Received").unwrap(),
                recommendation: "Use ReentrancyGuard and update all state before batch transfers.".to_string(),
                cwe_id: Some("CWE-841".to_string()),
                real_world_exploit: None,
            },

            // ============================================
            // ERC-4626 Vulnerabilities (CRITICAL)
            // ============================================
            EIPVulnerability {
                eip_number: 4626,
                vulnerability_id: "EIP4626-001".to_string(),
                title: "ERC-4626 First Depositor Inflation Attack".to_string(),
                description: "The first depositor can inflate the share price by depositing 1 wei, then directly transferring a large amount to the vault. Subsequent depositors receive 0 shares due to rounding.".to_string(),
                severity: VulnerabilitySeverity::Critical,
                pattern: Regex::new(r"(?i)(ERC4626|function\s+deposit\s*\(\s*uint256[^,]*,\s*address|function\s+convertToShares)").unwrap(),
                recommendation: "Implement virtual offset/dead shares: In constructor, mint a small amount of shares to address(0) or use virtual assets/shares. See OpenZeppelin ERC4626 for reference implementation.".to_string(),
                cwe_id: Some("CWE-682".to_string()),
                real_world_exploit: Some("Multiple vault protocols in 2023-2024".to_string()),
            },
            EIPVulnerability {
                eip_number: 4626,
                vulnerability_id: "EIP4626-002".to_string(),
                title: "ERC-4626 Share/Asset Rounding Exploit".to_string(),
                description: "Incorrect rounding direction in convertToShares/convertToAssets can be exploited to drain vault assets over many transactions.".to_string(),
                severity: VulnerabilitySeverity::High,
                pattern: Regex::new(r"convertToShares\s*\([^)]*\)\s*\{[^}]*\/").unwrap(),
                recommendation: "Round DOWN when converting assets to shares (deposits), round UP when converting shares to assets (withdrawals). Use OpenZeppelin's Math.mulDiv with proper rounding.".to_string(),
                cwe_id: Some("CWE-682".to_string()),
                real_world_exploit: None,
            },

            // ============================================
            // ERC-2612 Permit Vulnerabilities
            // ============================================
            EIPVulnerability {
                eip_number: 2612,
                vulnerability_id: "EIP2612-001".to_string(),
                title: "Permit Signature Replay Attack".to_string(),
                description: "Permit signatures can be replayed on different chains if DOMAIN_SEPARATOR doesn't include chainId, or replayed within the same contract if nonces aren't properly managed.".to_string(),
                severity: VulnerabilitySeverity::High,
                pattern: Regex::new(r"function\s+permit\s*\(.*ecrecover|permit.*DOMAIN_SEPARATOR").unwrap(),
                recommendation: "Ensure DOMAIN_SEPARATOR includes block.chainid. Verify nonce is incremented atomically. Check deadline hasn't passed.".to_string(),
                cwe_id: Some("CWE-294".to_string()),
                real_world_exploit: Some("Multiple protocols after chain forks".to_string()),
            },
            EIPVulnerability {
                eip_number: 2612,
                vulnerability_id: "EIP2612-002".to_string(),
                title: "Permit Front-Running Vulnerability".to_string(),
                description: "Permit transactions can be front-run, allowing attackers to use the signature before the intended transaction.".to_string(),
                severity: VulnerabilitySeverity::Medium,
                pattern: Regex::new(r"permit\s*\([^)]+\)\s*;[^}]*transfer").unwrap(),
                recommendation: "Use permit in the same transaction as the action (e.g., permitAndDeposit). Don't expose permit calls separately.".to_string(),
                cwe_id: Some("CWE-362".to_string()),
                real_world_exploit: None,
            },

            // ============================================
            // ERC-2771 Meta Transaction Vulnerabilities
            // ============================================
            EIPVulnerability {
                eip_number: 2771,
                vulnerability_id: "EIP2771-001".to_string(),
                title: "Trusted Forwarder Bypass".to_string(),
                description: "If the trusted forwarder is compromised or incorrectly validated, attackers can spoof any msg.sender.".to_string(),
                severity: VulnerabilitySeverity::Critical,
                pattern: Regex::new(r"isTrustedForwarder\s*\([^)]+\)\s*\{[^}]*return\s+true").unwrap(),
                recommendation: "Use hardcoded forwarder address or implement proper forwarder registry. Never return true unconditionally.".to_string(),
                cwe_id: Some("CWE-345".to_string()),
                real_world_exploit: Some("KiloEx - $7.4M (2024)".to_string()),
            },
            EIPVulnerability {
                eip_number: 2771,
                vulnerability_id: "EIP2771-002".to_string(),
                title: "Meta Transaction _msgSender Confusion".to_string(),
                description: "Mixing msg.sender and _msgSender() in the same contract can lead to authorization bypasses.".to_string(),
                severity: VulnerabilitySeverity::High,
                pattern: Regex::new(r"msg\.sender.*_msgSender|_msgSender.*msg\.sender").unwrap(),
                recommendation: "Always use _msgSender() consistently throughout ERC-2771 compatible contracts. Never mix with msg.sender.".to_string(),
                cwe_id: Some("CWE-284".to_string()),
                real_world_exploit: None,
            },

            // ============================================
            // ERC-4337 Account Abstraction Vulnerabilities
            // ============================================
            EIPVulnerability {
                eip_number: 4337,
                vulnerability_id: "EIP4337-001".to_string(),
                title: "Insufficient UserOp Validation".to_string(),
                description: "validateUserOp must properly verify the signature and nonce. Weak validation allows attackers to execute unauthorized operations.".to_string(),
                severity: VulnerabilitySeverity::Critical,
                pattern: Regex::new(r"function\s+validateUserOp[^{]+\{[^}]*return\s+0").unwrap(),
                recommendation: "Implement proper signature verification. Return SIG_VALIDATION_FAILED for invalid signatures. Use proper nonce management.".to_string(),
                cwe_id: Some("CWE-287".to_string()),
                real_world_exploit: None,
            },
            EIPVulnerability {
                eip_number: 4337,
                vulnerability_id: "EIP4337-002".to_string(),
                title: "Account Abstraction Execution Reentrancy".to_string(),
                description: "The execute() function can be re-entered if it makes external calls without proper guards.".to_string(),
                severity: VulnerabilitySeverity::High,
                pattern: Regex::new(r"function\s+execute\s*\([^)]*address[^)]*\).*\.call").unwrap(),
                recommendation: "Use ReentrancyGuard on execute(). Validate caller is EntryPoint.".to_string(),
                cwe_id: Some("CWE-841".to_string()),
                real_world_exploit: None,
            },

            // ============================================
            // ERC-1967/ERC-1822 Proxy Vulnerabilities
            // ============================================
            EIPVulnerability {
                eip_number: 1967,
                vulnerability_id: "EIP1967-001".to_string(),
                title: "Unprotected Proxy Upgrade Function".to_string(),
                description: "The upgradeTo or upgradeToAndCall function lacks access control, allowing anyone to change the implementation.".to_string(),
                severity: VulnerabilitySeverity::Critical,
                pattern: Regex::new(r"function\s+upgradeTo\s*\([^)]*\)\s*(external|public)").unwrap(),
                recommendation: "Add onlyOwner or similar access control to upgrade functions. Use OpenZeppelin's UUPSUpgradeable.".to_string(),
                cwe_id: Some("CWE-284".to_string()),
                real_world_exploit: Some("Multiple proxy exploits including Wormhole incident".to_string()),
            },
            EIPVulnerability {
                eip_number: 1822,
                vulnerability_id: "EIP1822-001".to_string(),
                title: "UUPS Missing _authorizeUpgrade Protection".to_string(),
                description: "UUPS proxies require _authorizeUpgrade to be overridden with access control. Missing or weak implementation allows unauthorized upgrades.".to_string(),
                severity: VulnerabilitySeverity::Critical,
                pattern: Regex::new(r"function\s+_authorizeUpgrade\s*\([^)]*\)[^{]*\{[^}]*\}").unwrap(),
                recommendation: "Override _authorizeUpgrade with onlyOwner modifier. Never leave it empty or with weak checks.".to_string(),
                cwe_id: Some("CWE-284".to_string()),
                real_world_exploit: None,
            },

            // ============================================
            // EIP-1153 Transient Storage Vulnerabilities
            // ============================================
            EIPVulnerability {
                eip_number: 1153,
                vulnerability_id: "EIP1153-001".to_string(),
                title: "Transient Storage Reentrancy".to_string(),
                description: "Transient storage (tstore/tload) resets at end of transaction but persists across calls within the same tx, creating new reentrancy vectors.".to_string(),
                severity: VulnerabilitySeverity::High,
                pattern: Regex::new(r"assembly\s*\{[^}]*(tstore|tload)[^}]*\}").unwrap(),
                recommendation: "Be aware that transient storage is not a reentrancy guard replacement. Implement proper checks-effects-interactions pattern.".to_string(),
                cwe_id: Some("CWE-841".to_string()),
                real_world_exploit: None,
            },

            // ============================================
            // EIP-3156 Flash Loan Vulnerabilities
            // ============================================
            EIPVulnerability {
                eip_number: 3156,
                vulnerability_id: "EIP3156-001".to_string(),
                title: "Flash Loan Callback Reentrancy".to_string(),
                description: "The onFlashLoan callback can be exploited to manipulate state during the flash loan execution.".to_string(),
                severity: VulnerabilitySeverity::Critical,
                pattern: Regex::new(r"function\s+flashLoan|onFlashLoan").unwrap(),
                recommendation: "Implement strict reentrancy guards. Verify callback return value. Ensure all state changes are atomic.".to_string(),
                cwe_id: Some("CWE-841".to_string()),
                real_world_exploit: Some("Multiple flash loan attacks including $182M Beanstalk".to_string()),
            },
            EIPVulnerability {
                eip_number: 3156,
                vulnerability_id: "EIP3156-002".to_string(),
                title: "Flash Loan Unchecked Callback Return".to_string(),
                description: "Flash loan lender doesn't verify the callback return value, allowing attackers to abort repayment.".to_string(),
                severity: VulnerabilitySeverity::High,
                pattern: Regex::new(r"receiver\.onFlashLoan\s*\(|borrower\.onFlashLoan\s*\(").unwrap(),
                recommendation: "Always verify onFlashLoan returns keccak256('ERC3156FlashBorrower.onFlashLoan').".to_string(),
                cwe_id: Some("CWE-252".to_string()),
                real_world_exploit: None,
            },

            // ============================================
            // EIP-712 Signature Vulnerabilities
            // ============================================
            EIPVulnerability {
                eip_number: 712,
                vulnerability_id: "EIP712-001".to_string(),
                title: "EIP-712 Signature Malleability".to_string(),
                description: "ECDSA signatures without proper validation can be malleable, allowing signature reuse with modified v value.".to_string(),
                severity: VulnerabilitySeverity::High,
                pattern: Regex::new(r"ecrecover\s*\([^)]+\)").unwrap(),
                recommendation: "Use OpenZeppelin's ECDSA library which validates s is in lower half order and v is 27 or 28.".to_string(),
                cwe_id: Some("CWE-347".to_string()),
                real_world_exploit: None,
            },
            EIPVulnerability {
                eip_number: 712,
                vulnerability_id: "EIP712-002".to_string(),
                title: "Missing Chain ID in Domain Separator".to_string(),
                description: "DOMAIN_SEPARATOR without chainId allows signatures to be replayed on different chains after a fork.".to_string(),
                severity: VulnerabilitySeverity::High,
                pattern: Regex::new(r"DOMAIN_SEPARATOR\s*=\s*keccak256").unwrap(),
                recommendation: "Include block.chainid in DOMAIN_SEPARATOR. Recalculate on chain fork detection.".to_string(),
                cwe_id: Some("CWE-294".to_string()),
                real_world_exploit: Some("Post-merge signature replays".to_string()),
            },
        ]
    }

    /// Detect which EIPs are used in the contract
    pub fn detect_eips(&self, content: &str) -> Vec<DetectedEIP> {
        let mut detected = Vec::new();
        let lines: Vec<&str> = content.lines().collect();

        for eip_pattern in &self.eip_patterns {
            for (line_idx, line) in lines.iter().enumerate() {
                for pattern in &eip_pattern.detection_patterns {
                    if pattern.is_match(line) {
                        // Check for duplicates
                        if !detected.iter().any(|d: &DetectedEIP| d.eip_number == eip_pattern.eip_number) {
                            let method = if line.contains("import") {
                                EIPDetectionMethod::ImportStatement
                            } else if line.contains("interface") || line.contains(" is ") {
                                EIPDetectionMethod::InterfaceImplementation
                            } else if line.contains("function") {
                                EIPDetectionMethod::FunctionSignature
                            } else if line.contains("event") {
                                EIPDetectionMethod::EventSignature
                            } else if line.contains("//") || line.contains("/*") {
                                EIPDetectionMethod::CommentAnnotation
                            } else {
                                EIPDetectionMethod::InheritancePattern
                            };

                            detected.push(DetectedEIP {
                                eip_number: eip_pattern.eip_number,
                                name: eip_pattern.name.clone(),
                                detection_line: line_idx + 1,
                                detection_method: method,
                                confidence: 85,
                            });
                            break;
                        }
                    }
                }
            }
        }

        if self.verbose && !detected.is_empty() {
            println!("  {} Detected EIPs: {}",
                "📋".to_string(),
                detected.iter().map(|e| format!("EIP-{}", e.eip_number)).collect::<Vec<_>>().join(", ")
            );
        }

        detected
    }

    /// Analyze contract for EIP-specific vulnerabilities
    pub fn analyze(&self, content: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();
        let detected_eips = self.detect_eips(content);
        let lines: Vec<&str> = content.lines().collect();

        if detected_eips.is_empty() {
            return vulnerabilities;
        }

        if self.verbose {
            println!("  {} Scanning for EIP-specific vulnerabilities...", "🔒".to_string());
        }

        // Check each detected EIP for known vulnerabilities
        for detected_eip in &detected_eips {
            for vuln in &self.eip_vulnerabilities {
                if vuln.eip_number == detected_eip.eip_number {
                    // Search for the vulnerability pattern in the content
                    for mat in vuln.pattern.find_iter(content) {
                        let match_start = mat.start();
                        let line_number = content[..match_start].matches('\n').count() + 1;

                        // Get the matching line content
                        let code_snippet = if line_number > 0 && line_number <= lines.len() {
                            lines[line_number - 1].trim().to_string()
                        } else {
                            mat.as_str().chars().take(100).collect::<String>()
                        };

                        // Create vulnerability with enhanced information
                        let mut description = vuln.description.clone();
                        if let Some(ref exploit) = vuln.real_world_exploit {
                            description.push_str(&format!(" Real-world exploit: {}", exploit));
                        }

                        let category = self.map_eip_to_category(vuln.eip_number, &vuln.vulnerability_id);

                        let mut vulnerability = Vulnerability::high_confidence(
                            vuln.severity.clone(),
                            category,
                            format!("[EIP-{}] {}", vuln.eip_number, vuln.title),
                            description,
                            line_number,
                            code_snippet,
                            vuln.recommendation.clone(),
                        );

                        // Add SWC/CWE mapping
                        if let Some(ref cwe) = vuln.cwe_id {
                            vulnerability.swc_id = Some(SwcId::new(
                                &vuln.vulnerability_id,
                                &vuln.title,
                                Some(cwe),
                            ));
                        }

                        // Extract context
                        let (before, after) = Vulnerability::extract_context(content, line_number, 3);
                        vulnerability = vulnerability.with_context(before, after);

                        vulnerabilities.push(vulnerability);
                    }
                }
            }
        }

        // Remove duplicates based on line number and vulnerability ID
        vulnerabilities.sort_by(|a, b| a.line_number.cmp(&b.line_number));
        vulnerabilities.dedup_by(|a, b| {
            a.line_number == b.line_number && a.title == b.title
        });

        if self.verbose && !vulnerabilities.is_empty() {
            println!("  {} Found {} EIP-specific vulnerabilities",
                "⚠️".to_string(),
                vulnerabilities.len()
            );
        }

        vulnerabilities
    }

    /// Map EIP vulnerability to appropriate category
    fn map_eip_to_category(&self, eip_number: u32, vuln_id: &str) -> VulnerabilityCategory {
        match eip_number {
            20 => {
                if vuln_id.contains("001") {
                    VulnerabilityCategory::FrontRunning
                } else {
                    VulnerabilityCategory::UncheckedReturnValues
                }
            }
            721 | 777 | 1155 => VulnerabilityCategory::CallbackReentrancy,
            4626 => VulnerabilityCategory::ERC4626Inflation,
            2612 => VulnerabilityCategory::Permit2SignatureReuse,
            2771 => VulnerabilityCategory::TrustedForwarderBypass,
            4337 => VulnerabilityCategory::AccessControl,
            1967 | 1822 => VulnerabilityCategory::UnprotectedProxyUpgrade,
            1153 => VulnerabilityCategory::TransientStorageReentrancy,
            3156 => VulnerabilityCategory::FlashLoanAttack,
            712 => VulnerabilityCategory::SignatureVulnerabilities,
            _ => VulnerabilityCategory::LogicError,
        }
    }

    /// Get summary of detected EIPs for reporting
    pub fn get_eip_summary(&self, content: &str) -> String {
        let detected = self.detect_eips(content);
        if detected.is_empty() {
            return "No EIP implementations detected.".to_string();
        }

        let mut summary = String::from("Detected EIP implementations:\n");
        for eip in detected {
            summary.push_str(&format!(
                "  - EIP-{}: {} (line {}, confidence: {}%)\n",
                eip.eip_number, eip.name, eip.detection_line, eip.confidence
            ));
        }
        summary
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_erc20() {
        let analyzer = EIPAnalyzer::new(false);
        let content = r#"
            import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
            contract MyToken is ERC20 {
                function transfer(address to, uint256 amount) public returns (bool) {
                    return super.transfer(to, amount);
                }
            }
        "#;

        let detected = analyzer.detect_eips(content);
        assert!(detected.iter().any(|e| e.eip_number == 20));
    }

    #[test]
    fn test_detect_erc4626() {
        let analyzer = EIPAnalyzer::new(false);
        let content = r#"
            contract Vault is ERC4626 {
                function deposit(uint256 assets, address receiver) public returns (uint256) {
                    return super.deposit(assets, receiver);
                }
            }
        "#;

        let detected = analyzer.detect_eips(content);
        assert!(detected.iter().any(|e| e.eip_number == 4626));
    }

    #[test]
    fn test_erc777_vulnerability_detection() {
        let analyzer = EIPAnalyzer::new(false);
        let content = r#"
            import "@openzeppelin/contracts/token/ERC777/ERC777.sol";
            contract VulnerableVault {
                function deposit(IERC777 token, uint256 amount) external {
                    token.send(address(this), amount, "");
                    balances[msg.sender] += amount;
                }
            }
        "#;

        let vulns = analyzer.analyze(content);
        assert!(vulns.iter().any(|v| v.title.contains("ERC-777")));
    }
}
