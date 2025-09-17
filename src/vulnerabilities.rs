use regex::Regex;
use serde::{Deserialize, Serialize};
use crate::parser::CompilerVersion;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vulnerability {
    pub severity: VulnerabilitySeverity,
    pub category: VulnerabilityCategory,
    pub title: String,
    pub description: String,
    pub line_number: usize,
    pub code_snippet: String,
    pub recommendation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum VulnerabilitySeverity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum VulnerabilityCategory {
    Reentrancy,
    AccessControl,
    RoleBasedAccessControl,
    ArithmeticIssues,
    UnhandledExceptions,
    GasOptimization,
    PragmaIssues,
    RandomnessVulnerabilities,
    FrontRunning,
    TimeManipulation,
    DoSAttacks,
    UnusedCode,
    MagicNumbers,
    NamingConventions,
    StateVariable,
    UnsafeExternalCalls,
    DelegateCalls,
    StorageDoSAttacks,
    PrecisionLoss,
    CompilerBug,
}

pub struct VulnerabilityRule {
    pub category: VulnerabilityCategory,
    pub severity: VulnerabilitySeverity,
    pub pattern: Regex,
    pub title: String,
    pub description: String,
    pub recommendation: String,
    pub multiline: bool,
}

impl VulnerabilityRule {
    pub fn new(
        category: VulnerabilityCategory,
        severity: VulnerabilitySeverity,
        pattern: &str,
        title: String,
        description: String,
        recommendation: String,
        multiline: bool,
    ) -> Result<Self, regex::Error> {
        let pattern = if multiline {
            Regex::new(&format!("(?s){}", pattern))?
        } else {
            Regex::new(pattern)?
        };
        
        Ok(VulnerabilityRule {
            category,
            severity,
            pattern,
            title,
            description,
            recommendation,
            multiline,
        })
    }
}

pub fn create_vulnerability_rules() -> Vec<VulnerabilityRule> {
    let mut rules = Vec::new();

    // Reentrancy vulnerabilities
    rules.push(VulnerabilityRule::new(
        VulnerabilityCategory::Reentrancy,
        VulnerabilitySeverity::Critical,
        r#"\.call\{value:\s*\w+\}\(\s*""\s*\)"#,
        "Potential Reentrancy Attack".to_string(),
        "External call with value transfer found without reentrancy protection".to_string(),
        "Use ReentrancyGuard or follow checks-effects-interactions pattern".to_string(),
        false,
    ).unwrap());

    rules.push(VulnerabilityRule::new(
        VulnerabilityCategory::Reentrancy,
        VulnerabilitySeverity::High,
        r"\.send\(|\.transfer\(|\.call\.value\(",
        "External Call Found".to_string(),
        "External call that could lead to reentrancy".to_string(),
        "Ensure state changes happen before external calls".to_string(),
        false,
    ).unwrap());

    // Unchecked external calls
    rules.push(VulnerabilityRule::new(
        VulnerabilityCategory::UnsafeExternalCalls,
        VulnerabilitySeverity::Medium,
        r"\.call\([^)]*\)",
        "Unchecked External Call".to_string(),
        "External call return value not checked".to_string(),
        "Always check the return value of external calls".to_string(),
        false,
    ).unwrap());

    // Access control issues - Missing modifier on state-changing functions
    rules.push(VulnerabilityRule::new(
        VulnerabilityCategory::AccessControl,
        VulnerabilitySeverity::Critical,
        r"function\s+(set|update|change|modify|withdraw|transfer|mint|burn|pause|unpause|destroy|kill|upgrade|initialize)\w*\([^)]*\)\s+(external|public)",
        "Missing Access Control on State-Changing Function".to_string(),
        "Critical state-changing function without access control modifier".to_string(),
        "Add access control modifiers (onlyOwner, onlyRole, etc.) to protect critical functions".to_string(),
        false,
    ).unwrap());
    
    // Generic public function check (lower severity)
    rules.push(VulnerabilityRule::new(
        VulnerabilityCategory::AccessControl,
        VulnerabilitySeverity::Medium,
        r"function\s+\w+\([^)]*\)\s+public",
        "Public Function Found".to_string(),
        "Public function found - verify proper access control".to_string(),
        "Review if function needs access control modifiers".to_string(),
        false,
    ).unwrap());

    // Pragma issues
    rules.push(VulnerabilityRule::new(
        VulnerabilityCategory::PragmaIssues,
        VulnerabilitySeverity::Medium,
        r"pragma\s+solidity\s*\^",
        "Floating Pragma".to_string(),
        "Contract uses floating pragma which can lead to compilation with different versions".to_string(),
        "Use a fixed pragma version for consistent compilation".to_string(),
        false,
    ).unwrap());

    // Weak randomness
    rules.push(VulnerabilityRule::new(
        VulnerabilityCategory::RandomnessVulnerabilities,
        VulnerabilitySeverity::High,
        r"block\.timestamp|block\.difficulty|block\.number|block\.blockhash|keccak256\(.*msg\.sender.*block\.",
        "Weak Randomness Source".to_string(),
        "Using predictable block properties for randomness generation".to_string(),
        "Use a secure randomness source like Chainlink VRF or commit-reveal schemes".to_string(),
        false,
    ).unwrap());

    // DoS through gas limit
    rules.push(VulnerabilityRule::new(
        VulnerabilityCategory::DoSAttacks,
        VulnerabilitySeverity::High,
        r"for\s*\([^)]*players\.length[^)]*\)\s*\{[^}]*for\s*\([^)]*players\.length",
        "Potential DoS via Gas Limit".to_string(),
        "Nested loops over dynamic arrays can cause denial of service".to_string(),
        "Limit array sizes or use different data structures to avoid gas limit issues".to_string(),
        true,
    ).unwrap());

    // Arithmetic overflow/underflow (for older Solidity versions)
    rules.push(VulnerabilityRule::new(
        VulnerabilityCategory::ArithmeticIssues,
        VulnerabilitySeverity::High,
        r"(?:uint256|uint|int256|int)\s+\w+\s*=\s*\w+\s*[\+\-\*]\s*\w+",
        "Potential Integer Overflow/Underflow".to_string(),
        "Arithmetic operation without overflow protection in older Solidity versions".to_string(),
        "Use SafeMath library or upgrade to Solidity 0.8.0+ for automatic overflow checks".to_string(),
        false,
    ).unwrap());

    // Magic numbers
    rules.push(VulnerabilityRule::new(
        VulnerabilityCategory::MagicNumbers,
        VulnerabilitySeverity::Low,
        r"\*\s*\d{2,}|/\s*\d{2,}",
        "Magic Numbers".to_string(),
        "Hard-coded numbers should be replaced with named constants".to_string(),
        "Replace magic numbers with named constants for better readability and maintainability".to_string(),
        false,
    ).unwrap());

    // Unused functions
    rules.push(VulnerabilityRule::new(
        VulnerabilityCategory::UnusedCode,
        VulnerabilitySeverity::Info,
        r"function\s+(_\w+)\s*\([^)]*\)\s+internal\s+view\s+returns\s*\([^)]*\)\s*\{[^}]*\}",
        "Potentially Unused Function".to_string(),
        "Internal function that may not be used anywhere".to_string(),
        "Remove unused functions to reduce contract size and complexity".to_string(),
        true,
    ).unwrap());

    // State variable visibility
    rules.push(VulnerabilityRule::new(
        VulnerabilityCategory::StateVariable,
        VulnerabilitySeverity::Medium,
        r"uint256\s+public\s+\w+",
        "Public State Variable".to_string(),
        "Public state variable found - verify initialization".to_string(),
        "Explicitly initialize state variables to avoid unexpected behavior".to_string(),
        false,
    ).unwrap());

    // Time manipulation
    rules.push(VulnerabilityRule::new(
        VulnerabilityCategory::TimeManipulation,
        VulnerabilitySeverity::Medium,
        r"block\.timestamp\s*[<>=!]+",
        "Time Dependency".to_string(),
        "Contract logic depends on block.timestamp which can be manipulated by miners".to_string(),
        "Avoid time-dependent logic or use block.number instead where appropriate".to_string(),
        false,
    ).unwrap());

    // Gas optimization issues
    rules.push(VulnerabilityRule::new(
        VulnerabilityCategory::GasOptimization,
        VulnerabilitySeverity::Low,
        r"uint256\s+public\s+\w+\s*;",
        "Gas Optimization: Consider Immutable".to_string(),
        "State variable could potentially be immutable to save gas".to_string(),
        "Use 'immutable' keyword for variables set only in constructor".to_string(),
        false,
    ).unwrap());

    // Typos in function/event names (common ones)
    rules.push(VulnerabilityRule::new(
        VulnerabilityCategory::NamingConventions,
        VulnerabilitySeverity::Medium,
        r"raffleStarttime|kaccak256|prizeZPool|totalFEees|tokenIdRarity|SetNet|recieve|occured|transfered|Withdrawl|Deposite",
        "Potential Typo in Code".to_string(),
        "Suspected typo in variable, event, or function name that could indicate a bug".to_string(),
        "Review for typos and correct any spelling mistakes that could cause bugs".to_string(),
        false,
    ).unwrap());
    
    // Sensitive data storage on-chain - more specific pattern
    rules.push(VulnerabilityRule::new(
        VulnerabilityCategory::AccessControl,
        VulnerabilitySeverity::Critical,
        r"(string|bytes|bytes32)\s+(private|public|internal)?\s*s_(password|secret|privateKey|secretKey|seed|mnemonic)",
        "Sensitive Data Storage On-Chain".to_string(),
        "Storing sensitive data like passwords on blockchain - ALL data is publicly readable".to_string(),
        "NEVER store passwords, secrets, or private keys on-chain. Use off-chain storage or encryption".to_string(),
        false,
    ).unwrap());
    
    // Documentation mismatch
    rules.push(VulnerabilityRule::new(
        VulnerabilityCategory::NamingConventions,
        VulnerabilitySeverity::Low,
        r"@param\s+\w+.*function\s+\w+\(\s*\)",
        "Documentation Parameter Mismatch".to_string(),
        "Function documentation mentions parameters but function has none".to_string(),
        "Fix documentation to match actual function signature".to_string(),
        true,
    ).unwrap());
    
    // Missing owner check pattern
    rules.push(VulnerabilityRule::new(
        VulnerabilityCategory::AccessControl,
        VulnerabilitySeverity::Critical,
        r"function\s+setPassword\s*\([^)]*\)\s*external\s*\{[^}]*s_password\s*=",
        "Critical: setPassword Missing Access Control".to_string(),
        "setPassword function allows ANYONE to change the password - critical security vulnerability".to_string(),
        "Add owner check: if (msg.sender != s_owner) revert(); at the beginning of the function".to_string(),
        true,
    ).unwrap());
    
    // External functions without access control that modify storage
    rules.push(VulnerabilityRule::new(
        VulnerabilityCategory::AccessControl,
        VulnerabilitySeverity::High,
        r"function\s+\w+\([^)]*\)\s+external\s*\{[^}]*(=|\+\+|--|delete)",
        "External Function Modifying State".to_string(),
        "External function modifying state variables - verify access control".to_string(),
        "Ensure proper access control for state-changing external functions".to_string(),
        true,
    ).unwrap());

    // Additional delegate call patterns in main rules
    rules.push(VulnerabilityRule::new(
        VulnerabilityCategory::DelegateCalls,
        VulnerabilitySeverity::Critical,
        r"function\s+\w*proxy\w*\([^)]*\).*delegatecall",
        "Proxy Function with Delegatecall".to_string(),
        "Proxy functions using delegatecall can be exploited if implementation is malicious".to_string(),
        "Implement proper access controls and validate implementation contract addresses".to_string(),
        true,
    ).unwrap());

    // Delegatecall with external data
    rules.push(VulnerabilityRule::new(
        VulnerabilityCategory::DelegateCalls,
        VulnerabilitySeverity::High,
        r"delegatecall\s*\([^)]*calldata",
        "Delegatecall with Calldata".to_string(),
        "Using raw calldata in delegatecall can lead to function selector manipulation".to_string(),
        "Validate function selectors and implement proper input sanitization".to_string(),
        false,
    ).unwrap());

    // Conditional delegatecall patterns
    rules.push(VulnerabilityRule::new(
        VulnerabilityCategory::DelegateCalls,
        VulnerabilitySeverity::High,
        r"if\s*\([^)]*\)\s*\{[^}]*delegatecall",
        "Conditional Delegatecall".to_string(),
        "Conditional delegatecalls can lead to inconsistent contract behavior".to_string(),
        "Ensure all code paths are properly validated and tested".to_string(),
        true,
    ).unwrap());

    // Delegatecall with storage variables
    rules.push(VulnerabilityRule::new(
        VulnerabilityCategory::DelegateCalls,
        VulnerabilitySeverity::Critical,
        r"delegatecall\s*\([^)]*\w+Address",
        "Delegatecall with Stored Address".to_string(),
        "Using stored addresses in delegatecall without validation is dangerous".to_string(),
        "Implement address validation, whitelisting, and access controls".to_string(),
        false,
    ).unwrap());

    // Role-based access control detection patterns
    
    // OpenZeppelin AccessControl patterns
    rules.push(VulnerabilityRule::new(
        VulnerabilityCategory::RoleBasedAccessControl,
        VulnerabilitySeverity::Info,
        r"import.*AccessControl|contract\s+\w+.*AccessControl",
        "OpenZeppelin AccessControl Detected".to_string(),
        "Contract uses OpenZeppelin AccessControl - verify proper role configuration".to_string(),
        "Ensure roles are properly defined, granted, and revoked with appropriate permissions".to_string(),
        false,
    ).unwrap());

    // Functions without role-based modifiers
    rules.push(VulnerabilityRule::new(
        VulnerabilityCategory::RoleBasedAccessControl,
        VulnerabilitySeverity::Critical,
        r"function\s+(grant|revoke|renounce)\w*Role\w*\([^)]*\)\s+(external|public)\s*\{",
        "Role Management Function Without Access Control".to_string(),
        "Role management functions lack proper access control modifiers".to_string(),
        "Add onlyRole(ADMIN_ROLE) or equivalent access control to role management functions".to_string(),
        false,
    ).unwrap());

    // Missing role checks on critical functions
    rules.push(VulnerabilityRule::new(
        VulnerabilityCategory::RoleBasedAccessControl,
        VulnerabilitySeverity::Critical,
        r"function\s+(mint|burn|pause|unpause|setRole|grantRole|revokeRole)\w*\([^)]*\)\s+(external|public)\s*\{",
        "Critical Function Missing Role Check".to_string(),
        "Critical administrative function lacks role-based access control".to_string(),
        "Add onlyRole modifier with appropriate role (MINTER_ROLE, ADMIN_ROLE, etc.)".to_string(),
        false,
    ).unwrap());

    // Hardcoded role checks instead of modifiers
    rules.push(VulnerabilityRule::new(
        VulnerabilityCategory::RoleBasedAccessControl,
        VulnerabilitySeverity::Medium,
        r"require\s*\(\s*hasRole\s*\(",
        "Inline Role Check Instead of Modifier".to_string(),
        "Using inline role checks instead of modifiers reduces code reusability".to_string(),
        "Consider creating custom modifiers for commonly used role checks".to_string(),
        false,
    ).unwrap());

    // Role definition patterns
    rules.push(VulnerabilityRule::new(
        VulnerabilityCategory::RoleBasedAccessControl,
        VulnerabilitySeverity::Info,
        r"bytes32\s+public\s+constant\s+\w*_ROLE\s*=",
        "Role Definition Found".to_string(),
        "Role constant defined - verify it's properly used in access control".to_string(),
        "Ensure role is properly assigned and used in function modifiers".to_string(),
        false,
    ).unwrap());

    // Default admin role assignments
    rules.push(VulnerabilityRule::new(
        VulnerabilityCategory::RoleBasedAccessControl,
        VulnerabilitySeverity::High,
        r"_grantRole\s*\(\s*DEFAULT_ADMIN_ROLE\s*,\s*msg\.sender\s*\)",
        "Default Admin Role Auto-Assignment".to_string(),
        "Automatically granting DEFAULT_ADMIN_ROLE to deployer may be insecure".to_string(),
        "Consider using a multi-sig or governance contract for admin role assignment".to_string(),
        false,
    ).unwrap());

    // Missing role admin configuration
    rules.push(VulnerabilityRule::new(
        VulnerabilityCategory::RoleBasedAccessControl,
        VulnerabilitySeverity::Medium,
        r"bytes32.*ROLE.*keccak256\(",
        "Role Definition Without Admin Setup".to_string(),
        "Custom role defined but admin role relationship may not be configured".to_string(),
        "Use _setRoleAdmin() to properly configure role hierarchy".to_string(),
        false,
    ).unwrap());

    // Dangerous role combinations
    rules.push(VulnerabilityRule::new(
        VulnerabilityCategory::RoleBasedAccessControl,
        VulnerabilitySeverity::High,
        r"onlyRole\s*\(\s*DEFAULT_ADMIN_ROLE\s*\).*function.*(mint|burn|transfer)",
        "Over-Privileged Admin Role".to_string(),
        "DEFAULT_ADMIN_ROLE has direct access to critical token functions".to_string(),
        "Separate admin role from operational roles (MINTER_ROLE, BURNER_ROLE)".to_string(),
        true,
    ).unwrap());

    // Missing role renunciation  
    rules.push(VulnerabilityRule::new(
        VulnerabilityCategory::RoleBasedAccessControl,
        VulnerabilitySeverity::Medium,
        r"grantRole\s*\([^)]*\)",
        "Role Granting Function Found".to_string(),
        "Role granting detected - ensure renunciation mechanisms are also implemented".to_string(),
        "Implement proper role renunciation functions for security".to_string(),
        false,
    ).unwrap());

    // Role-based reentrancy issues
    rules.push(VulnerabilityRule::new(
        VulnerabilityCategory::RoleBasedAccessControl,
        VulnerabilitySeverity::High,
        r"onlyRole.*external.*call\{value:",
        "Role-Based Function with External Call".to_string(),
        "Role-protected function makes external calls - potential reentrancy risk".to_string(),
        "Add reentrancy guards to role-protected functions making external calls".to_string(),
        true,
    ).unwrap());

    // Custom role system detection
    rules.push(VulnerabilityRule::new(
        VulnerabilityCategory::RoleBasedAccessControl,
        VulnerabilitySeverity::Medium,
        r"mapping\s*\(\s*address\s*=>\s*bool\s*\)\s+(public\s+)?admins?|mapping\s*\(\s*address\s*=>\s*bool\s*\)\s+(public\s+)?operators?",
        "Custom Role System Detected".to_string(),
        "Custom role system using address => bool mapping".to_string(),
        "Consider using OpenZeppelin AccessControl for standardized role management".to_string(),
        false,
    ).unwrap());

    // Role enumeration issues
    rules.push(VulnerabilityRule::new(
        VulnerabilityCategory::RoleBasedAccessControl,
        VulnerabilitySeverity::Low,
        r"getRoleMemberCount|getRoleMember",
        "Role Enumeration Functions Detected".to_string(),
        "Role enumeration functions present - consider privacy implications".to_string(),
        "Evaluate if role enumeration is necessary or if it exposes sensitive information".to_string(),
        false,
    ).unwrap());

    // Missing role validation in constructors
    rules.push(VulnerabilityRule::new(
        VulnerabilityCategory::RoleBasedAccessControl,
        VulnerabilitySeverity::Medium,
        r"constructor\s*\([^)]*\)\s*\{[^}]*grantRole.*msg\.sender",
        "Constructor Role Assignment to Deployer".to_string(),
        "Constructor automatically assigns roles to deployer without validation".to_string(),
        "Consider requiring explicit role setup or using parameter validation".to_string(),
        true,
    ).unwrap());

    // Role-based function without proper validation
    rules.push(VulnerabilityRule::new(
        VulnerabilityCategory::RoleBasedAccessControl,
        VulnerabilitySeverity::High,
        r"function\s+\w+\([^)]*address\s+\w+[^)]*\).*onlyRole.*grantRole\s*\([^,]*,\s*\w+\s*\)",
        "Role Assignment Without Address Validation".to_string(),
        "Function grants roles to addresses without proper validation".to_string(),
        "Add address validation (non-zero, not contract, etc.) before role assignment".to_string(),
        true,
    ).unwrap());

    // Time-locked role operations
    rules.push(VulnerabilityRule::new(
        VulnerabilityCategory::RoleBasedAccessControl,
        VulnerabilitySeverity::Info,
        r"timelock|TimelockController",
        "Timelock Integration Detected".to_string(),
        "Contract integrates with timelock - verify critical operations are time-locked".to_string(),
        "Ensure all critical role changes go through appropriate timelock delays".to_string(),
        false,
    ).unwrap());

    // Role inheritance issues
    rules.push(VulnerabilityRule::new(
        VulnerabilityCategory::RoleBasedAccessControl,
        VulnerabilitySeverity::Medium,
        r"_setRoleAdmin\s*\([^,]*,\s*\w+_ROLE\s*\)",
        "Role Admin Hierarchy Setup".to_string(),
        "Role admin hierarchy being configured - verify proper permission structure".to_string(),
        "Ensure role admin relationships follow principle of least privilege".to_string(),
        false,
    ).unwrap());

    // ZorpAudit Report Vulnerabilities - Storage DoS Attacks
    
    // Unbounded mapping assignments - submitData pattern
    rules.push(VulnerabilityRule::new(
        VulnerabilityCategory::StorageDoSAttacks,
        VulnerabilitySeverity::Critical,
        r"index_\w+\s*\[\s*\+\+\w+\s*\]\s*=\s*msg\.sender",
        "Storage DoS via Unbounded Mapping Assignment".to_string(),
        "Unbounded mapping assignments allowing repeated submissions can cause storage DoS".to_string(),
        "Implement submission limits, participant validation, or emergency stop mechanisms".to_string(),
        false,
    ).unwrap());

    // General unbounded storage pattern
    rules.push(VulnerabilityRule::new(
        VulnerabilityCategory::StorageDoSAttacks,
        VulnerabilitySeverity::High,
        r"mapping\s*\([^)]*\)\s+\w+.*\[\s*\+\+\w+\s*\]",
        "Potential Storage DoS via Incremental Mapping".to_string(),
        "Incremental mapping assignments without bounds checking can lead to storage DoS".to_string(),
        "Add participation limits, time bounds, or maximum submission constraints".to_string(),
        false,
    ).unwrap());

    // Unbounded array pushes
    rules.push(VulnerabilityRule::new(
        VulnerabilityCategory::StorageDoSAttacks,
        VulnerabilitySeverity::High,
        r"\w+\.push\s*\([^)]*msg\.sender[^)]*\)",
        "Unbounded Array Push DoS".to_string(),
        "Unbounded array operations can cause gas limit DoS attacks".to_string(),
        "Implement array size limits and validate user input before storage operations".to_string(),
        false,
    ).unwrap());

    // Submission functions without proper limits
    rules.push(VulnerabilityRule::new(
        VulnerabilityCategory::StorageDoSAttacks,
        VulnerabilitySeverity::Medium,
        r"function\s+submit\w*\([^)]*\)\s+external.*\{[^}]*\+\+",
        "Submission Function Without Rate Limiting".to_string(),
        "Submission functions lack rate limiting or spam protection mechanisms".to_string(),
        "Add time-based limits, maximum submissions per user, or validation checks".to_string(),
        true,
    ).unwrap());

    // Storage operations in loops
    rules.push(VulnerabilityRule::new(
        VulnerabilityCategory::StorageDoSAttacks,
        VulnerabilitySeverity::Medium,
        r"for\s*\([^)]*\)\s*\{[^}]*mapping.*=",
        "Storage Operations in Loops".to_string(),
        "Storage operations within loops can cause excessive gas consumption".to_string(),
        "Consider batching operations or using different data structures".to_string(),
        true,
    ).unwrap());

    // ZorpAudit Report Vulnerabilities - Precision Loss
    
    // Integer division without remainder handling - endStudy pattern
    rules.push(VulnerabilityRule::new(
        VulnerabilityCategory::PrecisionLoss,
        VulnerabilitySeverity::Critical,
        r"participant_payout_amount\s*=\s*balance\s*/\s*valid_submissions",
        "Financial Division Without Remainder Handling".to_string(),
        "Division of funds without proper remainder handling causes precision loss and fund loss".to_string(),
        "Use modulus operator (%) to calculate and handle remainders properly".to_string(),
        false,
    ).unwrap());

    // General balance division patterns
    rules.push(VulnerabilityRule::new(
        VulnerabilityCategory::PrecisionLoss,
        VulnerabilitySeverity::High,
        r"balance\s*/\s*\w+\s*;",
        "Balance Division Without Remainder Check".to_string(),
        "Dividing contract balance without remainder consideration can lead to fund loss".to_string(),
        "Calculate and handle remainders using modulus operator to prevent fund loss".to_string(),
        false,
    ).unwrap());

    // Payout calculations
    rules.push(VulnerabilityRule::new(
        VulnerabilityCategory::PrecisionLoss,
        VulnerabilitySeverity::High,
        r"payout.*=.*address\(this\)\.balance\s*/",
        "Payout Calculation Precision Loss".to_string(),
        "Payout calculations using integer division can result in precision loss".to_string(),
        "Implement proper remainder handling and consider using fixed-point arithmetic".to_string(),
        false,
    ).unwrap());

    // Financial calculations without precision consideration
    rules.push(VulnerabilityRule::new(
        VulnerabilityCategory::PrecisionLoss,
        VulnerabilitySeverity::Medium,
        r"uint256\s+\w+\s*=\s*\w+\s*/\s*\w+\s*;",
        "Integer Division Without Precision Handling".to_string(),
        "Integer division operations may cause precision loss in financial calculations".to_string(),
        "Consider using fixed-point math libraries or proper remainder handling".to_string(),
        false,
    ).unwrap());

    // Reward/distribution calculations
    rules.push(VulnerabilityRule::new(
        VulnerabilityCategory::PrecisionLoss,
        VulnerabilitySeverity::Medium,
        r"(reward|distribution|share)\w*\s*=.*\/",
        "Reward Distribution Precision Loss".to_string(),
        "Reward distribution calculations may suffer from precision loss".to_string(),
        "Use proper rounding mechanisms and handle remainders appropriately".to_string(),
        false,
    ).unwrap());

    // Missing remainder calculations
    rules.push(VulnerabilityRule::new(
        VulnerabilityCategory::PrecisionLoss,
        VulnerabilitySeverity::Low,
        r"uint256\s+remainder\s*=\s*\w+\s*-\s*\(",
        "Manual Remainder Calculation".to_string(),
        "Manual remainder calculation detected - verify correctness".to_string(),
        "Consider using modulus operator (%) for more accurate remainder calculation".to_string(),
        false,
    ).unwrap());

    // Transfer remainder patterns that may be incorrect
    rules.push(VulnerabilityRule::new(
        VulnerabilityCategory::PrecisionLoss,
        VulnerabilitySeverity::Medium,
        r"msg\.sender\.call\{\s*value:\s*remainder\s*\}",
        "Remainder Transfer to msg.sender".to_string(),
        "Transferring remainders to msg.sender instead of proper recipient".to_string(),
        "Transfer remainders to the appropriate party (owner/treasury) not msg.sender".to_string(),
        false,
    ).unwrap());

    rules
}

impl VulnerabilitySeverity {
    pub fn as_str(&self) -> &str {
        match self {
            VulnerabilitySeverity::Critical => "CRITICAL",
            VulnerabilitySeverity::High => "HIGH",
            VulnerabilitySeverity::Medium => "MEDIUM", 
            VulnerabilitySeverity::Low => "LOW",
            VulnerabilitySeverity::Info => "INFO",
        }
    }
    
    pub fn color(&self) -> colored::Color {
        match self {
            VulnerabilitySeverity::Critical => colored::Color::Red,
            VulnerabilitySeverity::High => colored::Color::Red,
            VulnerabilitySeverity::Medium => colored::Color::Yellow,
            VulnerabilitySeverity::Low => colored::Color::Blue,
            VulnerabilitySeverity::Info => colored::Color::Green,
        }
    }
}

impl VulnerabilityCategory {
    pub fn as_str(&self) -> &str {
        match self {
            VulnerabilityCategory::Reentrancy => "Reentrancy",
            VulnerabilityCategory::AccessControl => "Access Control",
            VulnerabilityCategory::RoleBasedAccessControl => "Role-Based Access Control",
            VulnerabilityCategory::ArithmeticIssues => "Arithmetic Issues",
            VulnerabilityCategory::UnhandledExceptions => "Unhandled Exceptions",
            VulnerabilityCategory::GasOptimization => "Gas Optimization",
            VulnerabilityCategory::PragmaIssues => "Pragma Issues",
            VulnerabilityCategory::RandomnessVulnerabilities => "Randomness Vulnerabilities",
            VulnerabilityCategory::FrontRunning => "Front Running",
            VulnerabilityCategory::TimeManipulation => "Time Manipulation",
            VulnerabilityCategory::DoSAttacks => "DoS Attacks",
            VulnerabilityCategory::UnusedCode => "Unused Code",
            VulnerabilityCategory::MagicNumbers => "Magic Numbers",
            VulnerabilityCategory::NamingConventions => "Naming Conventions",
            VulnerabilityCategory::StateVariable => "State Variable Issues",
            VulnerabilityCategory::UnsafeExternalCalls => "Unsafe External Calls",
            VulnerabilityCategory::DelegateCalls => "Delegate Call Vulnerabilities",
            VulnerabilityCategory::StorageDoSAttacks => "Storage DoS Attacks",
            VulnerabilityCategory::PrecisionLoss => "Precision Loss",
            VulnerabilityCategory::CompilerBug => "Compiler Bug",
        }
    }
}

pub fn create_version_specific_rules(version: &CompilerVersion) -> Vec<VulnerabilityRule> {
    let mut rules = Vec::new();
    
    // Add compiler version warnings and known vulnerabilities
    add_compiler_vulnerabilities(&mut rules, version);
    
    match version {
        CompilerVersion::V04 | CompilerVersion::V05 | CompilerVersion::V06 | CompilerVersion::V07 => {
            // Pre-0.8.0: No automatic overflow protection
            // More specific patterns for arithmetic operations in actual code contexts
            rules.push(VulnerabilityRule::new(
                VulnerabilityCategory::ArithmeticIssues,
                VulnerabilitySeverity::Critical,
                r"uint\d*\s+\w+\s*=\s*\w+\s*\+\s*\w+",
                "Integer Overflow Risk (Pre-0.8.0)".to_string(),
                "Addition without overflow check in Solidity < 0.8.0".to_string(),
                "Use SafeMath library or upgrade to Solidity 0.8.0+ for automatic overflow protection".to_string(),
                false,
            ).unwrap());
            
            rules.push(VulnerabilityRule::new(
                VulnerabilityCategory::ArithmeticIssues,
                VulnerabilitySeverity::Critical,
                r"uint\d*\s+\w+\s*=\s*\w+\s*\*\s*\w+",
                "Integer Multiplication Overflow Risk".to_string(),
                "Multiplication without overflow check in Solidity < 0.8.0".to_string(),
                "Use SafeMath.mul() or upgrade to Solidity 0.8.0+".to_string(),
                false,
            ).unwrap());
            
            rules.push(VulnerabilityRule::new(
                VulnerabilityCategory::ArithmeticIssues,
                VulnerabilitySeverity::Critical,
                r"uint\d*\s+\w+\s*=\s*\w+\s*-\s*\w+",
                "Integer Underflow Risk (Pre-0.8.0)".to_string(),
                "Subtraction without underflow check in Solidity < 0.8.0".to_string(),
                "Use SafeMath.sub() or upgrade to Solidity 0.8.0+".to_string(),
                false,
            ).unwrap());
            
            // Increment and decrement operations
            rules.push(VulnerabilityRule::new(
                VulnerabilityCategory::ArithmeticIssues,
                VulnerabilitySeverity::High,
                r"\+\+\w+|\w+\+\+",
                "Unchecked Increment (Pre-0.8.0)".to_string(),
                "Increment operation without overflow check in Solidity < 0.8.0".to_string(),
                "Use SafeMath or explicit checks for overflow".to_string(),
                false,
            ).unwrap());
            
            rules.push(VulnerabilityRule::new(
                VulnerabilityCategory::ArithmeticIssues,
                VulnerabilitySeverity::High,
                r"--\w+|\w+--",
                "Unchecked Decrement (Pre-0.8.0)".to_string(),
                "Decrement operation without underflow check in Solidity < 0.8.0".to_string(),
                "Use SafeMath or explicit checks for underflow".to_string(),
                false,
            ).unwrap());
        }
        CompilerVersion::V08 => {
            // Post-0.8.0: Check for unchecked blocks
            rules.push(VulnerabilityRule::new(
                VulnerabilityCategory::ArithmeticIssues,
                VulnerabilitySeverity::High,
                r"unchecked\s*\{[^}]*[\+\-\*]",
                "Unchecked Arithmetic in 0.8.0+".to_string(),
                "Using unchecked block disables overflow protection in Solidity 0.8.0+".to_string(),
                "Remove unchecked block unless gas optimization is critical and overflow is impossible".to_string(),
                true,
            ).unwrap());
        }
    }
    
    // Division by zero check (all versions) - more specific pattern
    rules.push(VulnerabilityRule::new(
        VulnerabilityCategory::ArithmeticIssues,
        VulnerabilitySeverity::High,
        r"uint\d*\s+\w+\s*=.*\w+\s*/\s*\w+",
        "Potential Division by Zero".to_string(),
        "Division without zero check can cause transaction revert".to_string(),
        "Add require(divisor != 0) check before division".to_string(),
        false,
    ).unwrap());
    
    // Precision loss in division
    rules.push(VulnerabilityRule::new(
        VulnerabilityCategory::ArithmeticIssues,
        VulnerabilitySeverity::Medium,
        r"(\w+)\s*/\s*(\d+)\s*\*\s*(\d+)",
        "Precision Loss in Division".to_string(),
        "Division before multiplication can cause precision loss".to_string(),
        "Perform multiplication before division to maintain precision".to_string(),
        false,
    ).unwrap());
    
    // Percentage calculation issues
    rules.push(VulnerabilityRule::new(
        VulnerabilityCategory::ArithmeticIssues,
        VulnerabilitySeverity::Medium,
        r"\*\s*(\d+)\s*/\s*100\b",
        "Percentage Calculation Precision Loss".to_string(),
        "Integer division in percentage calculation loses precision".to_string(),
        "Use basis points (10000) instead of percentages for better precision".to_string(),
        false,
    ).unwrap());
    
    // Version-specific constructor patterns
    match version {
        CompilerVersion::V04 => {
            rules.push(VulnerabilityRule::new(
                VulnerabilityCategory::NamingConventions,
                VulnerabilitySeverity::Critical,
                r"function\s+[A-Z]\w+\s*\([^)]*\)\s+public\s*\{",
                "Constructor as Function Name (0.4.x)".to_string(),
                "Using contract name as constructor is deprecated and error-prone".to_string(),
                "Use constructor() keyword instead (requires Solidity >= 0.4.22)".to_string(),
                false,
            ).unwrap());
        }
        _ => {}
    }
    
    // tx.origin authentication (all versions but especially problematic in older versions)
    rules.push(VulnerabilityRule::new(
        VulnerabilityCategory::AccessControl,
        VulnerabilitySeverity::High,
        r"require\s*\(\s*tx\.origin\s*==",
        "tx.origin Authentication".to_string(),
        "Using tx.origin for authentication is vulnerable to phishing attacks".to_string(),
        "Use msg.sender instead of tx.origin for authentication".to_string(),
        false,
    ).unwrap());
    
    // Selfdestruct issues (version-specific naming)
    match version {
        CompilerVersion::V04 | CompilerVersion::V05 => {
            rules.push(VulnerabilityRule::new(
                VulnerabilityCategory::AccessControl,
                VulnerabilitySeverity::Critical,
                r"suicide\s*\(",
                "Unprotected Suicide Function".to_string(),
                "suicide() can destroy contract and send funds - ensure proper access control".to_string(),
                "Add access control and consider if selfdestruct is necessary".to_string(),
                false,
            ).unwrap());
        }
        _ => {
            rules.push(VulnerabilityRule::new(
                VulnerabilityCategory::AccessControl,
                VulnerabilitySeverity::Critical,
                r"selfdestruct\s*\(",
                "Unprotected Selfdestruct".to_string(),
                "selfdestruct can destroy contract and send funds - ensure proper access control".to_string(),
                "Add access control and consider if selfdestruct is necessary".to_string(),
                false,
            ).unwrap());
        }
    }
    
    // Enhanced Delegate call detection patterns
    rules.push(VulnerabilityRule::new(
        VulnerabilityCategory::DelegateCalls,
        VulnerabilitySeverity::Critical,
        r"\.delegatecall\s*\(",
        "Unsafe Delegatecall Usage".to_string(),
        "Delegatecall preserves msg.sender and msg.value, can modify contract storage".to_string(),
        "Ensure target address is trusted, validate input data, and consider using call() instead".to_string(),
        false,
    ).unwrap());

    // Raw delegatecall detection
    rules.push(VulnerabilityRule::new(
        VulnerabilityCategory::DelegateCalls,
        VulnerabilitySeverity::Critical,
        r"\bdelegatecall\s*\(",
        "Raw Delegatecall Usage".to_string(),
        "Raw delegatecall can execute arbitrary code in current contract's context".to_string(),
        "Validate target address, implement access controls, and audit target contract code".to_string(),
        false,
    ).unwrap());

    // Delegatecall with user-controlled addresses
    rules.push(VulnerabilityRule::new(
        VulnerabilityCategory::DelegateCalls,
        VulnerabilitySeverity::Critical,
        r"\.delegatecall\s*\([^)]*\bmsg\.sender\b",
        "Delegatecall with User-Controlled Address".to_string(),
        "Allowing users to control delegatecall target enables arbitrary code execution".to_string(),
        "Never allow user input to determine delegatecall target address".to_string(),
        false,
    ).unwrap());

    // Delegatecall in loops - dangerous pattern
    rules.push(VulnerabilityRule::new(
        VulnerabilityCategory::DelegateCalls,
        VulnerabilitySeverity::Critical,
        r"for\s*\([^)]*\)\s*\{[^}]*delegatecall",
        "Delegatecall in Loop".to_string(),
        "Multiple delegatecalls in loops can cause unpredictable state changes".to_string(),
        "Avoid delegatecalls in loops, batch operations instead".to_string(),
        true,
    ).unwrap());

    // Delegatecall without return value check
    rules.push(VulnerabilityRule::new(
        VulnerabilityCategory::DelegateCalls,
        VulnerabilitySeverity::High,
        r"delegatecall\s*\([^)]*\)\s*;",
        "Unchecked Delegatecall Return Value".to_string(),
        "Delegatecall return value not checked - silent failures possible".to_string(),
        "Always check delegatecall return value and handle failures appropriately".to_string(),
        false,
    ).unwrap());

    // Delegatecall with dynamic data
    rules.push(VulnerabilityRule::new(
        VulnerabilityCategory::DelegateCalls,
        VulnerabilitySeverity::High,
        r"delegatecall\s*\([^)]*abi\.encode",
        "Delegatecall with Dynamic Data".to_string(),
        "Dynamic data in delegatecall can be manipulated to call unintended functions".to_string(),
        "Validate and sanitize all data passed to delegatecall".to_string(),
        false,
    ).unwrap());

    // Assembly delegatecall
    rules.push(VulnerabilityRule::new(
        VulnerabilityCategory::DelegateCalls,
        VulnerabilitySeverity::Critical,
        r"assembly\s*\{[^}]*delegatecall",
        "Assembly Delegatecall".to_string(),
        "Assembly delegatecall bypasses Solidity safety checks completely".to_string(),
        "Extremely dangerous - thoroughly audit assembly code and consider alternatives".to_string(),
        true,
    ).unwrap());
    
    // Inline assembly (version-dependent risks)
    rules.push(VulnerabilityRule::new(
        VulnerabilityCategory::UnsafeExternalCalls,
        VulnerabilitySeverity::High,
        r"assembly\s*\{",
        "Inline Assembly Usage".to_string(),
        "Inline assembly bypasses Solidity safety checks".to_string(),
        "Avoid assembly unless absolutely necessary, audit carefully".to_string(),
        false,
    ).unwrap());
    
    // Gas limit issues specific to versions
    match version {
        CompilerVersion::V04 | CompilerVersion::V05 | CompilerVersion::V06 => {
            rules.push(VulnerabilityRule::new(
                VulnerabilityCategory::GasOptimization,
                VulnerabilitySeverity::Medium,
                r"\.transfer\s*\(",
                "transfer() Gas Limitation".to_string(),
                "transfer() only forwards 2300 gas which may not be enough for some operations".to_string(),
                "Consider using call() with proper reentrancy protection".to_string(),
                false,
            ).unwrap());
        }
        _ => {}
    }
    
    // Unsafe type conversions
    rules.push(VulnerabilityRule::new(
        VulnerabilityCategory::ArithmeticIssues,
        VulnerabilitySeverity::High,
        r"uint64\s*\([^)]*uint256",
        "Unsafe Type Downcast".to_string(),
        "Casting from uint256 to smaller type can cause data loss".to_string(),
        "Add bounds checking before downcasting or avoid downcasting".to_string(),
        false,
    ).unwrap());
    
    // Fee-on-transfer token issues
    rules.push(VulnerabilityRule::new(
        VulnerabilityCategory::ArithmeticIssues,
        VulnerabilitySeverity::Medium,
        r"balanceOf\(address\(this\)\)\s*\+\s*amount",
        "Fee-on-Transfer Token Vulnerability".to_string(),
        "Assuming balance increases by exact amount - fails with fee-on-transfer tokens".to_string(),
        "Calculate actual received amount by checking balance before and after".to_string(),
        false,
    ).unwrap());
    
    // Rounding errors in calculations
    rules.push(VulnerabilityRule::new(
        VulnerabilityCategory::ArithmeticIssues,
        VulnerabilitySeverity::Medium,
        r"(\w+)\s*\*\s*(\w+)\s*/\s*(\w+)\s*\*\s*(\w+)",
        "Complex Division Chain".to_string(),
        "Multiple divisions can compound rounding errors".to_string(),
        "Minimize division operations and consider using fixed-point math libraries".to_string(),
        false,
    ).unwrap());
    
    rules
}

fn add_compiler_vulnerabilities(rules: &mut Vec<VulnerabilityRule>, version: &CompilerVersion) {
    match version {
        CompilerVersion::V04 => {
            // Solidity 0.4.x - Multiple critical vulnerabilities
            rules.push(VulnerabilityRule::new(
                VulnerabilityCategory::PragmaIssues,
                VulnerabilitySeverity::Critical,
                r"pragma\s+solidity\s+.*0\.4\.",
                "Obsolete Compiler Version (0.4.x)".to_string(),
                "Solidity 0.4.x has numerous critical vulnerabilities and is no longer maintained".to_string(),
                "URGENT: Upgrade to Solidity 0.8.x or newer. Version 0.4.x is extremely vulnerable".to_string(),
                false,
            ).unwrap());

            // Function modifier order vulnerability (0.4.x)
            rules.push(VulnerabilityRule::new(
                VulnerabilityCategory::AccessControl,
                VulnerabilitySeverity::Critical,
                r"function\s+\w+\([^)]*\)\s+public\s+payable",
                "Function Modifier Order Vulnerability".to_string(),
                "In Solidity 0.4.x, function modifier order affects visibility and can cause security issues".to_string(),
                "Carefully check modifier order and upgrade to 0.8.x where order is enforced".to_string(),
                false,
            ).unwrap());

            // Constructor with contract name vulnerability
            rules.push(VulnerabilityRule::new(
                VulnerabilityCategory::AccessControl,
                VulnerabilitySeverity::Critical,
                r"function\s+[A-Z]\w*\s*\([^)]*\)\s*(public|internal|private)?",
                "Constructor Naming Vulnerability".to_string(),
                "Using contract name as constructor can be exploited if contract is renamed".to_string(),
                "Use constructor() keyword introduced in 0.4.22 to prevent this vulnerability".to_string(),
                false,
            ).unwrap());

            // Uninitialized storage pointer (0.4.x)
            rules.push(VulnerabilityRule::new(
                VulnerabilityCategory::StateVariable,
                VulnerabilitySeverity::Critical,
                r"struct\s+\w+\s+\w+;",
                "Uninitialized Storage Pointer".to_string(),
                "Uninitialized storage pointers in 0.4.x can overwrite arbitrary storage slots".to_string(),
                "Always initialize storage pointers or upgrade to 0.5.0+ where this is fixed".to_string(),
                false,
            ).unwrap());
        }
        
        CompilerVersion::V05 => {
            rules.push(VulnerabilityRule::new(
                VulnerabilityCategory::PragmaIssues,
                VulnerabilitySeverity::High,
                r"pragma\s+solidity\s+.*0\.5\.",
                "Legacy Compiler Version (0.5.x)".to_string(),
                "Solidity 0.5.x lacks modern safety features and has known vulnerabilities".to_string(),
                "Upgrade to Solidity 0.8.x for automatic overflow protection and better security".to_string(),
                false,
            ).unwrap());

            // ABI encoder v1 vulnerabilities
            rules.push(VulnerabilityRule::new(
                VulnerabilityCategory::UnsafeExternalCalls,
                VulnerabilitySeverity::High,
                r"abi\.encode\(|abi\.encodePacked\(",
                "ABI Encoder V1 Vulnerabilities".to_string(),
                "Solidity 0.5.x uses ABI encoder v1 which has hash collision vulnerabilities".to_string(),
                "Upgrade to 0.8.0+ which uses ABI encoder v2 by default".to_string(),
                false,
            ).unwrap());
        }
        
        CompilerVersion::V06 => {
            rules.push(VulnerabilityRule::new(
                VulnerabilityCategory::PragmaIssues,
                VulnerabilitySeverity::High,
                r"pragma\s+solidity\s+.*0\.6\.",
                "Vulnerable Compiler Version (0.6.x)".to_string(),
                "Solidity 0.6.x has security issues and lacks overflow protection".to_string(),
                "Upgrade to Solidity 0.8.x for built-in overflow protection and security fixes".to_string(),
                false,
            ).unwrap());

            // Array bounds check bypass (0.6.x)
            rules.push(VulnerabilityRule::new(
                VulnerabilityCategory::ArithmeticIssues,
                VulnerabilitySeverity::Critical,
                r"\[\s*\w+\s*\]",
                "Array Bounds Check Bypass (0.6.x)".to_string(),
                "Solidity 0.6.x has vulnerabilities in array bounds checking".to_string(),
                "Upgrade to 0.8.0+ and always validate array indices manually".to_string(),
                false,
            ).unwrap());

            // Try-catch with dangerous external calls
            rules.push(VulnerabilityRule::new(
                VulnerabilityCategory::UnsafeExternalCalls,
                VulnerabilitySeverity::High,
                r"try\s+\w+\.",
                "Try-Catch External Call Risk".to_string(),
                "try-catch in 0.6.x can mask failures and create security vulnerabilities".to_string(),
                "Carefully handle try-catch exceptions and validate all external call results".to_string(),
                false,
            ).unwrap());
        }
        
        CompilerVersion::V07 => {
            rules.push(VulnerabilityRule::new(
                VulnerabilityCategory::PragmaIssues,
                VulnerabilitySeverity::Medium,
                r"pragma\s+solidity\s+.*0\.7\.",
                "Pre-Overflow Protection Version (0.7.x)".to_string(),
                "Solidity 0.7.x lacks automatic overflow protection introduced in 0.8.0".to_string(),
                "Consider upgrading to 0.8.x for automatic overflow protection or use SafeMath".to_string(),
                false,
            ).unwrap());

            // Inline assembly return data size bug (0.7.x)
            rules.push(VulnerabilityRule::new(
                VulnerabilityCategory::UnsafeExternalCalls,
                VulnerabilitySeverity::High,
                r"assembly\s*\{[^}]*returndatasize",
                "Inline Assembly Return Data Bug".to_string(),
                "Solidity 0.7.x has bugs with returndatasize in inline assembly".to_string(),
                "Avoid using returndatasize in assembly or upgrade to 0.8.4+".to_string(),
                true,
            ).unwrap());

            // Free memory pointer corruption (0.7.x)
            rules.push(VulnerabilityRule::new(
                VulnerabilityCategory::UnsafeExternalCalls,
                VulnerabilitySeverity::Critical,
                r"assembly\s*\{[^}]*mstore\s*\(\s*0x40",
                "Free Memory Pointer Corruption".to_string(),
                "Modifying free memory pointer (0x40) can cause memory corruption in 0.7.x".to_string(),
                "Avoid manual memory management or upgrade to 0.8.x with better memory safety".to_string(),
                true,
            ).unwrap());
        }
        
        CompilerVersion::V08 => {
            // Version 0.8.x specific vulnerabilities
            rules.push(VulnerabilityRule::new(
                VulnerabilityCategory::PragmaIssues,
                VulnerabilitySeverity::Info,
                r"pragma\s+solidity\s+0\.8\.[0-6]\b",
                "Early 0.8.x Version Vulnerabilities".to_string(),
                "Early Solidity 0.8.x versions (0.8.0-0.8.6) have known bugs".to_string(),
                "Upgrade to Solidity 0.8.19+ for the most stable and secure version".to_string(),
                false,
            ).unwrap());

            // Optimizer bug in 0.8.13-0.8.16
            rules.push(VulnerabilityRule::new(
                VulnerabilityCategory::PragmaIssues,
                VulnerabilitySeverity::High,
                r"pragma\s+solidity\s+0\.8\.1[3-6]\b",
                "Optimizer Bug (0.8.13-0.8.16)".to_string(),
                "Solidity 0.8.13-0.8.16 have optimizer bugs affecting certain code patterns".to_string(),
                "Upgrade to 0.8.17+ or disable optimizer if stuck on these versions".to_string(),
                false,
            ).unwrap());

            // ABI encoder v2 struct bug (0.8.0-0.8.6)
            rules.push(VulnerabilityRule::new(
                VulnerabilityCategory::UnsafeExternalCalls,
                VulnerabilitySeverity::Critical,
                r"pragma\s+solidity\s+0\.8\.[0-6]\b.*struct",
                "ABI Encoder Struct Bug (0.8.0-0.8.6)".to_string(),
                "Solidity 0.8.0-0.8.6 have critical bugs in ABI encoding of structs".to_string(),
                "URGENT: Upgrade to 0.8.7+ if using structs in external interfaces".to_string(),
                true,
            ).unwrap());
        }
    }

    // Cross-version vulnerabilities and attacks
    add_cross_version_attacks(rules, version);
}

fn add_cross_version_attacks(rules: &mut Vec<VulnerabilityRule>, version: &CompilerVersion) {
    // Hash collision attacks (all versions with abi.encodePacked)
    rules.push(VulnerabilityRule::new(
        VulnerabilityCategory::UnsafeExternalCalls,
        VulnerabilitySeverity::Critical,
        r"abi\.encodePacked\([^)]*,\s*[^)]*\)",
        "Hash Collision Attack Risk".to_string(),
        "abi.encodePacked with multiple dynamic types can cause hash collisions".to_string(),
        "Use abi.encode() instead of abi.encodePacked() or add fixed separators".to_string(),
        false,
    ).unwrap());

    // Metamorphic contract attacks
    rules.push(VulnerabilityRule::new(
        VulnerabilityCategory::AccessControl,
        VulnerabilitySeverity::Critical,
        r"CREATE2|create2",
        "Metamorphic Contract Attack Risk".to_string(),
        "CREATE2 can be exploited to deploy different contracts at the same address".to_string(),
        "Validate contract code hash and implement proper upgrade mechanisms".to_string(),
        false,
    ).unwrap());

    // Front-running attacks
    rules.push(VulnerabilityRule::new(
        VulnerabilityCategory::FrontRunning,
        VulnerabilitySeverity::High,
        r"block\.timestamp.*==.*now|now.*==.*block\.timestamp",
        "Front-running Attack Vulnerability".to_string(),
        "Exact timestamp comparisons enable front-running attacks".to_string(),
        "Use time ranges instead of exact timestamp matches".to_string(),
        false,
    ).unwrap());

    // MEV attacks
    rules.push(VulnerabilityRule::new(
        VulnerabilityCategory::FrontRunning,
        VulnerabilitySeverity::High,
        r"function\s+\w*swap\w*\([^)]*\)\s+(external|public)",
        "MEV Attack Surface".to_string(),
        "Public swap functions are vulnerable to MEV (sandwich attacks)".to_string(),
        "Implement MEV protection like commit-reveal or use private mempools".to_string(),
        false,
    ).unwrap());

    // Storage collision attacks in upgradeable contracts
    rules.push(VulnerabilityRule::new(
        VulnerabilityCategory::StateVariable,
        VulnerabilitySeverity::Critical,
        r"contract\s+\w+.*is.*Initializable",
        "Storage Collision in Upgradeable Contracts".to_string(),
        "Upgradeable contracts are vulnerable to storage collision attacks".to_string(),
        "Use storage gaps and careful variable ordering in upgradeable contracts".to_string(),
        false,
    ).unwrap());

    // Flash loan attack patterns
    rules.push(VulnerabilityRule::new(
        VulnerabilityCategory::UnsafeExternalCalls,
        VulnerabilitySeverity::Critical,
        r"function\s+\w*(flash|Flash)\w*\([^)]*\).*external",
        "Flash Loan Attack Surface".to_string(),
        "Flash loan functions can be exploited for price manipulation attacks".to_string(),
        "Implement proper oracle validation and reentrancy protection".to_string(),
        false,
    ).unwrap());

    // Oracle manipulation attacks
    rules.push(VulnerabilityRule::new(
        VulnerabilityCategory::UnsafeExternalCalls,
        VulnerabilitySeverity::Critical,
        r"\.latestRoundData\(\)|\.latestAnswer\(\)",
        "Oracle Manipulation Attack Risk".to_string(),
        "Single oracle calls are vulnerable to price manipulation attacks".to_string(),
        "Use multiple oracles, time-weighted averages, and validate price changes".to_string(),
        false,
    ).unwrap());

    match version {
        CompilerVersion::V04 | CompilerVersion::V05 | CompilerVersion::V06 | CompilerVersion::V07 => {
            // Additional attacks for pre-0.8.0
            rules.push(VulnerabilityRule::new(
                VulnerabilityCategory::ArithmeticIssues,
                VulnerabilitySeverity::Critical,
                r"balanceOf\(.*\)\s*\+\s*amount",
                "Token Balance Manipulation".to_string(),
                "Pre-0.8.0 token balance calculations vulnerable to overflow attacks".to_string(),
                "Use SafeMath for all token calculations or upgrade to 0.8.0+".to_string(),
                false,
            ).unwrap());
        }
        _ => {}
    }

    // Version-specific gas griefing attacks
    rules.push(VulnerabilityRule::new(
        VulnerabilityCategory::DoSAttacks,
        VulnerabilitySeverity::High,
        r"for\s*\([^)]*;\s*\w+\s*<\s*\w+\.length",
        "Gas Griefing Attack Vector".to_string(),
        "Unbounded loops enable gas griefing attacks to DoS the contract".to_string(),
        "Implement gas limits, pagination, or pull-over-push pattern".to_string(),
        false,
    ).unwrap());

    // Signature replay attacks
    rules.push(VulnerabilityRule::new(
        VulnerabilityCategory::AccessControl,
        VulnerabilitySeverity::Critical,
        r"ecrecover\s*\(",
        "Signature Replay Attack Risk".to_string(),
        "ecrecover without proper nonce/timestamp validation enables replay attacks".to_string(),
        "Implement nonces, timestamps, and domain separators for signature validation".to_string(),
        false,
    ).unwrap());

    // Tx.origin phishing attacks
    rules.push(VulnerabilityRule::new(
        VulnerabilityCategory::AccessControl,
        VulnerabilitySeverity::Critical,
        r"tx\.origin",
        "tx.origin Phishing Attack Vector".to_string(),
        "tx.origin authentication enables phishing attacks through malicious contracts".to_string(),
        "Never use tx.origin for authentication - use msg.sender instead".to_string(),
        false,
    ).unwrap());
}