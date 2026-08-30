use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Result;
use std::path::Path;

// Compiled once per process — version parsing runs for every scanned file.
static VERSION_TRIPLE_RE: Lazy<regex::Regex> =
    Lazy::new(|| regex::Regex::new(r"(\d+)\.(\d+)\.(\d+)").unwrap());

/// Exclusive upper bound of a range pragma, e.g. the `<0.9.0` in `>=0.4.22 <0.9.0`.
static PRAGMA_UPPER_BOUND_RE: Lazy<regex::Regex> =
    Lazy::new(|| regex::Regex::new(r"<\s*(\d+)\.(\d+)(?:\.\d+)?").unwrap());

/// Any `major.minor` pair appearing in a pragma.
static PRAGMA_VERSION_PAIR_RE: Lazy<regex::Regex> =
    Lazy::new(|| regex::Regex::new(r"(\d+)\.(\d+)(?:\.\d+)?").unwrap());

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum CompilerVersion {
    V04, // 0.4.x - Very old, many issues
    V05, // 0.5.x - Breaking changes from 0.4
    V06, // 0.6.x - Try-catch, array slices
    V07, // 0.7.x - Last version before overflow protection
    V08, // 0.8.x - Built-in overflow protection
}

#[derive(Debug, Clone, PartialEq)]
pub struct DetailedVersion {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
}

impl std::fmt::Display for DetailedVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

/// How the pragma constrains the compiler version.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum PragmaConstraint {
    /// `^0.8.19` — allows patches but not minor bumps
    Caret,
    /// `>=0.8.0` — allows any version at or above
    GreaterEqual,
    /// `>=0.8.0 <0.9.0` — bounded range
    Range,
    /// `0.8.19` — exact pinned version (no operator)
    Exact,
    /// `>0.8.0` — strictly greater
    Greater,
    /// Other or unparseable constraint
    Other,
}

impl std::fmt::Display for PragmaConstraint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PragmaConstraint::Caret => write!(f, "Floating (^)"),
            PragmaConstraint::GreaterEqual => write!(f, "Floating (>=)"),
            PragmaConstraint::Range => write!(f, "Range"),
            PragmaConstraint::Greater => write!(f, "Floating (>)"),
            PragmaConstraint::Exact => write!(f, "Pinned"),
            PragmaConstraint::Other => write!(f, "Unknown"),
        }
    }
}

/// How outdated the compiler version is.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum VersionAge {
    /// Latest stable (0.8.28+)
    Current,
    /// Recent but not latest (0.8.20-0.8.27)
    Recent,
    /// Getting old (0.8.0-0.8.19)
    Aging,
    /// Pre-0.8 without overflow protection (0.6-0.7)
    Outdated,
    /// Critically old (0.4-0.5)
    Critical,
}

impl std::fmt::Display for VersionAge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VersionAge::Current => write!(f, "Current"),
            VersionAge::Recent => write!(f, "Recent"),
            VersionAge::Aging => write!(f, "Aging"),
            VersionAge::Outdated => write!(f, "Outdated"),
            VersionAge::Critical => write!(f, "Critically Outdated"),
        }
    }
}

/// EVM features available at a given compiler version.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvmFeatures {
    /// Built-in overflow/underflow protection (0.8+)
    pub overflow_protection: bool,
    /// try/catch for external calls (0.6+)
    pub try_catch: bool,
    /// Custom errors with `error` keyword (0.8.4+)
    pub custom_errors: bool,
    /// User-defined value types (0.8.8+)
    pub user_defined_value_types: bool,
    /// PUSH0 opcode / Shanghai EVM target (0.8.20+)
    pub push0_opcode: bool,
    /// Transient storage TSTORE/TLOAD (0.8.24+)
    pub transient_storage: bool,
    /// Immutable variables (0.6.5+)
    pub immutable_vars: bool,
    /// ABI coder v2 by default (0.8.0+)
    pub abi_coder_v2_default: bool,
}

/// Comprehensive compiler version information extracted from a Solidity source file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompilerInfo {
    /// The raw pragma line (e.g., "pragma solidity ^0.8.19;")
    pub pragma_raw: String,
    /// Parsed version string (e.g., "0.8.19")
    pub version_string: String,
    /// Major.minor.patch components
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
    /// How the pragma constrains the version
    pub constraint: PragmaConstraint,
    /// Whether the pragma is floating (allows different versions to compile)
    pub is_floating: bool,
    /// How old this version is
    pub age: VersionAge,
    /// The latest recommended Solidity version
    pub latest_recommended: String,
    /// Whether an upgrade is recommended
    pub upgrade_recommended: bool,
    /// EVM features available at this version
    pub evm_features: EvmFeatures,
    /// Number of known compiler CVEs for this version
    pub known_cves: usize,
    /// Security recommendation based on version analysis
    pub security_note: String,
}

pub struct SolidityParser;

impl Default for SolidityParser {
    fn default() -> Self {
        Self::new()
    }
}

impl SolidityParser {
    pub fn new() -> Self {
        Self
    }

    pub fn read_file<P: AsRef<Path>>(&self, path: P) -> Result<String> {
        fs::read_to_string(path)
    }

    pub fn get_pragma_version(&self, content: &str) -> Option<String> {
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("pragma solidity") {
                return Some(trimmed.to_string());
            }
        }
        None
    }

    /// Determine which compiler generation's rule set applies to this source.
    ///
    /// The version selected is the HIGHEST the pragma permits, because that is what the
    /// project will actually be compiled with. This matters for range pragmas: the old
    /// implementation was an ordered chain of `pragma.contains("0.4.")` tests against the
    /// whole pragma string, so the ubiquitous `pragma solidity >=0.4.22 <0.9.0;` matched
    /// the first arm and was treated as Solidity 0.4 — running the entire legacy 0.4 rule
    /// set, including pre-0.8 unchecked-arithmetic findings, against code that in practice
    /// compiles under 0.8 and has built-in overflow checks.
    pub fn get_compiler_version(&self, content: &str) -> Option<CompilerVersion> {
        let pragma = self.get_pragma_version(content)?;

        // An exclusive upper bound (`<0.9.0`) caps the range: the highest usable minor is
        // one below it. This dominates any lower bound present in the same pragma.
        if let Some(caps) = PRAGMA_UPPER_BOUND_RE.captures(&pragma) {
            if let (Some(major), Some(minor)) = (caps.get(1), caps.get(2)) {
                let major: u32 = major.as_str().parse().ok()?;
                let minor: u32 = minor.as_str().parse().ok()?;
                // `<0.9.0` permits 0.8.x; `<0.8.0` permits 0.7.x.
                let effective_minor = minor.saturating_sub(1);
                return Self::minor_to_compiler_version(major, effective_minor);
            }
        }

        // Otherwise take the highest minor version mentioned anywhere in the pragma,
        // which covers both a bare pin (`0.8.20`) and a floor (`^0.8.0`, `>=0.6.2`).
        let mut best: Option<(u32, u32)> = None;
        for caps in PRAGMA_VERSION_PAIR_RE.captures_iter(&pragma) {
            let major: u32 = caps.get(1)?.as_str().parse().ok()?;
            let minor: u32 = caps.get(2)?.as_str().parse().ok()?;
            if best.is_none_or(|(bmaj, bmin)| (major, minor) > (bmaj, bmin)) {
                best = Some((major, minor));
            }
        }
        let (major, minor) = best?;
        Self::minor_to_compiler_version(major, minor)
    }

    /// Map a `major.minor` pair onto the coarse rule-set generation.
    ///
    /// Anything at or above 0.8 uses the 0.8 rule set; that is the newest generation the
    /// scanner models, and later releases keep 0.8's checked-arithmetic semantics.
    fn minor_to_compiler_version(major: u32, minor: u32) -> Option<CompilerVersion> {
        if major > 0 || minor >= 8 {
            return Some(CompilerVersion::V08);
        }
        match minor {
            7 => Some(CompilerVersion::V07),
            6 => Some(CompilerVersion::V06),
            5 => Some(CompilerVersion::V05),
            0..=4 => Some(CompilerVersion::V04),
            _ => None,
        }
    }

    pub fn get_detailed_version(&self, content: &str) -> Option<DetailedVersion> {
        if let Some(pragma) = self.get_pragma_version(content) {
            // Extract version number from pragma
            // Handles formats like: "^0.8.19", ">=0.8.0", "0.8.20", etc.
            if let Some(captures) = VERSION_TRIPLE_RE.captures(&pragma) {
                let major = captures.get(1)?.as_str().parse().ok()?;
                let minor = captures.get(2)?.as_str().parse().ok()?;
                let patch = captures.get(3)?.as_str().parse().ok()?;

                return Some(DetailedVersion {
                    major,
                    minor,
                    patch,
                });
            }
        }
        None
    }

    /// Extract comprehensive compiler information from contract source.
    /// Returns None if no pragma solidity statement is found.
    pub fn extract_compiler_info(&self, content: &str) -> Option<CompilerInfo> {
        let pragma_raw = self.get_pragma_version(content)?;
        let detailed = self.get_detailed_version(content)?;

        let version_string = format!("{}.{}.{}", detailed.major, detailed.minor, detailed.patch);

        // Determine pragma constraint type
        let constraint = {
            let after_solidity = pragma_raw
                .trim()
                .strip_prefix("pragma solidity")
                .unwrap_or("")
                .trim();
            if after_solidity.contains(">=") && after_solidity.contains('<') {
                PragmaConstraint::Range
            } else if after_solidity.starts_with('^') || after_solidity.contains('^') {
                PragmaConstraint::Caret
            } else if after_solidity.starts_with(">=") || after_solidity.contains(">=") {
                PragmaConstraint::GreaterEqual
            } else if after_solidity.starts_with('>') || after_solidity.contains('>') {
                PragmaConstraint::Greater
            } else if after_solidity
                .chars()
                .next()
                .is_some_and(|c| c.is_ascii_digit())
            {
                PragmaConstraint::Exact
            } else {
                PragmaConstraint::Other
            }
        };

        let is_floating = matches!(
            constraint,
            PragmaConstraint::Caret | PragmaConstraint::GreaterEqual | PragmaConstraint::Greater
        );

        // Determine version age
        let age = match (detailed.major, detailed.minor) {
            (0, 4) | (0, 5) => VersionAge::Critical,
            (0, 6) | (0, 7) => VersionAge::Outdated,
            (0, 8) if detailed.patch < 20 => VersionAge::Aging,
            (0, 8) if detailed.patch < 28 => VersionAge::Recent,
            (0, 8) => VersionAge::Current,
            _ => VersionAge::Current,
        };

        let latest_recommended = "0.8.28".to_string();
        let upgrade_recommended =
            !(detailed.major == 0 && detailed.minor == 8 && detailed.patch >= 28);

        // Determine EVM features
        let evm_features = EvmFeatures {
            overflow_protection: detailed.minor >= 8 || detailed.major > 0,
            try_catch: (detailed.minor >= 6 || detailed.major > 0),
            custom_errors: (detailed.minor > 8 || (detailed.minor == 8 && detailed.patch >= 4))
                || detailed.major > 0,
            user_defined_value_types: (detailed.minor > 8
                || (detailed.minor == 8 && detailed.patch >= 8))
                || detailed.major > 0,
            push0_opcode: (detailed.minor > 8 || (detailed.minor == 8 && detailed.patch >= 20))
                || detailed.major > 0,
            transient_storage: (detailed.minor > 8
                || (detailed.minor == 8 && detailed.patch >= 24))
                || detailed.major > 0,
            immutable_vars: (detailed.minor > 6 || (detailed.minor == 6 && detailed.patch >= 5))
                || detailed.major > 0,
            abi_coder_v2_default: detailed.minor >= 8 || detailed.major > 0,
        };

        // Count known CVEs
        let cves = self.is_version_vulnerable(&detailed);
        let known_cves = cves.len();

        // Build security note
        let security_note = match &age {
            VersionAge::Critical => format!(
                "CRITICAL: Solidity {} is severely outdated with {} known issues. \
                 Missing overflow protection, modern error handling, and years of security fixes. \
                 Upgrade to {} immediately.",
                version_string, known_cves, latest_recommended
            ),
            VersionAge::Outdated => format!(
                "WARNING: Solidity {} lacks built-in overflow protection and has {} known issues. \
                 Requires SafeMath for arithmetic safety. Upgrade to {} strongly recommended.",
                version_string, known_cves, latest_recommended
            ),
            VersionAge::Aging => format!(
                "Solidity {} has {} known compiler issues. \
                 Consider upgrading to {} for latest security patches and gas optimizations.",
                version_string, known_cves, latest_recommended
            ),
            VersionAge::Recent if known_cves > 0 => format!(
                "Solidity {} has {} minor known issue{}. \
                 Upgrading to {} is recommended for the latest fixes.",
                version_string,
                known_cves,
                if known_cves > 1 { "s" } else { "" },
                latest_recommended
            ),
            VersionAge::Recent => format!(
                "Solidity {} is a recent version with no critical known issues.",
                version_string
            ),
            VersionAge::Current => format!(
                "Solidity {} is a current version. No upgrade needed.",
                version_string
            ),
        };

        Some(CompilerInfo {
            pragma_raw,
            version_string,
            major: detailed.major,
            minor: detailed.minor,
            patch: detailed.patch,
            constraint,
            is_floating,
            age,
            latest_recommended,
            upgrade_recommended,
            evm_features,
            known_cves,
            security_note,
        })
    }

    pub fn is_version_vulnerable(&self, version: &DetailedVersion) -> Vec<String> {
        let mut vulnerabilities = Vec::new();

        match (version.major, version.minor) {
            // Solidity 0.8.x: cumulative CVE checks (each fires independently)
            (0, 8) => {
                let patch = version.patch;
                if patch <= 12 {
                    vulnerabilities.push(
                        "Version < 0.8.13: Vulnerable to optimizer bug with inline assembly"
                            .to_string(),
                    );
                }
                if patch <= 14 {
                    vulnerabilities
                        .push("Version < 0.8.15: ABI coder v2 issues with tuples".to_string());
                }
                if patch <= 16 {
                    vulnerabilities.push(
                        "Version < 0.8.17: Vulnerable to storage write reentrancy in libraries"
                            .to_string(),
                    );
                }
                if patch <= 18 {
                    vulnerabilities.push(
                        "Version < 0.8.19: Optimizer bug affecting constant expressions"
                            .to_string(),
                    );
                }
                if patch <= 19 {
                    vulnerabilities.push(
                        "Version < 0.8.20: Missing check in bytes.concat() with dynamic arrays"
                            .to_string(),
                    );
                }
                if patch <= 20 {
                    vulnerabilities.push(
                        "Version < 0.8.21: Potential issues with using for directive and libraries"
                            .to_string(),
                    );
                }
                if patch <= 21 {
                    vulnerabilities.push(
                        "Version < 0.8.22: Head overflow bug in calldata tuple decoder".to_string(),
                    );
                }
                if patch == 22 {
                    vulnerabilities.push(
                        "Version 0.8.22: Contains unchecked loop increment overflow bug"
                            .to_string(),
                    );
                }
                if patch <= 23 {
                    vulnerabilities.push(
                        "Version < 0.8.24: Missing check for extra data in CREATE2 deployments"
                            .to_string(),
                    );
                }
                if patch <= 24 {
                    vulnerabilities.push(
                        "Version < 0.8.25: Optimizer bug with multiple memory copies".to_string(),
                    );
                }
                if patch <= 25 {
                    vulnerabilities.push(
                        "Version < 0.8.26: Potential issues with transient storage (TSTORE/TLOAD)"
                            .to_string(),
                    );
                }
                if patch == 27 {
                    vulnerabilities.push("Version 0.8.27: Known issue with constructor visibility (deprecated but still compilable)".to_string());
                }
                if patch <= 27 {
                    vulnerabilities.push(
                        "Version < 0.8.28: Vulnerable to specific edge cases in unchecked blocks"
                            .to_string(),
                    );
                }
                if patch == 29 {
                    vulnerabilities.push("Version 0.8.29: Memory expansion cost miscalculation in specific scenarios".to_string());
                }
                if patch == 30 {
                    vulnerabilities.push("Version 0.8.30: Latest - Check Solidity blog for any recent security advisories".to_string());
                }
            }

            // Solidity 0.7.x vulnerabilities
            (0, 7) => {
                vulnerabilities.push(
                    "Version 0.7.x: No automatic overflow/underflow protection - use SafeMath"
                        .to_string(),
                );
                if version.patch < 6 {
                    vulnerabilities
                        .push("Version < 0.7.6: Vulnerable to shift operation bugs".to_string());
                }
            }

            // Solidity 0.6.x vulnerabilities
            (0, 6) => {
                vulnerabilities
                    .push("Version 0.6.x: No automatic overflow/underflow protection".to_string());
                if version.patch < 12 {
                    vulnerabilities.push(
                        "Version < 0.6.12: Array slice bug can cause data corruption".to_string(),
                    );
                }
            }

            // Solidity 0.5.x vulnerabilities
            (0, 5) => {
                vulnerabilities.push(
                    "Version 0.5.x: Outdated - many security improvements missing".to_string(),
                );
                if version.patch < 17 {
                    vulnerabilities.push("Version < 0.5.17: ABIEncoderV2 bugs present".to_string());
                }
            }

            // Solidity 0.4.x vulnerabilities
            (0, 4) => {
                vulnerabilities.push(
                    "Version 0.4.x: CRITICALLY OUTDATED - Multiple severe vulnerabilities"
                        .to_string(),
                );
                vulnerabilities
                    .push("No constructor keyword - using contract name is deprecated".to_string());
                vulnerabilities.push("No automatic overflow protection".to_string());
                vulnerabilities.push("Delegatecall return value not properly checked".to_string());
            }

            _ => {}
        }

        vulnerabilities
    }
}

/// Strip Solidity comments, preserving line count and column positions.
///
/// Every comment character is replaced by a space and every newline is kept, so a
/// stripped line has the same index and length as the raw line it came from. This is a
/// real state machine: it understands string literals, so `"https://example.com"` and
/// `revert("/* not a comment */")` survive intact.
///
/// This is the single source of truth for comment stripping. Three near-identical
/// copies previously existed; two of them used `line.split("//").next()`, which
/// truncated any line containing a URL in a string literal, and treated a continuation
/// line beginning with `*` as a comment.
///
/// Note: non-ASCII characters inside comments each become one ASCII space, so *byte*
/// offsets are not preserved for such files — line and character indices are.
pub fn strip_comments(content: &str) -> String {
    #[derive(PartialEq)]
    enum State {
        Code,
        LineComment,
        BlockComment,
        DoubleQuote,
        SingleQuote,
    }
    let mut out = String::with_capacity(content.len());
    let mut state = State::Code;
    let mut chars = content.chars().peekable();
    while let Some(c) = chars.next() {
        match state {
            State::Code => match c {
                '/' if chars.peek() == Some(&'/') => {
                    state = State::LineComment;
                    out.push(' ');
                }
                '/' if chars.peek() == Some(&'*') => {
                    state = State::BlockComment;
                    out.push(' ');
                }
                '"' => {
                    state = State::DoubleQuote;
                    out.push(c);
                }
                '\'' => {
                    state = State::SingleQuote;
                    out.push(c);
                }
                _ => out.push(c),
            },
            State::LineComment => {
                if c == '\n' {
                    state = State::Code;
                    out.push('\n');
                } else {
                    out.push(' ');
                }
            }
            State::BlockComment => {
                if c == '*' && chars.peek() == Some(&'/') {
                    chars.next();
                    out.push_str("  ");
                    state = State::Code;
                } else if c == '\n' {
                    out.push('\n');
                } else {
                    out.push(' ');
                }
            }
            State::DoubleQuote | State::SingleQuote => {
                let quote = if state == State::DoubleQuote {
                    '"'
                } else {
                    '\''
                };
                if c == '\\' {
                    out.push(c);
                    if let Some(next) = chars.next() {
                        out.push(next);
                    }
                } else {
                    if c == quote || c == '\n' {
                        state = State::Code;
                    }
                    out.push(c);
                }
            }
        }
    }
    out
}
