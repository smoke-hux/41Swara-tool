//! Secret redaction applied to every byte of source before it leaves the process.
//!
//! `.sol` files and the fixtures next to them routinely carry deployment private keys,
//! mnemonics and API tokens. The AI layer strips them *before* the prompt is built, so
//! a secret can never reach a remote provider even if the user did not notice it.
//!
//! The redaction is deliberately aggressive: it will occasionally blank a `bytes32`
//! storage-slot constant that merely looks like a 64-hex private key. Losing a constant
//! costs nothing for review quality; leaking a key is unrecoverable.

use once_cell::sync::Lazy;
use regex::Regex;

/// A single class of secret that was found and removed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SecretKind {
    /// 64 hex characters: an secp256k1 private key (or a look-alike constant).
    Hex64,
    /// A BIP-39 style seed phrase in a string literal.
    Mnemonic,
    /// A provider API token (Anthropic, OpenAI, AWS, GitHub, ...).
    ApiKey,
    /// A `key = "..."` / `password: '...'` style assignment.
    Assignment,
}

impl SecretKind {
    /// Placeholder substituted into the outgoing text.
    fn placeholder(self) -> &'static str {
        match self {
            SecretKind::Hex64 => "0x<REDACTED_HEX64>",
            SecretKind::Mnemonic => "\"<REDACTED_MNEMONIC>\"",
            SecretKind::ApiKey => "<REDACTED_API_KEY>",
            SecretKind::Assignment => "<REDACTED_SECRET>",
        }
    }

    /// Label used in the scan report.
    pub fn label(self) -> &'static str {
        match self {
            SecretKind::Hex64 => "private-key-shaped 64-hex literal",
            SecretKind::Mnemonic => "seed phrase",
            SecretKind::ApiKey => "API token",
            SecretKind::Assignment => "secret assignment",
        }
    }
}

/// Result of scrubbing a chunk of source.
#[derive(Debug, Clone, PartialEq)]
pub struct Redacted {
    /// The text that is safe to transmit.
    pub text: String,
    /// Which classes of secret were removed, deduplicated and sorted.
    pub kinds: Vec<SecretKind>,
    /// How many individual substitutions were made.
    pub count: usize,
}

static HEX64: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)\b(?:0x)?[0-9a-f]{64}\b").expect("HEX64 regex"));

// 12+ lowercase words separated by single spaces inside a quoted string: the shape of a
// BIP-39 mnemonic. Requires quotes so ordinary English prose in a comment is untouched.
static MNEMONIC: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"["']([a-z]{3,8}(?: [a-z]{3,8}){11,23})["']"#).expect("MNEMONIC regex")
});

static API_KEY: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?x)
        sk-ant-[A-Za-z0-9_\-]{16,}
      | sk-[A-Za-z0-9]{24,}
      | AKIA[0-9A-Z]{16}
      | gh[pousr]_[A-Za-z0-9]{20,}
      | xox[baprs]-[A-Za-z0-9\-]{10,}
      | AIza[0-9A-Za-z_\-]{30,}
    ",
    )
    .expect("API_KEY regex")
});

// `PRIVATE_KEY = "…"`, `mnemonic: '…'`, `apiKey="…"` and friends.
static ASSIGNMENT: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?i)((?:private[_\-]?key|secret[_\-]?key|api[_\-]?key|access[_\-]?token|auth[_\-]?token|passphrase|mnemonic|seed[_\-]?phrase|password)\s*[:=]\s*)["'][^"'\n]{8,}["']"#,
    )
    .expect("ASSIGNMENT regex")
});

/// Apply one rule in place, recording what it removed.
fn apply_rule(
    text: &mut String,
    re: &Regex,
    replacement: &str,
    kind: SecretKind,
    kinds: &mut Vec<SecretKind>,
    count: &mut usize,
) {
    let hits = re.find_iter(text.as_str()).count();
    if hits == 0 {
        return;
    }
    *count += hits;
    if !kinds.contains(&kind) {
        kinds.push(kind);
    }
    *text = re.replace_all(text.as_str(), replacement).into_owned();
}

/// Strip every secret-shaped literal from `input`.
///
/// Order matters: the narrow, high-signal patterns run first so that a mnemonic is
/// labelled as a mnemonic rather than being partially eaten by a broader rule. The
/// assignment rule keeps the left-hand side, so a reviewer still sees that a key was
/// configured here; only the value is destroyed.
pub fn redact(input: &str) -> Redacted {
    let mut text = input.to_string();
    let mut kinds: Vec<SecretKind> = Vec::new();
    let mut count = 0usize;

    let rules: [(&Regex, &str, SecretKind); 4] = [
        (
            &MNEMONIC,
            SecretKind::Mnemonic.placeholder(),
            SecretKind::Mnemonic,
        ),
        (
            &API_KEY,
            SecretKind::ApiKey.placeholder(),
            SecretKind::ApiKey,
        ),
        (
            &ASSIGNMENT,
            "${1}\"<REDACTED_SECRET>\"",
            SecretKind::Assignment,
        ),
        (&HEX64, SecretKind::Hex64.placeholder(), SecretKind::Hex64),
    ];
    for (re, replacement, kind) in rules {
        apply_rule(&mut text, re, replacement, kind, &mut kinds, &mut count);
    }

    kinds.sort();
    Redacted { text, kinds, count }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn removes_a_raw_private_key() {
        let src = "// deploy key: 0x4c0883a69102937d6231471b5dbb6204fe5129617082790f4b4b7f8b2c5c2b1a\nuint x;";
        let out = redact(src);
        assert!(!out.text.contains("4c0883a69102937d"));
        assert!(out.text.contains("0x<REDACTED_HEX64>"));
        assert_eq!(out.kinds, vec![SecretKind::Hex64]);
        assert_eq!(out.count, 1);
    }

    #[test]
    fn removes_a_mnemonic() {
        let src = r#"const m = "legal winner thank year wave sausage worth useful legal winner thank yellow";"#;
        let out = redact(src);
        assert!(!out.text.contains("sausage"));
        assert!(out.text.contains("<REDACTED_MNEMONIC>"));
        assert_eq!(out.kinds, vec![SecretKind::Mnemonic]);
    }

    #[test]
    fn removes_api_tokens_of_several_shapes() {
        let src = "sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAA\nAKIAIOSFODNN7EXAMPLE\nghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let out = redact(src);
        assert!(!out.text.contains("sk-ant-api03"));
        assert!(!out.text.contains("AKIAIOSFODNN7EXAMPLE"));
        assert!(!out.text.contains("ghp_"));
        assert_eq!(out.count, 3);
    }

    #[test]
    fn removes_assignment_values_but_keeps_the_name() {
        let src = "PRIVATE_KEY = \"hunter2hunter2hunter2\"\nmnemonic: 'this is not a real seed'";
        let out = redact(src);
        assert!(out.text.contains("PRIVATE_KEY ="));
        assert!(!out.text.contains("hunter2"));
        assert!(!out.text.contains("this is not a real seed"));
        assert!(out.kinds.contains(&SecretKind::Assignment));
    }

    #[test]
    fn ordinary_solidity_is_untouched() {
        let src = "function withdraw(uint256 amount) external {\n    balances[msg.sender] -= amount;\n    (bool ok, ) = msg.sender.call{value: amount}(\"\");\n    require(ok);\n}";
        let out = redact(src);
        assert_eq!(out.count, 0);
        assert_eq!(out.text, src);
    }

    #[test]
    fn addresses_survive_because_they_are_public_data() {
        let src = "address owner = 0x5B38Da6a701c568545dCfcB03FcB875f56beddC4;";
        let out = redact(src);
        assert_eq!(out.count, 0);
        assert!(out
            .text
            .contains("0x5B38Da6a701c568545dCfcB03FcB875f56beddC4"));
    }
}
