//! Declared-but-never-enforced analysis (41S-093, 41S-094).
//!
//! Both detections in this module share one shape: the source *declares* something
//! that reads as a safety guarantee, and then never honours it. That makes them
//! invisible to substring-matching rules, because the declaration itself contains
//! the very keyword a naive filter looks for. `scanner.rs`'s `MissingSwapDeadline`
//! filter, for instance, suppresses its finding whenever the word "deadline" appears
//! near the function - which an unused `uint64 deadline` parameter satisfies. The
//! bug hides its own detector.
//!
//! Both patterns are drawn from the public Cyfrin T-Swap audit (2023-09-01):
//!   * H-1 - `TSwapPool::deposit` accepts a `deadline` it never checks.
//!   * L-2 - `TSwapPool::swapExactInput` declares `returns (uint256 output)`,
//!     assigns a different local, and so always returns 0.
//!
//! This module deliberately does not reuse [`crate::logic_analyzer`]'s
//! `extract_functions`: that helper matches a signature and its opening brace on a
//! single line, so it skips every multi-line signature - the dominant style once
//! `forge fmt` wraps a long parameter list, and the exact style both T-Swap findings
//! live in. The small parser here walks braces and parentheses instead, so a
//! signature may span any number of lines.

use crate::vulnerabilities::{Vulnerability, VulnerabilityCategory, VulnerabilitySeverity};
use once_cell::sync::Lazy;
use regex::Regex;

/// Parameter names that carry a time-bound promise. Matched case-insensitively
/// against the whole identifier, so `deadline`, `_deadline` and `swapDeadline`
/// all qualify while `deadlineCount` style names still match on the stem.
static DEADLINE_NAMES: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)^_?(?:deadline|expiry|expires|expiration|validuntil|validbefore|notafter)$")
        .expect("static deadline-name regex")
});

/// Start of a function declaration. The parameter list and body are located by
/// balanced-delimiter scanning rather than by regex, so multi-line signatures work.
static FUNC_START: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\bfunction\s+(\w+)\s*\(").expect("static function-start regex"));

/// One declared parameter or named return: a type, optional data location and
/// modifiers, then the identifier. Only the trailing identifier is captured.
static DECL_IDENT: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(\w+)\s*$").expect("static declaration-identifier regex"));

/// A parsed Solidity function with its signature split into usable parts.
struct ParsedFunction {
    name: String,
    /// 1-based line of the `function` keyword.
    line_start: usize,
    /// Raw text between the parameter-list parentheses.
    params: String,
    /// Text between the parameter list and the opening brace: visibility,
    /// mutability, modifiers and the `returns (...)` clause.
    header_tail: String,
    /// Raw text between the outermost braces of the body.
    body: String,
}

/// Detects declarations that are never honoured.
pub struct UnusedDeclarationAnalyzer;

impl Default for UnusedDeclarationAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl UnusedDeclarationAnalyzer {
    pub fn new() -> Self {
        Self
    }

    /// Runs both passes over a contract source file.
    pub fn analyze(&self, content: &str) -> Vec<Vulnerability> {
        let mut findings = Vec::new();
        for func in parse_functions(content) {
            findings.extend(self.check_unenforced_deadline(&func));
            findings.extend(self.check_unassigned_named_return(&func));
        }
        findings
    }

    /// 41S-093: a `deadline`-shaped parameter that nothing consumes.
    ///
    /// The parameter counts as enforced if the identifier appears anywhere outside
    /// its own declaration - in a modifier argument (`revertIfDeadlinePassed(deadline)`),
    /// in a `require`/`if` in the body, or passed on to another call. Only a
    /// parameter that is declared and then never mentioned again is reported.
    fn check_unenforced_deadline(&self, func: &ParsedFunction) -> Vec<Vulnerability> {
        let mut findings = Vec::new();

        for param in split_top_level(&func.params) {
            let Some(ident) = declared_identifier(&param) else {
                continue;
            };
            if !DEADLINE_NAMES.is_match(&ident) {
                continue;
            }
            // The modifier list and the body are the two places the parameter could
            // legitimately be consumed.
            if identifier_used(&func.header_tail, &ident) || identifier_used(&func.body, &ident) {
                continue;
            }

            findings.push(
                Vulnerability::new(
                    VulnerabilitySeverity::High,
                    VulnerabilityCategory::UnenforcedDeadlineParameter,
                    format!("Deadline Parameter Never Enforced in {}()", func.name),
                    format!(
                        "`{}()` accepts a `{}` parameter but never reads it - no modifier consumes \
                         it and the body never references it. Callers reasonably assume the \
                         transaction expires, so they sign it and stop watching. Because nothing \
                         checks the value, the transaction stays valid indefinitely: a searcher or \
                         validator can hold it in the mempool and land it much later, at a price or \
                         market state of their choosing. This is the T-Swap H-1 pattern and a \
                         recurring high-severity finding in AMM and router audits.",
                        func.name, ident
                    ),
                    func.line_start,
                    format!("function {}(... {} ...)", func.name, ident),
                    format!(
                        "Enforce the parameter or remove it. Add a guard such as \
                         `if (block.timestamp > {ident}) revert Expired();` as the first statement, \
                         or apply a `revertIfDeadlinePassed({ident})` modifier. Leaving the \
                         parameter in place unused is worse than having none, because it advertises \
                         a protection the contract does not provide."
                    ),
                )
                .with_confidence_percent(88),
            );
        }

        findings
    }

    /// 41S-094: a named return value that is never written.
    ///
    /// Solidity zero-initialises named returns, so a function that never assigns one
    /// and never uses an explicit `return` silently yields 0 / false / address(0).
    /// An explicit `return <expr>` anywhere in the body supplies the value directly,
    /// so its presence clears the finding.
    fn check_unassigned_named_return(&self, func: &ParsedFunction) -> Vec<Vulnerability> {
        let mut findings = Vec::new();

        let Some(returns_clause) = extract_returns_clause(&func.header_tail) else {
            return findings;
        };
        // An explicit `return expr;` (not a bare `return;`) provides the value.
        if has_value_return(&func.body) {
            return findings;
        }

        for decl in split_top_level(&returns_clause) {
            let Some(ident) = declared_identifier(&decl) else {
                continue;
            };
            if is_assigned(&func.body, &ident) {
                continue;
            }

            findings.push(
                Vulnerability::new(
                    VulnerabilitySeverity::Medium,
                    VulnerabilityCategory::UnassignedNamedReturn,
                    format!("Named Return `{}` Never Assigned in {}()", ident, func.name),
                    format!(
                        "`{}()` declares the named return value `{}` but never assigns to it, and \
                         the body contains no explicit `return` statement. Solidity zero-initialises \
                         named returns, so this function always returns the zero value no matter what \
                         it computed internally. Callers and integrating contracts that branch on the \
                         result - slippage checks, accounting, router hops - silently read 0. This is \
                         the T-Swap L-2 pattern.",
                        func.name, ident
                    ),
                    func.line_start,
                    format!("function {}() returns (... {})", func.name, ident),
                    format!(
                        "Assign the computed value to `{ident}` (often the local the function already \
                         computes should simply *be* `{ident}`), or replace the named return with an \
                         explicit `return <value>;`. If the value is genuinely unused, drop it from \
                         the signature so callers are not misled."
                    ),
                )
                .with_confidence_percent(85),
            );
        }

        findings
    }
}

/// Walks the source and extracts every function that has a body.
///
/// Interface and abstract declarations end in `;` rather than `{` and are skipped:
/// they have nothing to enforce a deadline in and no body to assign a return from.
fn parse_functions(content: &str) -> Vec<ParsedFunction> {
    // Blank comments first so a commented-out function is never parsed. This is
    // length- and newline-preserving, so offsets and line numbers still line up
    // with the original source.
    let content = &strip_comments(content);
    let bytes: Vec<char> = content.chars().collect();
    let mut functions = Vec::new();

    for caps in FUNC_START.captures_iter(content) {
        let whole = caps.get(0).expect("group 0 always present");
        let name = caps
            .get(1)
            .expect("function name group")
            .as_str()
            .to_string();

        // Char index of the '(' that opens the parameter list.
        let Some(open_paren) = char_index_of(content, whole.end() - 1) else {
            continue;
        };
        let Some(close_paren) = match_delimiter(&bytes, open_paren, '(', ')') else {
            continue;
        };

        // Everything between the parameter list and the body opener.
        let mut cursor = close_paren + 1;
        while cursor < bytes.len() && bytes[cursor] != '{' && bytes[cursor] != ';' {
            cursor += 1;
        }
        // No body - interface, abstract, or malformed.
        if cursor >= bytes.len() || bytes[cursor] == ';' {
            continue;
        }
        let Some(close_brace) = match_delimiter(&bytes, cursor, '{', '}') else {
            continue;
        };

        let line_start = content[..whole.start()].lines().count().max(1);

        functions.push(ParsedFunction {
            name,
            line_start,
            params: bytes[open_paren + 1..close_paren].iter().collect(),
            header_tail: bytes[close_paren + 1..cursor].iter().collect(),
            body: bytes[cursor + 1..close_brace].iter().collect(),
        });
    }

    functions
}

/// Converts a byte offset into a char index.
fn char_index_of(content: &str, byte_offset: usize) -> Option<usize> {
    content
        .char_indices()
        .position(|(idx, _)| idx == byte_offset)
}

/// Returns the index of the delimiter closing the one at `start`, honouring
/// nesting, string literals and both comment styles.
fn match_delimiter(chars: &[char], start: usize, open: char, close: char) -> Option<usize> {
    let mut depth = 0usize;
    let mut idx = start;

    while idx < chars.len() {
        let ch = chars[idx];

        // Skip line comments.
        if ch == '/' && idx + 1 < chars.len() && chars[idx + 1] == '/' {
            while idx < chars.len() && chars[idx] != '\n' {
                idx += 1;
            }
            continue;
        }
        // Skip block comments.
        if ch == '/' && idx + 1 < chars.len() && chars[idx + 1] == '*' {
            idx += 2;
            while idx + 1 < chars.len() && !(chars[idx] == '*' && chars[idx + 1] == '/') {
                idx += 1;
            }
            idx += 2;
            continue;
        }
        // Skip string literals.
        if ch == '"' || ch == '\'' {
            let quote = ch;
            idx += 1;
            while idx < chars.len() && chars[idx] != quote {
                // Honour backslash escapes.
                if chars[idx] == '\\' {
                    idx += 1;
                }
                idx += 1;
            }
            idx += 1;
            continue;
        }

        if ch == open {
            depth += 1;
        } else if ch == close {
            depth -= 1;
            if depth == 0 {
                return Some(idx);
            }
        }
        idx += 1;
    }

    None
}

/// Splits a parameter or returns list on top-level commas, ignoring commas nested
/// inside `(...)` or `[...]` (function types, fixed-size arrays, tuples).
fn split_top_level(list: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut depth = 0i32;
    let mut current = String::new();

    for ch in list.chars() {
        match ch {
            '(' | '[' => {
                depth += 1;
                current.push(ch);
            }
            ')' | ']' => {
                depth -= 1;
                current.push(ch);
            }
            ',' if depth == 0 => {
                parts.push(std::mem::take(&mut current));
            }
            _ => current.push(ch),
        }
    }
    if !current.trim().is_empty() {
        parts.push(current);
    }

    parts
}

/// Pulls the declared identifier out of one parameter/return declaration.
///
/// Returns `None` for an anonymous declaration (`uint256` with no name), which is
/// legal for both parameters and returns and has nothing to report.
fn declared_identifier(decl: &str) -> Option<String> {
    let trimmed = strip_comments(decl);
    let trimmed = trimmed.trim();
    if trimmed.is_empty() {
        return None;
    }

    let ident = DECL_IDENT.captures(trimmed)?.get(1)?.as_str().to_string();

    // A single token is a bare type (`uint256`), not a named declaration.
    if trimmed.split_whitespace().count() < 2 {
        return None;
    }
    // Guard against a trailing keyword being mistaken for a name.
    const KEYWORDS: [&str; 6] = [
        "memory", "calldata", "storage", "payable", "indexed", "returns",
    ];
    if KEYWORDS.contains(&ident.as_str()) {
        return None;
    }

    Some(ident)
}

/// Extracts the text inside the `returns (...)` clause of a header tail.
fn extract_returns_clause(header_tail: &str) -> Option<String> {
    let chars: Vec<char> = header_tail.chars().collect();
    let idx = header_tail.find("returns")?;
    let start = header_tail[idx..].find('(')? + idx;
    let start_char = header_tail[..start].chars().count();
    let end_char = match_delimiter(&chars, start_char, '(', ')')?;
    Some(chars[start_char + 1..end_char].iter().collect())
}

/// True when `ident` appears as a whole word in `haystack`, ignoring comments.
fn identifier_used(haystack: &str, ident: &str) -> bool {
    let cleaned = strip_comments(haystack);
    let found = word_positions(&cleaned, ident).next().is_some();
    found
}

/// True when `ident` appears as an assignment target: `x =`, `x +=`, `(a, x) = ...`.
/// A comparison (`==`) or the declaration itself does not count.
fn is_assigned(body: &str, ident: &str) -> bool {
    let cleaned = strip_comments(body);
    let chars: Vec<char> = cleaned.chars().collect();

    for pos in word_positions(&cleaned, ident) {
        let mut idx = pos + ident.chars().count();
        while idx < chars.len() && chars[idx].is_whitespace() {
            idx += 1;
        }
        if idx >= chars.len() {
            continue;
        }
        // Compound assignment: += -= *= /= |= &= ^= %=
        if matches!(chars[idx], '+' | '-' | '*' | '/' | '|' | '&' | '^' | '%')
            && idx + 1 < chars.len()
            && chars[idx + 1] == '='
        {
            return true;
        }
        // Plain assignment, but not `==`.
        if chars[idx] == '=' && (idx + 1 >= chars.len() || chars[idx + 1] != '=') {
            // Not a `>=` / `<=` / `!=` whose operator char we already passed.
            return true;
        }
        // Tuple destructuring: the identifier sits inside `(...)` followed by `=`.
        if chars[idx] == ',' || chars[idx] == ')' {
            let mut scan = idx;
            while scan < chars.len() && chars[scan] != ')' && chars[scan] != ';' {
                scan += 1;
            }
            if scan < chars.len() && chars[scan] == ')' {
                let mut after = scan + 1;
                while after < chars.len() && chars[after].is_whitespace() {
                    after += 1;
                }
                if after < chars.len()
                    && chars[after] == '='
                    && (after + 1 >= chars.len() || chars[after + 1] != '=')
                {
                    return true;
                }
            }
        }
    }

    false
}

/// True when the body contains `return <expression>;` rather than a bare `return;`.
fn has_value_return(body: &str) -> bool {
    let cleaned = strip_comments(body);
    let chars: Vec<char> = cleaned.chars().collect();

    for pos in word_positions(&cleaned, "return") {
        let mut idx = pos + "return".chars().count();
        while idx < chars.len() && chars[idx].is_whitespace() {
            idx += 1;
        }
        if idx < chars.len() && chars[idx] != ';' {
            return true;
        }
    }

    false
}

/// Yields char indices where `needle` occurs as a whole identifier.
fn word_positions<'a>(haystack: &'a str, needle: &'a str) -> impl Iterator<Item = usize> + 'a {
    let chars: Vec<char> = haystack.chars().collect();
    let target: Vec<char> = needle.chars().collect();

    (0..chars.len()).filter(move |&i| {
        if i + target.len() > chars.len() || chars[i..i + target.len()] != target[..] {
            return false;
        }
        let before_ok = i == 0 || !is_ident_char(chars[i - 1]);
        let after_idx = i + target.len();
        let after_ok = after_idx >= chars.len() || !is_ident_char(chars[after_idx]);
        before_ok && after_ok
    })
}

fn is_ident_char(ch: char) -> bool {
    ch.is_alphanumeric() || ch == '_' || ch == '$'
}

/// Blanks `//` and `/* */` comments so a mitigation mentioned only in a comment
/// never counts as real usage, and a commented-out function is never parsed.
///
/// Comment characters are replaced with spaces rather than deleted, and newlines
/// are preserved verbatim. That keeps the result the same char length as the input,
/// so char offsets and 1-based line numbers computed against it stay exact.
fn strip_comments(source: &str) -> String {
    let chars: Vec<char> = source.chars().collect();
    let mut out = String::with_capacity(source.len());
    let mut idx = 0;

    // Replaces one char with a space, but keeps newlines so line numbers hold.
    let blank = |ch: char| if ch == '\n' { '\n' } else { ' ' };

    while idx < chars.len() {
        if chars[idx] == '/' && idx + 1 < chars.len() && chars[idx + 1] == '/' {
            while idx < chars.len() && chars[idx] != '\n' {
                out.push(' ');
                idx += 1;
            }
            continue;
        }
        if chars[idx] == '/' && idx + 1 < chars.len() && chars[idx + 1] == '*' {
            out.push(' ');
            out.push(' ');
            idx += 2;
            while idx + 1 < chars.len() && !(chars[idx] == '*' && chars[idx + 1] == '/') {
                out.push(blank(chars[idx]));
                idx += 1;
            }
            // Blank the closing `*/` if it is present.
            for _ in 0..2 {
                if idx < chars.len() {
                    out.push(blank(chars[idx]));
                    idx += 1;
                }
            }
            continue;
        }
        out.push(chars[idx]);
        idx += 1;
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn categories(src: &str) -> Vec<VulnerabilityCategory> {
        UnusedDeclarationAnalyzer::new()
            .analyze(src)
            .into_iter()
            .map(|v| v.category)
            .collect()
    }

    /// The T-Swap H-1 shape: a multi-line signature declaring an unused deadline.
    #[test]
    fn flags_deadline_parameter_that_is_never_read() {
        let src = r#"
        contract P {
            function deposit(
                uint256 wethToDeposit,
                uint64 deadline
            )
                external
                revertIfZero(wethToDeposit)
                returns (uint256 minted)
            {
                minted = wethToDeposit;
            }
        }"#;
        assert!(categories(src).contains(&VulnerabilityCategory::UnenforcedDeadlineParameter));
    }

    /// A deadline consumed by a modifier is enforced - the exact contrast T-Swap's
    /// own `swapExactInput` provides against `deposit`.
    #[test]
    fn deadline_consumed_by_modifier_is_not_flagged() {
        let src = r#"
        contract P {
            function swap(
                uint256 amount,
                uint64 deadline
            )
                public
                revertIfDeadlinePassed(deadline)
                returns (uint256 out)
            {
                out = amount;
            }
        }"#;
        assert!(!categories(src).contains(&VulnerabilityCategory::UnenforcedDeadlineParameter));
    }

    #[test]
    fn deadline_checked_in_body_is_not_flagged() {
        let src = r#"
        contract P {
            function swap(uint256 amount, uint64 deadline) public returns (uint256 out) {
                require(block.timestamp <= deadline, "expired");
                out = amount;
            }
        }"#;
        assert!(!categories(src).contains(&VulnerabilityCategory::UnenforcedDeadlineParameter));
    }

    /// A deadline mentioned only in a comment is not enforcement.
    #[test]
    fn deadline_named_only_in_a_comment_is_still_flagged() {
        let src = r#"
        contract P {
            function deposit(uint256 amt, uint64 deadline) external returns (uint256 m) {
                // deadline is validated by the router before it calls us
                m = amt;
            }
        }"#;
        assert!(categories(src).contains(&VulnerabilityCategory::UnenforcedDeadlineParameter));
    }

    /// The T-Swap L-2 shape: `output` declared, `outputAmount` assigned instead.
    #[test]
    fn flags_named_return_that_is_never_assigned() {
        let src = r#"
        contract P {
            function swapExactInput(
                uint256 inputAmount,
                uint64 deadline
            )
                public
                revertIfDeadlinePassed(deadline)
                returns (uint256 output)
            {
                uint256 outputAmount = inputAmount * 2;
                _swap(outputAmount);
            }
        }"#;
        assert!(categories(src).contains(&VulnerabilityCategory::UnassignedNamedReturn));
    }

    #[test]
    fn assigned_named_return_is_not_flagged() {
        let src = r#"
        contract P {
            function f(uint256 a) public pure returns (uint256 out) {
                out = a * 2;
            }
        }"#;
        assert!(!categories(src).contains(&VulnerabilityCategory::UnassignedNamedReturn));
    }

    #[test]
    fn compound_assignment_counts_as_assigned() {
        let src = r#"
        contract P {
            function f(uint256 a) public pure returns (uint256 out) {
                out += a;
            }
        }"#;
        assert!(!categories(src).contains(&VulnerabilityCategory::UnassignedNamedReturn));
    }

    #[test]
    fn explicit_value_return_clears_the_finding() {
        let src = r#"
        contract P {
            function f(uint256 a) public pure returns (uint256 out) {
                return a * 2;
            }
        }"#;
        assert!(!categories(src).contains(&VulnerabilityCategory::UnassignedNamedReturn));
    }

    #[test]
    fn tuple_destructuring_counts_as_assigned() {
        let src = r#"
        contract P {
            function f() public returns (uint256 a, uint256 b) {
                (a, b) = _compute();
            }
        }"#;
        assert!(!categories(src).contains(&VulnerabilityCategory::UnassignedNamedReturn));
    }

    /// Unnamed returns cannot be "unassigned" - the caller gets an explicit value.
    #[test]
    fn unnamed_return_is_not_flagged() {
        let src = r#"
        contract P {
            function f(uint256 a) public pure returns (uint256) {
                return a;
            }
        }"#;
        assert!(!categories(src).contains(&VulnerabilityCategory::UnassignedNamedReturn));
    }

    /// Interface declarations have no body and nothing to enforce.
    #[test]
    fn interface_declarations_are_skipped() {
        let src = r#"
        interface IP {
            function deposit(uint256 amt, uint64 deadline) external returns (uint256 out);
        }"#;
        assert!(categories(src).is_empty());
    }

    /// A commented-out function must not produce findings.
    #[test]
    fn commented_out_function_is_ignored() {
        let src = r#"
        contract P {
            // function deposit(uint256 amt, uint64 deadline) external returns (uint256 out) {
            //     out = amt;
            // }
            function ok(uint256 a) public pure returns (uint256 b) { b = a; }
        }"#;
        assert!(categories(src).is_empty());
    }

    #[test]
    fn nested_braces_in_body_do_not_truncate_parsing() {
        let src = r#"
        contract P {
            function f(uint256 a, uint64 deadline) public returns (uint256 out) {
                if (a > 1) { if (a > 2) { a = a - 1; } }
                out = a;
                require(block.timestamp <= deadline);
            }
        }"#;
        assert!(categories(src).is_empty());
    }
}
