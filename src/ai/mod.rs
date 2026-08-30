//! Opt-in AI review layer.
//!
//! Runs only when the user passes `--ai`. The offline static scanner is unchanged and
//! remains the default path.
//!
//! # Design rules
//!
//! * **No network unless asked.** Nothing in this module opens a socket at import time,
//!   in a constructor, or from a lazy static. The only call that performs I/O is
//!   [`provider::Provider::complete`], reached exclusively through [`review::AiSession`],
//!   which the CLI builds only when `--ai` is present.
//! * **Strictly additive.** Every failure path returns the offline findings unchanged.
//!   A broken API key, a rate limit, a malformed response and an unreachable Ollama all
//!   degrade to "offline results, plus a note in the report".
//! * **Secrets never leave.** Source is passed through [`redact`] before a prompt is
//!   built, so a private key or mnemonic in a `.sol` file or fixture is destroyed before
//!   transmission.
//! * **Untrusted input.** The Solidity we send is attacker-controlled; see [`prompt`]
//!   for the injection threat model and the validation that contains it.
//!
//! # Usage from the CLI
//!
//! ```text
//! use crate::ai::{AiConfig, review::AiSession};
//!
//! // `enabled` is the interlock: with it false, review_file() is a no-op and
//! // nothing is ever transmitted.
//! let config = AiConfig { enabled: true, ..AiConfig::default() };
//! let session = AiSession::new(config)?;
//! if let Some(notice) = session.disclosure() {
//!     eprintln!("{notice}");
//! }
//! let (vulns, report) = session.review_file(std::path::Path::new("V.sol"), &source, vulns);
//! session.finish();
//! println!("{}", report.summary_line());
//! ```

pub mod prompt;
pub mod provider;
pub mod redact;
pub mod review;
pub mod verdict_cache;

use std::path::PathBuf;

// Re-export only what a caller names directly. `AiError`, `CostEstimate` and
// `DroppedFinding` are reached through return types and struct fields, so they stay at
// `ai::provider::AiError` / `ai::review::{CostEstimate, DroppedFinding}`.
pub use provider::ProviderKind;
pub use review::{AiReport, AiSession};

/// What to do with a finding the model calls a false positive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FpPolicy {
    /// Remove it from the results. Still recorded in [`AiReport::dropped`], and a
    /// Critical or High finding is only removed on a very confident verdict.
    Drop,
    /// Keep it but rewrite it to Info severity with the model's reasoning attached.
    Downgrade,
    /// Change nothing except the title tag and the attached reasoning.
    Annotate,
}

impl FpPolicy {
    /// Parse a CLI value.
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "drop" => Some(FpPolicy::Drop),
            "downgrade" => Some(FpPolicy::Downgrade),
            "annotate" => Some(FpPolicy::Annotate),
            _ => None,
        }
    }

    /// Name for reports and help text.
    pub fn label(self) -> &'static str {
        match self {
            FpPolicy::Drop => "drop",
            FpPolicy::Downgrade => "downgrade",
            FpPolicy::Annotate => "annotate",
        }
    }
}

/// Everything the CLI needs to populate to drive the AI layer.
///
/// [`Default`] is the safe configuration: disabled, Anthropic, downgrade rather than
/// drop, a one-dollar cap, and caching on.
#[derive(Debug, Clone)]
pub struct AiConfig {
    /// Master switch. The CLI sets this from `--ai`; when false nothing here runs.
    pub enabled: bool,
    /// Which backend to use (`--provider`).
    pub provider: ProviderKind,
    /// Model override (`--ai-model`). `None` uses the provider default.
    pub model: Option<String>,
    /// Endpoint override, e.g. a proxy or a remote Ollama host.
    pub api_base: Option<String>,
    /// Run the business-logic pass as well (`--ai-deep`).
    pub deep: bool,
    /// Hard spend cap in USD (`--ai-max-cost`). `0.0` disables the cap.
    pub max_cost_usd: f64,
    /// Hard cap on requests per run. `0` disables the cap.
    pub max_requests: usize,
    /// Concurrent in-flight requests.
    pub concurrency: usize,
    /// Whether to read and write the verdict cache.
    pub cache: bool,
    /// Directory holding the verdict cache. `None` keeps it in memory.
    pub cache_dir: Option<PathBuf>,
    /// What to do with a verified false positive.
    pub fp_policy: FpPolicy,
    /// Minimum model confidence before a false-positive verdict changes anything.
    pub min_confidence: f64,
    /// Minimum confidence for a deep-pass finding to be reported at all.
    pub deep_min_confidence: f64,
    /// Upper bound on deep-pass findings kept per file.
    pub max_deep_findings: usize,
    /// Largest file (in characters) the deep pass will accept. Larger files are
    /// skipped with a note rather than silently truncated.
    pub max_deep_chars: usize,
    /// Findings per verification request.
    pub batch_size: usize,
    /// Lines of context either side of a flagged line (so `25` sends ~50 lines).
    pub context_lines: usize,
    /// Per-request timeout in seconds.
    pub timeout_secs: u64,
    /// Retries on 429/5xx and transport errors.
    pub max_retries: u32,
    /// Reasoning effort for models that support `output_config.effort`.
    pub effort: String,
    /// Send the server-side refusal-fallback beta. Dropped automatically for the rest
    /// of the session if the API rejects it.
    pub server_side_fallbacks: bool,
}

impl Default for AiConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            provider: ProviderKind::Anthropic,
            model: None,
            api_base: None,
            deep: false,
            max_cost_usd: 1.00,
            max_requests: 200,
            concurrency: 4,
            cache: true,
            cache_dir: Some(PathBuf::from(".")),
            // Downgrade by default: a scanner that silently deletes findings on a
            // model's say-so is worse than one that mislabels a few.
            fp_policy: FpPolicy::Downgrade,
            min_confidence: 0.75,
            deep_min_confidence: 0.70,
            max_deep_findings: 8,
            max_deep_chars: 120_000,
            batch_size: 10,
            context_lines: 25,
            timeout_secs: 120,
            max_retries: 3,
            effort: "medium".to_string(),
            server_side_fallbacks: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_off_and_conservative() {
        let c = AiConfig::default();
        assert!(!c.enabled, "offline stays the default");
        assert_eq!(c.fp_policy, FpPolicy::Downgrade);
        assert!(c.max_cost_usd > 0.0, "a cap is always in force");
        assert!(c.max_requests > 0);
        assert_eq!(c.provider, ProviderKind::Anthropic);
    }

    #[test]
    fn policy_parses_from_cli_values() {
        assert_eq!(FpPolicy::parse("drop"), Some(FpPolicy::Drop));
        assert_eq!(FpPolicy::parse(" Downgrade "), Some(FpPolicy::Downgrade));
        assert_eq!(FpPolicy::parse("annotate"), Some(FpPolicy::Annotate));
        assert_eq!(FpPolicy::parse("delete-everything"), None);
        assert_eq!(FpPolicy::Drop.label(), "drop");
    }
}
