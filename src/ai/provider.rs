//! Provider abstraction for the opt-in AI review layer.
//!
//! Nothing in this module performs network I/O at construction time. A provider is a
//! plain value describing *where* a request would go; the socket is opened only when
//! [`Provider::complete`] is called, which only happens after the user passed `--ai`.

use std::fmt;
use std::time::Duration;

use serde::Deserialize;
use serde_json::{json, Value};

/// Environment variable holding the Anthropic API key. Read at provider construction;
/// never logged, never echoed into an error message, never written to the cache.
pub const ANTHROPIC_KEY_ENV: &str = "ANTHROPIC_API_KEY";

/// Default Anthropic model. Sourced from the bundled `claude-api` skill's model table
/// (cached 2026-06-24), which lists `claude-opus-5` as the default choice for code work.
pub const DEFAULT_ANTHROPIC_MODEL: &str = "claude-opus-5";

/// Default local model for Ollama. Overridable with `--ai-model`.
pub const DEFAULT_OLLAMA_MODEL: &str = "qwen2.5-coder:7b";

/// Default Ollama endpoint.
pub const DEFAULT_OLLAMA_BASE: &str = "http://localhost:11434";

const ANTHROPIC_BASE: &str = "https://api.anthropic.com";
const ANTHROPIC_VERSION: &str = "2023-06-01";
/// Beta flag for server-side refusal fallbacks. Automatically dropped for the rest of
/// the session if the API rejects it, so an org without the beta still gets a working
/// AI pass.
const FALLBACK_BETA: &str = "server-side-fallback-2026-07-01";

/// Which backend the AI layer talks to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderKind {
    /// Anthropic's Claude API. Sends source code to a third party.
    Anthropic,
    /// A local Ollama daemon. Stays on the machine.
    Ollama,
}

impl ProviderKind {
    /// Parse a CLI `--provider` value. Accepts a few common spellings.
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "anthropic" | "claude" => Some(ProviderKind::Anthropic),
            "ollama" | "local" => Some(ProviderKind::Ollama),
            _ => None,
        }
    }
}

/// Token prices in USD per million tokens.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Pricing {
    /// Input (prompt) tokens, USD per 1M.
    pub input_per_mtok: f64,
    /// Output (completion) tokens, USD per 1M.
    pub output_per_mtok: f64,
}

impl Pricing {
    /// Zero-cost pricing, used for locally hosted models.
    pub const FREE: Pricing = Pricing {
        input_per_mtok: 0.0,
        output_per_mtok: 0.0,
    };

    /// Cost in USD for a given token split.
    pub fn cost_usd(&self, input_tokens: u64, output_tokens: u64) -> f64 {
        (input_tokens as f64 / 1_000_000.0) * self.input_per_mtok
            + (output_tokens as f64 / 1_000_000.0) * self.output_per_mtok
    }
}

/// Published Anthropic prices, from the `claude-api` skill's model table
/// (cached 2026-06-24). Unknown models fall back to the Opus tier so a budget cap
/// errs on the side of over-estimating spend rather than under-estimating it.
pub fn anthropic_pricing(model: &str) -> Pricing {
    let (input, output) = match model {
        "claude-fable-5" | "claude-mythos-5" => (10.00, 50.00),
        "claude-sonnet-5" => (2.00, 10.00),
        "claude-sonnet-4-6" => (3.00, 15.00),
        "claude-haiku-4-5" => (1.00, 5.00),
        // claude-opus-5 / 4-8 / 4-7 / 4-6 and anything unrecognised.
        _ => (5.00, 25.00),
    };
    Pricing {
        input_per_mtok: input,
        output_per_mtok: output,
    }
}

/// Rough token estimate used for pre-flight cost reporting and budget checks.
///
/// Deliberately conservative: ~3.5 characters per token over-counts dense Solidity
/// slightly, which is the safe direction for a spend cap.
pub fn estimate_tokens(text: &str) -> u64 {
    let chars = text.chars().count() as f64;
    (chars / 3.5).ceil() as u64
}

/// One model response plus its billed token counts.
#[derive(Debug, Clone, PartialEq)]
pub struct Completion {
    /// Concatenated text content of the response.
    pub text: String,
    /// Billed input tokens as reported by the provider.
    pub input_tokens: u64,
    /// Billed output tokens as reported by the provider.
    pub output_tokens: u64,
}

/// Everything that can go wrong in the AI layer.
///
/// Every variant is non-fatal to a scan: the caller degrades to the offline findings.
#[derive(Debug, Clone, PartialEq)]
pub enum AiError {
    /// `ANTHROPIC_API_KEY` was not set (or was empty).
    MissingApiKey,
    /// HTTP status >= 400. The body is truncated and never contains credentials,
    /// because credentials only ever travel in a request header.
    Http { status: u16, body: String },
    /// Connection/DNS/TLS/timeout failure.
    Transport(String),
    /// Response body was not the JSON envelope the provider documents.
    Decode(String),
    /// The model returned text we could not validate against the expected schema.
    Schema(String),
    /// Safety classifiers declined the request (`stop_reason: "refusal"`).
    Refused(String),
    /// The configured spend cap would be exceeded by the next request.
    BudgetExceeded { spent_usd: f64, cap_usd: f64 },
    /// The configured request cap has been reached.
    RequestCapReached(usize),
}

impl fmt::Display for AiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AiError::MissingApiKey => write!(
                f,
                "{ANTHROPIC_KEY_ENV} is not set. Export it, or run with `--provider ollama` for a fully local review."
            ),
            AiError::Http { status, body } => write!(f, "provider returned HTTP {status}: {body}"),
            AiError::Transport(e) => write!(f, "could not reach the AI provider: {e}"),
            AiError::Decode(e) => write!(f, "unexpected provider response shape: {e}"),
            AiError::Schema(e) => write!(f, "model response failed schema validation: {e}"),
            AiError::Refused(c) => write!(f, "model declined the request (category: {c})"),
            AiError::BudgetExceeded { spent_usd, cap_usd } => write!(
                f,
                "AI budget cap reached (spent ~${spent_usd:.4} of ${cap_usd:.4}); stopping before the next request"
            ),
            AiError::RequestCapReached(n) => {
                write!(f, "AI request cap reached ({n} requests); stopping")
            }
        }
    }
}

impl std::error::Error for AiError {}

/// A backend that can answer a single self-contained prompt.
pub trait Provider: Send + Sync {
    /// Short provider name for reports.
    fn name(&self) -> &'static str;

    /// The concrete model identifier in use.
    fn model(&self) -> &str;

    /// Token pricing, used for pre-flight estimates and budget enforcement.
    fn pricing(&self) -> Pricing;

    /// Whether using this provider transmits source code off the machine.
    /// Drives the third-party disclosure the CLI prints.
    fn transmits_offsite(&self) -> bool;

    /// Send one request. This is the only function in the AI layer that opens a socket.
    fn complete(&self, system: &str, user: &str, max_tokens: u32) -> Result<Completion, AiError>;
}

/// Backoff delay before retry `attempt` (0-based), honouring a `Retry-After` header.
///
/// Pure function so the schedule is unit-testable without sleeping or dialling out.
pub fn backoff_delay(attempt: u32, retry_after_secs: Option<u64>) -> Duration {
    if let Some(secs) = retry_after_secs {
        return Duration::from_secs(secs.min(60));
    }
    let millis = 500u64.saturating_mul(1u64 << attempt.min(5));
    Duration::from_millis(millis.min(16_000))
}

/// Whether an HTTP status is worth retrying.
pub fn is_retryable(status: u16) -> bool {
    status == 429 || status == 408 || (500..600).contains(&status)
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let head: String = s.chars().take(max).collect();
    format!("{head}... [truncated]")
}

// ---------------------------------------------------------------------------------
// Anthropic
// ---------------------------------------------------------------------------------

/// Claude API provider. Construction reads `ANTHROPIC_API_KEY` but performs no I/O.
pub struct AnthropicProvider {
    api_key: String,
    model: String,
    base: String,
    effort: String,
    max_retries: u32,
    agent: ureq::Agent,
    /// Cleared for the rest of the session if the API rejects the fallbacks beta.
    use_fallbacks: std::sync::atomic::AtomicBool,
}

impl AnthropicProvider {
    /// Build a provider from the environment. Fails fast with an actionable message
    /// when the key is absent; the key itself is never included in any error.
    pub fn from_env(
        model: Option<&str>,
        base: Option<&str>,
        effort: &str,
        timeout_secs: u64,
        max_retries: u32,
        server_side_fallbacks: bool,
    ) -> Result<Self, AiError> {
        let api_key = std::env::var(ANTHROPIC_KEY_ENV)
            .ok()
            .filter(|k| !k.trim().is_empty())
            .ok_or(AiError::MissingApiKey)?;
        Ok(Self {
            api_key,
            model: model.unwrap_or(DEFAULT_ANTHROPIC_MODEL).to_string(),
            base: base
                .unwrap_or(ANTHROPIC_BASE)
                .trim_end_matches('/')
                .to_string(),
            effort: effort.to_string(),
            max_retries,
            agent: ureq::AgentBuilder::new()
                .timeout(Duration::from_secs(timeout_secs))
                .build(),
            use_fallbacks: std::sync::atomic::AtomicBool::new(server_side_fallbacks),
        })
    }

    fn body(&self, system: &str, user: &str, max_tokens: u32, fallbacks: bool) -> Value {
        let mut body = json!({
            "model": self.model,
            "max_tokens": max_tokens,
            // Effort tunes thinking depth and spend. Note: `temperature` and
            // `budget_tokens` are rejected by current models, so neither is sent.
            "output_config": { "effort": self.effort },
            "system": [{
                "type": "text",
                "text": system,
                // The system prompt is byte-identical across every batch in a run,
                // so caching it turns repeated verification requests into cache reads.
                "cache_control": { "type": "ephemeral" }
            }],
            "messages": [{ "role": "user", "content": user }],
        });
        if fallbacks {
            body["betas"] = json!([FALLBACK_BETA]);
            body["fallbacks"] = json!("default");
        }
        body
    }

    fn send_once(&self, body: &Value) -> Result<Completion, AiError> {
        let url = format!("{}/v1/messages", self.base);
        let resp = self
            .agent
            .post(&url)
            .set("x-api-key", &self.api_key)
            .set("anthropic-version", ANTHROPIC_VERSION)
            .set("content-type", "application/json")
            .send_json(body);

        match resp {
            Ok(r) => parse_anthropic(r),
            Err(ureq::Error::Status(status, r)) => {
                let retry_after = r
                    .header("retry-after")
                    .and_then(|v| v.trim().parse::<u64>().ok());
                let text = r.into_string().unwrap_or_default();
                Err(AiError::Http {
                    status,
                    body: format!(
                        "{}{}",
                        truncate(text.trim(), 400),
                        retry_after
                            .map(|s| format!(" [retry-after: {s}s]"))
                            .unwrap_or_default()
                    ),
                })
            }
            Err(ureq::Error::Transport(t)) => Err(AiError::Transport(t.to_string())),
        }
    }
}

fn parse_anthropic(r: ureq::Response) -> Result<Completion, AiError> {
    #[derive(Deserialize)]
    struct Block {
        #[serde(rename = "type")]
        kind: String,
        #[serde(default)]
        text: String,
    }
    #[derive(Deserialize, Default)]
    struct Usage {
        #[serde(default)]
        input_tokens: u64,
        #[serde(default)]
        output_tokens: u64,
        #[serde(default)]
        cache_read_input_tokens: u64,
        #[serde(default)]
        cache_creation_input_tokens: u64,
    }
    #[derive(Deserialize)]
    struct StopDetails {
        #[serde(default)]
        category: Option<String>,
    }
    #[derive(Deserialize)]
    struct Resp {
        #[serde(default)]
        content: Vec<Block>,
        #[serde(default)]
        usage: Usage,
        #[serde(default)]
        stop_reason: Option<String>,
        #[serde(default)]
        stop_details: Option<StopDetails>,
    }

    let resp: Resp = r
        .into_json()
        .map_err(|e| AiError::Decode(format!("could not decode Anthropic response: {e}")))?;

    if resp.stop_reason.as_deref() == Some("refusal") {
        let category = resp
            .stop_details
            .and_then(|d| d.category)
            .unwrap_or_else(|| "unspecified".to_string());
        return Err(AiError::Refused(category));
    }

    let text = resp
        .content
        .iter()
        .filter(|b| b.kind == "text")
        .map(|b| b.text.as_str())
        .collect::<Vec<_>>()
        .join("");

    Ok(Completion {
        text,
        input_tokens: resp.usage.input_tokens
            + resp.usage.cache_read_input_tokens
            + resp.usage.cache_creation_input_tokens,
        output_tokens: resp.usage.output_tokens,
    })
}

impl Provider for AnthropicProvider {
    fn name(&self) -> &'static str {
        "anthropic"
    }

    fn model(&self) -> &str {
        &self.model
    }

    fn pricing(&self) -> Pricing {
        anthropic_pricing(&self.model)
    }

    fn transmits_offsite(&self) -> bool {
        true
    }

    fn complete(&self, system: &str, user: &str, max_tokens: u32) -> Result<Completion, AiError> {
        use std::sync::atomic::Ordering;
        let mut last = AiError::Transport("no attempt was made".to_string());
        for attempt in 0..=self.max_retries {
            let fallbacks = self.use_fallbacks.load(Ordering::Relaxed);
            let body = self.body(system, user, max_tokens, fallbacks);
            match self.send_once(&body) {
                Ok(c) => return Ok(c),
                Err(AiError::Http { status, body }) => {
                    // An org without the refusal-fallback beta rejects the flag. Drop
                    // it for the rest of the session and retry immediately rather than
                    // losing the whole AI pass over an optional parameter.
                    if status == 400 && fallbacks && mentions_fallback_beta(&body) {
                        self.use_fallbacks.store(false, Ordering::Relaxed);
                        last = AiError::Http { status, body };
                        continue;
                    }
                    if !is_retryable(status) || attempt == self.max_retries {
                        return Err(AiError::Http { status, body });
                    }
                    let retry_after = parse_retry_after(&body);
                    std::thread::sleep(backoff_delay(attempt, retry_after));
                    last = AiError::Http { status, body };
                }
                Err(e @ AiError::Transport(_)) => {
                    if attempt == self.max_retries {
                        return Err(e);
                    }
                    std::thread::sleep(backoff_delay(attempt, None));
                    last = e;
                }
                Err(e) => return Err(e),
            }
        }
        Err(last)
    }
}

fn mentions_fallback_beta(body: &str) -> bool {
    let lower = body.to_ascii_lowercase();
    lower.contains("fallback") || lower.contains("beta")
}

/// Pull `[retry-after: Ns]` back out of the formatted error body.
fn parse_retry_after(body: &str) -> Option<u64> {
    let idx = body.find("[retry-after: ")?;
    let rest = &body[idx + "[retry-after: ".len()..];
    let end = rest.find('s')?;
    rest[..end].parse::<u64>().ok()
}

// ---------------------------------------------------------------------------------
// Ollama
// ---------------------------------------------------------------------------------

/// Local Ollama provider. Free, and keeps source on the machine.
pub struct OllamaProvider {
    model: String,
    base: String,
    max_retries: u32,
    agent: ureq::Agent,
}

impl OllamaProvider {
    /// Build a local provider. No key required, no I/O at construction.
    pub fn new(
        model: Option<&str>,
        base: Option<&str>,
        timeout_secs: u64,
        max_retries: u32,
    ) -> Self {
        Self {
            model: model.unwrap_or(DEFAULT_OLLAMA_MODEL).to_string(),
            base: base
                .unwrap_or(DEFAULT_OLLAMA_BASE)
                .trim_end_matches('/')
                .to_string(),
            max_retries,
            agent: ureq::AgentBuilder::new()
                .timeout(Duration::from_secs(timeout_secs))
                .build(),
        }
    }

    fn send_once(&self, system: &str, user: &str, max_tokens: u32) -> Result<Completion, AiError> {
        #[derive(Deserialize)]
        struct Msg {
            #[serde(default)]
            content: String,
        }
        #[derive(Deserialize)]
        struct Resp {
            #[serde(default)]
            message: Option<Msg>,
            #[serde(default)]
            prompt_eval_count: u64,
            #[serde(default)]
            eval_count: u64,
        }

        let url = format!("{}/api/chat", self.base);
        let body = json!({
            "model": self.model,
            "stream": false,
            "format": "json",
            "messages": [
                { "role": "system", "content": system },
                { "role": "user", "content": user },
            ],
            "options": { "temperature": 0.0, "num_predict": max_tokens },
        });

        match self.agent.post(&url).send_json(&body) {
            Ok(r) => {
                let resp: Resp = r.into_json().map_err(|e| {
                    AiError::Decode(format!("could not decode Ollama response: {e}"))
                })?;
                Ok(Completion {
                    text: resp.message.map(|m| m.content).unwrap_or_default(),
                    input_tokens: resp.prompt_eval_count,
                    output_tokens: resp.eval_count,
                })
            }
            Err(ureq::Error::Status(status, r)) => Err(AiError::Http {
                status,
                body: truncate(r.into_string().unwrap_or_default().trim(), 400),
            }),
            Err(ureq::Error::Transport(t)) => Err(AiError::Transport(format!(
                "{t} (is `ollama serve` running on {}?)",
                self.base
            ))),
        }
    }
}

impl Provider for OllamaProvider {
    fn name(&self) -> &'static str {
        "ollama"
    }

    fn model(&self) -> &str {
        &self.model
    }

    fn pricing(&self) -> Pricing {
        Pricing::FREE
    }

    fn transmits_offsite(&self) -> bool {
        false
    }

    fn complete(&self, system: &str, user: &str, max_tokens: u32) -> Result<Completion, AiError> {
        let mut last = AiError::Transport("no attempt was made".to_string());
        for attempt in 0..=self.max_retries {
            match self.send_once(system, user, max_tokens) {
                Ok(c) => return Ok(c),
                Err(AiError::Http { status, body }) => {
                    if !is_retryable(status) || attempt == self.max_retries {
                        return Err(AiError::Http { status, body });
                    }
                    std::thread::sleep(backoff_delay(attempt, None));
                    last = AiError::Http { status, body };
                }
                Err(e @ AiError::Transport(_)) => {
                    if attempt == self.max_retries {
                        return Err(e);
                    }
                    std::thread::sleep(backoff_delay(attempt, None));
                    last = e;
                }
                Err(e) => return Err(e),
            }
        }
        Err(last)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_provider_names() {
        assert_eq!(ProviderKind::parse("claude"), Some(ProviderKind::Anthropic));
        assert_eq!(ProviderKind::parse(" Ollama "), Some(ProviderKind::Ollama));
        assert_eq!(ProviderKind::parse("openai"), None);
    }

    #[test]
    fn unknown_model_prices_at_opus_tier() {
        let p = anthropic_pricing("claude-something-unreleased");
        assert_eq!(p.input_per_mtok, 5.00);
        assert_eq!(p.output_per_mtok, 25.00);
        assert_eq!(anthropic_pricing("claude-haiku-4-5").input_per_mtok, 1.00);
    }

    #[test]
    fn cost_math_matches_published_rates() {
        // 1M input + 1M output on Opus tier = $5 + $25.
        let p = anthropic_pricing("claude-opus-5");
        assert!((p.cost_usd(1_000_000, 1_000_000) - 30.0).abs() < 1e-9);
        // 20k in / 2k out on a batch is fractions of a cent.
        assert!((p.cost_usd(20_000, 2_000) - 0.15).abs() < 1e-9);
        assert_eq!(Pricing::FREE.cost_usd(999_999, 999_999), 0.0);
    }

    #[test]
    fn token_estimate_is_conservative() {
        // 350 chars -> 100 tokens at 3.5 chars/token.
        assert_eq!(estimate_tokens(&"a".repeat(350)), 100);
        assert_eq!(estimate_tokens(""), 0);
    }

    #[test]
    fn backoff_grows_and_honours_retry_after() {
        assert_eq!(backoff_delay(0, None), Duration::from_millis(500));
        assert_eq!(backoff_delay(1, None), Duration::from_millis(1000));
        assert_eq!(backoff_delay(3, None), Duration::from_millis(4000));
        // Capped.
        assert_eq!(backoff_delay(30, None), Duration::from_millis(16_000));
        // Retry-After wins, and is itself capped.
        assert_eq!(backoff_delay(0, Some(7)), Duration::from_secs(7));
        assert_eq!(backoff_delay(0, Some(9999)), Duration::from_secs(60));
    }

    #[test]
    fn retryable_statuses() {
        assert!(is_retryable(429));
        assert!(is_retryable(500));
        assert!(is_retryable(503));
        assert!(!is_retryable(400));
        assert!(!is_retryable(401));
        assert!(!is_retryable(404));
    }

    #[test]
    fn missing_key_is_actionable_and_leaks_nothing() {
        let msg = AiError::MissingApiKey.to_string();
        assert!(msg.contains("ANTHROPIC_API_KEY"));
        assert!(msg.contains("--provider ollama"));
    }

    #[test]
    fn retry_after_roundtrips_through_error_body() {
        assert_eq!(
            parse_retry_after("rate limited [retry-after: 12s]"),
            Some(12)
        );
        assert_eq!(parse_retry_after("rate limited"), None);
    }

    #[test]
    fn anthropic_provider_requires_a_key() {
        // Only assert the error path when the environment genuinely has no key, so the
        // test is meaningful in CI and inert on a developer machine that exports one.
        if std::env::var(ANTHROPIC_KEY_ENV)
            .map(|v| v.trim().is_empty())
            .unwrap_or(true)
        {
            let err = AnthropicProvider::from_env(None, None, "medium", 30, 2, true)
                .err()
                .unwrap();
            assert_eq!(err, AiError::MissingApiKey);
        }
    }
}
