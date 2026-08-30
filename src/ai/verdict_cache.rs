//! Persistent cache of model verdicts.
//!
//! Keyed by a blake3 hash of (provider, model, rule identity, normalised code context),
//! so a re-scan of an unchanged file costs nothing and edits elsewhere in the file do
//! not invalidate unrelated verdicts. Nothing here touches the network, and no prompt
//! text or credential is ever written to disk - only the verdict itself.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

/// File name used when a cache directory is supplied, mirroring `.41swara_cache.json`
/// from the offline scan cache.
pub const CACHE_FILE: &str = ".41swara_ai_cache.json";

/// Entries older than this are dropped on load.
const TTL_SECS: u64 = 30 * 24 * 3600;

/// Bump when the prompt or schema changes in a way that invalidates old verdicts.
const SCHEMA_VERSION: &str = "ai-v1";

/// A cached model judgement.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CachedVerdict {
    /// Whether the model called it a false positive.
    pub is_false_positive: bool,
    /// Model confidence, 0.0-1.0.
    pub confidence: f64,
    /// The model's (already sanitised) reasoning.
    pub reasoning: String,
    /// Unix seconds when the verdict was stored.
    pub stored_at: u64,
}

/// Normalise a code context so cosmetic differences do not miss the cache.
///
/// Comments are preserved deliberately: a NatSpec note such as "reentrancy safe, see
/// audit" is exactly the evidence the model uses, so stripping comments would change
/// the meaning of the context rather than just its formatting.
pub fn normalize_context(context: &str) -> String {
    context
        .lines()
        .map(|l| l.split_whitespace().collect::<Vec<_>>().join(" "))
        .filter(|l| !l.is_empty())
        .collect::<Vec<_>>()
        .join("\n")
}

/// Compute the cache key for one finding.
///
/// `rule_id` should identify the rule, not the instance: two identical snippets flagged
/// by the same rule in different files legitimately share a verdict.
pub fn verdict_key(provider: &str, model: &str, rule_id: &str, context: &str) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(SCHEMA_VERSION.as_bytes());
    hasher.update(b"\x1f");
    hasher.update(provider.as_bytes());
    hasher.update(b"\x1f");
    hasher.update(model.as_bytes());
    hasher.update(b"\x1f");
    hasher.update(rule_id.as_bytes());
    hasher.update(b"\x1f");
    hasher.update(normalize_context(context).as_bytes());
    hasher.finalize().to_hex().to_string()
}

/// Verdict store. In-memory when no path is given.
#[derive(Debug, Default)]
pub struct VerdictCache {
    path: Option<PathBuf>,
    entries: HashMap<String, CachedVerdict>,
    hits: usize,
    misses: usize,
    dirty: bool,
    enabled: bool,
}

impl VerdictCache {
    /// Open a cache. `dir` is where `.41swara_ai_cache.json` lives; `None` keeps the
    /// cache in memory for the duration of the run. A corrupt or unreadable file is
    /// treated as an empty cache rather than an error.
    pub fn open(dir: Option<&Path>, enabled: bool) -> Self {
        let mut cache = Self {
            path: dir.map(|d| d.join(CACHE_FILE)),
            enabled,
            ..Default::default()
        };
        if !enabled {
            cache.path = None;
            return cache;
        }
        if let Some(path) = &cache.path {
            if let Ok(text) = std::fs::read_to_string(path) {
                if let Ok(map) = serde_json::from_str::<HashMap<String, CachedVerdict>>(&text) {
                    let now = now_secs();
                    cache.entries = map
                        .into_iter()
                        .filter(|(_, v)| now.saturating_sub(v.stored_at) < TTL_SECS)
                        .collect();
                }
            }
        }
        cache
    }

    /// Look up a verdict, recording a hit or a miss.
    pub fn get(&mut self, key: &str) -> Option<CachedVerdict> {
        if !self.enabled {
            return None;
        }
        match self.entries.get(key) {
            Some(v) => {
                self.hits += 1;
                Some(v.clone())
            }
            None => {
                self.misses += 1;
                None
            }
        }
    }

    /// Store a verdict.
    pub fn put(&mut self, key: String, is_false_positive: bool, confidence: f64, reasoning: &str) {
        if !self.enabled {
            return;
        }
        self.entries.insert(
            key,
            CachedVerdict {
                is_false_positive,
                confidence,
                reasoning: reasoning.to_string(),
                stored_at: now_secs(),
            },
        );
        self.dirty = true;
    }

    /// Cache hits so far.
    pub fn hits(&self) -> usize {
        self.hits
    }

    /// Cache misses so far.
    pub fn misses(&self) -> usize {
        self.misses
    }

    /// Persist to disk if a path was configured and anything changed. Best effort:
    /// a failure to write must never fail a scan.
    pub fn save(&mut self) -> bool {
        if !self.enabled || !self.dirty {
            return false;
        }
        let Some(path) = self.path.clone() else {
            return false;
        };
        let Ok(text) = serde_json::to_string(&self.entries) else {
            return false;
        };
        if std::fs::write(&path, text).is_ok() {
            self.dirty = false;
            return true;
        }
        false
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalisation_ignores_layout_but_keeps_comments() {
        let a = "  uint x = 1;\n\n\t// safe: guarded\n   call();  ";
        let b = "uint x = 1;\n// safe: guarded\ncall();";
        assert_eq!(normalize_context(a), normalize_context(b));
        assert!(normalize_context(a).contains("// safe: guarded"));
    }

    #[test]
    fn key_is_stable_and_scoped_to_provider_model_and_rule() {
        let ctx = "function f() { x = 1; }";
        let k = verdict_key("anthropic", "claude-opus-5", "SWC-107", ctx);
        assert_eq!(k, verdict_key("anthropic", "claude-opus-5", "SWC-107", ctx));
        // Re-indenting and re-spacing the same lines keeps the key; changing the line
        // structure does not, because line layout is part of what the model reads.
        assert_eq!(
            k,
            verdict_key("anthropic", "claude-opus-5", "SWC-107", "  function f() {   x  =  1; }  ")
        );
        assert_ne!(
            k,
            verdict_key("anthropic", "claude-opus-5", "SWC-107", "function f() {\n  x = 1;\n}")
        );
        // Anything else changes it.
        assert_ne!(k, verdict_key("ollama", "claude-opus-5", "SWC-107", ctx));
        assert_ne!(k, verdict_key("anthropic", "claude-sonnet-5", "SWC-107", ctx));
        assert_ne!(k, verdict_key("anthropic", "claude-opus-5", "SWC-101", ctx));
        assert_ne!(
            k,
            verdict_key("anthropic", "claude-opus-5", "SWC-107", "function f() { x = 2; }")
        );
    }

    #[test]
    fn hit_and_miss_are_counted() {
        let mut c = VerdictCache::open(None, true);
        assert_eq!(c.get("k"), None);
        assert_eq!((c.hits(), c.misses()), (0, 1));
        c.put("k".to_string(), true, 0.9, "guarded by nonReentrant");
        let hit = c.get("k").expect("stored verdict should be returned");
        assert!(hit.is_false_positive);
        assert_eq!(hit.reasoning, "guarded by nonReentrant");
        assert_eq!((c.hits(), c.misses()), (1, 1));
    }

    #[test]
    fn disabled_cache_never_stores_or_returns() {
        let mut c = VerdictCache::open(None, false);
        c.put("k".to_string(), true, 1.0, "x");
        assert_eq!(c.get("k"), None);
        assert_eq!((c.hits(), c.misses()), (0, 0));
        assert!(!c.save());
    }

    #[test]
    fn survives_a_round_trip_through_disk() {
        let dir = std::env::temp_dir().join(format!("41swara-ai-cache-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let _ = std::fs::remove_file(dir.join(CACHE_FILE));

        let mut c = VerdictCache::open(Some(&dir), true);
        c.put("key-a".to_string(), false, 0.75, "real bug");
        assert!(c.save());

        let mut reopened = VerdictCache::open(Some(&dir), true);
        let v = reopened.get("key-a").expect("verdict should persist");
        assert!(!v.is_false_positive);
        assert!((v.confidence - 0.75).abs() < 1e-9);
        assert_eq!(reopened.hits(), 1);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn corrupt_cache_file_degrades_to_empty() {
        let dir = std::env::temp_dir().join(format!("41swara-ai-bad-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(CACHE_FILE), "{not json").unwrap();
        let mut c = VerdictCache::open(Some(&dir), true);
        assert_eq!(c.get("anything"), None);
        std::fs::remove_dir_all(&dir).ok();
    }
}
