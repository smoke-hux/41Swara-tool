//! On-chain verified-source retrieval.
//!
//! Opt-in only: nothing here performs network I/O unless the caller explicitly invokes
//! a `fetch_*` method. `new()` and every constructor are pure — there are no lazy
//! statics that dial out, and importing this module contacts nothing. Offline is the
//! runtime default.
//!
//! Two providers are supported:
//!   * **Sourcify** — no API key. Verified sources are served with their file content
//!     inline, so multi-file projects come back complete.
//!   * **Etherscan-family V2 API** — one multichain endpoint keyed by `chainid`. The
//!     key is read from `ETHERSCAN_API_KEY` (never hardcoded, never logged).
//!
//! # Security model
//!
//! Every byte fetched here is **untrusted remote input** and is treated strictly as
//! data — nothing is ever executed. Verified-source responses routinely embed relative
//! import paths, and a malicious one can embed `../../../../etc/passwd`, absolute paths,
//! Windows separators, or NUL bytes. [`sanitize_relative_path`] rejects all of those and
//! guarantees writes stay inside the caller's target directory. Total bytes and file
//! count are capped, and every network call carries a timeout.

use std::path::{Component, Path, PathBuf};
use std::time::Duration;

/// Hard limits applied to any fetched source bundle.
const MAX_FILES: usize = 512;
const MAX_TOTAL_BYTES: usize = 32 * 1024 * 1024; // 32 MiB
const NETWORK_TIMEOUT: Duration = Duration::from_secs(30);

/// Supported chains for verified-source lookup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Chain {
    Ethereum,
    Base,
    Arbitrum,
    Optimism,
    Polygon,
}

impl Chain {
    /// EVM chain id used by both Sourcify and the Etherscan V2 API.
    pub fn chain_id(&self) -> u64 {
        match self {
            Chain::Ethereum => 1,
            Chain::Base => 8453,
            Chain::Arbitrum => 42161,
            Chain::Optimism => 10,
            Chain::Polygon => 137,
        }
    }

    /// Parse a chain from an id or a human name (case-insensitive).
    pub fn parse(s: &str) -> Result<Chain, OnchainError> {
        let t = s.trim().to_lowercase();
        let chain = match t.as_str() {
            "1" | "eth" | "ethereum" | "mainnet" => Chain::Ethereum,
            "8453" | "base" => Chain::Base,
            "42161" | "arb" | "arbitrum" | "arbitrum-one" => Chain::Arbitrum,
            "10" | "op" | "optimism" => Chain::Optimism,
            "137" | "polygon" | "matic" => Chain::Polygon,
            _ => return Err(OnchainError::UnknownChain(s.to_string())),
        };
        Ok(chain)
    }
}

/// Typed, actionable errors. Nothing here panics or `unwrap()`s a network result.
#[derive(Debug)]
pub enum OnchainError {
    /// Chain id/name not recognised.
    UnknownChain(String),
    /// Address is not a 0x-prefixed 40-hex-char value.
    BadAddress(String),
    /// The contract is not verified on the chosen provider.
    Unverified { address: String, provider: &'static str },
    /// Provider rate-limited the request.
    RateLimited(&'static str),
    /// The Etherscan API key env var is missing.
    MissingApiKey(&'static str),
    /// Network layer failed (DNS, TLS, connection refused, timeout, ...).
    NetworkUnreachable(String),
    /// Provider returned a response we could not parse.
    MalformedResponse(String),
    /// A source path in the response tried to escape the target directory, or was
    /// otherwise unsafe (absolute, `..`, NUL, empty).
    UnsafePath(String),
    /// The bundle exceeded the file-count or total-byte cap.
    TooLarge(String),
    /// Local filesystem error while writing sources.
    Io(String),
}

impl std::fmt::Display for OnchainError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OnchainError::UnknownChain(c) => write!(f, "unknown chain '{c}' (try: ethereum, base, arbitrum, optimism, polygon)"),
            OnchainError::BadAddress(a) => write!(f, "invalid contract address '{a}' (expected 0x + 40 hex chars)"),
            OnchainError::Unverified { address, provider } => {
                write!(f, "contract {address} is not verified on {provider}")
            }
            OnchainError::RateLimited(p) => write!(f, "{p} rate-limited the request; retry later"),
            OnchainError::MissingApiKey(var) => write!(f, "missing API key: set the {var} environment variable"),
            OnchainError::NetworkUnreachable(e) => write!(f, "network error: {e}"),
            OnchainError::MalformedResponse(e) => write!(f, "malformed provider response: {e}"),
            OnchainError::UnsafePath(p) => write!(f, "refused unsafe source path from remote response: '{p}'"),
            OnchainError::TooLarge(e) => write!(f, "verified-source bundle too large: {e}"),
            OnchainError::Io(e) => write!(f, "filesystem error: {e}"),
        }
    }
}

impl std::error::Error for OnchainError {}

/// One verified source file: a relative path plus its content.
#[derive(Debug, Clone, PartialEq)]
pub struct SourceFile {
    pub path: String,
    pub content: String,
}

/// What a successful fetch produced.
#[derive(Debug)]
pub struct FetchReport {
    pub provider: &'static str,
    pub chain: Chain,
    pub address: String,
    pub files_written: Vec<PathBuf>,
    pub total_bytes: usize,
}

/// Validate a checksum-agnostic EVM address (0x + 40 hex). Returns the lowercased form.
pub fn validate_address(address: &str) -> Result<String, OnchainError> {
    let a = address.trim();
    let hex = a.strip_prefix("0x").or_else(|| a.strip_prefix("0X"));
    match hex {
        Some(h) if h.len() == 40 && h.bytes().all(|b| b.is_ascii_hexdigit()) => {
            Ok(format!("0x{}", h.to_lowercase()))
        }
        _ => Err(OnchainError::BadAddress(address.to_string())),
    }
}

/// Sanitise an untrusted relative path from a remote response and resolve it *lexically*
/// under `base`, guaranteeing the result stays inside `base`.
///
/// Rejects: empty paths, absolute paths (Unix `/` or Windows `C:\`), any `..` component,
/// bare `.`-only paths, NUL bytes, and Windows drive/UNC prefixes. Backslashes are
/// normalised to `/` first so `..\..\x` cannot slip through. No filesystem access and no
/// symlink following: containment is purely lexical, so a not-yet-created `base` is fine.
pub fn sanitize_relative_path(base: &Path, untrusted: &str) -> Result<PathBuf, OnchainError> {
    if untrusted.is_empty() {
        return Err(OnchainError::UnsafePath("<empty>".to_string()));
    }
    if untrusted.contains('\0') {
        return Err(OnchainError::UnsafePath(untrusted.to_string()));
    }

    // Normalise Windows separators so backslash traversal is caught by the same checks.
    let normalised = untrusted.replace('\\', "/");

    // Reject absolute Unix paths and Windows drive prefixes (e.g. "C:/", "C:foo").
    if normalised.starts_with('/') {
        return Err(OnchainError::UnsafePath(untrusted.to_string()));
    }
    let looks_like_drive = normalised
        .as_bytes()
        .get(1)
        .map(|&b| b == b':')
        .unwrap_or(false);
    if looks_like_drive {
        return Err(OnchainError::UnsafePath(untrusted.to_string()));
    }

    let mut safe = PathBuf::new();
    for comp in Path::new(&normalised).components() {
        match comp {
            Component::Normal(seg) => {
                // Defend against embedded NULs surfacing per-segment on odd platforms.
                if seg.to_string_lossy().contains('\0') {
                    return Err(OnchainError::UnsafePath(untrusted.to_string()));
                }
                safe.push(seg);
            }
            // Drop harmless "./" segments.
            Component::CurDir => {}
            // Anything that could escape: reject the whole path.
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(OnchainError::UnsafePath(untrusted.to_string()));
            }
        }
    }

    if safe.as_os_str().is_empty() {
        // e.g. the path was just "." or "./".
        return Err(OnchainError::UnsafePath(untrusted.to_string()));
    }

    Ok(base.join(safe))
}

/// Parse a verified-source payload into concrete files, handling the three real shapes:
///
/// 1. **Flat source** — a single Solidity file as a raw string (not JSON). Returned under
///    `default_name`.
/// 2. **Standard JSON input** — `{"language":"Solidity","sources":{"<path>":{"content":"..."}}}`,
///    including Etherscan's double-brace `{{ ... }}` wrapping quirk.
/// 3. **Multi-file map** — `{"<path>": {"content":"..."}}` or `{"<path>": "<source>"}`.
///
/// Paths inside the payload are returned verbatim here; they are sanitised at write time
/// by [`sanitize_relative_path`].
pub fn parse_verified_sources(raw: &str, default_name: &str) -> Result<Vec<SourceFile>, OnchainError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(OnchainError::MalformedResponse("empty source payload".to_string()));
    }

    // Etherscan wraps standard-json-input in an extra pair of braces: "{{ ... }}".
    let unwrapped = if trimmed.starts_with("{{") && trimmed.ends_with("}}") {
        &trimmed[1..trimmed.len() - 1]
    } else {
        trimmed
    };

    // Try to parse as JSON; if it is not JSON at all, it is a flat single source file.
    let value: serde_json::Value = match serde_json::from_str(unwrapped) {
        Ok(v) => v,
        Err(_) => {
            return Ok(vec![SourceFile {
                path: default_name.to_string(),
                content: raw.to_string(),
            }]);
        }
    };

    let obj = match value.as_object() {
        Some(o) => o,
        // Valid JSON but not an object (e.g. a JSON string literal) -> treat as flat.
        None => {
            let content = value.as_str().map(|s| s.to_string()).unwrap_or_else(|| raw.to_string());
            return Ok(vec![SourceFile {
                path: default_name.to_string(),
                content,
            }]);
        }
    };

    // Shape 2: standard-json-input has a top-level "sources" map.
    let sources_map = if let Some(sources) = obj.get("sources").and_then(|s| s.as_object()) {
        sources
    } else {
        // Shape 3: the object itself is the file map.
        obj
    };

    let mut files = Vec::new();
    for (path, entry) in sources_map {
        let content = if let Some(c) = entry.get("content").and_then(|c| c.as_str()) {
            c.to_string()
        } else if let Some(s) = entry.as_str() {
            s.to_string()
        } else {
            // Skip entries with no inline content (e.g. keccak/urls-only metadata refs).
            continue;
        };
        files.push(SourceFile {
            path: path.clone(),
            content,
        });
    }

    if files.is_empty() {
        return Err(OnchainError::MalformedResponse(
            "no inline source content found in payload".to_string(),
        ));
    }
    Ok(files)
}

/// Verified-source fetcher. Construction is pure; no I/O happens until a `fetch_*` call.
pub struct SourceFetcher {
    timeout: Duration,
    max_files: usize,
    max_total_bytes: usize,
}

impl Default for SourceFetcher {
    fn default() -> Self {
        Self::new()
    }
}

impl SourceFetcher {
    /// Create a fetcher with default limits. Performs no I/O.
    pub fn new() -> Self {
        Self {
            timeout: NETWORK_TIMEOUT,
            max_files: MAX_FILES,
            max_total_bytes: MAX_TOTAL_BYTES,
        }
    }

    /// Write a set of parsed sources under `out_dir`, enforcing path safety and caps.
    ///
    /// Every path is run through [`sanitize_relative_path`]; the total file count and byte
    /// count are checked against the fetcher's caps *before* anything is written past the
    /// limit. Parent directories are created as needed, all inside `out_dir`.
    pub fn write_sources(
        &self,
        out_dir: &Path,
        files: &[SourceFile],
    ) -> Result<Vec<PathBuf>, OnchainError> {
        if files.len() > self.max_files {
            return Err(OnchainError::TooLarge(format!(
                "{} files exceeds cap of {}",
                files.len(),
                self.max_files
            )));
        }

        // Pre-validate paths and size before touching the filesystem.
        let mut total = 0usize;
        let mut resolved = Vec::with_capacity(files.len());
        for f in files {
            total = total.saturating_add(f.content.len());
            if total > self.max_total_bytes {
                return Err(OnchainError::TooLarge(format!(
                    "total bytes exceed cap of {}",
                    self.max_total_bytes
                )));
            }
            let dest = sanitize_relative_path(out_dir, &f.path)?;
            resolved.push((dest, &f.content));
        }

        let mut written = Vec::with_capacity(resolved.len());
        for (dest, content) in resolved {
            if let Some(parent) = dest.parent() {
                std::fs::create_dir_all(parent).map_err(|e| OnchainError::Io(e.to_string()))?;
            }
            std::fs::write(&dest, content.as_bytes()).map_err(|e| OnchainError::Io(e.to_string()))?;
            written.push(dest);
        }
        Ok(written)
    }

    /// Fetch verified source for `address` on `chain`, writing it under `out_dir`.
    ///
    /// Tries Sourcify first (no key needed); if the contract is not on Sourcify and an
    /// `ETHERSCAN_API_KEY` is set, falls back to the Etherscan V2 API. Returns a typed
    /// error otherwise. Explicitly invoking this is the only way the module touches the
    /// network.
    pub fn fetch_verified_source(
        &self,
        chain: Chain,
        address: &str,
        out_dir: &Path,
    ) -> Result<FetchReport, OnchainError> {
        let addr = validate_address(address)?;

        // Provider 1: Sourcify.
        match self.fetch_sourcify(chain, &addr) {
            Ok(files) => return self.finish(chain, addr, "sourcify", files, out_dir),
            Err(OnchainError::Unverified { .. }) => { /* fall through to Etherscan */ }
            Err(e) => return Err(e),
        }

        // Provider 2: Etherscan V2 (optional, key-gated).
        let files = self.fetch_etherscan(chain, &addr)?;
        self.finish(chain, addr, "etherscan", files, out_dir)
    }

    fn finish(
        &self,
        chain: Chain,
        address: String,
        provider: &'static str,
        files: Vec<SourceFile>,
        out_dir: &Path,
    ) -> Result<FetchReport, OnchainError> {
        let total_bytes = files.iter().map(|f| f.content.len()).sum();
        let files_written = self.write_sources(out_dir, &files)?;
        Ok(FetchReport {
            provider,
            chain,
            address,
            files_written,
            total_bytes,
        })
    }

    /// Fetch from Sourcify's server API, which returns file content inline.
    fn fetch_sourcify(&self, chain: Chain, address: &str) -> Result<Vec<SourceFile>, OnchainError> {
        // `/files/any/...` returns both full and partial matches with content.
        // Reference layout: https://repo.sourcify.dev/contracts/{full_match,partial_match}/{chainId}/{address}/sources/...
        let url = format!(
            "https://sourcify.dev/server/files/any/{}/{}",
            chain.chain_id(),
            address
        );

        let agent = ureq::AgentBuilder::new()
            .timeout(self.timeout)
            .build();

        let resp = match agent.get(&url).call() {
            Ok(r) => r,
            Err(ureq::Error::Status(404, _)) => {
                return Err(OnchainError::Unverified {
                    address: address.to_string(),
                    provider: "sourcify",
                })
            }
            Err(ureq::Error::Status(429, _)) => return Err(OnchainError::RateLimited("sourcify")),
            Err(ureq::Error::Status(code, _)) => {
                return Err(OnchainError::MalformedResponse(format!("sourcify HTTP {code}")))
            }
            Err(ureq::Error::Transport(t)) => {
                return Err(OnchainError::NetworkUnreachable(t.to_string()))
            }
        };

        let body = resp
            .into_string()
            .map_err(|e| OnchainError::NetworkUnreachable(e.to_string()))?;
        self.parse_sourcify_body(&body, address)
    }

    /// Parse Sourcify's `{"status":..,"files":[{"name","path","content"}]}` body.
    fn parse_sourcify_body(&self, body: &str, address: &str) -> Result<Vec<SourceFile>, OnchainError> {
        let value: serde_json::Value = serde_json::from_str(body)
            .map_err(|e| OnchainError::MalformedResponse(e.to_string()))?;

        let arr = value
            .get("files")
            .and_then(|f| f.as_array())
            // Some deployments return a bare array.
            .or_else(|| value.as_array())
            .ok_or_else(|| OnchainError::Unverified {
                address: address.to_string(),
                provider: "sourcify",
            })?;

        let mut files = Vec::new();
        for entry in arr {
            let content = match entry.get("content").and_then(|c| c.as_str()) {
                Some(c) => c.to_string(),
                None => continue,
            };
            // Prefer the repo-relative `path`; fall back to `name`.
            let raw_path = entry
                .get("path")
                .and_then(|p| p.as_str())
                .or_else(|| entry.get("name").and_then(|n| n.as_str()))
                .unwrap_or("contract.sol");
            files.push(SourceFile {
                path: strip_sourcify_prefix(raw_path, address),
                content,
            });
        }

        if files.is_empty() {
            return Err(OnchainError::Unverified {
                address: address.to_string(),
                provider: "sourcify",
            });
        }
        Ok(files)
    }

    /// Fetch from the Etherscan-family V2 multichain API. Key from `ETHERSCAN_API_KEY`.
    fn fetch_etherscan(&self, chain: Chain, address: &str) -> Result<Vec<SourceFile>, OnchainError> {
        let key = std::env::var("ETHERSCAN_API_KEY")
            .map_err(|_| OnchainError::MissingApiKey("ETHERSCAN_API_KEY"))?;
        if key.trim().is_empty() {
            return Err(OnchainError::MissingApiKey("ETHERSCAN_API_KEY"));
        }

        let url = format!(
            "https://api.etherscan.io/v2/api?chainid={}&module=contract&action=getsourcecode&address={}&apikey={}",
            chain.chain_id(),
            address,
            key
        );

        let agent = ureq::AgentBuilder::new().timeout(self.timeout).build();

        let resp = match agent.get(&url).call() {
            Ok(r) => r,
            Err(ureq::Error::Status(429, _)) => return Err(OnchainError::RateLimited("etherscan")),
            Err(ureq::Error::Status(code, _)) => {
                return Err(OnchainError::MalformedResponse(format!("etherscan HTTP {code}")))
            }
            Err(ureq::Error::Transport(t)) => {
                return Err(OnchainError::NetworkUnreachable(t.to_string()))
            }
        };

        let body = resp
            .into_string()
            .map_err(|e| OnchainError::NetworkUnreachable(e.to_string()))?;
        self.parse_etherscan_body(&body, address)
    }

    /// Parse an Etherscan `getsourcecode` response body.
    fn parse_etherscan_body(&self, body: &str, address: &str) -> Result<Vec<SourceFile>, OnchainError> {
        let value: serde_json::Value = serde_json::from_str(body)
            .map_err(|e| OnchainError::MalformedResponse(e.to_string()))?;

        // Rate-limit is often signalled in the message with status "0".
        let status = value.get("status").and_then(|s| s.as_str()).unwrap_or("");
        let message = value.get("message").and_then(|m| m.as_str()).unwrap_or("");
        if status == "0" && message.to_lowercase().contains("rate limit") {
            return Err(OnchainError::RateLimited("etherscan"));
        }

        let first = value
            .get("result")
            .and_then(|r| r.as_array())
            .and_then(|a| a.first())
            .ok_or_else(|| OnchainError::MalformedResponse("no result array".to_string()))?;

        let source_code = first
            .get("SourceCode")
            .and_then(|s| s.as_str())
            .unwrap_or("");
        if source_code.trim().is_empty() {
            return Err(OnchainError::Unverified {
                address: address.to_string(),
                provider: "etherscan",
            });
        }

        let default_name = first
            .get("ContractName")
            .and_then(|n| n.as_str())
            .filter(|n| !n.is_empty())
            .map(|n| format!("{n}.sol"))
            .unwrap_or_else(|| "Contract.sol".to_string());

        parse_verified_sources(source_code, &default_name)
    }
}

/// Strip Sourcify's `contracts/full_match/<chain>/<address>/sources/` prefix so files
/// land at their natural project-relative locations.
fn strip_sourcify_prefix(path: &str, address: &str) -> String {
    let needle_full = format!("/{address}/sources/");
    let needle_lower = format!("/{}/sources/", address.to_lowercase());
    for needle in [needle_full.as_str(), needle_lower.as_str()] {
        if let Some(pos) = path.find(needle) {
            return path[pos + needle.len()..].to_string();
        }
    }
    // Also handle a leading "sources/" without the address prefix.
    if let Some(rest) = path.strip_prefix("sources/") {
        return rest.to_string();
    }
    path.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chain_parse_by_id_and_name() {
        assert_eq!(Chain::parse("1").unwrap(), Chain::Ethereum);
        assert_eq!(Chain::parse("base").unwrap(), Chain::Base);
        assert_eq!(Chain::parse("ARBITRUM").unwrap(), Chain::Arbitrum);
        assert_eq!(Chain::parse("optimism").unwrap().chain_id(), 10);
        assert_eq!(Chain::parse("137").unwrap(), Chain::Polygon);
        assert!(matches!(Chain::parse("dogechain"), Err(OnchainError::UnknownChain(_))));
    }

    #[test]
    fn address_validation() {
        let ok = validate_address("0xAbC0000000000000000000000000000000000001").unwrap();
        assert_eq!(ok, "0xabc0000000000000000000000000000000000001");
        assert!(matches!(validate_address("0x1234"), Err(OnchainError::BadAddress(_))));
        assert!(matches!(validate_address("nope"), Err(OnchainError::BadAddress(_))));
        assert!(matches!(
            validate_address("0xZZZ0000000000000000000000000000000000001"),
            Err(OnchainError::BadAddress(_))
        ));
    }

    #[test]
    fn path_traversal_is_rejected() {
        let base = Path::new("/tmp/out");
        // Classic dot-dot escape.
        assert!(matches!(
            sanitize_relative_path(base, "../../../../etc/passwd"),
            Err(OnchainError::UnsafePath(_))
        ));
        // Absolute Unix path.
        assert!(matches!(
            sanitize_relative_path(base, "/etc/passwd"),
            Err(OnchainError::UnsafePath(_))
        ));
        // Windows separators used for traversal.
        assert!(matches!(
            sanitize_relative_path(base, "..\\..\\windows\\system32"),
            Err(OnchainError::UnsafePath(_))
        ));
        // Windows drive prefix.
        assert!(matches!(
            sanitize_relative_path(base, "C:/Windows/system32"),
            Err(OnchainError::UnsafePath(_))
        ));
        // Embedded dot-dot in the middle.
        assert!(matches!(
            sanitize_relative_path(base, "contracts/../../escape.sol"),
            Err(OnchainError::UnsafePath(_))
        ));
        // NUL byte.
        assert!(matches!(
            sanitize_relative_path(base, "a\0b.sol"),
            Err(OnchainError::UnsafePath(_))
        ));
        // Empty.
        assert!(matches!(
            sanitize_relative_path(base, ""),
            Err(OnchainError::UnsafePath(_))
        ));
    }

    #[test]
    fn safe_paths_are_accepted_and_contained() {
        let base = Path::new("/tmp/out");
        let p = sanitize_relative_path(base, "contracts/token/ERC20.sol").unwrap();
        assert_eq!(p, PathBuf::from("/tmp/out/contracts/token/ERC20.sol"));
        assert!(p.starts_with(base));
        // Leading "./" is harmless and stripped.
        let p2 = sanitize_relative_path(base, "./a/b.sol").unwrap();
        assert_eq!(p2, PathBuf::from("/tmp/out/a/b.sol"));
    }

    #[test]
    fn parse_shape_flat_source() {
        let raw = "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.0;\ncontract A {}";
        let files = parse_verified_sources(raw, "A.sol").unwrap();
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].path, "A.sol");
        assert!(files[0].content.contains("contract A"));
    }

    #[test]
    fn parse_shape_standard_json_input_double_braced() {
        // Etherscan's double-brace standard-json-input.
        let raw = r#"{{"language":"Solidity","sources":{"contracts/A.sol":{"content":"contract A {}"},"contracts/B.sol":{"content":"contract B {}"}},"settings":{}}}"#;
        let mut files = parse_verified_sources(raw, "default.sol").unwrap();
        files.sort_by(|a, b| a.path.cmp(&b.path));
        assert_eq!(files.len(), 2);
        assert_eq!(files[0].path, "contracts/A.sol");
        assert_eq!(files[1].content, "contract B {}");
    }

    #[test]
    fn parse_shape_multifile_map() {
        // A bare map of path -> {content}, and path -> string.
        let raw = r#"{"src/X.sol":{"content":"contract X {}"},"src/Y.sol":"contract Y {}"}"#;
        let mut files = parse_verified_sources(raw, "default.sol").unwrap();
        files.sort_by(|a, b| a.path.cmp(&b.path));
        assert_eq!(files.len(), 2);
        assert_eq!(files[0].path, "src/X.sol");
        assert_eq!(files[1].content, "contract Y {}");
    }

    #[test]
    fn write_sources_enforces_containment_and_writes() {
        let dir = std::env::temp_dir().join(format!("onchain_write_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let fetcher = SourceFetcher::new();

        // A malicious path in the bundle must abort the whole write with UnsafePath.
        let evil = vec![SourceFile {
            path: "../evil.sol".to_string(),
            content: "x".to_string(),
        }];
        assert!(matches!(
            fetcher.write_sources(&dir, &evil),
            Err(OnchainError::UnsafePath(_))
        ));

        // A safe bundle writes and stays inside `dir`.
        let good = vec![SourceFile {
            path: "contracts/A.sol".to_string(),
            content: "contract A {}".to_string(),
        }];
        let written = fetcher.write_sources(&dir, &good).unwrap();
        assert_eq!(written.len(), 1);
        assert!(written[0].starts_with(&dir));
        assert!(written[0].is_file());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn write_sources_rejects_too_many_files() {
        let fetcher = SourceFetcher {
            timeout: NETWORK_TIMEOUT,
            max_files: 2,
            max_total_bytes: MAX_TOTAL_BYTES,
        };
        let files: Vec<SourceFile> = (0..3)
            .map(|i| SourceFile {
                path: format!("f{i}.sol"),
                content: "x".to_string(),
            })
            .collect();
        assert!(matches!(
            fetcher.write_sources(Path::new("/tmp/whatever"), &files),
            Err(OnchainError::TooLarge(_))
        ));
    }

    #[test]
    fn write_sources_rejects_oversized_total() {
        let fetcher = SourceFetcher {
            timeout: NETWORK_TIMEOUT,
            max_files: 10,
            max_total_bytes: 8,
        };
        let files = vec![SourceFile {
            path: "big.sol".to_string(),
            content: "0123456789".to_string(),
        }];
        assert!(matches!(
            fetcher.write_sources(Path::new("/tmp/whatever"), &files),
            Err(OnchainError::TooLarge(_))
        ));
    }

    #[test]
    fn fetch_report_exposes_all_fields() {
        // Documents the report shape the CLI consumes, and reads every field.
        let report = FetchReport {
            provider: "sourcify",
            chain: Chain::Base,
            address: "0xabc".to_string(),
            files_written: vec![PathBuf::from("/tmp/out/A.sol")],
            total_bytes: 12,
        };
        assert_eq!(report.provider, "sourcify");
        assert_eq!(report.chain, Chain::Base);
        assert_eq!(report.address, "0xabc");
        assert_eq!(report.files_written.len(), 1);
        assert_eq!(report.total_bytes, 12);
    }

    #[test]
    fn fetch_rejects_bad_address_before_any_network() {
        // Bad address short-circuits inside fetch_verified_source; no I/O occurs.
        let fetcher = SourceFetcher::new();
        let res = fetcher.fetch_verified_source(Chain::Ethereum, "0xbad", Path::new("/tmp/x"));
        assert!(matches!(res, Err(OnchainError::BadAddress(_))));
    }

    #[test]
    fn sourcify_prefix_stripping() {
        let addr = "0xabc0000000000000000000000000000000000001";
        let full = format!("contracts/full_match/1/{addr}/sources/contracts/Token.sol");
        assert_eq!(strip_sourcify_prefix(&full, addr), "contracts/Token.sol");
        assert_eq!(strip_sourcify_prefix("sources/A.sol", addr), "A.sol");
        assert_eq!(strip_sourcify_prefix("A.sol", addr), "A.sol");
    }

    #[test]
    fn etherscan_body_parsing_flat_and_unverified() {
        let fetcher = SourceFetcher::new();
        let flat = r#"{"status":"1","message":"OK","result":[{"SourceCode":"contract A {}","ContractName":"A"}]}"#;
        let files = fetcher.parse_etherscan_body(flat, "0xabc").unwrap();
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].path, "A.sol");

        let unverified = r#"{"status":"1","message":"OK","result":[{"SourceCode":"","ContractName":""}]}"#;
        assert!(matches!(
            fetcher.parse_etherscan_body(unverified, "0xabc"),
            Err(OnchainError::Unverified { .. })
        ));

        let rate = r#"{"status":"0","message":"NOTOK Max rate limit reached","result":"..."}"#;
        assert!(matches!(
            fetcher.parse_etherscan_body(rate, "0xabc"),
            Err(OnchainError::RateLimited("etherscan"))
        ));
    }

    #[test]
    fn sourcify_body_parsing() {
        let fetcher = SourceFetcher::new();
        let addr = "0xabc0000000000000000000000000000000000001";
        let body = format!(
            r#"{{"status":"full","files":[{{"name":"Token.sol","path":"contracts/full_match/1/{addr}/sources/contracts/Token.sol","content":"contract Token {{}}"}}]}}"#
        );
        let files = fetcher.parse_sourcify_body(&body, addr).unwrap();
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].path, "contracts/Token.sol");
        assert!(files[0].content.contains("contract Token"));
    }
}
