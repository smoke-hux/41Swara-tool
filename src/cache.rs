//! Incremental Parsing Cache
//!
//! Caches AST and analysis results by file hash for:
//! - Skipping unchanged files on rescan
//! - Persisting cache to disk for CI/CD
//! - Fast incremental analysis

#![allow(dead_code)]

use blake3::Hasher;
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{BufReader, BufWriter};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use crate::vulnerabilities::Vulnerability;

/// Cache entry for a single file
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheEntry {
    pub file_hash: String,
    pub file_path: String,
    pub last_modified: u64,
    pub vulnerabilities: Vec<CachedVulnerability>,
    pub scan_timestamp: u64,
}

/// Serializable vulnerability for caching
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedVulnerability {
    pub title: String,
    pub description: String,
    pub severity: String,
    pub category: String,
    pub line_number: usize,
    pub code_snippet: String,
    pub recommendation: String,
    pub confidence: String,
}

impl From<&Vulnerability> for CachedVulnerability {
    fn from(v: &Vulnerability) -> Self {
        Self {
            title: v.title.clone(),
            description: v.description.clone(),
            severity: format!("{:?}", v.severity),
            category: format!("{:?}", v.category),
            line_number: v.line_number,
            code_snippet: v.code_snippet.clone(),
            recommendation: v.recommendation.clone(),
            confidence: format!("{:?}", v.confidence),
        }
    }
}

/// Cache statistics
#[derive(Debug, Default, Clone)]
pub struct CacheStats {
    pub hits: usize,
    pub misses: usize,
    pub invalidations: usize,
    pub total_entries: usize,
}

/// Incremental scanning cache
pub struct ScanCache {
    /// In-memory cache using concurrent hashmap
    entries: Arc<DashMap<String, CacheEntry>>,
    /// Path to persistent cache file
    cache_path: Option<PathBuf>,
    /// Cache TTL (time-to-live)
    ttl: Duration,
    /// Statistics
    stats: Arc<Mutex<CacheStats>>,
}

impl ScanCache {
    /// Create a new cache with optional persistence
    pub fn new(cache_path: Option<&Path>, ttl_hours: u64) -> Self {
        let cache = Self {
            entries: Arc::new(DashMap::new()),
            cache_path: cache_path.map(|p| p.to_path_buf()),
            ttl: Duration::from_secs(ttl_hours * 3600),
            stats: Arc::new(Mutex::new(CacheStats::default())),
        };

        // Load existing cache from disk
        if let Some(path) = &cache.cache_path {
            if path.exists() {
                cache.load_from_disk();
            }
        }

        cache
    }

    /// Create in-memory only cache
    pub fn in_memory() -> Self {
        Self::new(None, 24)
    }

    /// Create persistent cache
    pub fn persistent(cache_dir: &Path) -> Self {
        let cache_file = cache_dir.join(".41swara_cache.json");
        Self::new(Some(&cache_file), 168) // 1 week TTL
    }

    /// Compute hash for file content
    pub fn compute_hash(content: &str) -> String {
        let mut hasher = Hasher::new();
        hasher.update(content.as_bytes());
        hasher.finalize().to_hex().to_string()
    }

    /// Check if file is cached and still valid
    pub fn is_cached(&self, file_path: &str, content: &str) -> bool {
        let hash = Self::compute_hash(content);

        if let Some(entry) = self.entries.get(file_path) {
            // Check hash match
            if entry.file_hash != hash {
                self.stats.lock().unwrap().invalidations += 1;
                return false;
            }

            // Check TTL
            let now = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs();

            if now - entry.scan_timestamp > self.ttl.as_secs() {
                self.stats.lock().unwrap().invalidations += 1;
                return false;
            }

            self.stats.lock().unwrap().hits += 1;
            true
        } else {
            self.stats.lock().unwrap().misses += 1;
            false
        }
    }

    /// Get cached vulnerabilities for a file
    pub fn get(&self, file_path: &str) -> Option<Vec<CachedVulnerability>> {
        self.entries.get(file_path).map(|e| e.vulnerabilities.clone())
    }

    /// Store scan results in cache
    pub fn put(&self, file_path: &str, content: &str, vulnerabilities: &[Vulnerability]) {
        let hash = Self::compute_hash(content);
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let last_modified = fs::metadata(file_path)
            .and_then(|m| m.modified())
            .map(|t| t.duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs())
            .unwrap_or(now);

        let entry = CacheEntry {
            file_hash: hash,
            file_path: file_path.to_string(),
            last_modified,
            vulnerabilities: vulnerabilities.iter().map(CachedVulnerability::from).collect(),
            scan_timestamp: now,
        };

        self.entries.insert(file_path.to_string(), entry);
    }

    /// Invalidate cache entry for a file
    pub fn invalidate(&self, file_path: &str) {
        self.entries.remove(file_path);
        self.stats.lock().unwrap().invalidations += 1;
    }

    /// Clear entire cache
    pub fn clear(&self) {
        self.entries.clear();
        let mut stats = self.stats.lock().unwrap();
        *stats = CacheStats::default();
    }

    /// Save cache to disk
    pub fn save_to_disk(&self) -> Result<(), std::io::Error> {
        if let Some(path) = &self.cache_path {
            // Create parent directory if needed
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)?;
            }

            let cache_data: HashMap<String, CacheEntry> = self.entries
                .iter()
                .map(|e| (e.key().clone(), e.value().clone()))
                .collect();

            let file = File::create(path)?;
            let writer = BufWriter::new(file);
            serde_json::to_writer_pretty(writer, &cache_data)?;
        }
        Ok(())
    }

    /// Load cache from disk
    pub fn load_from_disk(&self) {
        if let Some(path) = &self.cache_path {
            if let Ok(file) = File::open(path) {
                let reader = BufReader::new(file);
                if let Ok(cache_data) = serde_json::from_reader::<_, HashMap<String, CacheEntry>>(reader) {
                    for (key, value) in cache_data {
                        self.entries.insert(key, value);
                    }
                }
            }
        }

        self.stats.lock().unwrap().total_entries = self.entries.len();
    }

    /// Get cache statistics
    pub fn stats(&self) -> CacheStats {
        let mut stats = self.stats.lock().unwrap().clone();
        stats.total_entries = self.entries.len();
        stats
    }

    /// Prune expired entries
    pub fn prune_expired(&self) {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let ttl_secs = self.ttl.as_secs();

        self.entries.retain(|_, entry| {
            now - entry.scan_timestamp <= ttl_secs
        });
    }

    /// Get number of cached files
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if cache is empty
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Check which files from a list need scanning (not cached or modified)
    pub fn files_needing_scan(&self, files: &[(String, String)]) -> Vec<String> {
        files.iter()
            .filter(|(path, content)| !self.is_cached(path, content))
            .map(|(path, _)| path.clone())
            .collect()
    }
}

impl Drop for ScanCache {
    fn drop(&mut self) {
        // Auto-save on drop
        let _ = self.save_to_disk();
    }
}

/// Batch cache operations for parallel scanning
pub struct BatchCache {
    cache: Arc<ScanCache>,
}

impl BatchCache {
    pub fn new(cache: Arc<ScanCache>) -> Self {
        Self { cache }
    }

    /// Batch check for cached files
    pub fn batch_check(&self, files: &[(&str, &str)]) -> Vec<bool> {
        files.iter()
            .map(|(path, content)| self.cache.is_cached(path, content))
            .collect()
    }

    /// Batch put results
    pub fn batch_put(&self, results: &[(&str, &str, &[Vulnerability])]) {
        for (path, content, vulns) in results {
            self.cache.put(path, content, vulns);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_computation() {
        let content = "pragma solidity ^0.8.0;";
        let hash = ScanCache::compute_hash(content);
        assert!(!hash.is_empty());

        // Same content = same hash
        let hash2 = ScanCache::compute_hash(content);
        assert_eq!(hash, hash2);

        // Different content = different hash
        let hash3 = ScanCache::compute_hash("pragma solidity ^0.7.0;");
        assert_ne!(hash, hash3);
    }

    #[test]
    fn test_cache_operations() {
        let cache = ScanCache::in_memory();

        let path = "test.sol";
        let content = "contract Test {}";

        // Initially not cached
        assert!(!cache.is_cached(path, content));

        // Add to cache
        cache.put(path, content, &[]);

        // Now cached
        assert!(cache.is_cached(path, content));

        // Different content = not cached
        assert!(!cache.is_cached(path, "contract Test2 {}"));

        // Invalidate
        cache.invalidate(path);
        assert!(!cache.is_cached(path, content));
    }

    #[test]
    fn test_cache_stats() {
        let cache = ScanCache::in_memory();

        let path = "test.sol";
        let content = "contract Test {}";

        // Miss
        let _ = cache.is_cached(path, content);

        // Put
        cache.put(path, content, &[]);

        // Hit
        let _ = cache.is_cached(path, content);

        let stats = cache.stats();
        assert_eq!(stats.misses, 1);
        assert_eq!(stats.hits, 1);
    }
}
