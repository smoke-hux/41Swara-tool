//! 41Swara Smart Contract Security Scanner - Security Researcher Edition
//!
//! High-performance vulnerability scanner for Ethereum Foundation and blockchain security researchers.
//! Features parallel scanning, severity filtering, CWE/SWC mapping, and multiple output formats.

// --- External crate imports ---
use clap::{Parser, ValueEnum}; // CLI argument parsing framework
use colored::*; // Terminal color output support
use git2::{Delta, DiffOptions, Repository}; // Git integration for diff-based scanning
use glob::Pattern;
use indicatif::{ProgressBar, ProgressStyle}; // Progress bars for directory scans
use notify::{Event, EventKind, RecursiveMode, Result as NotifyResult, Watcher}; // File watcher for --watch mode
use rayon::prelude::*; // Parallel iterator support for multi-threaded scanning
use std::path::{Path, PathBuf};
use std::sync::mpsc::channel; // Channel for file watcher event communication
use std::sync::{Arc, Mutex}; // Thread-safe shared state for parallel scanning
use std::time::Instant; // Performance timing
use walkdir::WalkDir; // Recursive directory traversal // Glob pattern matching for --exclude-pattern

// --- Internal module declarations ---
mod abi_scanner; // ABI JSON file vulnerability scanner
mod advanced_analysis; // DeFi/NFT/exploit pattern analyzers
mod parser; // Solidity source code parser (line splitting, version extraction)
mod professional_reporter; // Professional audit-style report generation
mod project_scanner; // Cross-file project-wide analysis
mod reporter; // Terminal-based vulnerability report output
mod sarif;
mod scanner; // Core scanning orchestration engine
mod vulnerabilities; // Vulnerability rules, types, and severity definitions // SARIF 2.1.0 output format (GitHub Code Scanning integration)

// Phase 1: AST-Based Analysis Engine
mod ast;

// Phase 2: DeFi-Specific Analyzers (AMM, lending, oracle patterns)
mod defi;

// Phase 4: Performance & Caching (incremental scanning support)
mod cache;

// Phase 5: Tool Integration (Slither/Foundry correlation)
mod integrations;

// Phase 6: Advanced Analysis Engine (business logic, reachability, dependencies, threat models)
mod dependency_analyzer;
mod logic_analyzer;
mod reachability_analyzer;
mod threat_model;

// Phase 7: EIP Analysis & Enhanced False Positive Filtering
mod attack_path;
mod cvss; // CVSS 3.1 base score calculator
mod eip_analyzer; // ERC-20/721/777/1155/4626/2771 standard compliance checks
mod exploit_db; // Real-world exploit reference database
mod false_positive_filter; // Multi-pass false positive reduction (~90% FP reduction) // Attack narrative generator

// Phase 8: Configuration System
mod config; // TOML-based custom rules and scanner settings

// --- Re-exports used across main ---
use abi_scanner::ABIScanner;
use professional_reporter::{AuditInfo, ProfessionalReporter};
use reporter::VulnerabilityReporter;
use sarif::SarifReport;
use scanner::{ContractScanner, ScannerConfig};
use vulnerabilities::{Vulnerability, VulnerabilitySeverity};

/// Type alias for thread-safe shared scan results (reduces type complexity warnings).
type SharedResults<T> = Arc<Mutex<Vec<T>>>;

/// Minimum severity threshold for filtering scan results.
/// Used with `--min-severity` CLI flag to suppress lower-priority findings.
/// Ordered from most to least severe: Critical > High > Medium > Low > Info.
#[derive(Debug, Clone, Copy, ValueEnum, PartialEq, Eq, PartialOrd, Ord)]
enum MinSeverity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl MinSeverity {
    /// Returns true if the given vulnerability severity meets or exceeds this threshold.
    /// For example, MinSeverity::High matches Critical and High but not Medium/Low/Info.
    fn matches(&self, severity: &VulnerabilitySeverity) -> bool {
        match (self, severity) {
            (MinSeverity::Critical, VulnerabilitySeverity::Critical) => true,
            (MinSeverity::Critical, _) => false,
            (MinSeverity::High, VulnerabilitySeverity::Critical | VulnerabilitySeverity::High) => {
                true
            }
            (MinSeverity::High, _) => false,
            (
                MinSeverity::Medium,
                VulnerabilitySeverity::Critical
                | VulnerabilitySeverity::High
                | VulnerabilitySeverity::Medium,
            ) => true,
            (MinSeverity::Medium, _) => false,
            (MinSeverity::Low, VulnerabilitySeverity::Info) => false,
            (MinSeverity::Low, _) => true,
            (MinSeverity::Info, _) => true,
        }
    }
}

#[derive(Parser)]
#[command(name = "solidity-scanner")]
#[command(version = env!("CARGO_PKG_VERSION"))]
#[command(author = "41Swara Security Team")]
#[command(
    about = "High-performance smart contract vulnerability scanner - Security Researcher Edition"
)]
#[command(long_about = None)]
struct Args {
    /// Path to smart contract file (.sol) or directory to scan (default: current directory)
    #[arg(value_name = "PATH", default_value = ".")]
    path: PathBuf,

    /// Output format
    #[arg(short, long, default_value = "text", value_parser = ["text", "json", "sarif"])]
    format: String,

    /// Minimum severity level to report
    #[arg(long, value_enum, default_value = "info")]
    min_severity: MinSeverity,

    /// Enable verbose output with detailed analysis
    #[arg(short, long)]
    verbose: bool,

    /// Number of parallel threads (0 = auto-detect CPU cores)
    #[arg(short = 'j', long, default_value = "0")]
    threads: usize,

    /// Show usage examples
    #[arg(long)]
    examples: bool,

    /// Generate clean PDF-style report
    #[arg(long)]
    report: bool,

    /// Generate professional audit report
    #[arg(long, conflicts_with = "report")]
    audit: bool,

    /// Project name for audit report (requires --audit)
    #[arg(long, requires = "audit")]
    project: Option<String>,

    /// Sponsor name for audit report (requires --audit)
    #[arg(long, requires = "audit")]
    sponsor: Option<String>,

    /// Enable advanced project-wide analysis with cross-file vulnerability detection
    #[arg(long)]
    project_analysis: bool,

    /// Scan ABI JSON file for security vulnerabilities
    #[arg(long)]
    abi: bool,

    /// Show performance statistics
    #[arg(long)]
    stats: bool,

    /// Quiet mode - only show summary
    #[arg(short, long)]
    quiet: bool,

    /// Fail with non-zero exit code if findings above threshold
    #[arg(long, value_enum, value_name = "SEVERITY")]
    fail_on: Option<MinSeverity>,

    /// Enable git diff mode - scan only modified .sol files
    #[arg(long)]
    git_diff: bool,

    /// Git branch/commit to compare against (default: HEAD)
    #[arg(long, default_value = "HEAD", requires = "git_diff")]
    git_branch: String,

    /// Watch mode - continuously monitor and rescan on file changes
    #[arg(long, conflicts_with = "git_diff")]
    watch: bool,

    /// Output file path (default: stdout)
    #[arg(short, long, value_name = "FILE")]
    output: Option<PathBuf>,

    // ============================================================================
    // NEW CLI OPTIONS (Phase 5: Tool Integration)
    // ============================================================================
    /// Combine results with Slither JSON output
    #[arg(long, value_name = "PATH")]
    slither_json: Option<PathBuf>,

    /// Generate Foundry PoC tests for findings
    #[arg(long)]
    generate_poc: bool,

    /// Run and correlate with Foundry test results
    #[arg(long)]
    foundry_correlate: bool,

    /// Enable DeFi-specific analysis (AMM, lending, oracle, MEV)
    #[arg(long)]
    defi_analysis: bool,

    /// Enable Phase 6 advanced detectors (ERC4626, Permit2, LayerZero, etc.)
    #[arg(long)]
    advanced_detectors: bool,

    /// Enable incremental scanning with caching
    #[arg(long)]
    cache: bool,

    /// Path to cache directory (default: .41swara_cache)
    #[arg(long, value_name = "DIR")]
    cache_dir: Option<PathBuf>,

    // ============================================================================
    // NEW CLI OPTIONS (v0.7.0 - Security Researcher Edition)
    // ============================================================================
    /// Only show findings above confidence percentage (0-100)
    #[arg(long, value_name = "PERCENT", value_parser = clap::value_parser!(u8).range(0..=100))]
    confidence_threshold: Option<u8>,

    /// Exclude files matching glob pattern (can be used multiple times)
    #[arg(long, value_name = "GLOB", action = clap::ArgAction::Append)]
    exclude_pattern: Vec<String>,

    /// Only check specific SWC IDs (comma-separated, e.g., SWC-107,SWC-105)
    #[arg(long, value_name = "IDS", value_delimiter = ',')]
    include_swc: Vec<String>,

    /// Skip specific SWC IDs (comma-separated)
    #[arg(long, value_name = "IDS", value_delimiter = ',')]
    exclude_swc: Vec<String>,

    /// Compare against baseline results JSON file (suppress known findings)
    #[arg(long, value_name = "FILE")]
    baseline: Option<PathBuf>,

    /// Export current results as baseline JSON file
    #[arg(long, value_name = "FILE")]
    export_baseline: Option<PathBuf>,

    /// Disable colored output
    #[arg(long)]
    no_color: bool,

    /// Skip files larger than specified size in MB (default: 10)
    #[arg(long, value_name = "MB", default_value = "10")]
    max_file_size: u64,

    /// Show full version info including build details
    #[arg(long)]
    version_full: bool,

    /// Show what the tool does - overview for new users
    #[arg(long)]
    about: bool,

    // ============================================================================
    // ADVANCED ANALYSIS OPTIONS (v0.7.0)
    // All features are ENABLED by default for maximum accuracy
    // ============================================================================
    /// Disable all advanced analysis features (fast mode)
    #[arg(long)]
    fast: bool,

    /// Disable logic vulnerability analysis
    #[arg(long)]
    no_logic_analysis: bool,

    /// Disable reachability analysis
    #[arg(long)]
    no_reachability_analysis: bool,

    /// Disable dependency/import analysis
    #[arg(long)]
    no_dependency_analysis: bool,

    /// Disable threat model generation
    #[arg(long)]
    no_threat_model: bool,

    /// Show detailed fix suggestions for vulnerabilities
    #[arg(long)]
    show_fixes: bool,

    // ============================================================================
    // EIP ANALYSIS & FALSE POSITIVE FILTERING (v0.8.0)
    // Both are ENABLED by default for professional-grade accuracy.
    // Use --no-eip-analysis / --no-fp-filter to disable.
    // ============================================================================
    /// Disable EIP-specific vulnerability analysis
    #[arg(long)]
    no_eip_analysis: bool,

    /// Disable enhanced false positive filtering
    #[arg(long)]
    no_fp_filter: bool,

    /// (Hidden) Legacy alias for --no-eip-analysis=false (kept for backwards compat)
    #[arg(long, hide = true)]
    eip_analysis: bool,

    /// (Hidden) Legacy alias for --no-fp-filter=false (kept for backwards compat)
    #[arg(long, hide = true)]
    strict_filter: bool,

    /// Path to custom rule configuration file (.41swara.toml)
    #[arg(long, value_name = "FILE")]
    config: Option<PathBuf>,

    /// Show STRIDE threat model findings (hidden by default)
    #[arg(long)]
    show_threat_model: bool,

    /// Show diff against baseline: [NEW], [KNOWN], [RESOLVED] labels
    #[arg(long, requires = "baseline")]
    diff_output: bool,
}

fn main() {
    let args = Args::parse();

    // Handle --no-color flag
    if args.no_color {
        colored::control::set_override(false);
    }

    // Handle --version-full flag
    if args.version_full {
        print_version_full();
        return;
    }

    // Handle --about flag
    if args.about {
        print_about();
        return;
    }

    // Configure thread pool for parallel scanning
    if args.threads > 0 {
        rayon::ThreadPoolBuilder::new()
            .num_threads(args.threads)
            .build_global()
            .unwrap_or_else(|e| eprintln!("Warning: Could not set thread count: {e}"));
    }

    // Show examples if requested
    if args.examples {
        show_examples();
        return;
    }

    // Get path (defaults to current directory ".")
    let path = args.path.clone();

    // Print scanner header (unless quiet mode)
    if !args.quiet && args.format != "json" && args.format != "sarif" {
        println!(
            "{}",
            format!(
                "41Swara Smart Contract Scanner v{}",
                env!("CARGO_PKG_VERSION")
            )
            .bright_blue()
            .bold()
        );
        println!("{}", "Security Researcher Edition".bright_cyan());
        println!(
            "{}",
            "High-performance security analysis for Ethereum & Base".bright_blue()
        );
        println!("{}", "=".repeat(55).bright_blue());
    }

    // Validate path exists
    if !path.exists() {
        eprintln!(
            "{} Path does not exist: {}",
            "Error:".red().bold(),
            path.display()
        );
        std::process::exit(10);
    }

    let start_time = Instant::now();

    // Process based on path type
    let exit_code = if path.is_file() {
        process_file(&args, &path)
    } else if path.is_dir() {
        process_directory(&args, &path)
    } else {
        eprintln!("{} Invalid path type", "Error:".red().bold());
        10
    };

    // Show performance stats
    if args.stats && !args.quiet {
        let elapsed = start_time.elapsed();
        eprintln!("\n{}", "Performance Statistics".bright_cyan().bold());
        eprintln!("  Total time: {:.3}s", elapsed.as_secs_f64());
        eprintln!("  Threads: {}", rayon::current_num_threads());
    }

    std::process::exit(exit_code);
}

/// Create a scanner with configuration based on CLI arguments
/// All advanced features are enabled by default - use --fast or --no-* flags to disable
fn create_scanner(args: &Args) -> ContractScanner {
    // If --fast is set, disable all advanced features for faster scanning
    // Otherwise, each feature is enabled unless its specific --no-* flag is set
    let config = if args.fast {
        ScannerConfig {
            enable_logic_analysis: false,
            enable_reachability_analysis: false,
            enable_dependency_analysis: false,
            enable_threat_model: false,
            enable_defi_analysis: args.defi_analysis,
            enable_phase6_analysis: args.advanced_detectors,
            enable_eip_analysis: false,
            enable_strict_filter: false,
        }
    } else {
        ScannerConfig {
            enable_logic_analysis: !args.no_logic_analysis,
            enable_reachability_analysis: !args.no_reachability_analysis,
            enable_dependency_analysis: !args.no_dependency_analysis,
            enable_threat_model: !args.no_threat_model,
            enable_defi_analysis: true,
            enable_phase6_analysis: true,
            // v0.8.0: enabled by default; --no-eip-analysis disables
            enable_eip_analysis: !args.no_eip_analysis,
            // v0.8.0: enabled by default; --no-fp-filter disables
            enable_strict_filter: !args.no_fp_filter,
        }
    };

    let mut scanner = ContractScanner::with_config(args.verbose, config);

    // Load TOML configuration (custom rules + overrides)
    let scan_config = load_scan_config(args);
    if let Some(cfg) = scan_config {
        // Add custom rules
        let custom_rules = cfg.compile_custom_rules();
        if !custom_rules.is_empty() {
            if !args.quiet {
                eprintln!(
                    "{} Loaded {} custom rules from config",
                    "Config:".cyan(),
                    custom_rules.len()
                );
            }
            scanner.add_custom_rules(custom_rules);
        }

        // Apply severity overrides and disabled rules
        let disabled = cfg.disabled_rule_ids();
        if !disabled.is_empty() && !args.quiet {
            eprintln!(
                "{} {} rules disabled via config",
                "Config:".cyan(),
                disabled.len()
            );
        }
        scanner.apply_rule_overrides(&cfg);
    }

    scanner
}

/// Load scan configuration from --config flag or auto-discovered .41swara.toml.
fn load_scan_config(args: &Args) -> Option<config::ScanConfig> {
    // Explicit --config flag takes priority
    if let Some(ref config_path) = args.config {
        match config::ScanConfig::load_from_file(config_path) {
            Ok(cfg) => return Some(cfg),
            Err(e) => {
                eprintln!("{} {}", "Config error:".red(), e);
                return None;
            }
        }
    }

    // Auto-discover .41swara.toml from scan directory upward
    if let Some(config_path) = config::ScanConfig::find_config(&args.path) {
        match config::ScanConfig::load_from_file(&config_path) {
            Ok(cfg) => {
                if !args.quiet {
                    eprintln!(
                        "{} Using config: {}",
                        "Config:".cyan(),
                        config_path.display()
                    );
                }
                return Some(cfg);
            }
            Err(e) => {
                eprintln!("{} {}", "Config warning:".yellow(), e);
            }
        }
    }

    None
}

/// Convert a cached vulnerability back into a full Vulnerability struct.
/// Uses string matching to reconstruct severity/category/confidence enums.
fn convert_cached_to_vulnerability(cv: &cache::CachedVulnerability) -> Option<Vulnerability> {
    use vulnerabilities::VulnerabilityConfidence;

    let severity = match cv.severity.as_str() {
        "Critical" => VulnerabilitySeverity::Critical,
        "High" => VulnerabilitySeverity::High,
        "Medium" => VulnerabilitySeverity::Medium,
        "Low" => VulnerabilitySeverity::Low,
        "Info" => VulnerabilitySeverity::Info,
        _ => return None,
    };

    let confidence = match cv.confidence.as_str() {
        "High" => VulnerabilityConfidence::High,
        "Medium" => VulnerabilityConfidence::Medium,
        "Low" => VulnerabilityConfidence::Low,
        _ => VulnerabilityConfidence::Medium,
    };

    // Default to LogicError for unknown categories; the title/description carry the real info
    let category = parse_vulnerability_category(&cv.category);

    Some(Vulnerability {
        severity,
        category,
        title: cv.title.clone(),
        description: cv.description.clone(),
        line_number: cv.line_number,
        end_line_number: None,
        code_snippet: cv.code_snippet.clone(),
        context_before: None,
        context_after: None,
        recommendation: cv.recommendation.clone(),
        confidence,
        confidence_percent: match cv.confidence.as_str() {
            "High" => 85,
            "Medium" => 65,
            "Low" => 35,
            _ => 50,
        },
        swc_id: None,
        fix_suggestion: None,
        cvss_score: None,
        cvss_vector: None,
        exploit_references: Vec::new(),
        attack_path: None,
    })
}

/// Parse a VulnerabilityCategory from its Debug string representation.
fn parse_vulnerability_category(s: &str) -> vulnerabilities::VulnerabilityCategory {
    use vulnerabilities::VulnerabilityCategory::*;
    match s {
        "Reentrancy" => Reentrancy,
        "AccessControl" => AccessControl,
        "ArithmeticIssues" => ArithmeticIssues,
        "UnsafeExternalCalls" => UnsafeExternalCalls,
        "DelegateCalls" => DelegateCalls,
        "GasOptimization" => GasOptimization,
        "PragmaIssues" => PragmaIssues,
        "RandomnessVulnerabilities" => RandomnessVulnerabilities,
        "FrontRunning" => FrontRunning,
        "TimeManipulation" => TimeManipulation,
        "DoSAttacks" => DoSAttacks,
        "UnusedCode" => UnusedCode,
        "MagicNumbers" => MagicNumbers,
        "NamingConventions" => NamingConventions,
        "StateVariable" => StateVariable,
        "PrecisionLoss" => PrecisionLoss,
        "UnusedReturnValues" => UnusedReturnValues,
        "OracleManipulation" => OracleManipulation,
        "FlashLoanAttack" => FlashLoanAttack,
        "LogicError" => LogicError,
        "MissingEvents" => MissingEvents,
        "SignatureVulnerabilities" => SignatureVulnerabilities,
        "ProxyAdminVulnerability" => ProxyAdminVulnerability,
        "CallbackReentrancy" => CallbackReentrancy,
        "CompilerBug" => CompilerBug,
        "ComplexityIssues" => ComplexityIssues,
        "StorageDoSAttacks" => StorageDoSAttacks,
        "LowLevelCalls" => LowLevelCalls,
        "AssemblyUsage" => AssemblyUsage,
        "ShadowingIssues" => ShadowingIssues,
        "TxOriginAuth" => TxOriginAuth,
        "DeprecatedFunctions" => DeprecatedFunctions,
        "UninitializedVariables" => UninitializedVariables,
        "UncheckedReturnValues" => UncheckedReturnValues,
        "ImmutabilityIssues" => ImmutabilityIssues,
        "IncorrectEquality" => IncorrectEquality,
        "InputValidationFailure" => InputValidationFailure,
        "MEVExploitable" => MEVExploitable,
        "GovernanceAttack" => GovernanceAttack,
        "BridgeVulnerability" => BridgeVulnerability,
        "LiquidityManipulation" => LiquidityManipulation,
        _ => LogicError,
    }
}

/// Apply CLI filters (confidence threshold, SWC include/exclude, baseline, threat model) to scan results.
/// Mutates the vector in place, removing findings that don't pass the filters.
fn apply_filters(
    vulns: &mut Vec<Vulnerability>,
    args: &Args,
    baseline_ids: &std::collections::HashSet<String>,
) {
    // v0.8.0: Suppress [Threat Model] findings unless --show-threat-model is set
    if !args.show_threat_model {
        vulns.retain(|v| !v.title.starts_with("[Threat Model]"));
    }

    // Filter by confidence threshold
    if let Some(threshold) = args.confidence_threshold {
        vulns.retain(|v| v.confidence_percent >= threshold);
    }

    // Filter by --include-swc (only keep findings matching these SWC IDs)
    if !args.include_swc.is_empty() {
        vulns.retain(|v| {
            if let Some(ref swc) = v.swc_id {
                args.include_swc
                    .iter()
                    .any(|id| swc.id.eq_ignore_ascii_case(id))
            } else {
                false // No SWC ID means it doesn't match any include filter
            }
        });
    }

    // Filter by --exclude-swc (remove findings matching these SWC IDs)
    if !args.exclude_swc.is_empty() {
        vulns.retain(|v| {
            if let Some(ref swc) = v.swc_id {
                !args
                    .exclude_swc
                    .iter()
                    .any(|id| swc.id.eq_ignore_ascii_case(id))
            } else {
                true // No SWC ID means it's not excluded
            }
        });
    }

    // Filter by baseline (suppress previously-known findings)
    if !baseline_ids.is_empty() {
        vulns.retain(|v| {
            let fingerprint = make_finding_fingerprint(v);
            !baseline_ids.contains(&fingerprint)
        });
    }
}

/// Create a stable fingerprint for a vulnerability finding (for baseline comparison).
/// Uses category + title + line number + code snippet hash.
fn make_finding_fingerprint(v: &Vulnerability) -> String {
    format!(
        "{}:{}:{}:{:x}",
        v.category.as_str(),
        v.title,
        v.line_number,
        {
            // Simple hash of code snippet for stability
            let mut h: u64 = 0;
            for b in v.code_snippet.bytes() {
                h = h.wrapping_mul(31).wrapping_add(b as u64);
            }
            h
        }
    )
}

/// Load baseline fingerprints from a JSON file exported by --export-baseline.
fn load_baseline(path: &Path) -> std::collections::HashSet<String> {
    let mut set = std::collections::HashSet::new();
    if let Ok(content) = std::fs::read_to_string(path) {
        if let Ok(arr) = serde_json::from_str::<Vec<String>>(&content) {
            for id in arr {
                set.insert(id);
            }
        } else {
            eprintln!(
                "{} Failed to parse baseline file: {}",
                "Warning:".yellow(),
                path.display()
            );
        }
    } else {
        eprintln!(
            "{} Failed to read baseline file: {}",
            "Warning:".yellow(),
            path.display()
        );
    }
    set
}

/// Export vulnerability fingerprints as baseline JSON for future --baseline comparison.
fn export_baseline(vulns: &[(PathBuf, Vec<Vulnerability>)], path: &Path) {
    let fingerprints: Vec<String> = vulns
        .iter()
        .flat_map(|(_, vs)| vs.iter().map(make_finding_fingerprint))
        .collect();
    match serde_json::to_string_pretty(&fingerprints) {
        Ok(json) => {
            if let Err(e) = std::fs::write(path, json) {
                eprintln!("{} Failed to write baseline: {}", "Error:".red().bold(), e);
            } else {
                eprintln!(
                    "{} Baseline exported to: {} ({} findings)",
                    "Saved".green().bold(),
                    path.display(),
                    fingerprints.len()
                );
            }
        }
        Err(e) => eprintln!(
            "{} Failed to serialize baseline: {}",
            "Error:".red().bold(),
            e
        ),
    }
}

/// Check if a file path should be excluded based on --exclude-pattern glob patterns.
fn should_exclude_file(path: &std::path::Path, exclude_patterns: &[Pattern]) -> bool {
    if exclude_patterns.is_empty() {
        return false;
    }
    let path_str = path.to_string_lossy();
    exclude_patterns.iter().any(|pat| pat.matches(&path_str))
}

/// Parse --exclude-pattern strings into compiled glob patterns.
fn compile_exclude_patterns(patterns: &[String]) -> Vec<Pattern> {
    patterns
        .iter()
        .filter_map(|p| {
            Pattern::new(p)
                .map_err(|e| {
                    eprintln!(
                        "{} Invalid exclude pattern '{}': {}",
                        "Warning:".yellow(),
                        p,
                        e
                    );
                    e
                })
                .ok()
        })
        .collect()
}

/// Generate an auto-save markdown report from collected scan results.
/// If `--output` is specified, use that path. Otherwise, auto-generate a filename
/// based on the scan target name and current timestamp.
/// Returns the path where the report was saved, or None if saving was skipped/failed.
fn save_markdown_report(
    reporter: &VulnerabilityReporter,
    target_path: &Path,
    output_override: &Option<PathBuf>,
    quiet: bool,
) -> Option<PathBuf> {
    let report_content = reporter.generate_markdown_report();

    // Determine output path
    let output_path = if let Some(ref path) = output_override {
        path.clone()
    } else {
        // Auto-generate filename: 41swara_report_<name>_<timestamp>.md
        let target_name = target_path
            .file_stem()
            .or_else(|| target_path.file_name())
            .and_then(|n| n.to_str())
            .unwrap_or("scan");
        // Sanitize: replace non-alphanumeric characters
        let clean_name: String = target_name
            .chars()
            .map(|c| {
                if c.is_alphanumeric() || c == '-' || c == '_' {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        let timestamp = chrono::Utc::now().format("%Y%m%d_%H%M%S");
        let reports_dir = PathBuf::from("reports");
        if !reports_dir.exists() {
            let _ = std::fs::create_dir_all(&reports_dir);
        }
        reports_dir.join(format!("41swara_report_{clean_name}_{timestamp}.md"))
    };

    // Write the report
    match std::fs::write(&output_path, &report_content) {
        Ok(()) => {
            if !quiet {
                eprintln!(
                    "\n{} Report saved to: {}",
                    "📄".green(),
                    output_path.display().to_string().bright_white().bold()
                );
            }
            Some(output_path)
        }
        Err(e) => {
            eprintln!(
                "{} Failed to save report to {}: {}",
                "Error:".red().bold(),
                output_path.display(),
                e
            );
            None
        }
    }
}

/// Merge Slither findings with 41Swara findings for correlation.
/// Boosts confidence of findings confirmed by both tools; adds Slither-only findings.
fn merge_slither_findings(
    vulnerabilities: &mut Vec<Vulnerability>,
    slither_path: &Path,
    quiet: bool,
) {
    use integrations::slither::{CorrelationType, SlitherIntegration};

    let mut slither = SlitherIntegration::new();
    match slither.load_from_file(slither_path) {
        Ok(count) => {
            if !quiet {
                eprintln!(
                    "{} Loaded {} Slither findings for correlation",
                    "Slither:".cyan(),
                    count
                );
            }
            let correlated = slither.correlate(vulnerabilities);

            // Boost confidence for corroborated findings
            let mut boosted = 0usize;
            for cf in &correlated {
                if cf.correlation == CorrelationType::BothFound {
                    if let Some(ref swara_f) = cf.swara_finding {
                        for v in vulnerabilities.iter_mut() {
                            if v.line_number == swara_f.line_number && v.title == swara_f.title {
                                v.confidence_percent = (v.confidence_percent + 15).min(100);
                                boosted += 1;
                                break;
                            }
                        }
                    }
                }
            }

            // Add Slither-only findings
            let mut added = 0usize;
            for cf in &correlated {
                if cf.correlation == CorrelationType::SlitherOnly {
                    if let Some(ref sf) = cf.slither_finding {
                        vulnerabilities.push(slither.convert_to_vulnerability(sf));
                        added += 1;
                    }
                }
            }

            if !quiet {
                eprintln!(
                    "{} {} corroborated (boosted), {} Slither-only added",
                    "Slither:".cyan(),
                    boosted,
                    added
                );
            }
        }
        Err(e) => {
            eprintln!("{} Failed to load Slither JSON: {}", "Warning:".yellow(), e);
        }
    }
}

/// Generate Foundry PoC test files for Critical/High findings.
fn generate_foundry_pocs(vulnerabilities: &[Vulnerability], base_path: &Path, quiet: bool) {
    use integrations::foundry::FoundryIntegration;

    let foundry = FoundryIntegration::new(&base_path.to_string_lossy());
    let generated_files = foundry.generate_poc_tests(vulnerabilities);

    if !quiet && !generated_files.is_empty() {
        eprintln!(
            "{} Generated {} PoC test files",
            "Foundry:".cyan(),
            generated_files.len()
        );
        let index = foundry.generate_test_index(&generated_files);
        eprintln!("{index}");
    }
}

/// Process a single file (either .sol or .json ABI).
/// Returns an exit code: 0 = clean, 1 = critical/high, 2 = medium, 3 = low/info, 10 = error.
fn process_file(args: &Args, path: &PathBuf) -> i32 {
    let extension = path.extension().and_then(|e| e.to_str());

    match extension {
        Some("sol") => {
            let scanner = create_scanner(args);

            if args.audit {
                scan_file_professional_audit(path, args);
                return 0; // Audit mode always returns 0
            } else if args.report {
                let reporter = VulnerabilityReporter::new(&args.format);
                scan_file_clean_report(&scanner, &reporter, path);
                return 0; // Report mode always returns 0
            }

            // Load baseline if provided
            let baseline_ids = args
                .baseline
                .as_ref()
                .map(|p| load_baseline(p))
                .unwrap_or_default();

            // Scan once and reuse results for all output paths
            match scanner.scan_file(path) {
                Ok(scan_result) => {
                    let compiler_info = scan_result.compiler_info;
                    let mut vulnerabilities = scan_result.vulnerabilities;

                    // Print compiler version info (text mode, non-quiet)
                    if !args.quiet && args.format == "text" {
                        print_compiler_info(&compiler_info);
                    }

                    // Slither correlation: merge findings if --slither-json is provided
                    if let Some(ref slither_path) = args.slither_json {
                        merge_slither_findings(&mut vulnerabilities, slither_path, args.quiet);
                    }

                    // Apply severity filter
                    vulnerabilities.retain(|v| args.min_severity.matches(&v.severity));
                    // Apply CLI filters (confidence, SWC, baseline)
                    apply_filters(&mut vulnerabilities, args, &baseline_ids);

                    // Generate Foundry PoC tests if requested
                    if args.generate_poc {
                        generate_foundry_pocs(&vulnerabilities, path, args.quiet);
                    }

                    // Export baseline if requested
                    if let Some(ref export_path) = args.export_baseline {
                        export_baseline(&[(path.clone(), vulnerabilities.clone())], export_path);
                    }

                    // Build a reporter for both terminal output and report saving
                    let mut reporter = VulnerabilityReporter::new(&args.format);
                    if let Some(ref info) = compiler_info {
                        reporter.set_compiler_info(path, info.clone());
                    }

                    // Output results based on format (single scan, no double-scan)
                    if args.format == "json" {
                        let json_output = serde_json::json!({
                            "version": env!("CARGO_PKG_VERSION"),
                            "files_scanned": 1,
                            "total_vulnerabilities": vulnerabilities.len(),
                            "compiler_info": compiler_info_to_json(&compiler_info),
                            "min_severity_filter": format!("{:?}", args.min_severity),
                            "results": [{
                                "file": path.to_string_lossy(),
                                "vulnerabilities": &vulnerabilities,
                            }],
                        });
                        println!("{}", serde_json::to_string_pretty(&json_output).unwrap());
                        reporter.add_file_results_silent(path, vulnerabilities.clone());
                    } else if args.format == "sarif" {
                        let sarif_results = vec![(path.clone(), vulnerabilities.clone())];
                        let sarif_report =
                            SarifReport::new(sarif_results, env!("CARGO_PKG_VERSION"));
                        println!("{}", serde_json::to_string_pretty(&sarif_report).unwrap());
                        reporter.add_file_results_silent(path, vulnerabilities.clone());
                    } else {
                        reporter.add_file_results(path, vulnerabilities.clone());
                        reporter.print_summary();
                    }

                    // Auto-save markdown report with compiler info
                    save_markdown_report(&reporter, path, &args.output, args.quiet);

                    // Calculate exit code
                    if let Some(ref fail_severity) = args.fail_on {
                        let has_failures = vulnerabilities
                            .iter()
                            .any(|v| fail_severity.matches(&v.severity));
                        return if has_failures { 1 } else { 0 };
                    }

                    // Default exit code based on max severity
                    if vulnerabilities.is_empty() {
                        0
                    } else {
                        vulnerabilities
                            .iter()
                            .map(|v| severity_to_exit_code(&v.severity))
                            .min()
                            .unwrap_or(0)
                    }
                }
                Err(e) => {
                    eprintln!(
                        "{} scanning {}: {}",
                        "Error".red().bold(),
                        path.display(),
                        e
                    );
                    10 // Scanner error
                }
            }
        }
        Some("json") if args.abi => {
            scan_abi_file(path, args);
            0
        }
        Some("json") => {
            eprintln!(
                "{} Use --abi flag for JSON ABI files",
                "Error:".red().bold()
            );
            10
        }
        _ => {
            eprintln!(
                "{} Unsupported file type. Supported: .sol, .json (with --abi)",
                "Error:".red().bold()
            );
            10
        }
    }
}

/// Get list of modified .sol files from git diff
fn get_git_modified_files(repo_path: &PathBuf, base_ref: &str) -> Result<Vec<PathBuf>, String> {
    let repo =
        Repository::open(repo_path).map_err(|e| format!("Failed to open git repository: {e}"))?;

    // Get the HEAD tree
    let head = repo
        .head()
        .map_err(|e| format!("Failed to get HEAD: {e}"))?;
    let head_tree = head
        .peel_to_tree()
        .map_err(|e| format!("Failed to get HEAD tree: {e}"))?;

    // Get the base reference tree
    let base_obj = repo
        .revparse_single(base_ref)
        .map_err(|e| format!("Failed to resolve '{base_ref}': {e}"))?;
    let base_tree = base_obj
        .peel_to_tree()
        .map_err(|e| format!("Failed to get base tree: {e}"))?;

    // Create diff
    let mut diff_opts = DiffOptions::new();
    let diff = repo
        .diff_tree_to_tree(Some(&base_tree), Some(&head_tree), Some(&mut diff_opts))
        .map_err(|e| format!("Failed to create diff: {e}"))?;

    let mut modified_files = Vec::new();
    let workdir = repo
        .workdir()
        .ok_or_else(|| "Repository has no working directory".to_string())?;

    diff.foreach(
        &mut |delta, _progress| {
            // Only include modified or added files
            match delta.status() {
                Delta::Added | Delta::Modified => {
                    if let Some(new_file) = delta.new_file().path() {
                        if let Some(ext) = new_file.extension() {
                            if ext == "sol" {
                                let full_path = workdir.join(new_file);
                                if full_path.exists() {
                                    modified_files.push(full_path);
                                }
                            }
                        }
                    }
                }
                _ => {}
            }
            true
        },
        None,
        None,
        None,
    )
    .map_err(|e| format!("Failed to process diff: {e}"))?;

    // Also check for unstaged changes
    let mut diff_opts_workdir = DiffOptions::new();
    let diff_workdir = repo
        .diff_tree_to_workdir_with_index(Some(&head_tree), Some(&mut diff_opts_workdir))
        .map_err(|e| format!("Failed to create workdir diff: {e}"))?;

    diff_workdir
        .foreach(
            &mut |delta, _progress| {
                match delta.status() {
                    Delta::Added | Delta::Modified => {
                        if let Some(new_file) = delta.new_file().path() {
                            if let Some(ext) = new_file.extension() {
                                if ext == "sol" {
                                    let full_path = workdir.join(new_file);
                                    if full_path.exists() && !modified_files.contains(&full_path) {
                                        modified_files.push(full_path);
                                    }
                                }
                            }
                        }
                    }
                    _ => {}
                }
                true
            },
            None,
            None,
            None,
        )
        .map_err(|e| format!("Failed to process workdir diff: {e}"))?;

    Ok(modified_files)
}

/// Run watch mode - continuously monitor and rescan on file changes
fn run_watch_mode(dir: &PathBuf, args: &Args) -> i32 {
    println!("{}", "\n🔍 Watch Mode Activated".bright_green().bold());
    println!("{} {}", "Monitoring directory:".green(), dir.display());
    println!("{}", "Press Ctrl+C to stop watching...".yellow());
    println!("{}", "━".repeat(60).blue());

    let (tx, rx) = channel();
    let mut watcher = notify::recommended_watcher(move |res: NotifyResult<Event>| {
        if let Ok(event) = res {
            let _ = tx.send(event);
        }
    })
    .expect("Failed to create watcher");

    watcher
        .watch(dir.as_ref(), RecursiveMode::Recursive)
        .expect("Failed to watch directory");

    let scanner = create_scanner(args);

    // Perform initial scan
    println!("\n{} Performing initial scan...", "→".bright_blue());
    perform_quick_scan(&scanner, dir, args);
    let mut last_scan = std::time::SystemTime::now();

    loop {
        match rx.recv() {
            Ok(event) => {
                // Only process file modifications
                match event.kind {
                    EventKind::Modify(_) | EventKind::Create(_) => {
                        // Check if any .sol files were modified
                        let sol_files: Vec<_> = event
                            .paths
                            .iter()
                            .filter(|p| p.extension().is_some_and(|ext| ext == "sol"))
                            .collect();

                        if !sol_files.is_empty() {
                            // Debounce: wait 500ms between scans
                            if let Ok(elapsed) =
                                std::time::SystemTime::now().duration_since(last_scan)
                            {
                                if elapsed.as_millis() < 500 {
                                    continue;
                                }
                            }

                            println!(
                                "\n{} File changed: {}",
                                "⟳".bright_cyan().bold(),
                                sol_files
                                    .iter()
                                    .map(|p| p.file_name().unwrap().to_string_lossy())
                                    .collect::<Vec<_>>()
                                    .join(", ")
                            );
                            println!("{} Rescanning...", "→".bright_blue());

                            perform_quick_scan(&scanner, dir, args);
                            last_scan = std::time::SystemTime::now();
                        }
                    }
                    _ => {}
                }
            }
            Err(e) => {
                eprintln!("{} Watch error: {}", "Error:".red().bold(), e);
                return 1;
            }
        }
    }
}

/// Perform a quick scan for watch mode
fn perform_quick_scan(scanner: &ContractScanner, dir: &PathBuf, args: &Args) {
    let sol_files: Vec<PathBuf> = WalkDir::new(dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .filter(|e| e.path().extension().is_some_and(|ext| ext == "sol"))
        .map(|e| e.path().to_path_buf())
        .collect();

    if sol_files.is_empty() {
        return;
    }

    let all_results: SharedResults<(PathBuf, Vec<Vulnerability>)> =
        Arc::new(Mutex::new(Vec::new()));

    sol_files.par_iter().for_each(|file_path| {
        if let Ok(scan_result) = scanner.scan_file(file_path) {
            let mut vulns = scan_result.vulnerabilities;
            vulns.retain(|v| args.min_severity.matches(&v.severity));
            // Suppress threat model findings unless opted-in
            if !args.show_threat_model {
                vulns.retain(|v| !v.title.starts_with("[Threat Model]"));
            }
            if !vulns.is_empty() {
                all_results.lock().unwrap().push((file_path.clone(), vulns));
            }
        }
    });

    let results = all_results.lock().unwrap();
    let total_vulns: usize = results.iter().map(|(_, v)| v.len()).sum();

    if total_vulns == 0 {
        println!("{} No vulnerabilities found", "✓".green().bold());
    } else {
        println!(
            "{} {} vulnerabilities found",
            "⚠".yellow().bold(),
            total_vulns
        );

        // Show summary by severity
        let mut critical = 0;
        let mut high = 0;
        let mut medium = 0;
        let mut low = 0;
        let mut info = 0;

        for (_, vulns) in results.iter() {
            for vuln in vulns {
                match vuln.severity {
                    VulnerabilitySeverity::Critical => critical += 1,
                    VulnerabilitySeverity::High => high += 1,
                    VulnerabilitySeverity::Medium => medium += 1,
                    VulnerabilitySeverity::Low => low += 1,
                    VulnerabilitySeverity::Info => info += 1,
                }
            }
        }

        if critical > 0 {
            println!("  {} Critical: {}", "🚨".red(), critical);
        }
        if high > 0 {
            println!("  {} High: {}", "⚠".red(), high);
        }
        if medium > 0 {
            println!("  {} Medium: {}", "⚡".yellow(), medium);
        }
        if low > 0 {
            println!("  {} Low: {}", "💡".blue(), low);
        }
        if info > 0 {
            println!("  {} Info: {}", "ℹ".bright_blue(), info);
        }
    }

    println!("{}", "━".repeat(60).blue());
}

/// Process a directory of Solidity files using parallel scanning with rayon.
/// Supports git-diff mode, watch mode, project analysis, audit reports, and normal scanning.
/// Returns exit code based on the highest severity finding discovered.
fn process_directory(args: &Args, dir: &PathBuf) -> i32 {
    if !args.quiet {
        println!("\n{} {}", "Scanning directory:".green(), dir.display());
    }

    // Handle special modes
    if args.project_analysis {
        return run_project_analysis(dir, args);
    }

    if args.audit {
        scan_directory_professional_audit(dir, args);
        return 0;
    }

    if args.report {
        let scanner = create_scanner(args);
        let reporter = VulnerabilityReporter::new(&args.format);
        scan_directory_clean_report(&scanner, &reporter, dir);
        return 0;
    }

    // Watch mode - continuous monitoring
    if args.watch {
        return run_watch_mode(dir, args);
    }

    // Compile exclude patterns once
    let exclude_patterns = compile_exclude_patterns(&args.exclude_pattern);

    // Load baseline if provided
    let baseline_ids = args
        .baseline
        .as_ref()
        .map(|p| load_baseline(p))
        .unwrap_or_default();

    // Collect .sol files
    let sol_files: Vec<PathBuf> = if args.git_diff {
        // Git diff mode - only scan modified files
        match get_git_modified_files(dir, &args.git_branch) {
            Ok(files) => {
                let files: Vec<PathBuf> = files
                    .into_iter()
                    .filter(|f| !should_exclude_file(f, &exclude_patterns))
                    .collect();
                if !args.quiet {
                    println!(
                        "{} {} modified .sol files from git diff",
                        "Found".green(),
                        files.len()
                    );
                }
                files
            }
            Err(e) => {
                eprintln!("{} {}", "Git error:".red().bold(), e);
                eprintln!(
                    "{} Make sure you're in a git repository and the branch exists",
                    "Hint:".yellow()
                );
                return 1;
            }
        }
    } else {
        // Normal mode - scan all files, applying exclude patterns
        WalkDir::new(dir)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
            .filter(|e| e.path().extension().is_some_and(|ext| ext == "sol"))
            .filter(|e| !should_exclude_file(e.path(), &exclude_patterns))
            .map(|e| e.path().to_path_buf())
            .collect()
    };

    if sol_files.is_empty() {
        if !args.quiet {
            println!("{}", "No .sol files found in directory".yellow());
        }
        return 0;
    }

    if !args.quiet && args.format != "json" && args.format != "sarif" {
        println!(
            "{} {} Solidity files found",
            "Found".green(),
            sol_files.len()
        );
    }

    // Set up progress bar for directory scans
    let show_progress = !args.quiet && args.format == "text" && sol_files.len() > 1;
    let progress = if show_progress {
        let pb = ProgressBar::new(sol_files.len() as u64);
        pb.set_style(
            ProgressStyle::default_bar()
                .template("{spinner:.green} [{bar:40.cyan/blue}] {pos}/{len} files ({eta})")
                .unwrap_or_else(|_| ProgressStyle::default_bar())
                .progress_chars("=>-"),
        );
        Some(pb)
    } else {
        None
    };

    // PARALLEL SCANNING with rayon
    let scanner = create_scanner(args);
    let all_results: SharedResults<(PathBuf, Vec<Vulnerability>)> =
        Arc::new(Mutex::new(Vec::new()));
    let error_count: Arc<Mutex<usize>> = Arc::new(Mutex::new(0));
    let min_severity = args.min_severity;
    let progress_ref = progress.as_ref();

    // Initialize cache if --cache is enabled
    let scan_cache = if args.cache {
        let cache_dir = args
            .cache_dir
            .clone()
            .unwrap_or_else(|| dir.join(".41swara_cache"));
        let cache = cache::ScanCache::persistent(&cache_dir);
        cache.prune_expired();
        if !args.quiet && args.format == "text" {
            let stats = cache.stats();
            if stats.total_entries > 0 {
                eprintln!(
                    "{} Loaded {} cached entries",
                    "Cache:".cyan(),
                    stats.total_entries
                );
            }
        }
        Some(Arc::new(cache))
    } else {
        None
    };
    let cache_ref = scan_cache.clone();
    let cache_hits = Arc::new(Mutex::new(0usize));
    let cache_hits_ref = cache_hits.clone();

    sol_files.par_iter().for_each(|file_path| {
        // Try cache hit first
        if let Some(ref cache) = cache_ref {
            if let Ok(content) = std::fs::read_to_string(file_path) {
                let path_str = file_path.to_string_lossy().to_string();
                if cache.is_cached(&path_str, &content) {
                    if let Some(cached_vulns) = cache.get(&path_str) {
                        let mut vulns: Vec<Vulnerability> = cached_vulns
                            .into_iter()
                            .filter_map(|cv| convert_cached_to_vulnerability(&cv))
                            .collect();
                        vulns.retain(|v| min_severity.matches(&v.severity));
                        if !vulns.is_empty() {
                            all_results.lock().unwrap().push((file_path.clone(), vulns));
                        }
                        *cache_hits_ref.lock().unwrap() += 1;
                        if let Some(pb) = progress_ref {
                            pb.inc(1);
                        }
                        return;
                    }
                }
            }
        }

        match scanner.scan_file(file_path) {
            Ok(scan_result) => {
                let mut vulns = scan_result.vulnerabilities;

                // Store in cache before filtering
                if let Some(ref cache) = cache_ref {
                    if let Ok(content) = std::fs::read_to_string(file_path) {
                        let path_str = file_path.to_string_lossy().to_string();
                        cache.put(&path_str, &content, &vulns);
                    }
                }

                // Apply severity filter
                vulns.retain(|v| min_severity.matches(&v.severity));

                if !vulns.is_empty() {
                    all_results.lock().unwrap().push((file_path.clone(), vulns));
                }
            }
            Err(e) => {
                if args.verbose {
                    eprintln!("{} scanning {}: {}", "Error".red(), file_path.display(), e);
                }
                *error_count.lock().unwrap() += 1;
            }
        }
        if let Some(pb) = progress_ref {
            pb.inc(1);
        }
    });

    // Show cache stats
    if args.cache && !args.quiet && args.format == "text" {
        let hits = *cache_hits.lock().unwrap();
        if hits > 0 {
            eprintln!(
                "{} {} cache hits, {} files scanned",
                "Cache:".cyan(),
                hits,
                sol_files.len() - hits
            );
        }
    }

    if let Some(pb) = progress {
        pb.finish_and_clear();
    }

    // Apply CLI filters (confidence, SWC, baseline) to all results
    let mut results: Vec<(PathBuf, Vec<Vulnerability>)> = match Arc::try_unwrap(all_results) {
        Ok(mutex) => mutex.into_inner().unwrap(),
        Err(arc) => arc.lock().unwrap().clone(),
    };

    // Slither correlation: merge findings if --slither-json is provided
    if let Some(ref slither_path) = args.slither_json {
        for (_, vulns) in &mut results {
            merge_slither_findings(vulns, slither_path, args.quiet);
        }
    }

    for (_, vulns) in &mut results {
        apply_filters(vulns, args, &baseline_ids);
    }
    // Remove files that ended up with no findings after filtering
    results.retain(|(_, vulns)| !vulns.is_empty());

    // Generate Foundry PoC tests if requested
    if args.generate_poc {
        let all_vulns: Vec<Vulnerability> = results.iter().flat_map(|(_, vs)| vs.clone()).collect();
        if !all_vulns.is_empty() {
            generate_foundry_pocs(&all_vulns, dir, args.quiet);
        }
    }

    let total_vulns: usize = results.iter().map(|(_, v)| v.len()).sum();

    // Export baseline if requested
    if let Some(ref export_path) = args.export_baseline {
        export_baseline(&results, export_path);
    }

    // Build a reporter with all results (used for both terminal output and markdown save)
    let mut reporter = VulnerabilityReporter::new("text");
    for (path, vulns) in results.iter() {
        if args.format != "text" {
            reporter.add_file_results_silent(path, vulns.clone());
        } else {
            reporter.add_file_results(path, vulns.clone());
        }
    }

    // Generate terminal output
    if args.format == "json" {
        let json_output = serde_json::json!({
            "version": env!("CARGO_PKG_VERSION"),
            "files_scanned": sol_files.len(),
            "total_vulnerabilities": total_vulns,
            "min_severity_filter": format!("{:?}", args.min_severity),
            "results": results.iter().map(|(path, vulns)| {
                serde_json::json!({
                    "file": path.to_string_lossy(),
                    "vulnerabilities": vulns,
                })
            }).collect::<Vec<_>>(),
        });
        println!("{}", serde_json::to_string_pretty(&json_output).unwrap());
    } else if args.format == "sarif" {
        let sarif_results: Vec<(PathBuf, Vec<Vulnerability>)> = results
            .iter()
            .map(|(path, vulns)| (path.clone(), vulns.clone()))
            .collect();
        let sarif_report = SarifReport::new(sarif_results, env!("CARGO_PKG_VERSION"));
        println!("{}", serde_json::to_string_pretty(&sarif_report).unwrap());
    } else {
        reporter.print_summary();
    }

    // Auto-save markdown report to file
    if !args.watch {
        save_markdown_report(&reporter, dir, &args.output, args.quiet);
    }

    // Determine exit code based on severity or --fail-on override
    if let Some(ref fail_severity) = args.fail_on {
        let has_failures = results
            .iter()
            .any(|(_, vulns)| vulns.iter().any(|v| fail_severity.matches(&v.severity)));
        if has_failures {
            return 1;
        }
        return 0;
    }

    // Default exit codes based on max severity
    let errors = *error_count.lock().unwrap();
    if errors > 0 && total_vulns == 0 {
        return 10;
    }

    let max_severity = results
        .iter()
        .flat_map(|(_, vulns)| vulns.iter())
        .map(|v| severity_to_exit_code(&v.severity))
        .min()
        .unwrap_or(0);

    max_severity
}

/// Convert severity to exit code (lower is more severe)
fn severity_to_exit_code(severity: &VulnerabilitySeverity) -> i32 {
    match severity {
        VulnerabilitySeverity::Critical | VulnerabilitySeverity::High => 1,
        VulnerabilitySeverity::Medium => 2,
        VulnerabilitySeverity::Low | VulnerabilitySeverity::Info => 3,
    }
}

/// Print compiler version information to the terminal.
fn print_compiler_info(compiler_info: &Option<parser::CompilerInfo>) {
    use parser::VersionAge;

    match compiler_info {
        Some(info) => {
            let version_color = match info.age {
                VersionAge::Current => "green",
                VersionAge::Recent => "cyan",
                VersionAge::Aging => "yellow",
                VersionAge::Outdated => "red",
                VersionAge::Critical => "bright red",
            };

            let age_icon = match info.age {
                VersionAge::Current => "✅",
                VersionAge::Recent => "🟢",
                VersionAge::Aging => "🟡",
                VersionAge::Outdated => "🟠",
                VersionAge::Critical => "🔴",
            };

            println!("\n{}", "📋 COMPILER VERSION ANALYSIS".bright_cyan().bold());
            println!("{}", "━".repeat(55).bright_cyan());

            println!(
                "  {} {}: {}",
                "📄".bright_white(),
                "Pragma".bright_white().bold(),
                info.pragma_raw.bright_white()
            );

            let version_display = format!("Solidity {}", info.version_string);
            let colored_version = match version_color {
                "green" => version_display.bright_green().bold(),
                "cyan" => version_display.bright_cyan().bold(),
                "yellow" => version_display.bright_yellow().bold(),
                "red" => version_display.bright_red().bold(),
                _ => version_display.bright_red().bold(),
            };
            println!(
                "  {} {}: {}",
                "🔧".bright_white(),
                "Version".bright_white().bold(),
                colored_version
            );

            println!(
                "  {} {}: {}",
                "📌".bright_white(),
                "Constraint".bright_white().bold(),
                format!("{}", info.constraint).bright_white()
            );

            println!(
                "  {} {}: {} {}",
                age_icon,
                "Status".bright_white().bold(),
                format!("{}", info.age).color(version_color).bold(),
                if info.known_cves > 0 {
                    format!(
                        "({} known compiler issue{})",
                        info.known_cves,
                        if info.known_cves > 1 { "s" } else { "" }
                    )
                    .bright_yellow()
                    .to_string()
                } else {
                    "".to_string()
                }
            );

            if info.is_floating {
                println!(
                    "  {} {}: {}",
                    "⚠️ ".bright_yellow(),
                    "Warning".bright_yellow().bold(),
                    "Floating pragma - different compiler versions may produce different bytecode"
                        .bright_yellow()
                );
            }

            // EVM features summary
            let mut features = Vec::new();
            if info.evm_features.overflow_protection {
                features.push("overflow-safe");
            }
            if info.evm_features.custom_errors {
                features.push("custom-errors");
            }
            if info.evm_features.push0_opcode {
                features.push("PUSH0");
            }
            if info.evm_features.transient_storage {
                features.push("transient-storage");
            }
            if !info.evm_features.overflow_protection {
                features.push("NO-overflow-protection");
            }

            println!(
                "  {} {}: {}",
                "⚡".bright_white(),
                "EVM Features".bright_white().bold(),
                features.join(", ").bright_white()
            );

            if info.upgrade_recommended {
                println!(
                    "  {} {}: Upgrade to Solidity {} for latest security fixes",
                    "💡".bright_green(),
                    "Recommendation".bright_green().bold(),
                    info.latest_recommended.bright_green().bold()
                );
            }

            println!("{}", "━".repeat(55).bright_cyan());
        }
        None => {
            println!("\n{}", "📋 COMPILER VERSION ANALYSIS".bright_cyan().bold());
            println!("{}", "━".repeat(55).bright_cyan());
            println!(
                "  {} No pragma solidity statement found",
                "⚠️ ".bright_yellow()
            );
            println!(
                "  {} Add a pragma statement to enable version-specific analysis",
                "💡".bright_green()
            );
            println!("{}", "━".repeat(55).bright_cyan());
        }
    }
}

/// Convert CompilerInfo to a JSON value for structured output.
fn compiler_info_to_json(compiler_info: &Option<parser::CompilerInfo>) -> serde_json::Value {
    match compiler_info {
        Some(info) => serde_json::json!({
            "pragma": info.pragma_raw,
            "version": info.version_string,
            "major": info.major,
            "minor": info.minor,
            "patch": info.patch,
            "constraint": format!("{}", info.constraint),
            "is_floating": info.is_floating,
            "age": format!("{}", info.age),
            "latest_recommended": info.latest_recommended,
            "upgrade_recommended": info.upgrade_recommended,
            "known_cves": info.known_cves,
            "security_note": info.security_note,
            "evm_features": {
                "overflow_protection": info.evm_features.overflow_protection,
                "try_catch": info.evm_features.try_catch,
                "custom_errors": info.evm_features.custom_errors,
                "push0_opcode": info.evm_features.push0_opcode,
                "transient_storage": info.evm_features.transient_storage,
                "immutable_vars": info.evm_features.immutable_vars,
            }
        }),
        None => serde_json::json!(null),
    }
}

/// Run cross-file project-wide analysis for inter-contract vulnerabilities.
fn run_project_analysis(dir: &PathBuf, args: &Args) -> i32 {
    use crate::project_scanner::ProjectScanner;

    let mut project_scanner = ProjectScanner::new(dir.clone(), args.verbose);
    match project_scanner.scan_project() {
        Ok(result) => {
            project_scanner.print_analysis_report(&result);
            0
        }
        Err(e) => {
            eprintln!("{} during project analysis: {}", "Error".red(), e);
            1
        }
    }
}

/// Generate a clean markdown-style report for a single file.
fn scan_file_clean_report(
    scanner: &ContractScanner,
    reporter: &VulnerabilityReporter,
    path: &PathBuf,
) {
    match scanner.scan_file(path) {
        Ok(scan_result) => {
            reporter.generate_clean_report(path, &scan_result.vulnerabilities);
        }
        Err(e) => {
            eprintln!("Error scanning {}: {}", path.display(), e);
            std::process::exit(1);
        }
    }
}

/// Generate a professional security audit report for a single file with auditor metadata.
fn scan_file_professional_audit(path: &PathBuf, args: &Args) {
    use chrono::Utc;

    let scanner = create_scanner(args);
    let project_name = args.project.as_deref().unwrap_or("Smart Contract Project");
    let sponsor = args.sponsor.as_deref().unwrap_or("Unknown Sponsor");
    let today = Utc::now().format("%B %d, %Y").to_string();

    let audit_info = AuditInfo {
        project_name: format!("{} - Security Analysis", project_name),
        sponsor: sponsor.to_string(),
        auditor: "41Swara Security Team".to_string(),
        start_date: today.clone(),
        end_date: today,
        repository_url: None,
        commit_hash: None,
    };

    let mut professional_reporter = ProfessionalReporter::new(audit_info);

    match scanner.scan_file(path) {
        Ok(scan_result) => {
            let file_path_str = path.to_string_lossy();
            professional_reporter.add_vulnerabilities(scan_result.vulnerabilities, &file_path_str);
            let report = professional_reporter.generate_professional_report();
            println!("{}", report);
        }
        Err(e) => {
            eprintln!("Error scanning {}: {}", path.display(), e);
            std::process::exit(1);
        }
    }
}

/// Generate a professional audit report scanning all .sol files in a directory.
/// Uses parallel scanning with rayon for performance, then assembles the report sequentially.
fn scan_directory_professional_audit(dir: &PathBuf, args: &Args) {
    use chrono::Utc;

    let scanner = create_scanner(args);

    println!("\n{} {}", "Scanning for audit:".green(), dir.display());

    let exclude_patterns = compile_exclude_patterns(&args.exclude_pattern);

    let sol_files: Vec<_> = WalkDir::new(dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .filter(|e| e.path().extension().is_some_and(|ext| ext == "sol"))
        .filter(|e| !should_exclude_file(e.path(), &exclude_patterns))
        .collect();

    if sol_files.is_empty() {
        println!("{}", "No .sol files found in directory".yellow());
        return;
    }

    println!(
        "{} {} Solidity files found",
        "Found".green(),
        sol_files.len()
    );

    // Progress bar for audit scanning
    let show_progress = !args.quiet && sol_files.len() > 1;
    let progress = if show_progress {
        let pb = ProgressBar::new(sol_files.len() as u64);
        pb.set_style(
            ProgressStyle::default_bar()
                .template("{spinner:.green} [{bar:40.cyan/blue}] {pos}/{len} files ({eta})")
                .unwrap_or_else(|_| ProgressStyle::default_bar())
                .progress_chars("=>-"),
        );
        Some(pb)
    } else {
        None
    };

    // Parallel scan: collect (relative_path_string, vulnerabilities) pairs
    let audit_results: SharedResults<(String, Vec<Vulnerability>)> =
        Arc::new(Mutex::new(Vec::new()));
    let progress_ref = progress.as_ref();

    sol_files.par_iter().for_each(|entry| {
        let path = entry.path().to_path_buf();
        let relative_path = path.strip_prefix(dir).unwrap_or(&path);
        let file_path_str = relative_path.to_string_lossy().to_string();

        match scanner.scan_file(&path) {
            Ok(scan_result) => {
                audit_results
                    .lock()
                    .unwrap()
                    .push((file_path_str, scan_result.vulnerabilities));
            }
            Err(e) => {
                eprintln!("  Error scanning {}: {}", relative_path.display(), e);
            }
        }
        if let Some(pb) = progress_ref {
            pb.inc(1);
        }
    });

    if let Some(pb) = progress {
        pb.finish_and_clear();
    }

    // Assemble professional report sequentially
    let project_name = args.project.as_deref().unwrap_or("Smart Contract Project");
    let sponsor = args.sponsor.as_deref().unwrap_or("Unknown Sponsor");
    let today = Utc::now().format("%B %d, %Y").to_string();

    let audit_info = AuditInfo {
        project_name: format!("{} - Security Analysis", project_name),
        sponsor: sponsor.to_string(),
        auditor: "41Swara Security Team".to_string(),
        start_date: today.clone(),
        end_date: today,
        repository_url: None,
        commit_hash: None,
    };

    let mut professional_reporter = ProfessionalReporter::new(audit_info);

    let results = audit_results.lock().unwrap();
    for (file_path_str, vulnerabilities) in results.iter() {
        professional_reporter.add_vulnerabilities(vulnerabilities.clone(), file_path_str);
    }

    let report = professional_reporter.generate_professional_report();
    println!("{}", report);
}

/// Generate a combined clean markdown report for all .sol files in a directory.
fn scan_directory_clean_report(
    scanner: &ContractScanner,
    reporter: &VulnerabilityReporter,
    dir: &PathBuf,
) {
    use std::collections::HashMap;

    println!("\n{} {}", "Generating report for:".green(), dir.display());

    let sol_files: Vec<_> = WalkDir::new(dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .filter(|e| e.path().extension().is_some_and(|ext| ext == "sol"))
        .collect();

    if sol_files.is_empty() {
        println!("{}", "No .sol files found".yellow());
        return;
    }

    let mut all_vulnerabilities: HashMap<PathBuf, Vec<Vulnerability>> = HashMap::new();

    for entry in &sol_files {
        let path = entry.path().to_path_buf();
        if let Ok(scan_result) = scanner.scan_file(&path) {
            all_vulnerabilities.insert(path.clone(), scan_result.vulnerabilities);
        }
    }

    // Generate combined report
    println!("# Smart Contract Vulnerability Report\n");
    println!("**Directory**: `{}`", dir.display());
    println!("**Files scanned**: {}", sol_files.len());
    println!(
        "**Date**: {}\n",
        chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC")
    );

    let total_vulns: usize = all_vulnerabilities.values().map(|v| v.len()).sum();
    println!("**Total vulnerabilities**: {}\n", total_vulns);

    for (file_path, vulnerabilities) in &all_vulnerabilities {
        if !vulnerabilities.is_empty() {
            let relative_path = file_path.strip_prefix(dir).unwrap_or(file_path);
            println!("## {}\n", relative_path.display());
            reporter.generate_clean_report(file_path, vulnerabilities);
            println!();
        }
    }
}

/// Parse and scan an ABI JSON file for interface-level security issues.
fn scan_abi_file(path: &PathBuf, args: &Args) {
    println!("\n{} {}", "Scanning ABI:".green(), path.display());

    let abi_scanner = ABIScanner::new(args.verbose);

    match std::fs::read_to_string(path) {
        Ok(abi_content) => match abi_scanner.parse_abi(&abi_content) {
            Ok(analysis) => {
                println!(
                    "{} {} functions, {} events",
                    "Parsed:".green(),
                    analysis.functions.len(),
                    analysis.events.len()
                );

                let vulnerabilities = abi_scanner.scan_abi(&analysis);

                if args.format == "json" {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&vulnerabilities).unwrap()
                    );
                } else if args.format == "sarif" {
                    let sarif_results = vec![(path.clone(), vulnerabilities)];
                    let sarif_report = SarifReport::new(sarif_results, env!("CARGO_PKG_VERSION"));
                    println!("{}", serde_json::to_string_pretty(&sarif_report).unwrap());
                } else {
                    print_abi_vulnerabilities(&vulnerabilities, path);
                }
            }
            Err(e) => {
                eprintln!("{} Failed to parse ABI: {}", "Error:".red().bold(), e);
                std::process::exit(1);
            }
        },
        Err(e) => {
            eprintln!("{} Failed to read file: {}", "Error:".red().bold(), e);
            std::process::exit(1);
        }
    }
}

/// Pretty-print ABI analysis results grouped by vulnerability category.
fn print_abi_vulnerabilities(vulnerabilities: &[Vulnerability], path: &PathBuf) {
    println!(
        "\n{} ABI ANALYSIS: {}",
        "Results".bright_blue().bold(),
        path.display()
    );
    println!("{}", "=".repeat(70).bright_blue());

    if vulnerabilities.is_empty() {
        println!("{}", "No security issues found!".green().bold());
        return;
    }

    let mut categories: std::collections::HashMap<String, Vec<&Vulnerability>> =
        std::collections::HashMap::new();
    for vuln in vulnerabilities {
        categories
            .entry(vuln.category.as_str().to_string())
            .or_default()
            .push(vuln);
    }

    for (category, vulns) in categories {
        println!("\n{} {}", "Category:".bright_cyan().bold(), category);
        for vuln in vulns {
            let icon = match vuln.severity {
                VulnerabilitySeverity::Critical => "!!",
                VulnerabilitySeverity::High => "! ",
                VulnerabilitySeverity::Medium => "* ",
                VulnerabilitySeverity::Low => "- ",
                VulnerabilitySeverity::Info => "i ",
            };
            println!(
                "  {} {} [{}]",
                icon,
                vuln.title,
                vuln.severity.as_str().color(vuln.severity.color())
            );
            println!("     {}", vuln.description);
        }
    }

    println!("\n{}", "=".repeat(70).bright_blue());
    println!("Total issues: {}", vulnerabilities.len());
}

/// Print comprehensive usage examples for all scanner features.
fn show_examples() {
    println!(
        "{}",
        format!(
            "41Swara Smart Contract Scanner v{} - Usage Examples",
            env!("CARGO_PKG_VERSION")
        )
        .bright_blue()
        .bold()
    );
    println!("{}", "Security Researcher Edition".bright_cyan());
    println!("{}", "=".repeat(60).bright_blue());

    println!("\n{}", "Basic Scanning:".bright_green().bold());
    println!("  {} Scan current directory", "41".bright_white());
    println!(
        "  {} Scan current directory (explicit)",
        "41 .".bright_white()
    );
    println!("  {} Scan single file", "41 Contract.sol".bright_white());
    println!("  {} Scan directory", "41 contracts/".bright_white());
    println!(
        "  {} Scan absolute path",
        "41 /path/to/project".bright_white()
    );

    println!(
        "\n{}",
        "Severity & Confidence Filtering:".bright_green().bold()
    );
    println!(
        "  {} Only critical/high",
        "41 --min-severity high".bright_white()
    );
    println!(
        "  {} Only critical",
        "41 --min-severity critical".bright_white()
    );
    println!(
        "  {} High confidence only (70%+)",
        "41 --confidence-threshold 70".bright_white()
    );

    println!("\n{}", "SWC/CWE ID Filtering:".bright_green().bold());
    println!(
        "  {} Only reentrancy (SWC-107)",
        "41 --include-swc SWC-107".bright_white()
    );
    println!(
        "  {} Multiple SWCs",
        "41 --include-swc SWC-107,SWC-105,SWC-114".bright_white()
    );
    println!(
        "  {} Exclude specific SWCs",
        "41 --exclude-swc SWC-103,SWC-102".bright_white()
    );

    println!("\n{}", "File Filtering:".bright_green().bold());
    println!(
        "  {} Exclude test files",
        "41 --exclude-pattern \"**/test/**\"".bright_white()
    );
    println!(
        "  {} Exclude mocks",
        "41 --exclude-pattern \"**/*Mock*\"".bright_white()
    );
    println!(
        "  {} Skip large files",
        "41 --max-file-size 5".bright_white()
    );

    println!("\n{}", "Performance:".bright_green().bold());
    println!("  {} Use 8 threads", "41 -j 8".bright_white());
    println!("  {} Show stats", "41 --stats".bright_white());

    println!("\n{}", "Baseline Comparison:".bright_green().bold());
    println!(
        "  {} Export baseline",
        "41 --export-baseline baseline.json".bright_white()
    );
    println!(
        "  {} Compare to baseline",
        "41 --baseline baseline.json".bright_white()
    );

    println!("\n{}", "Git Diff Mode (Incremental):".bright_green().bold());
    println!(
        "  {} Scan only modified files",
        "41 --git-diff".bright_white()
    );
    println!(
        "  {} Compare against main",
        "41 --git-diff --git-branch main".bright_white()
    );
    println!(
        "  {} CI: modified files only",
        "41 --git-diff --fail-on high".bright_white()
    );

    println!("\n{}", "Watch Mode (Continuous):".bright_green().bold());
    println!("  {} Monitor for changes", "41 --watch".bright_white());
    println!(
        "  {} Watch with filter",
        "41 --watch --min-severity high".bright_white()
    );

    println!("\n{}", "CI/CD Integration:".bright_green().bold());
    println!(
        "  {} Fail on critical",
        "41 --fail-on critical -q".bright_white()
    );
    println!("  {} JSON output", "41 --format json".bright_white());
    println!(
        "  {} SARIF for GitHub",
        "41 --format sarif -o results.sarif".bright_white()
    );
    println!("  {} No color for logs", "41 --no-color".bright_white());

    println!("\n{}", "Professional Audits:".bright_green().bold());
    println!(
        "  {} Full audit",
        "41 --audit --project MyDApp".bright_white()
    );
    println!(
        "  {} Project analysis",
        "41 --project-analysis".bright_white()
    );

    println!(
        "\n{}",
        "Detected Vulnerabilities (SWC IDs):".bright_yellow().bold()
    );
    println!(
        "  {} Reentrancy (SWC-107), Access Control (SWC-105), Proxy Admin",
        "CRITICAL".red()
    );
    println!(
        "  {} Oracle Manipulation, Signature Issues (SWC-117), DoS (SWC-128)",
        "HIGH".red()
    );
    println!(
        "  {} Precision Loss, Time Manipulation (SWC-116)",
        "MEDIUM".yellow()
    );
    println!("  {} Gas Optimization, Code Quality", "LOW/INFO".blue());

    println!("\n{}", "Exit Codes:".bright_cyan().bold());
    println!("  {} No findings", "0".bright_green());
    println!("  {} Critical/High findings", "1".bright_red());
    println!("  {} Medium findings only", "2".bright_yellow());
    println!("  {} Low/Info findings only", "3".bright_blue());
    println!("  {} Scanner error", "10".red());
}

/// Print a user-friendly overview of what the tool does, its capabilities, and how to get started.
fn print_about() {
    println!();
    println!(
        "{}",
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
            .bright_blue()
    );
    println!(
        "{}",
        format!(
            "  41Swara Smart Contract Security Scanner v{}",
            env!("CARGO_PKG_VERSION")
        )
        .bright_blue()
        .bold()
    );
    println!("{}", "  Security Researcher Edition".bright_cyan());
    println!(
        "{}",
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
            .bright_blue()
    );
    println!();
    println!();
    println!("  - Fully offline, zero API keys, 100% local analysis");
    println!("  - Designed for bug bounty hunters, security auditors, and researchers");
    println!("  - Detects real-world exploit patterns from $3.1B+ in DeFi losses");
    println!();
    println!("{}", "WHAT IT DETECTS".bright_green().bold());
    println!(
        "  {} 150+ vulnerability patterns with CWE/SWC ID mapping",
        "->".bright_yellow()
    );
    println!(
        "  {} Reentrancy, access control, oracle manipulation, flash loans",
        "->".bright_yellow()
    );
    println!(
        "  {} DeFi-specific: AMM, lending, staking, bridge, MEV patterns",
        "->".bright_yellow()
    );
    println!(
        "  {} L2/cross-chain: sequencer downtime, PUSH0 compat, gas oracle",
        "->".bright_yellow()
    );
    println!(
        "  {} Modern Solidity 0.8.20+: transient storage, EIP-4844, permits",
        "->".bright_yellow()
    );
    println!(
        "  {} Real exploits: ERC-777 reentrancy, ERC-4626 inflation, Permit2",
        "->".bright_yellow()
    );
    println!(
        "  {} Business logic bugs, state machine issues, race conditions",
        "->".bright_yellow()
    );
    println!(
        "  {} STRIDE threat model auto-generation per contract",
        "->".bright_yellow()
    );
    println!();
    println!("{}", "HOW IT WORKS".bright_green().bold());
    println!("  1. Parses your Solidity source code");
    println!("  2. Runs 150+ regex rules + advanced analyzers (DeFi, logic, reachability)");
    println!("  3. Filters false positives (90%+ reduction) using context-aware analysis");
    println!("  4. Reports findings with severity, confidence %, and fix recommendations");
    println!();
    println!("{}", "QUICK START".bright_green().bold());
    println!(
        "  {} {}        Scan current directory",
        "$".bright_white(),
        "41swara".bright_cyan().bold()
    );
    println!(
        "  {} {} {}  Scan a contract",
        "$".bright_white(),
        "41swara".bright_cyan().bold(),
        "MyContract.sol".bright_white()
    );
    println!(
        "  {} {} {}    Scan all contracts in a folder",
        "$".bright_white(),
        "41swara".bright_cyan().bold(),
        "contracts/".bright_white()
    );
    println!();
    println!("{}", "KEY FLAGS".bright_green().bold());
    println!(
        "  {}           Only show critical/high findings",
        "--min-severity high".bright_white()
    );
    println!(
        "  {}  Only high-confidence results",
        "--confidence-threshold 70".bright_white()
    );
    println!(
        "  {}         DeFi protocol analysis (AMM, oracle, MEV)",
        "--defi-analysis".bright_white()
    );
    println!(
        "  {}     ERC-4626, Permit2, LayerZero, L2 detectors",
        "--advanced-detectors".bright_white()
    );
    println!(
        "  {}          EIP-specific vulnerability checks",
        "--eip-analysis".bright_white()
    );
    println!(
        "  {}        Enhanced false positive filtering",
        "--strict-filter".bright_white()
    );
    println!(
        "  {}              Fast mode (regex only, no advanced analysis)",
        "--fast".bright_white()
    );
    println!(
        "  {}          Verbose output with analysis details",
        "-v".bright_white()
    );
    println!(
        "  {}         JSON output for scripting/CI",
        "-f json".bright_white()
    );
    println!(
        "  {}        SARIF output for GitHub Code Scanning",
        "-f sarif".bright_white()
    );
    println!();
    println!("{}", "OUTPUT FORMATS".bright_green().bold());
    println!(
        "  {} Text     Colored terminal output with severity indicators",
        "->".bright_yellow()
    );
    println!(
        "  {} JSON     Structured data for CI/CD pipelines and scripting",
        "->".bright_yellow()
    );
    println!(
        "  {} SARIF    GitHub Code Scanning integration with CWE IDs",
        "->".bright_yellow()
    );
    println!(
        "  {} Report   Auto-saved markdown report for every scan",
        "->".bright_yellow()
    );
    println!();
    println!("{}", "SEVERITY LEVELS".bright_green().bold());
    println!(
        "  {}  CRITICAL  Immediate fund loss, contract compromise",
        "!!".bright_red().bold()
    );
    println!(
        "  {}   HIGH      Significant risk, likely exploitable",
        "!".bright_red()
    );
    println!(
        "  {}   MEDIUM    Conditional risk, specific circumstances",
        "*".bright_yellow()
    );
    println!(
        "  {}   LOW       Best practice violation, minor risk",
        "-".bright_white()
    );
    println!();
    println!("{}", "LEARN MORE".bright_green().bold());
    println!(
        "  {} {}    See all CLI flags",
        "$".bright_white(),
        "41swara --help".bright_cyan()
    );
    println!(
        "  {} {}    See usage examples",
        "$".bright_white(),
        "41swara --examples".bright_cyan()
    );
    println!(
        "  {} {}    Build and feature info",
        "$".bright_white(),
        "41swara --version-full".bright_cyan()
    );
    println!();
    println!("  Homepage:  {}", "41Swara.com".bright_white());
    println!("  License:   MIT | Built by 41Swara Security Team");
    println!();
    println!(
        "{}",
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
            .bright_blue()
    );
    println!(
        "  {}",
        "Detect vulnerabilities before attackers do."
            .bright_cyan()
            .italic()
    );
    println!(
        "{}",
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
            .bright_blue()
    );
    println!();
}

/// Print detailed version info including build target, features, and SWC coverage.
fn print_version_full() {
    println!("{}", "41Swara Smart Contract Scanner".bright_blue().bold());
    println!("{}", "Security Researcher Edition".bright_cyan());
    println!();
    println!(
        "Version:       {}",
        env!("CARGO_PKG_VERSION").bright_white().bold()
    );
    println!("Build Target:  {}", std::env::consts::ARCH);
    println!("OS:            {}", std::env::consts::OS);
    println!("Rust Version:  {}", env!("CARGO_PKG_RUST_VERSION", "1.70+"));
    println!();
    println!("{}", "Features:".bright_green().bold());
    println!("  - 150+ vulnerability patterns");
    println!("  - CWE/SWC ID mapping for compliance");
    println!("  - Confidence scoring (0-100%)");
    println!("  - Modern Solidity 0.8.20+ support");
    println!("  - L2/Base chain patterns");
    println!("  - SARIF 2.1.0 output for CI/CD");
    println!("  - Parallel scanning with rayon");
    println!("License:  MIT");
}
