//! 41Swara Smart Contract Security Scanner v0.3.0
//!
//! High-performance vulnerability scanner for blockchain security researchers.
//! Features parallel scanning, severity filtering, and multiple output formats.

use clap::{Parser, ValueEnum};
use colored::*;
use rayon::prelude::*;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Instant;
use walkdir::WalkDir;
use git2::{Repository, DiffOptions, Delta};
use notify::{Watcher, RecursiveMode, Event, Result as NotifyResult, EventKind};
use std::sync::mpsc::channel;

mod scanner;
mod vulnerabilities;
mod parser;
mod reporter;
mod professional_reporter;
mod project_scanner;
mod advanced_analysis;
mod abi_scanner;
mod sarif;

// Phase 1: AST-Based Analysis Engine
mod ast;

// Phase 2: DeFi-Specific Analyzers
mod defi;


// Phase 4: Performance & Caching
mod cache;

// Phase 5: Tool Integration
mod integrations;

use scanner::ContractScanner;
use reporter::VulnerabilityReporter;
use vulnerabilities::{Vulnerability, VulnerabilitySeverity};
use abi_scanner::ABIScanner;
use professional_reporter::{ProfessionalReporter, AuditInfo};
use sarif::SarifReport;

/// Minimum severity level filter
#[derive(Debug, Clone, Copy, ValueEnum, PartialEq, Eq, PartialOrd, Ord)]
enum MinSeverity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl MinSeverity {
    fn matches(&self, severity: &VulnerabilitySeverity) -> bool {
        match (self, severity) {
            (MinSeverity::Critical, VulnerabilitySeverity::Critical) => true,
            (MinSeverity::Critical, _) => false,
            (MinSeverity::High, VulnerabilitySeverity::Critical | VulnerabilitySeverity::High) => true,
            (MinSeverity::High, _) => false,
            (MinSeverity::Medium, VulnerabilitySeverity::Critical | VulnerabilitySeverity::High | VulnerabilitySeverity::Medium) => true,
            (MinSeverity::Medium, _) => false,
            (MinSeverity::Low, VulnerabilitySeverity::Info) => false,
            (MinSeverity::Low, _) => true,
            (MinSeverity::Info, _) => true,
        }
    }
}

#[derive(Parser)]
#[command(name = "solidity-scanner")]
#[command(version = "0.3.0")]
#[command(author = "41Swara Security Team")]
#[command(about = "High-performance smart contract vulnerability scanner for security researchers")]
#[command(long_about = r#"
41Swara Smart Contract Security Scanner v0.3.0

A fully offline, API-independent security scanner for blockchain researchers.
Features AST-based analysis, DeFi-specific detectors, Slither/Foundry integration,
and 100+ vulnerability patterns including real-world exploit patterns from $3.1B+ in DeFi losses.

FEATURES:
  - Parallel scanning for 4-10x performance improvement
  - Severity filtering (--min-severity critical/high/medium/low/info)
  - Multiple output formats (text, json, sarif)
  - Professional audit report generation
  - Cross-file project analysis

EXAMPLES:
  # Quick scan with severity filter
  solidity-scanner -p contracts/ --min-severity high

  # Fast parallel scan with stats
  solidity-scanner -p . -j 8 --stats

  # JSON output for CI/CD
  solidity-scanner -p . --format json --min-severity critical

  # Professional audit report
  solidity-scanner -p . --audit --project "MyDApp" --sponsor "Client Inc"

  # Quiet mode (only show summary)
  solidity-scanner -p . -q --fail-on critical

VULNERABILITY CATEGORIES:
  Critical: Reentrancy, Access Control, Proxy Admin, Arbitrary Calls
  High:     Oracle Manipulation, Signature Issues, DoS, MEV/Front-running
  Medium:   Precision Loss, Time Manipulation, Unchecked Returns
  Low/Info: Gas Optimization, Code Quality, Best Practices
"#)]
struct Args {
    /// Path to smart contract file (.sol) or directory to scan
    #[arg(short, long, value_name = "FILE_OR_DIR")]
    path: Option<PathBuf>,

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
}

fn main() {
    let args = Args::parse();

    // Configure thread pool for parallel scanning
    if args.threads > 0 {
        rayon::ThreadPoolBuilder::new()
            .num_threads(args.threads)
            .build_global()
            .unwrap_or_else(|e| eprintln!("Warning: Could not set thread count: {}", e));
    }

    // Show examples if requested
    if args.examples {
        show_examples();
        return;
    }

    // Check if path is provided
    let path = match &args.path {
        Some(p) => p.clone(),
        None => {
            eprintln!("{}", "Error: Path is required. Use -p or --path".red().bold());
            eprintln!("{}", "Use --help for more information or --examples for usage examples".yellow());
            std::process::exit(1);
        }
    };

    // Print scanner header (unless quiet mode)
    if !args.quiet && args.format != "json" && args.format != "sarif" {
        println!("{}", "41Swara Smart Contract Scanner v0.3.0".bright_blue().bold());
        println!("{}", "High-performance security analysis for blockchain".bright_blue());
        println!("{}", "=".repeat(55).bright_blue());
    }

    // Validate path exists
    if !path.exists() {
        eprintln!("{} Path does not exist: {}", "Error:".red().bold(), path.display());
        std::process::exit(1);
    }

    let start_time = Instant::now();

    // Process based on path type
    let exit_code = if path.is_file() {
        process_file(&args, &path)
    } else if path.is_dir() {
        process_directory(&args, &path)
    } else {
        eprintln!("{} Invalid path type", "Error:".red().bold());
        1
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

fn process_file(args: &Args, path: &PathBuf) -> i32 {
    let extension = path.extension().and_then(|e| e.to_str());

    match extension {
        Some("sol") => {
            if args.audit {
                scan_file_professional_audit(path, args);
            } else if args.report {
                let scanner = ContractScanner::new(args.verbose);
                let reporter = VulnerabilityReporter::new(&args.format);
                scan_file_clean_report(&scanner, &reporter, path);
            } else if args.format == "json" || args.format == "sarif" {
                // Handle JSON and SARIF formats for single file
                let scanner = ContractScanner::new(args.verbose);
                scan_file_structured_format(&scanner, path, args);
            } else {
                let scanner = ContractScanner::new(args.verbose);
                let mut reporter = VulnerabilityReporter::new(&args.format);
                scan_file_with_filter(&scanner, &mut reporter, path, args);
                reporter.print_summary();
            }
            0
        }
        Some("json") if args.abi => {
            scan_abi_file(path, args);
            0
        }
        Some("json") => {
            eprintln!("{} Use --abi flag for JSON ABI files", "Error:".red().bold());
            1
        }
        _ => {
            eprintln!("{} Unsupported file type. Supported: .sol, .json (with --abi)", "Error:".red().bold());
            1
        }
    }
}

/// Get list of modified .sol files from git diff
fn get_git_modified_files(repo_path: &PathBuf, base_ref: &str) -> Result<Vec<PathBuf>, String> {
    let repo = Repository::open(repo_path)
        .map_err(|e| format!("Failed to open git repository: {}", e))?;

    // Get the HEAD tree
    let head = repo.head()
        .map_err(|e| format!("Failed to get HEAD: {}", e))?;
    let head_tree = head.peel_to_tree()
        .map_err(|e| format!("Failed to get HEAD tree: {}", e))?;

    // Get the base reference tree
    let base_obj = repo.revparse_single(base_ref)
        .map_err(|e| format!("Failed to resolve '{}': {}", base_ref, e))?;
    let base_tree = base_obj.peel_to_tree()
        .map_err(|e| format!("Failed to get base tree: {}", e))?;

    // Create diff
    let mut diff_opts = DiffOptions::new();
    let diff = repo.diff_tree_to_tree(Some(&base_tree), Some(&head_tree), Some(&mut diff_opts))
        .map_err(|e| format!("Failed to create diff: {}", e))?;

    let mut modified_files = Vec::new();
    let workdir = repo.workdir()
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
        None, None, None,
    ).map_err(|e| format!("Failed to process diff: {}", e))?;

    // Also check for unstaged changes
    let mut diff_opts_workdir = DiffOptions::new();
    let diff_workdir = repo.diff_tree_to_workdir_with_index(Some(&head_tree), Some(&mut diff_opts_workdir))
        .map_err(|e| format!("Failed to create workdir diff: {}", e))?;

    diff_workdir.foreach(
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
        None, None, None,
    ).map_err(|e| format!("Failed to process workdir diff: {}", e))?;

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
    }).expect("Failed to create watcher");

    watcher.watch(dir.as_ref(), RecursiveMode::Recursive)
        .expect("Failed to watch directory");

    let scanner = ContractScanner::new(args.verbose);

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
                        let sol_files: Vec<_> = event.paths.iter()
                            .filter(|p| p.extension().map_or(false, |ext| ext == "sol"))
                            .collect();

                        if !sol_files.is_empty() {
                            // Debounce: wait 500ms between scans
                            if let Ok(elapsed) = std::time::SystemTime::now().duration_since(last_scan) {
                                if elapsed.as_millis() < 500 {
                                    continue;
                                }
                            }

                            println!("\n{} File changed: {}",
                                "⟳".bright_cyan().bold(),
                                sol_files.iter()
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
        .filter(|e| e.path().extension().map_or(false, |ext| ext == "sol"))
        .map(|e| e.path().to_path_buf())
        .collect();

    if sol_files.is_empty() {
        return;
    }

    let all_results: Arc<Mutex<Vec<(PathBuf, Vec<Vulnerability>)>>> = Arc::new(Mutex::new(Vec::new()));

    sol_files.par_iter().for_each(|file_path| {
        if let Ok(mut vulns) = scanner.scan_file(file_path) {
            vulns.retain(|v| args.min_severity.matches(&v.severity));
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
        println!("{} {} vulnerabilities found",
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

        if critical > 0 { println!("  {} Critical: {}", "🚨".red(), critical); }
        if high > 0 { println!("  {} High: {}", "⚠".red(), high); }
        if medium > 0 { println!("  {} Medium: {}", "⚡".yellow(), medium); }
        if low > 0 { println!("  {} Low: {}", "💡".blue(), low); }
        if info > 0 { println!("  {} Info: {}", "ℹ".bright_blue(), info); }
    }

    println!("{}", "━".repeat(60).blue());
}

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
        let scanner = ContractScanner::new(args.verbose);
        let reporter = VulnerabilityReporter::new(&args.format);
        scan_directory_clean_report(&scanner, &reporter, dir);
        return 0;
    }

    // Watch mode - continuous monitoring
    if args.watch {
        return run_watch_mode(dir, args);
    }

    // Collect .sol files
    let sol_files: Vec<PathBuf> = if args.git_diff {
        // Git diff mode - only scan modified files
        match get_git_modified_files(dir, &args.git_branch) {
            Ok(files) => {
                if !args.quiet {
                    println!("{} {} modified .sol files from git diff", "Found".green(), files.len());
                }
                files
            }
            Err(e) => {
                eprintln!("{} {}", "Git error:".red().bold(), e);
                eprintln!("{} Make sure you're in a git repository and the branch exists", "Hint:".yellow());
                return 1;
            }
        }
    } else {
        // Normal mode - scan all files
        WalkDir::new(dir)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
            .filter(|e| e.path().extension().map_or(false, |ext| ext == "sol"))
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
        println!("{} {} Solidity files found", "Found".green(), sol_files.len());
    }

    // PARALLEL SCANNING with rayon
    let scanner = ContractScanner::new(args.verbose);
    let all_results: Arc<Mutex<Vec<(PathBuf, Vec<Vulnerability>)>>> = Arc::new(Mutex::new(Vec::new()));
    let error_count: Arc<Mutex<usize>> = Arc::new(Mutex::new(0));
    let min_severity = args.min_severity;

    sol_files.par_iter().for_each(|file_path| {
        match scanner.scan_file(file_path) {
            Ok(mut vulns) => {
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
    });

    let results = all_results.lock().unwrap();
    let total_vulns: usize = results.iter().map(|(_, v)| v.len()).sum();

    // Generate output
    if args.format == "json" {
        let json_output = serde_json::json!({
            "version": "0.3.0",
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
        // SARIF 2.1.0 output for GitHub Code Scanning and CI/CD
        let sarif_results: Vec<(PathBuf, Vec<Vulnerability>)> = results
            .iter()
            .map(|(path, vulns)| (path.clone(), vulns.clone()))
            .collect();
        let sarif_report = SarifReport::new(sarif_results, "0.3.0");
        println!("{}", serde_json::to_string_pretty(&sarif_report).unwrap());
    } else {
        // Text output
        let mut reporter = VulnerabilityReporter::new("text");
        for (path, vulns) in results.iter() {
            reporter.add_file_results(path, vulns.clone());
        }
        reporter.print_summary();
    }

    // Determine exit code based on --fail-on
    if let Some(ref fail_severity) = args.fail_on {
        let has_failures = results.iter().any(|(_, vulns)| {
            vulns.iter().any(|v| fail_severity.matches(&v.severity))
        });
        if has_failures {
            return 1;
        }
    }

    0
}

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

fn scan_file_with_filter(scanner: &ContractScanner, reporter: &mut VulnerabilityReporter, path: &PathBuf, args: &Args) {
    if !args.quiet {
        println!("\n{} {}", "Scanning:".green(), path.display());
    }

    match scanner.scan_file(path) {
        Ok(mut vulnerabilities) => {
            // Apply severity filter
            vulnerabilities.retain(|v| args.min_severity.matches(&v.severity));
            reporter.add_file_results(path, vulnerabilities);
        }
        Err(e) => {
            eprintln!("{} {}: {}", "Error scanning".red(), path.display(), e);
        }
    }
}

fn scan_file_structured_format(scanner: &ContractScanner, path: &PathBuf, args: &Args) {
    if !args.quiet {
        println!("\n{} {}", "Scanning:".green(), path.display());
    }

    match scanner.scan_file(path) {
        Ok(mut vulnerabilities) => {
            // Apply severity filter
            vulnerabilities.retain(|v| args.min_severity.matches(&v.severity));

            if args.format == "json" {
                let json_output = serde_json::json!({
                    "version": "0.3.0",
                    "files_scanned": 1,
                    "total_vulnerabilities": vulnerabilities.len(),
                    "min_severity_filter": format!("{:?}", args.min_severity),
                    "results": [{
                        "file": path.to_string_lossy(),
                        "vulnerabilities": vulnerabilities,
                    }],
                });
                println!("{}", serde_json::to_string_pretty(&json_output).unwrap());
            } else if args.format == "sarif" {
                let sarif_results = vec![(path.clone(), vulnerabilities)];
                let sarif_report = SarifReport::new(sarif_results, "0.3.0");
                println!("{}", serde_json::to_string_pretty(&sarif_report).unwrap());
            }
        }
        Err(e) => {
            eprintln!("{} {}: {}", "Error scanning".red(), path.display(), e);
            std::process::exit(1);
        }
    }
}

fn scan_file_clean_report(scanner: &ContractScanner, reporter: &VulnerabilityReporter, path: &PathBuf) {
    match scanner.scan_file(path) {
        Ok(vulnerabilities) => {
            reporter.generate_clean_report(path, &vulnerabilities);
        }
        Err(e) => {
            eprintln!("Error scanning {}: {}", path.display(), e);
            std::process::exit(1);
        }
    }
}

fn scan_file_professional_audit(path: &PathBuf, args: &Args) {
    use chrono::Utc;

    let scanner = ContractScanner::new(args.verbose);
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
        Ok(vulnerabilities) => {
            let file_path_str = path.to_string_lossy();
            professional_reporter.add_vulnerabilities(vulnerabilities, &file_path_str);
            let report = professional_reporter.generate_professional_report();
            println!("{}", report);
        }
        Err(e) => {
            eprintln!("Error scanning {}: {}", path.display(), e);
            std::process::exit(1);
        }
    }
}

fn scan_directory_professional_audit(dir: &PathBuf, args: &Args) {
    use chrono::Utc;

    let scanner = ContractScanner::new(args.verbose);

    println!("\n{} {}", "Scanning for audit:".green(), dir.display());

    let sol_files: Vec<_> = WalkDir::new(dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .filter(|e| e.path().extension().map_or(false, |ext| ext == "sol"))
        .collect();

    if sol_files.is_empty() {
        println!("{}", "No .sol files found in directory".yellow());
        return;
    }

    println!("{} {} Solidity files found", "Found".green(), sol_files.len());

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

    for entry in &sol_files {
        let path = entry.path().to_path_buf();
        let relative_path = path.strip_prefix(dir).unwrap_or(&path);

        if !args.quiet {
            println!("  Analyzing: {}", relative_path.display());
        }

        match scanner.scan_file(&path) {
            Ok(vulnerabilities) => {
                let file_path_str = relative_path.to_string_lossy();
                professional_reporter.add_vulnerabilities(vulnerabilities, &file_path_str);
            }
            Err(e) => {
                eprintln!("  Error scanning {}: {}", relative_path.display(), e);
            }
        }
    }

    let report = professional_reporter.generate_professional_report();
    println!("{}", report);
}

fn scan_directory_clean_report(scanner: &ContractScanner, reporter: &VulnerabilityReporter, dir: &PathBuf) {
    use std::collections::HashMap;

    println!("\n{} {}", "Generating report for:".green(), dir.display());

    let sol_files: Vec<_> = WalkDir::new(dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .filter(|e| e.path().extension().map_or(false, |ext| ext == "sol"))
        .collect();

    if sol_files.is_empty() {
        println!("{}", "No .sol files found".yellow());
        return;
    }

    let mut all_vulnerabilities: HashMap<PathBuf, Vec<Vulnerability>> = HashMap::new();

    for entry in &sol_files {
        let path = entry.path().to_path_buf();
        if let Ok(vulnerabilities) = scanner.scan_file(&path) {
            all_vulnerabilities.insert(path.clone(), vulnerabilities);
        }
    }

    // Generate combined report
    println!("# Smart Contract Vulnerability Report\n");
    println!("**Directory**: `{}`", dir.display());
    println!("**Files scanned**: {}", sol_files.len());
    println!("**Date**: {}\n", chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC"));

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

fn scan_abi_file(path: &PathBuf, args: &Args) {
    println!("\n{} {}", "Scanning ABI:".green(), path.display());

    let abi_scanner = ABIScanner::new(args.verbose);

    match std::fs::read_to_string(path) {
        Ok(abi_content) => {
            match abi_scanner.parse_abi(&abi_content) {
                Ok(analysis) => {
                    println!("{} {} functions, {} events",
                        "Parsed:".green(), analysis.functions.len(), analysis.events.len());

                    let vulnerabilities = abi_scanner.scan_abi(&analysis);

                    if args.format == "json" {
                        println!("{}", serde_json::to_string_pretty(&vulnerabilities).unwrap());
                    } else if args.format == "sarif" {
                        let sarif_results = vec![(path.clone(), vulnerabilities)];
                        let sarif_report = SarifReport::new(sarif_results, "0.3.0");
                        println!("{}", serde_json::to_string_pretty(&sarif_report).unwrap());
                    } else {
                        print_abi_vulnerabilities(&vulnerabilities, path);
                    }
                }
                Err(e) => {
                    eprintln!("{} Failed to parse ABI: {}", "Error:".red().bold(), e);
                    std::process::exit(1);
                }
            }
        }
        Err(e) => {
            eprintln!("{} Failed to read file: {}", "Error:".red().bold(), e);
            std::process::exit(1);
        }
    }
}

fn print_abi_vulnerabilities(vulnerabilities: &[Vulnerability], path: &PathBuf) {
    println!("\n{} ABI ANALYSIS: {}", "Results".bright_blue().bold(), path.display());
    println!("{}", "=".repeat(70).bright_blue());

    if vulnerabilities.is_empty() {
        println!("{}", "No security issues found!".green().bold());
        return;
    }

    let mut categories: std::collections::HashMap<String, Vec<&Vulnerability>> = std::collections::HashMap::new();
    for vuln in vulnerabilities {
        categories.entry(vuln.category.as_str().to_string())
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
            println!("  {} {} [{}]", icon, vuln.title, vuln.severity.as_str().color(vuln.severity.color()));
            println!("     {}", vuln.description);
        }
    }

    println!("\n{}", "=".repeat(70).bright_blue());
    println!("Total issues: {}", vulnerabilities.len());
}

fn show_examples() {
    println!("{}", "41Swara Smart Contract Scanner - Usage Examples".bright_blue().bold());
    println!("{}", "=".repeat(60).bright_blue());

    println!("\n{}", "Basic Scanning:".bright_green().bold());
    println!("  {} Scan single file", "solidity-scanner -p Contract.sol".bright_white());
    println!("  {} Scan directory", "solidity-scanner -p contracts/".bright_white());

    println!("\n{}", "Severity Filtering:".bright_green().bold());
    println!("  {} Only critical/high", "solidity-scanner -p . --min-severity high".bright_white());
    println!("  {} Only critical", "solidity-scanner -p . --min-severity critical".bright_white());

    println!("\n{}", "Performance:".bright_green().bold());
    println!("  {} Use 8 threads", "solidity-scanner -p . -j 8".bright_white());
    println!("  {} Show stats", "solidity-scanner -p . --stats".bright_white());

    println!("\n{}", "Git Diff Mode (Incremental):".bright_green().bold());
    println!("  {} Scan only modified files", "solidity-scanner -p . --git-diff".bright_white());
    println!("  {} Compare against main", "solidity-scanner -p . --git-diff --git-branch main".bright_white());
    println!("  {} CI: modified files only", "solidity-scanner -p . --git-diff --fail-on high".bright_white());

    println!("\n{}", "Watch Mode (Continuous):".bright_green().bold());
    println!("  {} Monitor for changes", "solidity-scanner -p . --watch".bright_white());
    println!("  {} Watch with filter", "solidity-scanner -p . --watch --min-severity high".bright_white());

    println!("\n{}", "CI/CD Integration:".bright_green().bold());
    println!("  {} Fail on critical", "solidity-scanner -p . --fail-on critical -q".bright_white());
    println!("  {} JSON output", "solidity-scanner -p . --format json".bright_white());
    println!("  {} SARIF for GitHub", "solidity-scanner -p . --format sarif".bright_white());

    println!("\n{}", "Professional Audits:".bright_green().bold());
    println!("  {} Full audit", "solidity-scanner -p . --audit --project MyDApp".bright_white());
    println!("  {} Project analysis", "solidity-scanner -p . --project-analysis".bright_white());

    println!("\n{}", "Detected Vulnerabilities:".bright_yellow().bold());
    println!("  {} Reentrancy, Access Control, Proxy Admin", "CRITICAL".red());
    println!("  {} Oracle Manipulation, DoS, MEV", "HIGH".red());
    println!("  {} Precision Loss, Time Manipulation", "MEDIUM".yellow());
    println!("  {} Gas Optimization, Code Quality", "LOW/INFO".blue());
}
