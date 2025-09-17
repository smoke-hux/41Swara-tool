use clap::Parser;
use colored::*;
use std::path::PathBuf;
use walkdir::WalkDir;

mod scanner;
mod vulnerabilities;
mod parser;
mod reporter;
mod professional_reporter;
mod project_scanner;

use scanner::ContractScanner;
use reporter::VulnerabilityReporter;
use vulnerabilities::Vulnerability;
use professional_reporter::{ProfessionalReporter, AuditInfo};

#[derive(Parser)]
#[command(name = "solidity-scanner")]
#[command(about = "A comprehensive Rust-based smart contract vulnerability scanner")]
#[command(long_about = "
Smart Contract Vulnerability Scanner v0.1.0

DESCRIPTION:
    This tool analyzes Solidity smart contracts for common security vulnerabilities
    and code quality issues. It performs line-by-line analysis and provides detailed
    reports with specific recommendations for fixing identified issues.

EXAMPLES:
    # Scan a single contract file
    solidity-scanner --path MyContract.sol
    
    # Scan with verbose output
    solidity-scanner --path contracts/ --verbose
    
    # Generate JSON report
    solidity-scanner --path MyContract.sol --format json > report.json
    
    # Scan directory recursively
    solidity-scanner --path ./contracts --verbose

VULNERABILITY CATEGORIES:
    • Reentrancy attacks (Critical)
    • Access control issues (Critical) 
    • Weak randomness sources (High)
    • DoS vulnerabilities (High)
    • Integer overflow/underflow (High)
    • Time manipulation (Medium)
    • Gas optimization issues (Low)
    • Code quality issues (Info)
")]
struct Args {
    #[arg(
        short, 
        long, 
        help = "Path to the smart contract file (.sol) or directory to scan",
        value_name = "FILE_OR_DIR"
    )]
    path: Option<PathBuf>,
    
    #[arg(
        short, 
        long, 
        help = "Output format", 
        default_value = "text",
        value_parser = ["text", "json"]
    )]
    format: String,
    
    #[arg(short, long, help = "Enable verbose output with detailed analysis")]
    verbose: bool,
    
    #[arg(long, help = "Show usage examples")]
    examples: bool,
    
    #[arg(long, help = "Generate clean PDF-style report")]
    report: bool,
    
    #[arg(long, help = "Generate professional audit report", conflicts_with = "report")]
    audit: bool,
    
    #[arg(long, help = "Project name for audit report", requires = "audit")]
    project: Option<String>,
    
    #[arg(long, help = "Sponsor name for audit report", requires = "audit")]
    sponsor: Option<String>,
    
    #[arg(long, help = "Enable advanced project-wide analysis with cross-file vulnerability detection")]
    project_analysis: bool,
}

fn main() {
    let args = Args::parse();
    
    // Show examples if requested
    if args.examples {
        show_examples();
        return;
    }
    
    // Check if path is provided
    let path = match &args.path {
        Some(p) => p.clone(),
        None => {
            eprintln!("{}", "❌ Error: Path is required".red().bold());
            eprintln!("{}", "Use --help for more information or --examples for usage examples".yellow());
            std::process::exit(1);
        }
    };
    
    // Print scanner header
    println!("{}", "🔍 Smart Contract Vulnerability Scanner v0.1.0".bright_blue().bold());
    println!("{}", "=".repeat(55).bright_blue());
    
    // Validate and process the path
    if !path.exists() {
        eprintln!("{} Path does not exist: {}", "❌ Error:".red().bold(), path.display());
        std::process::exit(1);
    }
    
    let scanner = ContractScanner::new(args.verbose);
    let mut reporter = VulnerabilityReporter::new(&args.format);
    
    if path.is_file() {
        if let Some(extension) = path.extension() {
            if extension == "sol" {
                if args.audit {
                    scan_file_professional_audit(&scanner, &path, &args);
                } else if args.report {
                    scan_file_clean_report(&scanner, &reporter, &path);
                } else {
                    scan_file(&scanner, &mut reporter, &path);
                }
            } else {
                eprintln!("{} Only .sol files are supported. Found: {}", 
                    "❌ Error:".red().bold(), 
                    extension.to_string_lossy()
                );
                std::process::exit(1);
            }
        } else {
            eprintln!("{} File has no extension. Only .sol files are supported.", "❌ Error:".red().bold());
            std::process::exit(1);
        }
    } else if path.is_dir() {
        if args.project_analysis {
            // Use advanced project scanner
            use crate::project_scanner::ProjectScanner;
            let mut project_scanner = ProjectScanner::new(path.clone(), args.verbose);
            match project_scanner.scan_project() {
                Ok(result) => {
                    project_scanner.print_analysis_report(&result);
                }
                Err(e) => {
                    eprintln!("{} Error during project analysis: {}", "❌".red(), e);
                    std::process::exit(1);
                }
            }
        } else if args.audit {
            scan_directory_professional_audit(&scanner, &path, &args);
        } else if args.report {
            scan_directory_clean_report(&scanner, &reporter, &path);
        } else {
            scan_directory(&scanner, &mut reporter, &path);
        }
    }
    
    if !args.report && !args.audit {
        reporter.print_summary();
    }
}

fn show_examples() {
    println!("{}", "🔍 Smart Contract Vulnerability Scanner - Usage Examples".bright_blue().bold());
    println!("{}", "=".repeat(65).bright_blue());
    
    println!("\n{}", "📋 Basic Usage:".bright_green().bold());
    println!("  {}", "solidity-scanner --path MyContract.sol".bright_white());
    println!("    Scan a single contract file with standard output");
    
    println!("\n{}", "📋 Verbose Analysis:".bright_green().bold());
    println!("  {}", "solidity-scanner --path contracts/ --verbose".bright_white());
    println!("    Scan directory with detailed analysis information");
    
    println!("\n{}", "📋 JSON Report:".bright_green().bold());
    println!("  {}", "solidity-scanner --path MyContract.sol --format json".bright_white());
    println!("    Generate machine-readable JSON output");
    
    println!("\n{}", "📋 Save Report to File:".bright_green().bold());
    println!("  {}", "solidity-scanner --path MyContract.sol --format json > security-report.json".bright_white());
    println!("    Save vulnerability report to a file");
    
    println!("\n{}", "📋 Scan Multiple Files:".bright_green().bold());
    println!("  {}", "solidity-scanner --path ./contracts --verbose".bright_white());
    println!("    Recursively scan all .sol files in a directory");
    
    println!("\n{}", "📋 Quick Help:".bright_green().bold());
    println!("  {}", "solidity-scanner --help".bright_white());
    println!("    Show detailed help information");
    
    println!("\n{}", "🔒 Detected Vulnerability Types:".bright_yellow().bold());
    println!("  • {} Reentrancy attacks", "🚨".red());
    println!("  • {} Access control issues", "🚨".red());
    println!("  • {} Weak randomness sources", "⚠️ ".yellow());
    println!("  • {} DoS vulnerabilities", "⚠️ ".yellow());
    println!("  • {} Integer overflow/underflow", "⚠️ ".yellow());
    println!("  • {} Time manipulation", "⚡".blue());
    println!("  • {} Gas optimization issues", "💡".green());
    println!("  • {} Code quality issues", "ℹ️ ".cyan());
    
    println!("\n{}", "💡 Pro Tips:".bright_cyan().bold());
    println!("  • Use --verbose for detailed line-by-line analysis");
    println!("  • JSON format is perfect for CI/CD integration");
    println!("  • Always review recommendations for each finding");
    println!("  • Consider professional audits for production contracts");
}

fn scan_file(scanner: &ContractScanner, reporter: &mut VulnerabilityReporter, path: &PathBuf) {
    println!("\n{} {}", "📁 Scanning file:".green(), path.display());
    
    match scanner.scan_file(path) {
        Ok(vulnerabilities) => {
            reporter.add_file_results(path, vulnerabilities);
        }
        Err(e) => {
            eprintln!("{} {}: {}", "❌ Error scanning".red(), path.display(), e);
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

fn scan_file_professional_audit(scanner: &ContractScanner, path: &PathBuf, args: &Args) {
    use chrono::Utc;
    
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
            eprintln!("❌ Error scanning {}: {}", path.display(), e);
            std::process::exit(1);
        }
    }
}

fn scan_directory_professional_audit(scanner: &ContractScanner, dir: &PathBuf, args: &Args) {
    use chrono::Utc;
    use walkdir::WalkDir;
    
    println!("\n{} {}", "📁 Scanning project directory:".green(), dir.display());
    
    let sol_files: Vec<_> = WalkDir::new(dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .filter(|e| e.path().extension().map_or(false, |ext| ext == "sol"))
        .collect();
    
    if sol_files.is_empty() {
        println!("{}", "⚠️ No .sol files found in directory".yellow());
        return;
    }
    
    println!("{} {} Solidity files found for audit", "✅".green(), sol_files.len());
    
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
    
    // Scan all files and collect vulnerabilities
    for entry in &sol_files {
        let path = entry.path().to_path_buf();
        let relative_path = path.strip_prefix(dir).unwrap_or(&path);
        
        println!("  📝 Analyzing: {}", relative_path.display());
        
        match scanner.scan_file(&path) {
            Ok(vulnerabilities) => {
                let file_path_str = relative_path.to_string_lossy();
                professional_reporter.add_vulnerabilities(vulnerabilities, &file_path_str);
            }
            Err(e) => {
                eprintln!("  ❌ Error scanning {}: {}", relative_path.display(), e);
            }
        }
    }
    
    let report = professional_reporter.generate_professional_report();
    println!("{}", report);
}

fn scan_directory_clean_report(scanner: &ContractScanner, reporter: &VulnerabilityReporter, dir: &PathBuf) {
    use walkdir::WalkDir;
    use std::collections::HashMap;
    
    println!("\n{} {}", "📁 Generating clean report for directory:".green(), dir.display());
    
    let sol_files: Vec<_> = WalkDir::new(dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .filter(|e| e.path().extension().map_or(false, |ext| ext == "sol"))
        .collect();
    
    if sol_files.is_empty() {
        println!("{}", "⚠️ No .sol files found in directory".yellow());
        return;
    }
    
    let mut all_vulnerabilities: HashMap<PathBuf, Vec<Vulnerability>> = HashMap::new();
    
    // Scan all files
    for entry in &sol_files {
        let path = entry.path().to_path_buf();
        match scanner.scan_file(&path) {
            Ok(vulnerabilities) => {
                all_vulnerabilities.insert(path.clone(), vulnerabilities);
            }
            Err(e) => {
                eprintln!("Error scanning {}: {}", path.display(), e);
            }
        }
    }
    
    // Generate combined report
    println!("# Smart Contract Project Vulnerability Report");
    println!();
    println!("**Directory**: `{}`", dir.display());
    println!("**Total Files**: {}", sol_files.len());
    println!("**Analysis Date**: {}", chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC"));
    println!();
    
    let total_vulns: usize = all_vulnerabilities.values().map(|v| v.len()).sum();
    println!("**Total Vulnerabilities Found**: {}", total_vulns);
    println!();
    
    if total_vulns == 0 {
        println!("✅ No vulnerabilities found in the project!");
        return;
    }
    
    // Generate report for each file
    for (file_path, vulnerabilities) in &all_vulnerabilities {
        if !vulnerabilities.is_empty() {
            let relative_path = file_path.strip_prefix(dir).unwrap_or(file_path);
            println!("## File: `{}`", relative_path.display());
            println!();
            reporter.generate_clean_report(file_path, vulnerabilities);
            println!();
        }
    }
}

fn scan_directory(scanner: &ContractScanner, reporter: &mut VulnerabilityReporter, dir: &PathBuf) {
    println!("\n{} {}", "📁 Scanning directory:".green(), dir.display());
    
    let sol_files: Vec<_> = WalkDir::new(dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .filter(|e| e.path().extension().map_or(false, |ext| ext == "sol"))
        .collect();
    
    if sol_files.is_empty() {
        println!("{}", "⚠️ No .sol files found in directory".yellow());
        return;
    }
    
    println!("{} {} Solidity files found", "✅".green(), sol_files.len());
    
    // Display project structure
    println!("\n{}", "📂 Project Structure:".bright_cyan().bold());
    for entry in &sol_files {
        let relative_path = entry.path().strip_prefix(dir).unwrap_or(entry.path());
        println!("  └─ {}", relative_path.display());
    }
    println!();
    
    // Scan all files
    for entry in sol_files {
        let path = entry.path().to_path_buf();
        scan_file(scanner, reporter, &path);
    }
}
