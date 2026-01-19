use std::path::PathBuf;
use std::collections::HashMap;
use colored::*;

use crate::vulnerabilities::{Vulnerability, VulnerabilitySeverity, VulnerabilityConfidence};

pub struct VulnerabilityReporter {
    format: String,
    results: HashMap<PathBuf, Vec<Vulnerability>>,
}

impl VulnerabilityReporter {
    pub fn new(format: &str) -> Self {
        Self {
            format: format.to_string(),
            results: HashMap::new(),
        }
    }
    
    pub fn generate_clean_report(&self, file_path: &PathBuf, vulnerabilities: &[Vulnerability]) {
        if vulnerabilities.is_empty() {
            println!("No vulnerabilities found in {}", file_path.display());
            return;
        }
        
        println!("# Smart Contract Vulnerability Report");
        println!();
        println!("**File**: `{}`", file_path.display());
        println!("**Total Vulnerabilities**: {}", vulnerabilities.len());
        println!("**Analysis Date**: {}", chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC"));
        println!();
        
        // Group by severity
        let mut critical = Vec::new();
        let mut high = Vec::new();
        let mut medium = Vec::new();
        let mut low = Vec::new();
        let mut info = Vec::new();
        
        for vuln in vulnerabilities {
            match vuln.severity {
                VulnerabilitySeverity::Critical => critical.push(vuln),
                VulnerabilitySeverity::High => high.push(vuln),
                VulnerabilitySeverity::Medium => medium.push(vuln),
                VulnerabilitySeverity::Low => low.push(vuln),
                VulnerabilitySeverity::Info => info.push(vuln),
            }
        }
        
        // Print summary
        println!("## Vulnerability Summary");
        println!();
        println!("| Severity | Count |");
        println!("|----------|-------|");
        if !critical.is_empty() { println!("| **Critical** | {} |", critical.len()); }
        if !high.is_empty() { println!("| **High** | {} |", high.len()); }
        if !medium.is_empty() { println!("| **Medium** | {} |", medium.len()); }
        if !low.is_empty() { println!("| **Low** | {} |", low.len()); }
        if !info.is_empty() { println!("| **Info** | {} |", info.len()); }
        println!();
        
        // Print vulnerabilities by severity
        if !critical.is_empty() {
            self.print_severity_section("Critical Vulnerabilities", &critical, "🔴");
        }
        if !high.is_empty() {
            self.print_severity_section("High Severity Vulnerabilities", &high, "🟠");
        }
        if !medium.is_empty() {
            self.print_severity_section("Medium Severity Vulnerabilities", &medium, "🟡");
        }
        if !low.is_empty() {
            self.print_severity_section("Low Severity Vulnerabilities", &low, "🟢");
        }
        if !info.is_empty() {
            self.print_severity_section("Informational", &info, "🔵");
        }
    }
    
    fn print_severity_section(&self, title: &str, vulnerabilities: &[&Vulnerability], emoji: &str) {
        println!("## {} {}", emoji, title);
        println!();
        
        for (index, vuln) in vulnerabilities.iter().enumerate() {
            println!("### {}.{} {} (Line {})", 
                emoji, 
                index + 1, 
                vuln.title, 
                vuln.line_number
            );
            println!();
            println!("**Category**: {}", vuln.category.as_str());
            println!();
            println!("**Description**: {}", vuln.description);
            println!();
            println!("**Code Location**:");
            println!("```solidity");
            println!("{}", vuln.code_snippet);
            println!("```");
            println!();
            println!("**Recommendation**: {}", vuln.recommendation);
            println!();
            println!("---");
            println!();
        }
    }
    
    pub fn add_file_results(&mut self, file_path: &PathBuf, vulnerabilities: Vec<Vulnerability>) {
        // Print results immediately for better user experience
        if !vulnerabilities.is_empty() {
            match self.format.as_str() {
                "json" => self.print_json_results(file_path, &vulnerabilities),
                _ => self.print_text_results(file_path, &vulnerabilities),
            }
        } else {
            println!("{} No vulnerabilities found in {}", 
                "✅".green(), 
                file_path.display()
            );
        }
        
        self.results.insert(file_path.clone(), vulnerabilities);
    }
    
    fn print_text_results(&self, file_path: &PathBuf, vulnerabilities: &[Vulnerability]) {
        println!("\n{} {} (Line-by-line Analysis)",
            "🔍 SCAN RESULTS FOR".bold().bright_blue(),
            file_path.display().to_string().bright_white().bold()
        );
        println!("{}", "━".repeat(80).bright_blue());

        let mut current_category = None;

        for vuln in vulnerabilities {
            // Print category header if it's a new category
            if current_category.as_ref() != Some(&vuln.category) {
                println!("\n{} {}",
                    "📋".bright_yellow(),
                    vuln.category.as_str().bright_yellow().bold()
                );
                current_category = Some(vuln.category.clone());
            }

            // Format location string with line range if applicable
            let location = if let Some(end_line) = vuln.end_line_number {
                if end_line > vuln.line_number {
                    format!("Lines {}-{}", vuln.line_number, end_line)
                } else {
                    format!("Line {}", vuln.line_number)
                }
            } else {
                format!("Line {}", vuln.line_number)
            };

            // Print vulnerability details with confidence indicator
            let confidence_icon = match vuln.confidence {
                VulnerabilityConfidence::High => "●",
                VulnerabilityConfidence::Medium => "◐",
                VulnerabilityConfidence::Low => "○",
            };

            println!("\n  {} {} {} [{}]",
                self.get_severity_icon(&vuln.severity),
                confidence_icon.bright_white(),
                vuln.title.color(vuln.severity.color()).bold(),
                location.bright_white().bold()
            );

            println!("     {}: {}",
                "Description".bright_cyan().bold(),
                vuln.description
            );

            // Print context if available
            if let Some(ref context_before) = vuln.context_before {
                println!("     {}:", "Context".bright_blue().bold());
                for (i, line) in context_before.lines().enumerate() {
                    let line_num = vuln.line_number.saturating_sub(context_before.lines().count() - i);
                    println!("       {} │ {}",
                        format!("{:>4}", line_num).dimmed(),
                        line.dimmed()
                    );
                }
            }

            // Print the vulnerable code with line number
            println!("     {}:", "Vulnerable Code".bright_magenta().bold());
            println!("       {} │ {}",
                format!("{:>4}", vuln.line_number).bright_red(),
                vuln.code_snippet.bright_white().bold()
            );

            // Print context after if available
            if let Some(ref context_after) = vuln.context_after {
                for (i, line) in context_after.lines().enumerate() {
                    let line_num = vuln.line_number + 1 + i;
                    println!("       {} │ {}",
                        format!("{:>4}", line_num).dimmed(),
                        line.dimmed()
                    );
                }
            }

            println!("     {}: {}",
                "Recommendation".bright_green().bold(),
                vuln.recommendation
            );

            println!("     {}: {} | {}: {}",
                "Severity".bright_red().bold(),
                vuln.severity.as_str().color(vuln.severity.color()).bold(),
                "Confidence".bright_yellow().bold(),
                self.get_confidence_str(&vuln.confidence)
            );
        }

        println!("\n{}", "━".repeat(80).bright_blue());
    }

    fn get_confidence_str(&self, confidence: &VulnerabilityConfidence) -> ColoredString {
        match confidence {
            VulnerabilityConfidence::High => "High".bright_red().bold(),
            VulnerabilityConfidence::Medium => "Medium".bright_yellow(),
            VulnerabilityConfidence::Low => "Low".dimmed(),
        }
    }
    
    fn print_json_results(&self, file_path: &PathBuf, vulnerabilities: &[Vulnerability]) {
        let json_output = serde_json::json!({
            "file": file_path.to_string_lossy(),
            "vulnerabilities": vulnerabilities,
            "total_count": vulnerabilities.len()
        });
        
        println!("{}", serde_json::to_string_pretty(&json_output).unwrap());
    }
    
    pub fn print_summary(&self) {
        let total_files = self.results.len();
        let total_vulnerabilities: usize = self.results.values().map(|v| v.len()).sum();
        
        if self.format == "json" {
            let summary = serde_json::json!({
                "summary": {
                    "total_files_scanned": total_files,
                    "total_vulnerabilities": total_vulnerabilities,
                    "severity_breakdown": self.get_severity_breakdown(),
                    "category_breakdown": self.get_category_breakdown()
                }
            });
            println!("\n{}", serde_json::to_string_pretty(&summary).unwrap());
            return;
        }
        
        // Text format summary
        println!("\n{}", "📊 VULNERABILITY SCAN SUMMARY".bright_blue().bold());
        println!("{}", "━".repeat(50).bright_blue());
        
        println!("📁 Files scanned: {}", total_files.to_string().bright_white().bold());
        println!("🔍 Total issues found: {}", 
            if total_vulnerabilities > 0 {
                total_vulnerabilities.to_string().bright_red().bold()
            } else {
                total_vulnerabilities.to_string().bright_green().bold()
            }
        );
        
        if total_vulnerabilities > 0 {
            println!("\n{}", "🎯 SEVERITY BREAKDOWN".bright_yellow().bold());
            let severity_counts = self.get_severity_breakdown();
            for (severity, count) in [
                (VulnerabilitySeverity::Critical, severity_counts.get("CRITICAL").unwrap_or(&0)),
                (VulnerabilitySeverity::High, severity_counts.get("HIGH").unwrap_or(&0)),
                (VulnerabilitySeverity::Medium, severity_counts.get("MEDIUM").unwrap_or(&0)),
                (VulnerabilitySeverity::Low, severity_counts.get("LOW").unwrap_or(&0)),
                (VulnerabilitySeverity::Info, severity_counts.get("INFO").unwrap_or(&0)),
            ] {
                if *count > 0 {
                    println!("  {} {}: {}", 
                        self.get_severity_icon(&severity),
                        severity.as_str().color(severity.color()).bold(),
                        count.to_string().bright_white().bold()
                    );
                }
            }
            
            println!("\n{}", "📂 CATEGORY BREAKDOWN".bright_cyan().bold());
            let mut categories: Vec<_> = self.get_category_breakdown().into_iter().collect();
            categories.sort_by(|a, b| b.1.cmp(&a.1)); // Sort by count descending
            
            for (category, count) in categories.iter().take(10) { // Show top 10 categories
                if *count > 0 {
                    println!("  • {}: {}", 
                        category.bright_white(), 
                        count.to_string().bright_yellow().bold()
                    );
                }
            }
        }
        
        println!("\n{}", "━".repeat(50).bright_blue());
        
        if total_vulnerabilities > 0 {
            println!("⚠️  {}", "Review the issues above and follow the recommendations to improve your smart contract security.".bright_yellow());
        } else {
            println!("✅ {}", "Great! No obvious vulnerabilities detected in the scanned contracts.".bright_green());
        }
        
        println!("{}", "🔒 Remember: This tool provides basic vulnerability detection. Consider professional audits for production contracts.".bright_blue());
    }
    
    fn get_severity_breakdown(&self) -> HashMap<String, usize> {
        let mut breakdown = HashMap::new();
        
        for vulnerabilities in self.results.values() {
            for vuln in vulnerabilities {
                *breakdown.entry(vuln.severity.as_str().to_string()).or_insert(0) += 1;
            }
        }
        
        breakdown
    }
    
    fn get_category_breakdown(&self) -> HashMap<String, usize> {
        let mut breakdown = HashMap::new();
        
        for vulnerabilities in self.results.values() {
            for vuln in vulnerabilities {
                *breakdown.entry(vuln.category.as_str().to_string()).or_insert(0) += 1;
            }
        }
        
        breakdown
    }
    
    fn get_severity_icon(&self, severity: &VulnerabilitySeverity) -> &str {
        match severity {
            VulnerabilitySeverity::Critical => "🚨",
            VulnerabilitySeverity::High => "⚠️ ",
            VulnerabilitySeverity::Medium => "⚡",
            VulnerabilitySeverity::Low => "💡",
            VulnerabilitySeverity::Info => "ℹ️ ",
        }
    }
    
}