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

    /// Add results without printing to stdout.
    /// Used when output format is JSON/SARIF but we still need results for markdown report generation.
    pub fn add_file_results_silent(&mut self, file_path: &PathBuf, vulnerabilities: Vec<Vulnerability>) {
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

    /// Generate a full markdown report as a String for saving to a file.
    /// Includes title, scan metadata, severity summary table, per-file findings
    /// with code snippets, and a category breakdown.
    pub fn generate_markdown_report(&self) -> String {
        let mut report = String::new();
        let total_files = self.results.len();
        let total_vulnerabilities: usize = self.results.values().map(|v| v.len()).sum();
        let now = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC");

        // Header
        report.push_str("# 41Swara Smart Contract Security Report\n\n");
        report.push_str(&format!("**Scanner Version**: 0.6.0\n"));
        report.push_str(&format!("**Analysis Date**: {}\n", now));
        report.push_str(&format!("**Files Scanned**: {}\n", total_files));
        report.push_str(&format!("**Total Vulnerabilities**: {}\n\n", total_vulnerabilities));

        if total_vulnerabilities == 0 {
            report.push_str("No vulnerabilities detected. The scanned contracts passed all checks.\n\n");
            report.push_str("> **Note**: This is an automated scan. Consider a professional audit for production contracts.\n");
            return report;
        }

        // Severity summary table
        let severity_counts = self.get_severity_breakdown();
        report.push_str("## Severity Summary\n\n");
        report.push_str("| Severity | Count |\n");
        report.push_str("|----------|-------|\n");
        for (label, key) in [
            ("🚨 Critical", "CRITICAL"),
            ("⚠️  High", "HIGH"),
            ("⚡ Medium", "MEDIUM"),
            ("💡 Low", "LOW"),
            ("ℹ️  Info", "INFO"),
        ] {
            let count = severity_counts.get(key).unwrap_or(&0);
            if *count > 0 {
                report.push_str(&format!("| **{}** | {} |\n", label, count));
            }
        }
        report.push('\n');

        // Category breakdown
        let mut categories: Vec<_> = self.get_category_breakdown().into_iter().collect();
        categories.sort_by(|a, b| b.1.cmp(&a.1));
        if !categories.is_empty() {
            report.push_str("## Category Breakdown\n\n");
            report.push_str("| Category | Count |\n");
            report.push_str("|----------|-------|\n");
            for (category, count) in &categories {
                report.push_str(&format!("| {} | {} |\n", category, count));
            }
            report.push('\n');
        }

        // Per-file detailed findings
        report.push_str("---\n\n");
        report.push_str("## Detailed Findings\n\n");

        // Sort files for deterministic output
        let mut sorted_files: Vec<_> = self.results.iter().collect();
        sorted_files.sort_by_key(|(path, _)| (*path).clone());

        for (file_path, vulnerabilities) in &sorted_files {
            if vulnerabilities.is_empty() {
                continue;
            }

            report.push_str(&format!("### {}\n\n", file_path.display()));

            // Group vulnerabilities by severity for this file
            let mut by_severity: Vec<(&str, Vec<&Vulnerability>)> = Vec::new();
            for (label, severity) in [
                ("🚨 Critical", VulnerabilitySeverity::Critical),
                ("⚠️  High", VulnerabilitySeverity::High),
                ("⚡ Medium", VulnerabilitySeverity::Medium),
                ("💡 Low", VulnerabilitySeverity::Low),
                ("ℹ️  Info", VulnerabilitySeverity::Info),
            ] {
                let matching: Vec<&Vulnerability> = vulnerabilities.iter()
                    .filter(|v| v.severity == severity)
                    .collect();
                if !matching.is_empty() {
                    by_severity.push((label, matching));
                }
            }

            for (severity_label, vulns) in by_severity {
                report.push_str(&format!("#### {} ({})\n\n", severity_label, vulns.len()));

                for (i, vuln) in vulns.iter().enumerate() {
                    let location = if let Some(end_line) = vuln.end_line_number {
                        if end_line > vuln.line_number {
                            format!("Lines {}-{}", vuln.line_number, end_line)
                        } else {
                            format!("Line {}", vuln.line_number)
                        }
                    } else {
                        format!("Line {}", vuln.line_number)
                    };

                    let confidence_str = match vuln.confidence {
                        VulnerabilityConfidence::High => "High",
                        VulnerabilityConfidence::Medium => "Medium",
                        VulnerabilityConfidence::Low => "Low",
                    };

                    report.push_str(&format!("**{}.** {} — `{}`\n\n", i + 1, vuln.title, location));
                    report.push_str(&format!("- **Category**: {}\n", vuln.category.as_str()));
                    report.push_str(&format!("- **Confidence**: {} ({}%)\n", confidence_str, vuln.confidence_percent));
                    if let Some(ref swc) = vuln.swc_id {
                        report.push_str(&format!("- **SWC**: {}", swc.id));
                        if let Some(ref cwe) = swc.cwe_id {
                            report.push_str(&format!(" | **CWE**: {}", cwe));
                        }
                        report.push('\n');
                    }
                    report.push_str(&format!("- **Description**: {}\n", vuln.description));
                    report.push_str(&format!("\n```solidity\n{}\n```\n\n", vuln.code_snippet));
                    report.push_str(&format!("**Recommendation**: {}\n\n", vuln.recommendation));
                    report.push_str("---\n\n");
                }
            }
        }

        // Footer
        report.push_str("## Disclaimer\n\n");
        report.push_str("This report was generated by **41Swara Smart Contract Scanner v0.6.0**. ");
        report.push_str("Automated scanning provides broad coverage but may produce false positives or miss complex vulnerabilities. ");
        report.push_str("A professional manual audit is recommended for production contracts.\n");

        report
    }
}