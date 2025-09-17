use std::path::{Path, PathBuf};
use std::collections::HashMap;
use walkdir::WalkDir;
use crate::scanner::ContractScanner;
use crate::vulnerabilities::{Vulnerability, VulnerabilitySeverity};
use colored::*;

pub struct ProjectScanner {
    scanner: ContractScanner,
    project_path: PathBuf,
    contracts: HashMap<PathBuf, ContractInfo>,
    dependencies: HashMap<String, Vec<String>>,
    total_vulnerabilities: Vec<ProjectVulnerability>,
}

#[derive(Debug, Clone)]
pub struct ContractInfo {
    pub path: PathBuf,
    pub name: String,
    pub imports: Vec<String>,
    pub functions: Vec<String>,
    pub modifiers: Vec<String>,
    pub state_variables: Vec<String>,
    pub vulnerabilities: Vec<Vulnerability>,
}

#[derive(Debug, Clone)]
pub struct ProjectVulnerability {
    pub file_path: PathBuf,
    pub vulnerability: Vulnerability,
    pub cross_file_impact: Vec<PathBuf>,
}

#[derive(Debug, Clone)]
pub struct ProjectAnalysisResult {
    pub total_files: usize,
    pub total_contracts: usize,
    pub total_vulnerabilities: usize,
    pub critical_paths: Vec<CriticalPath>,
    pub dependency_graph: HashMap<String, Vec<String>>,
    pub vulnerability_hotspots: Vec<HotspotInfo>,
    pub risk_score: f64,
}

#[derive(Debug, Clone)]
pub struct CriticalPath {
    pub path: Vec<PathBuf>,
    pub severity: VulnerabilitySeverity,
    pub description: String,
}

#[derive(Debug, Clone)]
pub struct HotspotInfo {
    pub file: PathBuf,
    pub vulnerability_count: usize,
    pub severity_score: f64,
}

impl ProjectScanner {
    pub fn new(project_path: PathBuf, verbose: bool) -> Self {
        Self {
            scanner: ContractScanner::new(verbose),
            project_path,
            contracts: HashMap::new(),
            dependencies: HashMap::new(),
            total_vulnerabilities: Vec::new(),
        }
    }
    
    pub fn scan_project(&mut self) -> Result<ProjectAnalysisResult, std::io::Error> {
        println!("{}", "🔍 Starting Project-Wide Security Analysis".bright_blue().bold());
        println!("{}", "━".repeat(60).bright_blue());
        
        // Discover all Solidity files
        let sol_files = self.discover_solidity_files()?;
        
        if sol_files.is_empty() {
            println!("{}", "⚠️ No Solidity files found in project".yellow());
            return Ok(ProjectAnalysisResult {
                total_files: 0,
                total_contracts: 0,
                total_vulnerabilities: 0,
                critical_paths: Vec::new(),
                dependency_graph: HashMap::new(),
                vulnerability_hotspots: Vec::new(),
                risk_score: 0.0,
            });
        }
        
        println!("{} Found {} Solidity files", "✅".green(), sol_files.len());
        
        // Phase 1: Scan all files and extract information
        println!("\n{}", "📋 Phase 1: File Analysis".bright_cyan().bold());
        for file_path in &sol_files {
            self.analyze_file(file_path)?;
        }
        
        // Phase 2: Build dependency graph
        println!("\n{}", "📋 Phase 2: Dependency Analysis".bright_cyan().bold());
        self.build_dependency_graph();
        
        // Phase 3: Cross-file vulnerability analysis
        println!("\n{}", "📋 Phase 3: Cross-File Vulnerability Analysis".bright_cyan().bold());
        self.analyze_cross_file_vulnerabilities();
        
        // Phase 4: Identify critical paths and hotspots
        println!("\n{}", "📋 Phase 4: Risk Assessment".bright_cyan().bold());
        let critical_paths = self.identify_critical_paths();
        let hotspots = self.identify_vulnerability_hotspots();
        let risk_score = self.calculate_project_risk_score();
        
        // Generate analysis result
        Ok(ProjectAnalysisResult {
            total_files: sol_files.len(),
            total_contracts: self.contracts.len(),
            total_vulnerabilities: self.total_vulnerabilities.len(),
            critical_paths,
            dependency_graph: self.dependencies.clone(),
            vulnerability_hotspots: hotspots,
            risk_score,
        })
    }
    
    fn discover_solidity_files(&self) -> Result<Vec<PathBuf>, std::io::Error> {
        let mut files = Vec::new();
        
        for entry in WalkDir::new(&self.project_path)
            .follow_links(true)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            if entry.file_type().is_file() {
                if let Some(ext) = entry.path().extension() {
                    if ext == "sol" {
                        files.push(entry.path().to_path_buf());
                    }
                }
            }
        }
        
        files.sort();
        Ok(files)
    }
    
    fn analyze_file(&mut self, file_path: &Path) -> Result<(), std::io::Error> {
        let relative_path = file_path.strip_prefix(&self.project_path)
            .unwrap_or(file_path);
        
        println!("  📝 Analyzing: {}", relative_path.display());
        
        // Read file content
        let content = std::fs::read_to_string(file_path)?;
        
        // Extract contract information
        let contract_name = self.extract_contract_name(&content);
        let imports = self.extract_imports(&content);
        let functions = self.extract_functions(&content);
        let modifiers = self.extract_modifiers(&content);
        let state_variables = self.extract_state_variables(&content);
        
        // Scan for vulnerabilities
        let vulnerabilities = self.scanner.scan_file(file_path)?;
        
        // Store contract information
        let contract_info = ContractInfo {
            path: file_path.to_path_buf(),
            name: contract_name,
            imports,
            functions,
            modifiers,
            state_variables,
            vulnerabilities: vulnerabilities.clone(),
        };
        
        // Add vulnerabilities to project list
        for vuln in vulnerabilities {
            self.total_vulnerabilities.push(ProjectVulnerability {
                file_path: file_path.to_path_buf(),
                vulnerability: vuln,
                cross_file_impact: Vec::new(),
            });
        }
        
        self.contracts.insert(file_path.to_path_buf(), contract_info);
        Ok(())
    }
    
    fn extract_contract_name(&self, content: &str) -> String {
        for line in content.lines() {
            if line.contains("contract ") && !line.trim().starts_with("//") {
                if let Some(start) = line.find("contract ") {
                    let after_contract = &line[start + 9..];
                    if let Some(end) = after_contract.find(|c: char| !c.is_alphanumeric() && c != '_') {
                        return after_contract[..end].to_string();
                    }
                }
            }
        }
        "Unknown".to_string()
    }
    
    fn extract_imports(&self, content: &str) -> Vec<String> {
        let mut imports = Vec::new();
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("import ") {
                imports.push(trimmed.to_string());
            }
        }
        imports
    }
    
    fn extract_functions(&self, content: &str) -> Vec<String> {
        let mut functions = Vec::new();
        for line in content.lines() {
            if line.contains("function ") && !line.trim().starts_with("//") {
                if let Some(start) = line.find("function ") {
                    let after_function = &line[start + 9..];
                    if let Some(end) = after_function.find('(') {
                        let function_name = after_function[..end].trim();
                        if !function_name.is_empty() {
                            functions.push(function_name.to_string());
                        }
                    }
                }
            }
        }
        functions
    }
    
    fn extract_modifiers(&self, content: &str) -> Vec<String> {
        let mut modifiers = Vec::new();
        for line in content.lines() {
            if line.contains("modifier ") && !line.trim().starts_with("//") {
                if let Some(start) = line.find("modifier ") {
                    let after_modifier = &line[start + 9..];
                    if let Some(end) = after_modifier.find(|c: char| c == '(' || c == '{' || c.is_whitespace()) {
                        let modifier_name = after_modifier[..end].trim();
                        if !modifier_name.is_empty() {
                            modifiers.push(modifier_name.to_string());
                        }
                    }
                }
            }
        }
        modifiers
    }
    
    fn extract_state_variables(&self, content: &str) -> Vec<String> {
        let mut variables = Vec::new();
        let mut in_contract = false;
        let mut brace_count = 0;
        
        for line in content.lines() {
            let trimmed = line.trim();
            
            // Track when we're inside a contract
            if trimmed.contains("contract ") {
                in_contract = true;
            }
            
            if in_contract {
                brace_count += line.chars().filter(|&c| c == '{').count();
                brace_count = brace_count.saturating_sub(line.chars().filter(|&c| c == '}').count());
                
                if brace_count == 0 && line.contains('}') {
                    in_contract = false;
                }
                
                // Look for state variable declarations
                if brace_count == 1 && !trimmed.starts_with("//") && !trimmed.starts_with("function") && !trimmed.starts_with("modifier") {
                    if trimmed.contains("public") || trimmed.contains("private") || trimmed.contains("internal") {
                        variables.push(trimmed.to_string());
                    }
                }
            }
        }
        
        variables
    }
    
    fn build_dependency_graph(&mut self) {
        println!("  🔗 Building contract dependency graph...");
        
        for (_path, info) in &self.contracts {
            let mut deps = Vec::new();
            
            for import in &info.imports {
                // Extract imported contract names
                if let Some(contract_name) = self.extract_imported_contract(import) {
                    deps.push(contract_name);
                }
            }
            
            self.dependencies.insert(info.name.clone(), deps);
        }
        
        println!("  ✅ Dependency graph built with {} contracts", self.dependencies.len());
    }
    
    fn extract_imported_contract(&self, import_statement: &str) -> Option<String> {
        // Handle different import formats
        if import_statement.contains(" from ") {
            if let Some(start) = import_statement.find('{') {
                if let Some(end) = import_statement.find('}') {
                    let imports = &import_statement[start + 1..end];
                    // Return first imported item for simplicity
                    return imports.split(',').next().map(|s| s.trim().to_string());
                }
            }
        } else if import_statement.contains('"') || import_statement.contains("'") {
            // Extract filename from path
            let path = import_statement.split('"').nth(1)
                .or_else(|| import_statement.split('\'').nth(1));
            
            if let Some(path_str) = path {
                if let Some(filename) = Path::new(path_str).file_stem() {
                    return Some(filename.to_string_lossy().to_string());
                }
            }
        }
        None
    }
    
    fn analyze_cross_file_vulnerabilities(&mut self) {
        println!("  🔍 Analyzing cross-file vulnerability impacts...");
        
        let mut impact_count = 0;
        
        // Check for vulnerabilities that could affect other contracts
        for vuln in &mut self.total_vulnerabilities {
            let mut impacted_files = Vec::new();
            
            // Check which other contracts import this one
            if let Some(contract_info) = self.contracts.get(&vuln.file_path) {
                for (other_path, other_info) in &self.contracts {
                    if other_path != &vuln.file_path {
                        // Check if other contract imports this one
                        for import in &other_info.imports {
                            if import.contains(&contract_info.name) {
                                impacted_files.push(other_path.clone());
                                impact_count += 1;
                            }
                        }
                    }
                }
            }
            
            vuln.cross_file_impact = impacted_files;
        }
        
        println!("  ✅ Found {} cross-file vulnerability impacts", impact_count);
    }
    
    fn identify_critical_paths(&self) -> Vec<CriticalPath> {
        let mut critical_paths = Vec::new();
        
        // Find paths with high-severity vulnerabilities that affect multiple files
        for vuln in &self.total_vulnerabilities {
            if matches!(vuln.vulnerability.severity, VulnerabilitySeverity::Critical | VulnerabilitySeverity::High) {
                if !vuln.cross_file_impact.is_empty() {
                    let mut path = vec![vuln.file_path.clone()];
                    path.extend(vuln.cross_file_impact.clone());
                    
                    critical_paths.push(CriticalPath {
                        path,
                        severity: vuln.vulnerability.severity.clone(),
                        description: format!("{} - {}", 
                            vuln.vulnerability.title, 
                            vuln.vulnerability.description),
                    });
                }
            }
        }
        
        critical_paths
    }
    
    fn identify_vulnerability_hotspots(&self) -> Vec<HotspotInfo> {
        let mut hotspots = Vec::new();
        
        for (path, info) in &self.contracts {
            if !info.vulnerabilities.is_empty() {
                let severity_score = info.vulnerabilities.iter()
                    .map(|v| match v.severity {
                        VulnerabilitySeverity::Critical => 10.0,
                        VulnerabilitySeverity::High => 7.0,
                        VulnerabilitySeverity::Medium => 4.0,
                        VulnerabilitySeverity::Low => 2.0,
                        VulnerabilitySeverity::Info => 1.0,
                    })
                    .sum();
                
                hotspots.push(HotspotInfo {
                    file: path.clone(),
                    vulnerability_count: info.vulnerabilities.len(),
                    severity_score,
                });
            }
        }
        
        // Sort by severity score (descending)
        hotspots.sort_by(|a, b| b.severity_score.partial_cmp(&a.severity_score).unwrap());
        
        hotspots
    }
    
    fn calculate_project_risk_score(&self) -> f64 {
        if self.total_vulnerabilities.is_empty() {
            return 0.0;
        }
        
        let base_score: f64 = self.total_vulnerabilities.iter()
            .map(|v| match v.vulnerability.severity {
                VulnerabilitySeverity::Critical => 10.0,
                VulnerabilitySeverity::High => 7.0,
                VulnerabilitySeverity::Medium => 4.0,
                VulnerabilitySeverity::Low => 2.0,
                VulnerabilitySeverity::Info => 1.0,
            })
            .sum();
        
        // Add multiplier for cross-file impacts
        let impact_multiplier = 1.0 + (self.total_vulnerabilities.iter()
            .filter(|v| !v.cross_file_impact.is_empty())
            .count() as f64 * 0.1);
        
        // Normalize to 0-100 scale
        let risk_score = (base_score * impact_multiplier).min(100.0);
        
        risk_score
    }
    
    pub fn print_analysis_report(&self, result: &ProjectAnalysisResult) {
        println!("\n{}", "📊 PROJECT SECURITY ANALYSIS REPORT".bright_blue().bold());
        println!("{}", "━".repeat(60).bright_blue());
        
        // Overview
        println!("\n{}", "📋 Project Overview".bright_cyan().bold());
        println!("  Total Files Scanned: {}", result.total_files);
        println!("  Total Contracts: {}", result.total_contracts);
        println!("  Total Vulnerabilities: {}", result.total_vulnerabilities);
        println!("  Project Risk Score: {:.1}/100", result.risk_score);
        
        // Risk Assessment
        println!("\n{}", "⚠️ Risk Assessment".bright_yellow().bold());
        let risk_level = match result.risk_score {
            score if score >= 75.0 => "CRITICAL".red().bold(),
            score if score >= 50.0 => "HIGH".bright_red().bold(),
            score if score >= 25.0 => "MEDIUM".yellow().bold(),
            score if score > 0.0 => "LOW".green().bold(),
            _ => "MINIMAL".bright_green().bold(),
        };
        println!("  Overall Risk Level: {}", risk_level);
        
        // Vulnerability Hotspots
        if !result.vulnerability_hotspots.is_empty() {
            println!("\n{}", "🔥 Vulnerability Hotspots".bright_red().bold());
            for (idx, hotspot) in result.vulnerability_hotspots.iter().take(5).enumerate() {
                let relative_path = hotspot.file.strip_prefix(&self.project_path)
                    .unwrap_or(&hotspot.file);
                println!("  {}. {} ({} issues, severity score: {:.1})",
                    idx + 1,
                    relative_path.display(),
                    hotspot.vulnerability_count,
                    hotspot.severity_score
                );
            }
        }
        
        // Critical Paths
        if !result.critical_paths.is_empty() {
            println!("\n{}", "🚨 Critical Vulnerability Paths".bright_red().bold());
            for (idx, path) in result.critical_paths.iter().take(3).enumerate() {
                println!("  Path {}:", idx + 1);
                println!("    Severity: {:?}", path.severity);
                println!("    Description: {}", path.description);
                println!("    Affected files:");
                for file in &path.path {
                    let relative_path = file.strip_prefix(&self.project_path)
                        .unwrap_or(file);
                    println!("      - {}", relative_path.display());
                }
            }
        }
        
        // Dependency Graph Summary
        if !result.dependency_graph.is_empty() {
            println!("\n{}", "🔗 Contract Dependencies".bright_cyan().bold());
            for (contract, deps) in result.dependency_graph.iter().take(5) {
                if !deps.is_empty() {
                    println!("  {} depends on: {:?}", contract, deps);
                }
            }
        }
        
        println!("\n{}", "━".repeat(60).bright_blue());
        println!("{}", "✅ Analysis Complete".bright_green().bold());
    }
}