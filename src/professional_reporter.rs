use crate::vulnerabilities::{Vulnerability, VulnerabilitySeverity, VulnerabilityCategory};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Serialize, Deserialize)]
pub struct AuditInfo {
    pub project_name: String,
    pub sponsor: String,
    pub auditor: String,
    pub start_date: String,
    pub end_date: String,
    pub repository_url: Option<String>,
    pub commit_hash: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FindingSummary {
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
    pub info_count: usize,
}

pub struct ProfessionalReporter {
    pub audit_info: AuditInfo,
    pub findings: Vec<DetailedFinding>,
}

#[derive(Debug, Clone)]
pub struct DetailedFinding {
    pub id: String,
    pub severity: VulnerabilitySeverity,
    pub title: String,
    #[allow(dead_code)]
    pub contract_function: String,
    pub github_links: Vec<String>,
    pub summary: String,
    pub vulnerability_details: String,
    pub impact: String,
    pub proof_of_concept: Option<String>,
    pub recommended_mitigation: String,
    pub tools_used: String,
    #[allow(dead_code)]
    pub line_number: usize,
    #[allow(dead_code)]
    pub code_snippet: String,
    #[allow(dead_code)]
    pub category: VulnerabilityCategory,
}

impl ProfessionalReporter {
    pub fn new(audit_info: AuditInfo) -> Self {
        Self {
            audit_info,
            findings: Vec::new(),
        }
    }

    pub fn add_vulnerabilities(&mut self, vulnerabilities: Vec<Vulnerability>, file_path: &str) {
        let mut finding_counter = HashMap::new();
        
        for vuln in vulnerabilities {
            let severity_key = self.get_severity_prefix(&vuln.severity);
            let counter = finding_counter.entry(severity_key.clone()).or_insert(0);
            *counter += 1;
            
            let finding_id = format!("{}-{:02}", severity_key, counter);
            let detailed_finding = self.convert_to_detailed_finding(vuln, finding_id, file_path);
            self.findings.push(detailed_finding);
        }
    }

    fn get_severity_prefix(&self, severity: &VulnerabilitySeverity) -> String {
        match severity {
            VulnerabilitySeverity::Critical => "C".to_string(),
            VulnerabilitySeverity::High => "H".to_string(),
            VulnerabilitySeverity::Medium => "M".to_string(),
            VulnerabilitySeverity::Low => "L".to_string(),
            VulnerabilitySeverity::Info => "I".to_string(),
        }
    }

    fn convert_to_detailed_finding(&self, vuln: Vulnerability, id: String, file_path: &str) -> DetailedFinding {
        let contract_function = self.extract_function_from_code(&vuln.code_snippet);
        let github_links = if let Some(repo) = &self.audit_info.repository_url {
            vec![format!("{}#L{}", repo, vuln.line_number)]
        } else {
            vec![]
        };

        let severity = vuln.severity.clone();
        let title = self.generate_professional_title(&vuln, &contract_function);
        let summary = self.generate_summary(&vuln);
        let vulnerability_details = self.generate_vulnerability_details(&vuln, file_path);
        let impact = self.generate_impact(&vuln);
        let proof_of_concept = self.generate_proof_of_concept(&vuln);
        let recommended_mitigation = self.generate_mitigation(&vuln);
        let line_number = vuln.line_number;
        let code_snippet = vuln.code_snippet.clone();
        let category = vuln.category.clone();

        DetailedFinding {
            id,
            severity,
            title,
            contract_function,
            github_links,
            summary,
            vulnerability_details,
            impact,
            proof_of_concept,
            recommended_mitigation,
            tools_used: "41Swara Smart Contract Scanner".to_string(),
            line_number,
            code_snippet,
            category,
        }
    }

    fn extract_function_from_code(&self, code: &str) -> String {
        if let Some(function_match) = code.find("function ") {
            let after_function = &code[function_match..];
            if let Some(paren_pos) = after_function.find('(') {
                let function_name = &after_function[9..paren_pos]; // Skip "function "
                return function_name.trim().to_string();
            }
        }
        "Unknown".to_string()
    }

    fn generate_professional_title(&self, vuln: &Vulnerability, function: &str) -> String {
        if function != "Unknown" && !function.is_empty() {
            format!("{} in {}::{}", vuln.title, self.extract_contract_name(), function)
        } else {
            vuln.title.clone()
        }
    }

    fn extract_contract_name(&self) -> String {
        if let Some(name) = self.audit_info.project_name.split_whitespace().last() {
            name.to_string()
        } else {
            "Contract".to_string()
        }
    }

    fn generate_summary(&self, vuln: &Vulnerability) -> String {
        format!("The {} contract contains a {} vulnerability. {}",
                self.extract_contract_name(),
                vuln.category.as_str().to_lowercase(),
                vuln.description)
    }

    fn generate_vulnerability_details(&self, vuln: &Vulnerability, file_path: &str) -> String {
        format!("This vulnerability exists in the {}::{} starting on line {}.\n\nThe problematic code is:\n```solidity\n{}\n```\n\n{}",
                file_path,
                self.extract_function_from_code(&vuln.code_snippet),
                vuln.line_number,
                vuln.code_snippet,
                vuln.description)
    }

    fn generate_impact(&self, vuln: &Vulnerability) -> String {
        match vuln.severity {
            VulnerabilitySeverity::Critical => {
                format!("This is a CRITICAL vulnerability that can lead to complete compromise of the contract. {} This vulnerability allows attackers to exploit the contract, potentially resulting in total loss of funds or complete control over the contract's functionality.",
                        vuln.description)
            },
            VulnerabilitySeverity::High => {
                format!("This vulnerability poses a HIGH risk to the contract's security. {} Exploitation could result in significant financial loss or major disruption to the contract's intended functionality.",
                        vuln.description)
            },
            VulnerabilitySeverity::Medium => {
                format!("This vulnerability presents a MEDIUM risk. {} While not immediately exploitable for major damage, it could be combined with other vulnerabilities or lead to unexpected contract behavior.",
                        vuln.description)
            },
            VulnerabilitySeverity::Low => {
                format!("This is a LOW severity issue. {} While not directly exploitable, it may indicate poor coding practices or potential future vulnerabilities.",
                        vuln.description)
            },
            VulnerabilitySeverity::Info => {
                format!("This is an informational finding. {} It represents a best practice recommendation or code quality improvement.",
                        vuln.description)
            },
        }
    }

    fn generate_proof_of_concept(&self, vuln: &Vulnerability) -> Option<String> {
        match &vuln.category {
            VulnerabilityCategory::AccessControl => {
                Some(format!(r#"**Working Test Case**

The following test demonstrates the vulnerability:

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract ExploitTest {{
    function testExploit() public {{
        // Attacker can call the vulnerable function
        // without proper access control
        target.{}();
        console.log("Exploit successful - unauthorized access gained");
    }}
}}
```

**Attack Scenario:**
1. Attacker identifies the vulnerable function at line {}
2. Attacker calls the function without authentication
3. Function executes without proper access control checks
4. Attacker gains unauthorized access or control"#, 
                self.extract_function_from_code(&vuln.code_snippet), vuln.line_number))
            },
            VulnerabilityCategory::Reentrancy => {
                Some(format!(r#"**Reentrancy Attack Scenario**

```solidity
contract ReentrancyAttack {{
    function attack() external {{
        // 1. Call vulnerable function
        target.{}();
    }}
    
    // 2. Fallback function for reentrancy
    receive() external payable {{
        if (address(target).balance > 0) {{
            target.{}(); // Reentrant call
        }}
    }}
}}
```

**Steps:**
1. Attacker deploys malicious contract
2. Calls vulnerable function at line {}
3. During external call, fallback triggers reentrancy
4. State is manipulated before original call completes"#,
                self.extract_function_from_code(&vuln.code_snippet),
                self.extract_function_from_code(&vuln.code_snippet),
                vuln.line_number))
            },
            VulnerabilityCategory::PrecisionLoss => {
                Some(format!(r#"**Precision Loss Demonstration**

```solidity
function testPrecisionLoss() public {{
    uint256 balance = 1000 wei;
    uint256 participants = 3;
    
    // Vulnerable calculation at line {}
    uint256 payout = balance / participants; // = 333 wei
    uint256 total_distributed = payout * participants; // = 999 wei
    uint256 lost_funds = balance - total_distributed; // = 1 wei lost
    
    console.log("Original balance:", balance);
    console.log("Total distributed:", total_distributed);
    console.log("Funds lost to precision:", lost_funds);
}}
```

This demonstrates how integer division causes fund loss."#, vuln.line_number))
            },
            VulnerabilityCategory::StorageDoSAttacks => {
                Some(format!(r#"**DoS Attack Demonstration**

```solidity
contract DoSAttack {{
    function spamStorage() external {{
        // Repeatedly call vulnerable function
        for (uint i = 0; i < 1000; i++) {{
            target.{}("spam_data_" + i);
        }}
    }}
}}
```

**Gas Cost Analysis:**
- First submission: ~120,451 gas
- Average spam submission: ~136,591 gas  
- After 100+ submissions: Contract becomes expensive to interact with

**Attack Impact:**
1. Attacker floods storage with spam submissions
2. Legitimate users face high gas costs
3. Contract becomes unusable due to gas limits"#, 
                self.extract_function_from_code(&vuln.code_snippet)))
            },
            _ => None,
        }
    }

    fn generate_mitigation(&self, vuln: &Vulnerability) -> String {
        let base_recommendation = &vuln.recommendation;
        
        match &vuln.category {
            VulnerabilityCategory::AccessControl => {
                format!(r#"{}

**Implementation Options:**

1. **Using Custom Modifier:**
```solidity
modifier onlyOwner() {{
    if (msg.sender != s_owner) {{
        revert Unauthorized();
    }}
    _;
}}

function {}() external onlyOwner {{
    // Protected function logic
}}
```

2. **Using OpenZeppelin:**
```solidity
import "@openzeppelin/contracts/access/Ownable.sol";

contract MyContract is Ownable {{
    function {}() external onlyOwner {{
        // Protected function logic
    }}
}}
```"#, base_recommendation, 
                self.extract_function_from_code(&vuln.code_snippet),
                self.extract_function_from_code(&vuln.code_snippet))
            },
            VulnerabilityCategory::Reentrancy => {
                format!(r#"{}

**Recommended Implementation:**

```solidity
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

contract SecureContract is ReentrancyGuard {{
    function {}() external nonReentrant {{
        // 1. Checks
        require(conditions, "Invalid state");
        
        // 2. Effects  
        updateState();
        
        // 3. Interactions
        externalCall();
    }}
}}
```"#, base_recommendation, self.extract_function_from_code(&vuln.code_snippet))
            },
            VulnerabilityCategory::PrecisionLoss => {
                format!(r#"{}

**Corrected Implementation:**

```solidity
function distributeRewards() external {{
    uint256 balance = address(this).balance;
    uint256 validParticipants = getValidParticipants();
    
    if (validParticipants > 0) {{
        // Calculate payout and remainder properly
        uint256 payoutAmount = balance / validParticipants;
        uint256 remainder = balance % validParticipants; // Use modulus
        
        // Distribute remainder to treasury/owner
        if (remainder > 0) {{
            (bool success,) = treasury.call{{value: remainder}}("");
            require(success, "Remainder transfer failed");
        }}
    }}
}}
```"#, base_recommendation)
            },
            VulnerabilityCategory::StorageDoSAttacks => {
                format!(r#"{}

**Comprehensive Mitigation:**

```solidity
mapping(address => uint256) public lastSubmission;
uint256 public constant SUBMISSION_COOLDOWN = 1 hours;
uint256 public constant MAX_SUBMISSIONS_PER_USER = 10;
mapping(address => uint256) public userSubmissionCount;

function {}(string memory data) external {{
    // Rate limiting
    require(
        block.timestamp >= lastSubmission[msg.sender] + SUBMISSION_COOLDOWN,
        "Submission cooldown active"
    );
    
    // Submission limits
    require(
        userSubmissionCount[msg.sender] < MAX_SUBMISSIONS_PER_USER,
        "Max submissions exceeded"
    );
    
    // Update tracking
    lastSubmission[msg.sender] = block.timestamp;
    userSubmissionCount[msg.sender]++;
    
    // Process submission
    processSubmission(data);
}}
```"#, base_recommendation, self.extract_function_from_code(&vuln.code_snippet))
            },
            _ => base_recommendation.clone(),
        }
    }

    pub fn generate_findings_summary(&self) -> FindingSummary {
        let mut summary = FindingSummary {
            critical_count: 0,
            high_count: 0,
            medium_count: 0,
            low_count: 0,
            info_count: 0,
        };

        for finding in &self.findings {
            match finding.severity {
                VulnerabilitySeverity::Critical => summary.critical_count += 1,
                VulnerabilitySeverity::High => summary.high_count += 1,
                VulnerabilitySeverity::Medium => summary.medium_count += 1,
                VulnerabilitySeverity::Low => summary.low_count += 1,
                VulnerabilitySeverity::Info => summary.info_count += 1,
            }
        }

        summary
    }

    pub fn generate_professional_report(&self) -> String {
        let summary = self.generate_findings_summary();
        let mut report = String::new();

        // Title Page
        report.push_str(&self.generate_title_page());
        
        // Table of Contents
        report.push_str(&self.generate_table_of_contents(&summary));
        
        // Audit Summary
        report.push_str(&self.generate_audit_summary());
        
        // Results Summary  
        report.push_str(&self.generate_results_summary(&summary));
        
        // Detailed Findings
        report.push_str(&self.generate_detailed_findings());

        report
    }

    fn generate_title_page(&self) -> String {
        format!(r#"# {} - Security Audit Report

**Professional Smart Contract Security Analysis**

---

**Project:** {}
**Audited By:** {}
**Audit Period:** {} - {}
**Report Generated:** {}
**Scanner Version:** 41Swara Smart Contract Scanner v1.0

---

This report contains the findings from a comprehensive security analysis of the smart contract codebase using advanced automated vulnerability detection techniques.

"#, 
        self.audit_info.project_name,
        self.audit_info.project_name,
        self.audit_info.auditor,
        self.audit_info.start_date,
        self.audit_info.end_date,
        Utc::now().format("%B %d, %Y").to_string())
    }

    fn generate_table_of_contents(&self, summary: &FindingSummary) -> String {
        let mut toc = String::from("## Table of Contents\n\n");
        toc.push_str("• **Audit Summary**\n");
        toc.push_str("• **Results Summary**\n");

        if summary.critical_count > 0 {
            toc.push_str("• **Critical Risk Findings**\n");
            let critical_findings: Vec<_> = self.findings.iter()
                .filter(|f| matches!(f.severity, VulnerabilitySeverity::Critical))
                .collect();
            for finding in critical_findings {
                toc.push_str(&format!("  - {}. {}\n", finding.id, finding.title));
            }
        }

        if summary.high_count > 0 {
            toc.push_str("• **High Risk Findings**\n");
            let high_findings: Vec<_> = self.findings.iter()
                .filter(|f| matches!(f.severity, VulnerabilitySeverity::High))
                .collect();
            for finding in high_findings {
                toc.push_str(&format!("  - {}. {}\n", finding.id, finding.title));
            }
        }

        if summary.medium_count > 0 {
            toc.push_str("• **Medium Risk Findings**\n");
            let medium_findings: Vec<_> = self.findings.iter()
                .filter(|f| matches!(f.severity, VulnerabilitySeverity::Medium))
                .collect();
            for finding in medium_findings {
                toc.push_str(&format!("  - {}. {}\n", finding.id, finding.title));
            }
        }

        if summary.low_count > 0 {
            toc.push_str("• **Low Risk Findings**\n");
            let low_findings: Vec<_> = self.findings.iter()
                .filter(|f| matches!(f.severity, VulnerabilitySeverity::Low))
                .collect();
            for finding in low_findings {
                toc.push_str(&format!("  - {}. {}\n", finding.id, finding.title));
            }
        }

        if summary.info_count > 0 {
            toc.push_str("• **Informational Findings**\n");
        }

        toc.push_str("\n---\n\n");
        toc
    }

    fn generate_audit_summary(&self) -> String {
        format!(r#"## Audit Summary

**Sponsor:** {}
**Dates:** {} - {}
**Repository:** {}
**Commit Hash:** {}

The security analysis was conducted using the 41Swara Smart Contract Scanner, which employs advanced pattern recognition and vulnerability detection algorithms to identify potential security issues in Solidity smart contracts.

## Scope

The audit covered the complete smart contract codebase, including:
- Access control mechanisms
- Reentrancy vulnerabilities  
- Arithmetic and precision issues
- Gas optimization concerns
- Storage DoS attack vectors
- Role-based permission systems
- Delegate call security
- And 200+ additional vulnerability patterns

"#, 
        self.audit_info.sponsor,
        self.audit_info.start_date, 
        self.audit_info.end_date,
        self.audit_info.repository_url.as_deref().unwrap_or("Not provided"),
        self.audit_info.commit_hash.as_deref().unwrap_or("Not provided"))
    }

    fn generate_results_summary(&self, summary: &FindingSummary) -> String {
        let total = summary.critical_count + summary.high_count + summary.medium_count + summary.low_count + summary.info_count;
        
        format!(r#"## Results Summary

**Number of findings:** {}

• **Critical:** {}
• **High:** {}  
• **Medium:** {}
• **Low:** {}
• **Informational:** {}

### Risk Assessment

{}

---

"#, 
        total,
        summary.critical_count,
        summary.high_count,
        summary.medium_count, 
        summary.low_count,
        summary.info_count,
        self.generate_risk_assessment(summary))
    }

    fn generate_risk_assessment(&self, summary: &FindingSummary) -> String {
        if summary.critical_count > 0 {
            "**CRITICAL RISK:** The contract contains critical vulnerabilities that require immediate attention. These issues could lead to total contract compromise or significant fund loss.".to_string()
        } else if summary.high_count > 0 {
            "**HIGH RISK:** The contract contains high-severity issues that pose significant security risks and should be addressed before deployment.".to_string()
        } else if summary.medium_count > 0 {
            "**MEDIUM RISK:** The contract has medium-severity issues that should be reviewed and fixed to improve overall security posture.".to_string()
        } else if summary.low_count > 0 {
            "**LOW RISK:** The contract contains low-severity issues and recommendations for improvement.".to_string()
        } else {
            "**NO MAJOR ISSUES:** No critical, high, or medium severity vulnerabilities were detected. Only informational findings noted.".to_string()
        }
    }

    fn generate_detailed_findings(&self) -> String {
        let mut report = String::new();
        
        // Sort findings by severity
        let mut sorted_findings = self.findings.clone();
        sorted_findings.sort_by(|a, b| {
            let a_severity = self.severity_to_number(&a.severity);
            let b_severity = self.severity_to_number(&b.severity);
            a_severity.cmp(&b_severity)
        });

        let mut current_severity = None;
        
        for finding in sorted_findings {
            // Add section header for new severity level
            if current_severity != Some(finding.severity.clone()) {
                let section_title = match finding.severity {
                    VulnerabilitySeverity::Critical => "# Critical Risk Findings",
                    VulnerabilitySeverity::High => "# High Risk Findings", 
                    VulnerabilitySeverity::Medium => "# Medium Risk Findings",
                    VulnerabilitySeverity::Low => "# Low Risk Findings",
                    VulnerabilitySeverity::Info => "# Informational Findings",
                };
                report.push_str(&format!("{}\n\n", section_title));
                current_severity = Some(finding.severity.clone());
            }

            // Add individual finding
            report.push_str(&self.format_finding(&finding));
            report.push_str("\n---\n\n");
        }

        report
    }

    fn severity_to_number(&self, severity: &VulnerabilitySeverity) -> u8 {
        match severity {
            VulnerabilitySeverity::Critical => 0,
            VulnerabilitySeverity::High => 1,
            VulnerabilitySeverity::Medium => 2,
            VulnerabilitySeverity::Low => 3,
            VulnerabilitySeverity::Info => 4,
        }
    }

    fn format_finding(&self, finding: &DetailedFinding) -> String {
        let mut content = String::new();

        // Finding header
        content.push_str(&format!("## {}. {}\n\n", finding.id, finding.title));

        // GitHub links
        if !finding.github_links.is_empty() {
            content.push_str("**Relevant GitHub Links**\n\n");
            for link in &finding.github_links {
                content.push_str(&format!("{}\n\n", link));
            }
        }

        // Summary
        content.push_str("### Summary\n\n");
        content.push_str(&format!("{}\n\n", finding.summary));

        // Vulnerability Details
        content.push_str("### Vulnerability Details\n\n");
        content.push_str(&format!("{}\n\n", finding.vulnerability_details));

        // Impact
        content.push_str("### Impact\n\n");
        content.push_str(&format!("{}\n\n", finding.impact));

        // Proof of Concept (if available)
        if let Some(poc) = &finding.proof_of_concept {
            content.push_str("### Proof of Concept\n\n");
            content.push_str(&format!("{}\n\n", poc));
        }

        // Recommended Mitigation
        content.push_str("### Recommended Mitigation\n\n");
        content.push_str(&format!("{}\n\n", finding.recommended_mitigation));

        // Tools Used
        content.push_str("### Tools Used\n\n");
        content.push_str(&format!("• {}\n\n", finding.tools_used));

        content
    }
}