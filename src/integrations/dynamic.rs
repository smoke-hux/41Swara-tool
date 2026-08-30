//! Dynamic analysis and external tool orchestration.
//!
//! This module does not reimplement fuzzers, symbolic executors, provers, or
//! monitoring services. It provides a local orchestration layer that can:
//! - describe the audit pipeline,
//! - detect which command-line tools are installed,
//! - run supported local tools or dry-run their commands,
//! - report service/spec-only tools as configuration-required.

use serde::{Deserialize, Serialize};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Instant;

const OUTPUT_LIMIT: usize = 8_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DynamicToolCategory {
    Fuzzing,
    SymbolicExecution,
    FormalVerification,
    RuntimeMonitoring,
    DifferentialTesting,
    ExploitSimulation,
}

impl DynamicToolCategory {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Fuzzing => "Fuzzing",
            Self::SymbolicExecution => "Symbolic Execution",
            Self::FormalVerification => "Formal Verification",
            Self::RuntimeMonitoring => "Runtime Monitoring",
            Self::DifferentialTesting => "Differential Testing",
            Self::ExploitSimulation => "Exploit Simulation",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DynamicTool {
    Echidna,
    FoundryFuzz,
    Medusa,
    Ityfuzz,
    Manticore,
    Halmos,
    Hevm,
    Certora,
    Kevm,
    Tenderly,
    OpenZeppelinDefender,
    Forta,
    Phalcon,
    Diffusc,
    FoundryFork,
    Ape,
}

impl DynamicTool {
    pub fn all() -> Vec<Self> {
        vec![
            Self::Echidna,
            Self::FoundryFuzz,
            Self::Medusa,
            Self::Ityfuzz,
            Self::Manticore,
            Self::Halmos,
            Self::Hevm,
            Self::Certora,
            Self::Kevm,
            Self::Tenderly,
            Self::OpenZeppelinDefender,
            Self::Forta,
            Self::Phalcon,
            Self::Diffusc,
            Self::FoundryFork,
            Self::Ape,
        ]
    }

    pub fn default_pipeline() -> Vec<Self> {
        vec![
            Self::Echidna,
            Self::FoundryFuzz,
            Self::Medusa,
            Self::Ityfuzz,
            Self::Halmos,
            Self::Manticore,
            Self::Hevm,
            Self::Certora,
            Self::Kevm,
            Self::Forta,
            Self::Tenderly,
            Self::OpenZeppelinDefender,
            Self::Phalcon,
        ]
    }

    pub fn from_id(id: &str) -> Option<Self> {
        match normalize_id(id).as_str() {
            "echidna" | "echidna-test" => Some(Self::Echidna),
            "forge-fuzz" | "foundry-fuzz" | "foundry" => Some(Self::FoundryFuzz),
            "medusa" => Some(Self::Medusa),
            "ityfuzz" => Some(Self::Ityfuzz),
            "manticore" => Some(Self::Manticore),
            "halmos" => Some(Self::Halmos),
            "hevm" => Some(Self::Hevm),
            "certora" | "certora-prover" | "certorarun" => Some(Self::Certora),
            "kevm" | "k-framework" | "kframework" => Some(Self::Kevm),
            "tenderly" => Some(Self::Tenderly),
            "defender" | "openzeppelin-defender" | "oz-defender" => {
                Some(Self::OpenZeppelinDefender)
            }
            "forta" => Some(Self::Forta),
            "phalcon" | "blocksec-phalcon" => Some(Self::Phalcon),
            "diffusc" => Some(Self::Diffusc),
            "forge-fork" | "foundry-fork" | "fork" => Some(Self::FoundryFork),
            "ape" | "ape-framework" => Some(Self::Ape),
            _ => None,
        }
    }

    pub fn id(self) -> &'static str {
        match self {
            Self::Echidna => "echidna",
            Self::FoundryFuzz => "forge-fuzz",
            Self::Medusa => "medusa",
            Self::Ityfuzz => "ityfuzz",
            Self::Manticore => "manticore",
            Self::Halmos => "halmos",
            Self::Hevm => "hevm",
            Self::Certora => "certora",
            Self::Kevm => "kevm",
            Self::Tenderly => "tenderly",
            Self::OpenZeppelinDefender => "defender",
            Self::Forta => "forta",
            Self::Phalcon => "phalcon",
            Self::Diffusc => "diffusc",
            Self::FoundryFork => "forge-fork",
            Self::Ape => "ape",
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Echidna => "Echidna",
            Self::FoundryFuzz => "Foundry forge fuzz",
            Self::Medusa => "Medusa",
            Self::Ityfuzz => "Ityfuzz",
            Self::Manticore => "Manticore",
            Self::Halmos => "Halmos",
            Self::Hevm => "hevm",
            Self::Certora => "Certora Prover",
            Self::Kevm => "K Framework / KEVM",
            Self::Tenderly => "Tenderly",
            Self::OpenZeppelinDefender => "OpenZeppelin Defender",
            Self::Forta => "Forta Network",
            Self::Phalcon => "BlockSec Phalcon",
            Self::Diffusc => "Diffusc",
            Self::FoundryFork => "Foundry fork tests",
            Self::Ape => "Ape Framework",
        }
    }

    pub fn category(self) -> DynamicToolCategory {
        match self {
            Self::Echidna | Self::FoundryFuzz | Self::Medusa | Self::Ityfuzz => {
                DynamicToolCategory::Fuzzing
            }
            Self::Manticore | Self::Halmos | Self::Hevm => DynamicToolCategory::SymbolicExecution,
            Self::Certora | Self::Kevm => DynamicToolCategory::FormalVerification,
            Self::Tenderly | Self::OpenZeppelinDefender | Self::Forta | Self::Phalcon => {
                DynamicToolCategory::RuntimeMonitoring
            }
            Self::Diffusc => DynamicToolCategory::DifferentialTesting,
            Self::FoundryFork | Self::Ape => DynamicToolCategory::ExploitSimulation,
        }
    }

    pub fn command(self) -> Option<&'static str> {
        match self {
            Self::Echidna => Some("echidna-test"),
            Self::FoundryFuzz | Self::FoundryFork => Some("forge"),
            Self::Medusa => Some("medusa"),
            Self::Ityfuzz => Some("ityfuzz"),
            Self::Manticore => Some("manticore"),
            Self::Halmos => Some("halmos"),
            Self::Hevm => Some("hevm"),
            Self::Certora => Some("certoraRun"),
            Self::Kevm => Some("kevm"),
            Self::Forta => Some("forta"),
            Self::Ape => Some("ape"),
            Self::Diffusc => Some("diffusc"),
            Self::Tenderly | Self::OpenZeppelinDefender | Self::Phalcon => None,
        }
    }

    pub fn summary(self) -> &'static str {
        match self {
            Self::Echidna => "Property-based Solidity invariant fuzzing.",
            Self::FoundryFuzz => "Forge test fuzzing with randomized inputs.",
            Self::Medusa => "Parallel configurable EVM fuzzing with corpus support.",
            Self::Ityfuzz => "Coverage-guided fuzzing with fork/snapshot workflows.",
            Self::Manticore => "Symbolic execution for assertion and path exploration.",
            Self::Halmos => "Foundry-native symbolic tests with vm.assume constraints.",
            Self::Hevm => "DappTools symbolic execution and equivalence checking.",
            Self::Certora => "CVL rule-based formal verification.",
            Self::Kevm => "K/KEVM formal EVM semantics and proof workflows.",
            Self::Tenderly => "Transaction simulation and production alerting.",
            Self::OpenZeppelinDefender => "Sentinel-based live contract monitoring.",
            Self::Forta => "Custom live-transaction detection bots.",
            Self::Phalcon => "Exploit transaction tracing and attack-pattern exploration.",
            Self::Diffusc => "Differential fuzzing between contract versions.",
            Self::FoundryFork => "Mainnet fork tests for exploit simulation.",
            Self::Ape => "Python-based exploit and fork simulation scripting.",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct DynamicToolInfo {
    pub id: &'static str,
    pub name: &'static str,
    pub category: &'static str,
    pub command: Option<&'static str>,
    pub summary: &'static str,
}

pub fn tool_catalog() -> Vec<DynamicToolInfo> {
    DynamicTool::all()
        .into_iter()
        .map(|tool| DynamicToolInfo {
            id: tool.id(),
            name: tool.name(),
            category: tool.category().as_str(),
            command: tool.command(),
            summary: tool.summary(),
        })
        .collect()
}

#[derive(Debug, Clone)]
pub struct DynamicAnalysisOptions {
    pub selected_tools: Vec<DynamicTool>,
    pub dry_run: bool,
    pub fork_url: Option<String>,
    pub diff_target: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DynamicRunStatus {
    Planned,
    Passed,
    Failed,
    Skipped,
    RequiresConfiguration,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DynamicToolRun {
    pub tool_id: String,
    pub tool_name: String,
    pub category: String,
    pub status: DynamicRunStatus,
    pub command: Option<String>,
    pub args: Vec<String>,
    pub exit_code: Option<i32>,
    pub duration_ms: Option<u128>,
    pub stdout: Option<String>,
    pub stderr: Option<String>,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DynamicAnalysisReport {
    pub target: String,
    pub dry_run: bool,
    pub pipeline: Vec<String>,
    pub runs: Vec<DynamicToolRun>,
}

impl DynamicAnalysisReport {
    pub fn failed_count(&self) -> usize {
        self.runs
            .iter()
            .filter(|run| {
                matches!(
                    run.status,
                    DynamicRunStatus::Failed | DynamicRunStatus::Error
                )
            })
            .count()
    }

    pub fn planned_count(&self) -> usize {
        self.runs
            .iter()
            .filter(|run| run.status == DynamicRunStatus::Planned)
            .count()
    }

    pub fn skipped_count(&self) -> usize {
        self.runs
            .iter()
            .filter(|run| {
                matches!(
                    run.status,
                    DynamicRunStatus::Skipped | DynamicRunStatus::RequiresConfiguration
                )
            })
            .count()
    }
}

pub struct DynamicAnalysisRunner {
    options: DynamicAnalysisOptions,
}

impl DynamicAnalysisRunner {
    pub fn new(options: DynamicAnalysisOptions) -> Self {
        Self { options }
    }

    pub fn run(&self, target: &Path) -> DynamicAnalysisReport {
        let tools = if self.options.selected_tools.is_empty() {
            DynamicTool::default_pipeline()
        } else {
            self.options.selected_tools.clone()
        };

        let runs = tools
            .iter()
            .map(|tool| self.run_tool(*tool, target))
            .collect::<Vec<_>>();

        DynamicAnalysisReport {
            target: target.display().to_string(),
            dry_run: self.options.dry_run,
            pipeline: tools.iter().map(|tool| tool.id().to_string()).collect(),
            runs,
        }
    }

    fn run_tool(&self, tool: DynamicTool, target: &Path) -> DynamicToolRun {
        let mut run = DynamicToolRun {
            tool_id: tool.id().to_string(),
            tool_name: tool.name().to_string(),
            category: tool.category().as_str().to_string(),
            status: DynamicRunStatus::Skipped,
            command: tool.command().map(str::to_string),
            args: Vec::new(),
            exit_code: None,
            duration_ms: None,
            stdout: None,
            stderr: None,
            message: String::new(),
        };

        let Some(command) = tool.command() else {
            run.status = DynamicRunStatus::RequiresConfiguration;
            run.message = format!(
                "{} is a service/workflow integration. Configure it in the provider UI/API, then use 41Swara findings as watch conditions.",
                tool.name()
            );
            return run;
        };

        if matches!(tool, DynamicTool::Diffusc) && self.options.diff_target.is_none() {
            run.status = DynamicRunStatus::RequiresConfiguration;
            run.message = "Diffusc needs --dynamic-diff-target pointing at the comparison contract or project.".to_string();
            return run;
        }

        if matches!(tool, DynamicTool::FoundryFork) && self.options.fork_url.is_none() {
            run.status = DynamicRunStatus::RequiresConfiguration;
            run.message = "Foundry fork tests need --dynamic-fork-url.".to_string();
            return run;
        }

        if matches!(tool, DynamicTool::Certora) && !has_any_extension(target, &["conf", "spec"]) {
            run.status = DynamicRunStatus::RequiresConfiguration;
            run.message =
                "Certora Prover needs CVL specs or a certora .conf file in the target tree."
                    .to_string();
            return run;
        }

        if matches!(tool, DynamicTool::Kevm) && !has_any_extension(target, &["k"]) {
            run.status = DynamicRunStatus::RequiresConfiguration;
            run.message = "KEVM needs K proof/spec files in the target tree.".to_string();
            return run;
        }

        let args = tool_args(tool, target, &self.options);
        run.args = args.clone();

        if self.options.dry_run {
            run.status = DynamicRunStatus::Planned;
            run.message = format!("Dry run: would execute {} {}", command, args.join(" "));
            return run;
        }

        if find_command(command).is_none() {
            run.status = DynamicRunStatus::Skipped;
            run.message = format!(
                "{} executable '{}' was not found in PATH.",
                tool.name(),
                command
            );
            return run;
        }

        let start = Instant::now();
        let output = Command::new(command)
            .args(&args)
            .current_dir(working_dir(target))
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output();

        run.duration_ms = Some(start.elapsed().as_millis());

        match output {
            Ok(output) => {
                run.exit_code = output.status.code();
                run.stdout = non_empty_truncated(String::from_utf8_lossy(&output.stdout).as_ref());
                run.stderr = non_empty_truncated(String::from_utf8_lossy(&output.stderr).as_ref());
                if output.status.success() {
                    run.status = DynamicRunStatus::Passed;
                    run.message = format!("{} completed successfully.", tool.name());
                } else {
                    run.status = DynamicRunStatus::Failed;
                    run.message = format!(
                        "{} exited with code {:?}. Review tool output for failing invariants, counterexamples, or proof obligations.",
                        tool.name(),
                        output.status.code()
                    );
                }
            }
            Err(err) => {
                run.status = DynamicRunStatus::Error;
                run.message = format!("Failed to execute {}: {err}", tool.name());
            }
        }

        run
    }
}

fn normalize_id(id: &str) -> String {
    id.trim().to_ascii_lowercase().replace('_', "-")
}

fn target_arg(target: &Path) -> String {
    target.display().to_string()
}

fn tool_args(tool: DynamicTool, target: &Path, options: &DynamicAnalysisOptions) -> Vec<String> {
    match tool {
        DynamicTool::Echidna => vec![target_arg(target)],
        DynamicTool::FoundryFuzz => vec![
            "test".to_string(),
            "--fuzz-runs".to_string(),
            "256".to_string(),
        ],
        DynamicTool::Medusa => vec!["fuzz".to_string()],
        DynamicTool::Ityfuzz => {
            let mut args = vec!["evm".to_string(), "-t".to_string(), target_arg(target)];
            if let Some(fork_url) = &options.fork_url {
                args.push("--fork-url".to_string());
                args.push(fork_url.clone());
            }
            args
        }
        DynamicTool::Manticore => vec![target_arg(target)],
        DynamicTool::Halmos => vec![],
        DynamicTool::Hevm => vec!["test".to_string()],
        DynamicTool::Certora => certora_args(target),
        DynamicTool::Kevm => vec!["prove".to_string(), target_arg(target)],
        DynamicTool::Forta => vec!["run".to_string()],
        DynamicTool::Diffusc => {
            let mut args = vec![target_arg(target)];
            if let Some(diff_target) = &options.diff_target {
                args.push(diff_target.display().to_string());
            }
            args
        }
        DynamicTool::FoundryFork => {
            let mut args = vec!["test".to_string()];
            if let Some(fork_url) = &options.fork_url {
                args.push("--fork-url".to_string());
                args.push(fork_url.clone());
            }
            args
        }
        DynamicTool::Ape => {
            let mut args = vec!["test".to_string()];
            if options.fork_url.is_some() {
                args.push("--network".to_string());
                args.push("ethereum:mainnet-fork".to_string());
            }
            args
        }
        DynamicTool::Tenderly | DynamicTool::OpenZeppelinDefender | DynamicTool::Phalcon => {
            Vec::new()
        }
    }
}

fn certora_args(target: &Path) -> Vec<String> {
    if target.is_file()
        && target
            .extension()
            .and_then(|ext| ext.to_str())
            .is_some_and(|ext| ext == "conf")
    {
        return vec![target_arg(target)];
    }

    if target.is_dir() {
        if let Some(conf) = find_first_with_extension(target, "conf") {
            return vec![conf.display().to_string()];
        }
    }

    vec![target_arg(target)]
}

fn working_dir(target: &Path) -> PathBuf {
    if target.is_dir() {
        target.to_path_buf()
    } else {
        target
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("."))
    }
}

fn find_command(command: &str) -> Option<PathBuf> {
    let command_path = Path::new(command);
    if command_path.components().count() > 1 && is_executable_file(command_path) {
        return Some(command_path.to_path_buf());
    }

    env::var_os("PATH").and_then(|paths| {
        env::split_paths(&paths)
            .map(|path| path.join(command))
            .find(|candidate| is_executable_file(candidate))
    })
}

fn is_executable_file(path: &Path) -> bool {
    fs::metadata(path)
        .map(|metadata| metadata.is_file())
        .unwrap_or(false)
}

fn has_any_extension(target: &Path, extensions: &[&str]) -> bool {
    if target.is_file() {
        return target
            .extension()
            .and_then(|ext| ext.to_str())
            .is_some_and(|ext| extensions.contains(&ext));
    }

    if !target.is_dir() {
        return false;
    }

    let Ok(entries) = fs::read_dir(target) else {
        return false;
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            if has_any_extension(&path, extensions) {
                return true;
            }
        } else if path
            .extension()
            .and_then(|ext| ext.to_str())
            .is_some_and(|ext| extensions.contains(&ext))
        {
            return true;
        }
    }

    false
}

fn find_first_with_extension(target: &Path, extension: &str) -> Option<PathBuf> {
    let entries = fs::read_dir(target).ok()?;

    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            if let Some(found) = find_first_with_extension(&path, extension) {
                return Some(found);
            }
        } else if path
            .extension()
            .and_then(|ext| ext.to_str())
            .is_some_and(|ext| ext == extension)
        {
            return Some(path);
        }
    }

    None
}

fn non_empty_truncated(output: &str) -> Option<String> {
    let trimmed = output.trim();
    if trimmed.is_empty() {
        None
    } else if trimmed.len() > OUTPUT_LIMIT {
        Some(format!("{}... [truncated]", &trimmed[..OUTPUT_LIMIT]))
    } else {
        Some(trimmed.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_tool_aliases() {
        assert_eq!(DynamicTool::from_id("echidna"), Some(DynamicTool::Echidna));
        assert_eq!(
            DynamicTool::from_id("foundry_fuzz"),
            Some(DynamicTool::FoundryFuzz)
        );
        assert_eq!(
            DynamicTool::from_id("certoraRun"),
            Some(DynamicTool::Certora)
        );
        assert_eq!(DynamicTool::from_id("unknown"), None);
    }

    #[test]
    fn catalog_contains_requested_tool_families() {
        let ids: Vec<&str> = tool_catalog().iter().map(|tool| tool.id).collect();
        for expected in [
            "echidna",
            "forge-fuzz",
            "medusa",
            "ityfuzz",
            "manticore",
            "halmos",
            "hevm",
            "certora",
            "kevm",
            "tenderly",
            "defender",
            "forta",
            "phalcon",
            "diffusc",
            "forge-fork",
            "ape",
        ] {
            assert!(ids.contains(&expected), "missing {expected}");
        }
    }

    #[test]
    fn dry_run_reports_planned_when_command_exists() {
        let options = DynamicAnalysisOptions {
            selected_tools: vec![DynamicTool::FoundryFuzz],
            dry_run: true,
            fork_url: None,
            diff_target: None,
        };
        let report = DynamicAnalysisRunner::new(options).run(Path::new("."));
        assert_eq!(report.runs.len(), 1);
        assert!(matches!(
            report.runs[0].status,
            DynamicRunStatus::Planned | DynamicRunStatus::Skipped
        ));
    }
}
