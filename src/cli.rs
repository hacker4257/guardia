use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "guardia",
    about = "AI-enhanced code security scanner",
    long_about = "Guardia — Blazing fast code security scanner with AI-powered false positive filtering.\n\nDetects hardcoded secrets, API keys, tokens, and security vulnerabilities in your codebase.",
    version
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Scan a directory or file for security issues
    Scan {
        /// Path to scan (file or directory)
        #[arg(default_value = ".")]
        path: PathBuf,

        /// Output format
        #[arg(short, long, default_value = "text")]
        format: OutputFormat,

        /// Only scan for secrets (skip AST vulnerability analysis)
        #[arg(long)]
        secret_only: bool,

        /// Minimum severity to report: low, medium, high, critical
        #[arg(long, default_value = "low")]
        min_severity: SeverityArg,

        /// Disable progress bar
        #[arg(long)]
        no_progress: bool,

        /// Number of threads for parallel scanning
        #[arg(short, long, default_value = "0")]
        threads: usize,

        /// Enable AI-powered false positive filtering
        #[arg(long)]
        ai: bool,

        /// AI provider: ollama, openai, anthropic
        #[arg(long, default_value = "ollama")]
        ai_provider: String,

        /// AI model name (e.g. llama3, gpt-4o, claude-sonnet-4-20250514)
        #[arg(long, default_value = "llama3")]
        ai_model: String,

        /// Custom API base URL (for OpenAI-compatible services, e.g. http://localhost:8080/v1)
        #[arg(long)]
        ai_url: Option<String>,

        /// Max concurrent AI requests
        #[arg(long, default_value = "4")]
        ai_concurrency: usize,

        /// AI request timeout in seconds
        #[arg(long, default_value = "30")]
        ai_timeout: u64,

        /// Privacy mode: local-only, sanitized, unrestricted
        #[arg(long, default_value = "sanitized")]
        privacy: String,

        /// Path for privacy audit log
        #[arg(long, default_value = "guardia-audit.jsonl")]
        audit_log: String,

        /// Path to local CWE/CVE knowledge database (JSON)
        #[arg(long)]
        cve_db: Option<String>,

        /// Enable PoC sandbox verification (requires Docker)
        #[arg(long)]
        verify: bool,

        /// Sandbox verification timeout in seconds
        #[arg(long, default_value = "30")]
        verify_timeout: u64,

        /// Skip symbolic verification
        #[arg(long)]
        no_verify: bool,

        /// Launch interactive TUI dashboard
        #[arg(long)]
        tui: bool,
    },

    /// List all built-in detection rules
    Rules,

    /// Manage git pre-commit hook
    Hook {
        #[command(subcommand)]
        action: HookAction,
    },

    /// Generate GitHub Actions workflow YAML
    Ci,
}

#[derive(Subcommand, Clone)]
pub enum HookAction {
    /// Install guardia as a git pre-commit hook
    Install,
    /// Remove guardia pre-commit hook
    Remove,
}

#[derive(Clone, ValueEnum)]
pub enum OutputFormat {
    Text,
    Json,
    Sarif,
}

#[derive(Clone, ValueEnum)]
pub enum SeverityArg {
    Low,
    Medium,
    High,
    Critical,
}

impl From<SeverityArg> for crate::scanner::Severity {
    fn from(s: SeverityArg) -> Self {
        match s {
            SeverityArg::Low => crate::scanner::Severity::Low,
            SeverityArg::Medium => crate::scanner::Severity::Medium,
            SeverityArg::High => crate::scanner::Severity::High,
            SeverityArg::Critical => crate::scanner::Severity::Critical,
        }
    }
}
