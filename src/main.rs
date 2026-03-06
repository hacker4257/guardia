mod ai;
mod cli;
mod config;
mod hooks;
mod report;
mod scanner;
mod tui;

use anyhow::Result;
use clap::Parser;
use cli::{Cli, Commands, OutputFormat};
use colored::Colorize;
use std::time::Instant;

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Scan {
            path,
            format,
            secret_only,
            min_severity,
            no_progress,
            threads,
            ai: ai_flag,
            ai_provider,
            ai_model,
            tui: tui_flag,
        } => {
            let start = Instant::now();

            if !tui_flag {
                print_banner();
            }

            let config = config::ScanConfig {
                path: path.clone(),
                secret_only,
                min_severity: min_severity.into(),
                show_progress: !no_progress && !tui_flag,
                threads,
            };

            let mut findings = scanner::run_scan(&config)?;
            let duration = start.elapsed();

            if ai_flag && !findings.is_empty() {
                run_ai_analysis(&mut findings, &ai_provider, &ai_model, &path)?;
            }

            if tui_flag {
                tui::run_tui(findings, duration)?;
            } else {
                match format {
                    OutputFormat::Text => report::terminal::print_report(&findings, duration),
                    OutputFormat::Json => report::json::print_report(&findings)?,
                    OutputFormat::Sarif => report::sarif::print_report(&findings)?,
                }

                if findings.iter().any(|f| {
                    f.severity == scanner::Severity::Critical || f.severity == scanner::Severity::High
                }) {
                    std::process::exit(1);
                }
            }
        }
        Commands::Rules => {
            scanner::rules::print_rules();
        }
        Commands::Hook { action } => match action {
            cli::HookAction::Install => hooks::install_hook()?,
            cli::HookAction::Remove => hooks::remove_hook()?,
        },
        Commands::Ci => {
            println!("{}", hooks::generate_github_action());
        }
    }

    Ok(())
}

fn run_ai_analysis(
    findings: &mut Vec<scanner::Finding>,
    provider: &str,
    model: &str,
    _scan_path: &std::path::Path,
) -> Result<()> {
    let ai_config = match provider {
        "openai" => {
            let key = std::env::var("OPENAI_API_KEY")
                .unwrap_or_else(|_| {
                    eprintln!("  {} Set OPENAI_API_KEY environment variable", "⚠".yellow());
                    String::new()
                });
            if key.is_empty() { return Ok(()); }
            ai::AiConfig::openai(model, &key)
        }
        "anthropic" | "claude" => {
            let key = std::env::var("ANTHROPIC_API_KEY")
                .unwrap_or_else(|_| {
                    eprintln!("  {} Set ANTHROPIC_API_KEY environment variable", "⚠".yellow());
                    String::new()
                });
            if key.is_empty() { return Ok(()); }
            ai::AiConfig::anthropic(model, &key)
        }
        _ => ai::AiConfig::ollama(model),
    };

    eprintln!(
        "  {} Analyzing {} findings with AI ({})...",
        "🤖".to_string(),
        findings.len(),
        model
    );

    let mut file_contents = std::collections::HashMap::new();
    for f in findings.iter() {
        if !file_contents.contains_key(&f.file_path) {
            if let Ok(content) = std::fs::read_to_string(&f.file_path) {
                file_contents.insert(f.file_path.clone(), content);
            }
        }
    }

    let rt = tokio::runtime::Runtime::new()?;
    let analyses = rt.block_on(ai::analyze_findings(findings, &ai_config, &file_contents))?;

    let fp_count = analyses.iter().filter(|(_, a)| a.is_false_positive).count();
    if fp_count > 0 {
        eprintln!(
            "  {} AI filtered {} false positive(s)",
            "✓".green(),
            fp_count
        );
    }

    ai::apply_ai_filter(findings, &analyses);

    Ok(())
}

fn print_banner() {
    eprintln!(
        "{}",
        r#"
   ___                     _ _       
  / _ \_   _  __ _ _ __ __| (_) __ _ 
 / /_\/ | | |/ _` | '__/ _` | |/ _` |
/ /_\\| |_| | (_| | | | (_| | | (_| |
\____/ \__,_|\__,_|_|  \__,_|_|\__,_|
"#
        .cyan()
    );
    eprintln!(
        "  {} {}\n",
        "AI-Enhanced Code Security Scanner".bold(),
        format!("v{}", env!("CARGO_PKG_VERSION")).dimmed()
    );
}
