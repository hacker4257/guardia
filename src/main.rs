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
use std::collections::HashMap;
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
            ai_url,
            ai_concurrency,
            ai_timeout,
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

            let ai_annotations = if ai_flag && !findings.is_empty() {
                run_ai_analysis(
                    &mut findings,
                    &ai_provider,
                    &ai_model,
                    ai_url.as_deref(),
                    ai_timeout,
                    ai_concurrency,
                )?
            } else {
                HashMap::new()
            };

            if tui_flag {
                tui::run_tui(findings, duration)?;
            } else {
                match format {
                    OutputFormat::Text => report::terminal::print_report(&findings, duration, &ai_annotations),
                    OutputFormat::Json => report::json::print_report(&findings, &ai_annotations)?,
                    OutputFormat::Sarif => report::sarif::print_report(&findings, &ai_annotations)?,
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
    custom_url: Option<&str>,
    timeout_secs: u64,
    concurrency: usize,
) -> Result<HashMap<usize, ai::AiAnalysis>> {
    let config = ai::AiConfig::new(provider, model, custom_url, timeout_secs, concurrency);

    if config.missing_api_key() {
        eprintln!(
            "  {} Set {}_API_KEY environment variable for {} provider",
            "⚠".yellow(),
            config.provider_name().to_uppercase(),
            config.provider_name(),
        );
        return Ok(HashMap::new());
    }

    eprintln!(
        "  {} Analyzing {} findings with AI ({} / {})...",
        "🤖".to_string(),
        findings.len(),
        config.provider_name(),
        model,
    );

    let mut file_contents = HashMap::new();
    for f in findings.iter() {
        if !file_contents.contains_key(&f.file_path) {
            if let Ok(content) = std::fs::read_to_string(&f.file_path) {
                file_contents.insert(f.file_path.clone(), content);
            }
        }
    }

    let rt = tokio::runtime::Runtime::new()?;
    let analyses = rt.block_on(ai::analyze_findings(findings, &config, &file_contents))?;

    let fp_count = ai::apply_ai_filter(findings, &analyses);
    if fp_count > 0 {
        eprintln!(
            "  {} AI filtered {} false positive(s)",
            "✓".green(),
            fp_count,
        );
    }

    let annotations = ai::build_ai_annotations(findings, &analyses);
    let annotated = annotations.len();
    if annotated > 0 {
        eprintln!(
            "  {} AI annotated {} finding(s) with reasoning & fixes",
            "✓".green(),
            annotated,
        );
    }

    Ok(annotations)
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
