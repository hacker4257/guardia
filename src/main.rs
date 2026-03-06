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
            privacy,
            audit_log,
            cve_db,
            verify,
            verify_timeout,
            no_verify,
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

            let privacy_config = {
                let mut pc = ai::privacy::PrivacyConfig::from_mode_str(&privacy);
                pc.audit_log_path = Some(std::path::PathBuf::from(&audit_log));
                pc
            };

            let ai_annotations = if ai_flag && !findings.is_empty() {
                run_agent_analysis(
                    &mut findings,
                    &ai_provider,
                    &ai_model,
                    ai_url.as_deref(),
                    ai_timeout,
                    ai_concurrency,
                    &privacy_config,
                    cve_db.as_deref(),
                    verify,
                    verify_timeout,
                    no_verify,
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

fn run_agent_analysis(
    findings: &mut Vec<scanner::Finding>,
    provider: &str,
    model: &str,
    custom_url: Option<&str>,
    timeout_secs: u64,
    concurrency: usize,
    privacy_config: &ai::privacy::PrivacyConfig,
    cve_db_path: Option<&str>,
    verify_flag: bool,
    verify_timeout: u64,
    no_verify: bool,
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

    ai::privacy::check_privacy_gate(&config.provider, privacy_config)?;

    eprintln!(
        "  {} Analyzing {} findings with AI Agent pipeline ({} / {})...",
        "🤖".to_string(),
        findings.len(),
        config.provider_name(),
        model,
    );
    eprintln!(
        "  {} Privacy: {:?} | Verify: {}",
        "🔒".to_string(),
        privacy_config.mode,
        if no_verify { "disabled" } else if verify_flag { "sandbox+symbolic" } else { "symbolic-only" },
    );

    let mut file_contents = HashMap::new();
    for f in findings.iter() {
        if !file_contents.contains_key(&f.file_path) {
            if let Ok(content) = std::fs::read_to_string(&f.file_path) {
                file_contents.insert(f.file_path.clone(), content);
            }
        }
    }

    let _knowledge_base = ai::knowledge::KnowledgeBase::new(cve_db_path);

    let rt = tokio::runtime::Runtime::new()?;
    let results = rt.block_on(
        ai::orchestrator::run_agent_pipeline(findings, &config, &file_contents)
    )?;

    let mut verification_results: HashMap<usize, ai::verify::VerificationStatus> = HashMap::new();
    if !no_verify {
        for (idx, analysis, vuln_ctx) in &results {
            let finding_ref = findings.get(*idx);
            let symbolic = ai::verify::symbolic::run_symbolic_verification(
                finding_ref,
                vuln_ctx,
                &file_contents,
            );
            let sandbox = if verify_flag
                && analysis.confidence > 0.7
                && !analysis.is_false_positive
                && symbolic.reachable
            {
                if let Some(finding) = finding_ref {
                    if matches!(finding.severity, scanner::Severity::Critical | scanner::Severity::High) {
                        rt.block_on(ai::verify::sandbox::run_sandbox_verification(
                            finding,
                            vuln_ctx,
                            &config,
                            &reqwest::Client::new(),
                            verify_timeout,
                        )).ok()
                    } else { None }
                } else { None }
            } else { None };

            verification_results.insert(*idx, ai::verify::VerificationStatus {
                symbolic: symbolic.clone(),
                sandbox,
            });
        }
    }

    if !verification_results.is_empty() {
        let verified_count = verification_results.values()
            .filter(|v| v.sandbox.as_ref().map(|s| matches!(s.status, ai::verify::sandbox::VerifyStatus::Verified)).unwrap_or(false))
            .count();
        let symbolic_count = verification_results.len();
        eprintln!(
            "  {} Symbolic verification: {} findings | Sandbox verified: {}",
            "🔍".to_string(),
            symbolic_count,
            verified_count,
        );
    }

    let mut fp_count = 0;
    let mut annotations = HashMap::new();
    let false_positive_indices: std::collections::HashSet<usize> = results.iter()
        .filter(|(_, a, _)| a.is_false_positive && a.confidence > 0.7)
        .map(|(idx, _, _)| { fp_count += 1; *idx })
        .collect();

    if fp_count > 0 {
        eprintln!(
            "  {} AI agents filtered {} false positive(s)",
            "✓".green(),
            fp_count,
        );
    }

    let mut idx = 0;
    findings.retain(|_| {
        let keep = !false_positive_indices.contains(&idx);
        idx += 1;
        keep
    });

    for (original_idx, analysis, vuln_ctx) in &results {
        if !false_positive_indices.contains(original_idx) {
            let agent_count = vuln_ctx.agent_trace.len();
            let mut enriched = analysis.clone();

            if let Some(vstatus) = verification_results.get(original_idx) {
                let adj = vstatus.confidence_adjustment();
                enriched.confidence = (enriched.confidence + adj).clamp(0.0, 1.0);
                enriched.reasoning = format!(
                    "{} | Verification: {}",
                    enriched.reasoning,
                    vstatus.summary(),
                );
            }

            if agent_count > 1 {
                let trace_summary: String = vuln_ctx.agent_trace.iter()
                    .map(|s| format!("[{}]", s.agent))
                    .collect::<Vec<_>>()
                    .join(" → ");
                enriched.reasoning = format!(
                    "{} (agents: {})",
                    enriched.reasoning,
                    trace_summary,
                );
            }
            annotations.insert(*original_idx, enriched);
        }
    }

    let annotated = annotations.len();
    if annotated > 0 {
        eprintln!(
            "  {} AI agents annotated {} finding(s) with deep analysis",
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
