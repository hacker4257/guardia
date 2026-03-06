use colored::Colorize;
use std::collections::HashMap;
use std::time::Duration;

use crate::ai::AiAnalysis;
use crate::scanner::{Finding, Severity};

pub fn print_report(
    findings: &[Finding],
    duration: Duration,
    ai_annotations: &HashMap<usize, AiAnalysis>,
) {
    if findings.is_empty() {
        println!(
            "\n  {} {}\n",
            "✓".green().bold(),
            "No security issues found!".green().bold()
        );
        print_summary(findings, duration, !ai_annotations.is_empty());
        return;
    }

    println!("\n{}\n", " Security Findings ".bold().on_red().white());

    for (i, finding) in findings.iter().enumerate() {
        print_finding(i + 1, finding, ai_annotations.get(&i));
    }

    print_summary(findings, duration, !ai_annotations.is_empty());
}

fn print_finding(index: usize, finding: &Finding, ai: Option<&AiAnalysis>) {
    let severity_badge = match finding.severity {
        Severity::Critical => " CRITICAL ".on_red().white().bold().to_string(),
        Severity::High => " HIGH ".on_yellow().black().bold().to_string(),
        Severity::Medium => " MEDIUM ".on_blue().white().bold().to_string(),
        Severity::Low => " LOW ".on_white().black().to_string(),
    };

    let file_display = format!(
        "{}:{}",
        finding.file_path.display(),
        finding.line_number
    );

    println!(
        "  {} {} {} {}",
        format!("#{}", index).dimmed(),
        severity_badge,
        finding.title.bold(),
        format!("[{}]", finding.rule_id).dimmed()
    );
    println!("  {} {}", "File:".dimmed(), file_display.underline());
    println!("  {} {}", "Desc:".dimmed(), finding.description);

    let line_num_str = format!("{:>4} │ ", finding.line_number);
    let highlighted_line = highlight_match(&finding.line_content, &finding.matched_text);
    println!("  {}{}", line_num_str.dimmed(), highlighted_line);

    println!(
        "  {} {}",
        "Fix:".cyan().bold(),
        finding.suggestion.cyan()
    );

    if let Some(analysis) = ai {
        println!();
        let conf_label = if analysis.confidence >= 0.8 {
            format!("{:.0}%", analysis.confidence * 100.0).green().bold().to_string()
        } else if analysis.confidence >= 0.5 {
            format!("{:.0}%", analysis.confidence * 100.0).yellow().bold().to_string()
        } else {
            format!("{:.0}%", analysis.confidence * 100.0).red().bold().to_string()
        };

        println!(
            "  {} {} (confidence: {})",
            "🤖 AI:".magenta().bold(),
            analysis.reasoning.dimmed(),
            conf_label,
        );

        if let Some(fix) = &analysis.suggested_fix {
            println!("  {} ", "AI Suggested Fix:".magenta().bold());
            for line in fix.lines() {
                println!("       {}", line.green());
            }
        }
    }

    println!();
}

fn highlight_match(line: &str, _matched: &str) -> String {
    line.to_string()
}

fn print_summary(findings: &[Finding], duration: Duration, ai_used: bool) {
    let critical = findings.iter().filter(|f| f.severity == Severity::Critical).count();
    let high = findings.iter().filter(|f| f.severity == Severity::High).count();
    let medium = findings.iter().filter(|f| f.severity == Severity::Medium).count();
    let low = findings.iter().filter(|f| f.severity == Severity::Low).count();

    println!("{}", "─".repeat(60).dimmed());
    println!(
        "  {} {} findings in {:.2}s{}",
        "Summary:".bold(),
        findings.len().to_string().bold(),
        duration.as_secs_f64(),
        if ai_used { " (AI-enhanced)" } else { "" },
    );
    println!();

    if critical > 0 {
        println!(
            "    {} {} critical",
            "●".red(),
            critical.to_string().red().bold()
        );
    }
    if high > 0 {
        println!(
            "    {} {} high",
            "●".yellow(),
            high.to_string().yellow().bold()
        );
    }
    if medium > 0 {
        println!(
            "    {} {} medium",
            "●".blue(),
            medium.to_string().blue().bold()
        );
    }
    if low > 0 {
        println!("    {} {} low", "●".dimmed(), low);
    }

    println!();

    if critical > 0 || high > 0 {
        println!(
            "  {} {}\n",
            "⚠".red().bold(),
            "Critical/High severity issues found. Exiting with code 1.".red()
        );
    }
}
