use anyhow::Result;
use serde::Serialize;

use crate::scanner::Finding;

#[derive(Serialize)]
struct JsonReport {
    version: String,
    tool: String,
    findings: Vec<JsonFinding>,
    summary: Summary,
}

#[derive(Serialize)]
struct JsonFinding {
    rule_id: String,
    severity: String,
    title: String,
    description: String,
    file: String,
    line: usize,
    matched: String,
    suggestion: String,
}

#[derive(Serialize)]
struct Summary {
    total: usize,
    critical: usize,
    high: usize,
    medium: usize,
    low: usize,
}

pub fn print_report(findings: &[Finding]) -> Result<()> {
    let report = JsonReport {
        version: env!("CARGO_PKG_VERSION").to_string(),
        tool: "guardia".to_string(),
        findings: findings
            .iter()
            .map(|f| JsonFinding {
                rule_id: f.rule_id.clone(),
                severity: f.severity.to_string(),
                title: f.title.clone(),
                description: f.description.clone(),
                file: f.file_path.display().to_string(),
                line: f.line_number,
                matched: f.matched_text.clone(),
                suggestion: f.suggestion.clone(),
            })
            .collect(),
        summary: Summary {
            total: findings.len(),
            critical: findings
                .iter()
                .filter(|f| f.severity == crate::scanner::Severity::Critical)
                .count(),
            high: findings
                .iter()
                .filter(|f| f.severity == crate::scanner::Severity::High)
                .count(),
            medium: findings
                .iter()
                .filter(|f| f.severity == crate::scanner::Severity::Medium)
                .count(),
            low: findings
                .iter()
                .filter(|f| f.severity == crate::scanner::Severity::Low)
                .count(),
        },
    };

    let json = serde_json::to_string_pretty(&report)?;
    println!("{}", json);
    Ok(())
}
