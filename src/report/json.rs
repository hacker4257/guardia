use anyhow::Result;
use serde::Serialize;
use std::collections::HashMap;

use crate::ai::AiAnalysis;
use crate::scanner::Finding;

#[derive(Serialize)]
struct JsonReport {
    version: String,
    tool: String,
    ai_enhanced: bool,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    ai_analysis: Option<JsonAiAnalysis>,
}

#[derive(Serialize)]
struct JsonAiAnalysis {
    confidence: f32,
    reasoning: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    suggested_fix: Option<String>,
}

#[derive(Serialize)]
struct Summary {
    total: usize,
    critical: usize,
    high: usize,
    medium: usize,
    low: usize,
    ai_filtered_false_positives: bool,
}

pub fn print_report(
    findings: &[Finding],
    ai_annotations: &HashMap<usize, AiAnalysis>,
) -> Result<()> {
    let ai_enhanced = !ai_annotations.is_empty();

    let report = JsonReport {
        version: env!("CARGO_PKG_VERSION").to_string(),
        tool: "guardia".to_string(),
        ai_enhanced,
        findings: findings
            .iter()
            .enumerate()
            .map(|(i, f)| {
                let ai = ai_annotations.get(&i).map(|a| JsonAiAnalysis {
                    confidence: a.confidence,
                    reasoning: a.reasoning.clone(),
                    suggested_fix: a.suggested_fix.clone(),
                });
                JsonFinding {
                    rule_id: f.rule_id.clone(),
                    severity: f.severity.to_string(),
                    title: f.title.clone(),
                    description: f.description.clone(),
                    file: f.file_path.display().to_string(),
                    line: f.line_number,
                    matched: f.matched_text.clone(),
                    suggestion: f.suggestion.clone(),
                    ai_analysis: ai,
                }
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
            ai_filtered_false_positives: ai_enhanced,
        },
    };

    let json = serde_json::to_string_pretty(&report)?;
    println!("{}", json);
    Ok(())
}
