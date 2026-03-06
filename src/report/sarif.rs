use anyhow::Result;
use serde::Serialize;
use std::collections::HashMap;

use crate::ai::AiAnalysis;
use crate::scanner::{Finding, Severity};

#[derive(Serialize)]
struct SarifReport {
    #[serde(rename = "$schema")]
    schema: String,
    version: String,
    runs: Vec<SarifRun>,
}

#[derive(Serialize)]
struct SarifRun {
    tool: SarifTool,
    results: Vec<SarifResult>,
}

#[derive(Serialize)]
struct SarifTool {
    driver: SarifDriver,
}

#[derive(Serialize)]
struct SarifDriver {
    name: String,
    version: String,
    #[serde(rename = "informationUri")]
    information_uri: String,
    rules: Vec<SarifRule>,
}

#[derive(Serialize)]
struct SarifRule {
    id: String,
    name: String,
    #[serde(rename = "shortDescription")]
    short_description: SarifMessage,
    #[serde(rename = "defaultConfiguration")]
    default_configuration: SarifConfig,
}

#[derive(Serialize)]
struct SarifConfig {
    level: String,
}

#[derive(Serialize)]
struct SarifResult {
    #[serde(rename = "ruleId")]
    rule_id: String,
    level: String,
    message: SarifMessage,
    locations: Vec<SarifLocation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    fixes: Option<Vec<SarifFix>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    properties: Option<SarifProperties>,
}

#[derive(Serialize)]
struct SarifMessage {
    text: String,
}

#[derive(Serialize)]
struct SarifLocation {
    #[serde(rename = "physicalLocation")]
    physical_location: SarifPhysicalLocation,
}

#[derive(Serialize)]
struct SarifPhysicalLocation {
    #[serde(rename = "artifactLocation")]
    artifact_location: SarifArtifactLocation,
    region: SarifRegion,
}

#[derive(Serialize)]
struct SarifArtifactLocation {
    uri: String,
}

#[derive(Serialize)]
struct SarifRegion {
    #[serde(rename = "startLine")]
    start_line: usize,
}

#[derive(Serialize)]
struct SarifFix {
    description: SarifMessage,
}

#[derive(Serialize)]
struct SarifProperties {
    #[serde(rename = "ai-confidence")]
    ai_confidence: f32,
    #[serde(rename = "ai-reasoning")]
    ai_reasoning: String,
}

fn severity_to_sarif_level(severity: &Severity) -> &'static str {
    match severity {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low => "note",
    }
}

pub fn print_report(
    findings: &[Finding],
    ai_annotations: &HashMap<usize, AiAnalysis>,
) -> Result<()> {
    let mut seen_rules = std::collections::HashSet::new();
    let mut rules = Vec::new();

    for f in findings {
        if seen_rules.insert(f.rule_id.clone()) {
            rules.push(SarifRule {
                id: f.rule_id.clone(),
                name: f.title.clone(),
                short_description: SarifMessage {
                    text: f.description.clone(),
                },
                default_configuration: SarifConfig {
                    level: severity_to_sarif_level(&f.severity).to_string(),
                },
            });
        }
    }

    let report = SarifReport {
        schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json".to_string(),
        version: "2.1.0".to_string(),
        runs: vec![SarifRun {
            tool: SarifTool {
                driver: SarifDriver {
                    name: "guardia".to_string(),
                    version: env!("CARGO_PKG_VERSION").to_string(),
                    information_uri: "https://github.com/hacker4257/guardia".to_string(),
                    rules,
                },
            },
            results: findings
                .iter()
                .enumerate()
                .map(|(i, f)| {
                    let ai = ai_annotations.get(&i);

                    let fixes = ai
                        .and_then(|a| a.suggested_fix.as_ref())
                        .map(|fix| vec![SarifFix {
                            description: SarifMessage { text: fix.clone() },
                        }]);

                    let properties = ai.map(|a| SarifProperties {
                        ai_confidence: a.confidence,
                        ai_reasoning: a.reasoning.clone(),
                    });

                    SarifResult {
                        rule_id: f.rule_id.clone(),
                        level: severity_to_sarif_level(&f.severity).to_string(),
                        message: SarifMessage {
                            text: format!("{}: {}", f.title, f.description),
                        },
                        locations: vec![SarifLocation {
                            physical_location: SarifPhysicalLocation {
                                artifact_location: SarifArtifactLocation {
                                    uri: f.file_path.display().to_string().replace('\\', "/"),
                                },
                                region: SarifRegion {
                                    start_line: f.line_number,
                                },
                            },
                        }],
                        fixes,
                        properties,
                    }
                })
                .collect(),
        }],
    };

    let json = serde_json::to_string_pretty(&report)?;
    println!("{}", json);
    Ok(())
}
