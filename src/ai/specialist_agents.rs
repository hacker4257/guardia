use anyhow::Result;
use std::collections::HashMap;
use std::path::PathBuf;

use crate::scanner::Finding;
use super::context_window::ContextWindow;
use super::evidence::{SharedBoard, Evidence, EvidenceCategory, EvidenceSource, AgentVerdict};
use super::memory::{SharedMemory, RecalledContext};
use super::tools::{ToolBox, ToolCall};
use super::agents::{FileContext, DataflowTrace, gather_static_context, trace_static_dataflow};
use super::{AiConfig, call_with_retry, extract_json_object};

const AGENT_MAX_STEPS: usize = 5;
const AGENT_TOKEN_BUDGET: usize = 3000;

// ── Context Agent ──
// Gathers file-level context: language, test file, imports, function scope, callers

pub async fn run_context_agent(
    finding: &Finding,
    config: &AiConfig,
    client: &reqwest::Client,
    file_contents: &HashMap<PathBuf, String>,
    board: SharedBoard,
    memory: SharedMemory,
    recalled: &RecalledContext,
) -> Result<()> {
    let toolbox = ToolBox::new(file_contents.clone());
    let file_ctx = gather_static_context(finding, file_contents);

    board.lock().unwrap().add_evidence(Evidence {
        source_agent: "context".into(),
        category: EvidenceCategory::FileContext,
        content: format!(
            "Language: {}, Test: {}, Generated: {}, Function: {}, Callers: {}",
            file_ctx.language, file_ctx.is_test_file, file_ctx.is_generated,
            file_ctx.function_signature,
            if file_ctx.callers.is_empty() { "none".to_string() } else { file_ctx.callers.join(", ") },
        ),
        confidence: 0.95,
        source_type: EvidenceSource::StaticAnalysis,
        timestamp_ms: 0,
    });

    if file_ctx.is_test_file && finding.rule_id.starts_with("SEC") {
        board.lock().unwrap().add_verdict(AgentVerdict {
            agent: "context".into(),
            is_false_positive: true,
            confidence: 0.95,
            reasoning: format!("Secret in test/fixture file ({})", finding.file_path.display()),
            suggested_fix: None,
        });
        return Ok(());
    }

    let prompt = format!(
        r#"You are a Context Analysis Agent investigating a security finding.
Your ONLY job: understand the code context around this finding. Do NOT judge if it's a real vulnerability.

## Finding
Rule: {rule_id} — {title}
File: {file}:{line}
Matched: {matched}

## Already Known
{static_ctx}

## Memory
{recalled}

## Your Tools
- read_file: Read file content. Args: {{"path": "...", "start_line": "...", "end_line": "..."}}
- read_imports: Get imports. Args: {{"path": "..."}}
- find_callers: Find who calls a function. Args: {{"function_name": "..."}}
- done: Report your findings. Args: {{"context_summary": "...", "is_reachable": "true/false", "framework_detected": "..."}}

Gather context then call done. Respond with JSON: {{"tool": "...", "args": {{...}}}}"#,
        rule_id = finding.rule_id,
        title = finding.title,
        file = finding.file_path.display(),
        line = finding.line_number,
        matched = &finding.matched_text[..finding.matched_text.len().min(80)],
        static_ctx = format_file_context(&file_ctx),
        recalled = recalled.format_for_prompt(),
    );

    run_agent_loop("context", &prompt, &toolbox, config, client, board, memory, |args, board| {
        let summary = args.get("context_summary").cloned().unwrap_or_default();
        let is_reachable = args.get("is_reachable")
            .map(|v| v.contains("true"))
            .unwrap_or(true);

        board.lock().unwrap().add_evidence(Evidence {
            source_agent: "context".into(),
            category: EvidenceCategory::CallerAnalysis,
            content: format!("Reachable: {}. {}", is_reachable, summary),
            confidence: 0.8,
            source_type: EvidenceSource::LlmReasoning,
            timestamp_ms: 0,
        });

        if let Some(fw) = args.get("framework_detected") {
            if !fw.is_empty() && fw != "null" && fw != "none" {
                board.lock().unwrap().add_evidence(Evidence {
                    source_agent: "context".into(),
                    category: EvidenceCategory::CodePattern,
                    content: format!("Framework: {}", fw),
                    confidence: 0.85,
                    source_type: EvidenceSource::LlmReasoning,
                    timestamp_ms: 0,
                });
            }
        }
    }).await
}

// ── Dataflow Agent ──
// Traces data flow: sources, sinks, sanitizers, taint paths

pub async fn run_dataflow_agent(
    finding: &Finding,
    config: &AiConfig,
    client: &reqwest::Client,
    file_contents: &HashMap<PathBuf, String>,
    board: SharedBoard,
    memory: SharedMemory,
    recalled: &RecalledContext,
) -> Result<()> {
    let toolbox = ToolBox::new(file_contents.clone());
    let file_ctx = gather_static_context(finding, file_contents);
    let dataflow = trace_static_dataflow(finding, file_contents, &file_ctx);

    board.lock().unwrap().add_evidence(Evidence {
        source_agent: "dataflow".into(),
        category: EvidenceCategory::DataflowPath,
        content: format_dataflow_static(&dataflow),
        confidence: 0.7,
        source_type: EvidenceSource::StaticAnalysis,
        timestamp_ms: 0,
    });

    if finding.rule_id.starts_with("SEC") {
        board.lock().unwrap().add_verdict(AgentVerdict {
            agent: "dataflow".into(),
            is_false_positive: false,
            confidence: 0.5,
            reasoning: "Secret finding — dataflow analysis not primary for this type".into(),
            suggested_fix: None,
        });
        return Ok(());
    }

    let prompt = format!(
        r#"You are a Dataflow Tracing Agent investigating a security finding.
Your ONLY job: trace data flow from user input to dangerous operations. Do NOT make a final vulnerability judgment.

## Finding
Rule: {rule_id} — {title}
File: {file}:{line}
Description: {desc}

## Static Dataflow (pre-computed)
{static_df}

## Memory
{recalled}

## Your Tools
- read_file: Read file content. Args: {{"path": "...", "start_line": "...", "end_line": "..."}}
- search_code: Search across files. Args: {{"pattern": "..."}}
- check_sanitization: Check if variable is sanitized. Args: {{"path": "...", "variable": "...", "from_line": "...", "to_line": "..."}}
- find_function: Find function definition. Args: {{"function_name": "..."}}
- done: Report findings. Args: {{"taint_path": "source -> ... -> sink", "is_sanitized": "true/false", "sanitizer_details": "...", "dataflow_confidence": "0.0-1.0"}}

Trace the data flow then call done. Respond with JSON: {{"tool": "...", "args": {{...}}}}"#,
        rule_id = finding.rule_id,
        title = finding.title,
        file = finding.file_path.display(),
        line = finding.line_number,
        desc = &finding.description[..finding.description.len().min(200)],
        static_df = format_dataflow_static(&dataflow),
        recalled = recalled.format_for_prompt(),
    );

    run_agent_loop("dataflow", &prompt, &toolbox, config, client, board, memory, |args, board| {
        let taint_path = args.get("taint_path").cloned().unwrap_or_default();
        let is_sanitized = args.get("is_sanitized")
            .map(|v| v.contains("true"))
            .unwrap_or(false);
        let confidence: f32 = args.get("dataflow_confidence")
            .and_then(|v| v.parse().ok())
            .unwrap_or(0.6);

        board.lock().unwrap().add_evidence(Evidence {
            source_agent: "dataflow".into(),
            category: EvidenceCategory::SanitizationCheck,
            content: format!("Sanitized: {}. Path: {}", is_sanitized, taint_path),
            confidence,
            source_type: EvidenceSource::LlmReasoning,
            timestamp_ms: 0,
        });

        if is_sanitized {
            if let Some(details) = args.get("sanitizer_details") {
                board.lock().unwrap().add_evidence(Evidence {
                    source_agent: "dataflow".into(),
                    category: EvidenceCategory::SanitizationCheck,
                    content: format!("Sanitizer: {}", details),
                    confidence,
                    source_type: EvidenceSource::ToolOutput,
                    timestamp_ms: 0,
                });
            }
        }
    }).await
}

// ── Exploit Agent ──
// Assesses exploitability: attack vector, prerequisites, impact, PoC

pub async fn run_exploit_agent(
    finding: &Finding,
    config: &AiConfig,
    client: &reqwest::Client,
    file_contents: &HashMap<PathBuf, String>,
    board: SharedBoard,
    memory: SharedMemory,
    recalled: &RecalledContext,
) -> Result<()> {
    let toolbox = ToolBox::new(file_contents.clone());

    if finding.rule_id.starts_with("SEC") {
        board.lock().unwrap().add_evidence(Evidence {
            source_agent: "exploit".into(),
            category: EvidenceCategory::ExploitAssessment,
            content: "Secret finding — exploit assessment: check if secret is real and exposed".into(),
            confidence: 0.6,
            source_type: EvidenceSource::StaticAnalysis,
            timestamp_ms: 0,
        });
        return Ok(());
    }

    let prompt = format!(
        r#"You are an Exploit Assessment Agent investigating a security finding.
Your ONLY job: determine if this vulnerability is exploitable and assess its impact. Do NOT re-analyze data flow.

## Finding
Rule: {rule_id} — {title}
Severity: {severity}
File: {file}:{line}
Description: {desc}

## Memory
{recalled}

## Your Tools
- read_file: Read file content. Args: {{"path": "...", "start_line": "...", "end_line": "..."}}
- search_code: Search across files. Args: {{"pattern": "..."}}
- list_routes: Find HTTP endpoints. Args: {{"path": "..."}}
- get_config: Check security config. Args: {{"pattern": "..."}}
- done: Report findings. Args: {{"is_exploitable": "true/false", "attack_vector": "...", "impact": "high/medium/low", "prerequisites": "...", "poc_sketch": "..."}}

Assess exploitability then call done. Respond with JSON: {{"tool": "...", "args": {{...}}}}"#,
        rule_id = finding.rule_id,
        title = finding.title,
        severity = finding.severity,
        file = finding.file_path.display(),
        line = finding.line_number,
        desc = &finding.description[..finding.description.len().min(200)],
        recalled = recalled.format_for_prompt(),
    );

    run_agent_loop("exploit", &prompt, &toolbox, config, client, board, memory, |args, board| {
        let is_exploitable = args.get("is_exploitable")
            .map(|v| v.contains("true"))
            .unwrap_or(false);
        let attack_vector = args.get("attack_vector").cloned().unwrap_or_default();
        let impact = args.get("impact").cloned().unwrap_or_else(|| "unknown".into());
        let prerequisites = args.get("prerequisites").cloned().unwrap_or_default();
        let poc = args.get("poc_sketch").cloned();

        let content = format!(
            "Exploitable: {}, Attack: {}, Impact: {}, Prerequisites: {}{}",
            is_exploitable, attack_vector, impact, prerequisites,
            poc.as_ref().map(|p| format!(", PoC: {}", p)).unwrap_or_default(),
        );

        board.lock().unwrap().add_evidence(Evidence {
            source_agent: "exploit".into(),
            category: EvidenceCategory::ExploitAssessment,
            content,
            confidence: if is_exploitable { 0.8 } else { 0.7 },
            source_type: EvidenceSource::LlmReasoning,
            timestamp_ms: 0,
        });

        if is_exploitable {
            board.lock().unwrap().add_verdict(AgentVerdict {
                agent: "exploit".into(),
                is_false_positive: false,
                confidence: 0.8,
                reasoning: format!("Exploitable via {}. Impact: {}", attack_vector, impact),
                suggested_fix: None,
            });
        }
    }).await
}

// ── Generic agent loop: shared by all specialist agents ──

async fn run_agent_loop<F>(
    agent_name: &str,
    initial_prompt: &str,
    toolbox: &ToolBox,
    config: &AiConfig,
    client: &reqwest::Client,
    board: SharedBoard,
    memory: SharedMemory,
    on_done: F,
) -> Result<()>
where
    F: FnOnce(&HashMap<String, String>, &SharedBoard),
{
    let mut ctx_window = ContextWindow::new(AGENT_TOKEN_BUDGET, initial_prompt.to_string());

    for _step in 0..AGENT_MAX_STEPS {
        let prompt_text = ctx_window.render();
        let response = call_with_retry(client, config, &prompt_text).await
            .unwrap_or_else(|_| format!(
                r#"{{"tool": "done", "args": {{"error": "LLM call failed for {} agent"}}}}"#,
                agent_name
            ));

        ctx_window.add_assistant(response.clone());
        memory.lock().unwrap().learn_from_response(&response);

        if let Some(json_str) = extract_json_object(&response) {
            if let Ok(call) = serde_json::from_str::<ToolCall>(&json_str) {
                if call.tool == "done" {
                    on_done(&call.args, &board);
                    return Ok(());
                }

                let result = toolbox.execute(&call);
                ctx_window.add_tool_result(&call.tool, result.output);
                continue;
            }
        }

        ctx_window.add_nudge("Continue. Use a tool or call done with your findings. Respond with JSON.".into());
    }

    on_done(&HashMap::new(), &board);
    Ok(())
}

// ── Formatting helpers ──

fn format_file_context(ctx: &FileContext) -> String {
    format!(
        "Language: {}\nTest file: {}\nGenerated: {}\nFunction: {}\nImports: {}\nCallers: {}",
        ctx.language, ctx.is_test_file, ctx.is_generated,
        ctx.function_signature,
        if ctx.imports.is_empty() { "(none)".to_string() } else { ctx.imports.join(", ") },
        if ctx.callers.is_empty() { "(none)".to_string() } else { ctx.callers.join(", ") },
    )
}

fn format_dataflow_static(df: &DataflowTrace) -> String {
    let sources: String = df.sources.iter()
        .map(|s| format!("L{}: {}", s.line, s.expression))
        .collect::<Vec<_>>().join("; ");
    let sinks: String = df.sinks.iter()
        .map(|s| format!("L{}: {}", s.line, s.expression))
        .collect::<Vec<_>>().join("; ");
    let sanitizers: String = df.sanitizers.iter()
        .map(|s| format!("L{}: {}", s.line, s.expression))
        .collect::<Vec<_>>().join("; ");

    format!(
        "Sources: {}\nSanitizers: {}\nSinks: {}\nUser controlled: {}\nHas sanitization: {}",
        if sources.is_empty() { "(none)" } else { &sources },
        if sanitizers.is_empty() { "(none)" } else { &sanitizers },
        if sinks.is_empty() { "(none)" } else { &sinks },
        df.is_user_controlled,
        df.has_sanitization,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_file_context() {
        let ctx = FileContext {
            language: "Python".into(),
            is_test_file: false,
            is_generated: false,
            imports: vec!["import os".into()],
            function_signature: "def get_user(uid):".into(),
            function_body_snippet: String::new(),
            callers: vec!["admin.py:10".into()],
            related_files: vec![],
        };
        let s = format_file_context(&ctx);
        assert!(s.contains("Python"));
        assert!(s.contains("get_user"));
    }

    #[test]
    fn test_format_dataflow_static() {
        let df = DataflowTrace {
            sources: vec![super::super::agents::DataflowNode {
                kind: "source".into(), expression: "request.args".into(), file: String::new(), line: 5,
            }],
            sinks: vec![super::super::agents::DataflowNode {
                kind: "sink".into(), expression: "cursor.execute(q)".into(), file: String::new(), line: 10,
            }],
            sanitizers: vec![],
            taint_path: vec![],
            is_user_controlled: true,
            has_sanitization: false,
        };
        let s = format_dataflow_static(&df);
        assert!(s.contains("request.args"));
        assert!(s.contains("cursor.execute"));
        assert!(s.contains("User controlled: true"));
    }
}
