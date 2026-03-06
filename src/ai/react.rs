use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use crate::scanner::Finding;
use super::tools::{ToolBox, ToolCall};
use super::agents::{VulnContext, AgentStep, gather_static_context, trace_static_dataflow};
use super::{AiConfig, AiAnalysis, call_with_retry, extract_json_object};

const MAX_STEPS: usize = 8;
const MAX_REFLECTION_RETRIES: usize = 1;

// ── Project Memory: shared knowledge across findings ──

#[derive(Debug, Clone, Default)]
pub struct ProjectMemory {
    pub framework: Option<String>,
    pub auth_middleware: Option<String>,
    pub orm_used: Option<String>,
    pub known_sanitizers: Vec<String>,
    #[allow(dead_code)]
    pub project_type: Option<String>,
    pub facts: Vec<String>,
}

impl ProjectMemory {
    pub fn summary(&self) -> String {
        let mut parts = Vec::new();
        if let Some(fw) = &self.framework {
            parts.push(format!("Framework: {}", fw));
        }
        if let Some(auth) = &self.auth_middleware {
            parts.push(format!("Auth: {}", auth));
        }
        if let Some(orm) = &self.orm_used {
            parts.push(format!("ORM: {}", orm));
        }
        if !self.known_sanitizers.is_empty() {
            parts.push(format!("Known sanitizers: {}", self.known_sanitizers.join(", ")));
        }
        if !self.facts.is_empty() {
            for fact in self.facts.iter().take(5) {
                parts.push(format!("- {}", fact));
            }
        }
        if parts.is_empty() {
            "(no project knowledge yet)".to_string()
        } else {
            parts.join("\n")
        }
    }

    pub fn learn_from_response(&mut self, text: &str) {
        let lower = text.to_lowercase();

        let frameworks = [
            ("flask", "Flask"), ("django", "Django"), ("fastapi", "FastAPI"),
            ("express", "Express"), ("next.js", "Next.js"), ("nestjs", "NestJS"),
            ("spring", "Spring"), ("gin", "Gin"), ("actix", "Actix"),
        ];
        for (pattern, name) in &frameworks {
            if lower.contains(pattern) && self.framework.is_none() {
                self.framework = Some(name.to_string());
            }
        }

        let orms = [
            ("sqlalchemy", "SQLAlchemy"), ("django orm", "Django ORM"),
            ("sequelize", "Sequelize"), ("prisma", "Prisma"),
            ("hibernate", "Hibernate"), ("gorm", "GORM"),
        ];
        for (pattern, name) in &orms {
            if lower.contains(pattern) && self.orm_used.is_none() {
                self.orm_used = Some(name.to_string());
            }
        }
    }
}

// ── ReAct conversation turn ──

#[derive(Debug, Clone, Serialize)]
struct ReActTurn {
    role: String,
    content: String,
}

// ── Parsed LLM action ──

#[derive(Debug)]
enum AgentAction {
    ToolUse(ToolCall),
    Done(DoneVerdict),
    Thinking(String),
}

#[derive(Debug, Clone, Deserialize)]
struct DoneVerdict {
    #[serde(default)]
    verdict: String,
    #[serde(default = "default_conf")]
    confidence: String,
    #[serde(default)]
    reasoning: String,
    #[serde(default)]
    suggested_fix: Option<String>,
}

fn default_conf() -> String { "0.5".to_string() }

// ── Main ReAct loop ──

pub async fn react_analyze(
    finding: &Finding,
    config: &AiConfig,
    client: &reqwest::Client,
    file_contents: &HashMap<PathBuf, String>,
    memory: Arc<Mutex<ProjectMemory>>,
) -> Result<(AiAnalysis, VulnContext)> {
    let toolbox = ToolBox::new(file_contents.clone());
    let mut vuln_ctx = VulnContext::default();

    let file_ctx = gather_static_context(finding, file_contents);
    vuln_ctx.file_context = file_ctx.clone();

    let dataflow = trace_static_dataflow(finding, file_contents, &file_ctx);
    vuln_ctx.dataflow = dataflow.clone();

    // Quick exit for obvious cases
    if file_ctx.is_test_file && finding.rule_id.starts_with("SEC") {
        vuln_ctx.agent_trace.push(AgentStep {
            agent: "react".into(),
            action: "quick_exit".into(),
            result_summary: "Test file secret — auto false positive".into(),
        });
        return Ok((AiAnalysis {
            is_false_positive: true,
            confidence: 0.95,
            reasoning: format!("Secret in test/fixture file ({})", finding.file_path.display()),
            suggested_fix: None,
        }, vuln_ctx));
    }

    let memory_snapshot = memory.lock().unwrap().summary();

    let system_prompt = build_react_system_prompt(finding, &file_ctx, &dataflow, &memory_snapshot);
    let mut conversation: Vec<ReActTurn> = vec![
        ReActTurn { role: "system".into(), content: system_prompt },
    ];

    let mut analysis = None;
    let mut step_count = 0;

    while step_count < MAX_STEPS {
        step_count += 1;

        let prompt_text = format_conversation(&conversation);
        let response = call_with_retry(client, config, &prompt_text).await
            .unwrap_or_else(|_| "I'll make my assessment based on available information. {\"tool\": \"done\", \"args\": {\"verdict\": \"true_positive\", \"confidence\": \"0.5\", \"reasoning\": \"LLM call failed, defaulting to scanner verdict\"}}".to_string());

        conversation.push(ReActTurn {
            role: "assistant".into(),
            content: response.clone(),
        });

        memory.lock().unwrap().learn_from_response(&response);

        let action = parse_agent_action(&response);

        match action {
            AgentAction::ToolUse(call) => {
                let result = toolbox.execute(&call);
                vuln_ctx.agent_trace.push(AgentStep {
                    agent: "react".into(),
                    action: format!("tool:{}", call.tool),
                    result_summary: result.output.chars().take(150).collect(),
                });

                let observation = format!(
                    "[Tool Result: {}]\n{}",
                    call.tool,
                    if result.output.len() > 2000 {
                        format!("{}...(truncated)", &result.output[..2000])
                    } else {
                        result.output.clone()
                    }
                );

                conversation.push(ReActTurn {
                    role: "user".into(),
                    content: observation,
                });
            }
            AgentAction::Done(verdict) => {
                let confidence: f32 = verdict.confidence.parse().unwrap_or(0.5);
                let is_fp = verdict.verdict.contains("false");

                let candidate = AiAnalysis {
                    is_false_positive: is_fp,
                    confidence: confidence.clamp(0.0, 1.0),
                    reasoning: verdict.reasoning.chars().take(500).collect(),
                    suggested_fix: verdict.suggested_fix.filter(|s| !s.is_empty()),
                };

                vuln_ctx.agent_trace.push(AgentStep {
                    agent: "react".into(),
                    action: "verdict".into(),
                    result_summary: format!("fp={} conf={:.2}", is_fp, confidence),
                });

                // Self-reflection for low-confidence or surprising verdicts
                if should_reflect(&candidate, &file_ctx, &dataflow) {
                    if let Some(refined) = self_reflect(
                        &candidate, &conversation, config, client, &mut vuln_ctx,
                    ).await {
                        analysis = Some(refined);
                    } else {
                        analysis = Some(candidate);
                    }
                } else {
                    analysis = Some(candidate);
                }
                break;
            }
            AgentAction::Thinking(thought) => {
                vuln_ctx.agent_trace.push(AgentStep {
                    agent: "react".into(),
                    action: "think".into(),
                    result_summary: thought.chars().take(150).collect(),
                });

                conversation.push(ReActTurn {
                    role: "user".into(),
                    content: "Continue your analysis. Use a tool or call 'done' with your verdict.".into(),
                });
            }
        }
    }

    let final_analysis = analysis.unwrap_or(AiAnalysis {
        is_false_positive: false,
        confidence: 0.3,
        reasoning: format!("Agent reached step limit ({}) without verdict — defaulting to scanner result", MAX_STEPS),
        suggested_fix: None,
    });

    Ok((final_analysis, vuln_ctx))
}

// ── Self-Reflection ──

fn should_reflect(analysis: &AiAnalysis, file_ctx: &super::agents::FileContext, dataflow: &super::agents::DataflowTrace) -> bool {
    if analysis.confidence < 0.6 {
        return true;
    }
    // Contradiction: says false positive but there's unsanitized user input reaching a sink
    if analysis.is_false_positive && dataflow.is_user_controlled && !dataflow.has_sanitization && !dataflow.sinks.is_empty() {
        return true;
    }
    // Contradiction: says true positive but it's a test file
    if !analysis.is_false_positive && file_ctx.is_test_file {
        return true;
    }
    false
}

async fn self_reflect(
    candidate: &AiAnalysis,
    conversation: &[ReActTurn],
    config: &AiConfig,
    client: &reqwest::Client,
    vuln_ctx: &mut VulnContext,
) -> Option<AiAnalysis> {
    let last_few: String = conversation.iter()
        .rev()
        .take(4)
        .collect::<Vec<_>>()
        .iter()
        .rev()
        .map(|t| format!("[{}]: {}", t.role, &t.content[..t.content.len().min(300)]))
        .collect::<Vec<_>>()
        .join("\n\n");

    let reflection_prompt = format!(
        r#"You are reviewing your own security analysis for potential errors.

Your previous verdict:
- False positive: {}
- Confidence: {:.2}
- Reasoning: {}

Recent analysis steps:
{}

SELF-CHECK:
1. Does your reasoning contain any contradictions?
2. Did you miss any important evidence?
3. Are you being too confident or not confident enough?
4. Would a senior security engineer agree with your assessment?

If your verdict was correct, respond with:
{{"action": "confirm", "confidence_adjustment": 0.0}}

If you want to change your verdict, respond with:
{{"action": "revise", "false_positive": true/false, "confidence": 0.0-1.0, "reasoning": "revised explanation"}}"#,
        candidate.is_false_positive,
        candidate.confidence,
        candidate.reasoning,
        last_few,
    );

    for _ in 0..MAX_REFLECTION_RETRIES {
        if let Ok(resp) = call_with_retry(client, config, &reflection_prompt).await {
            vuln_ctx.agent_trace.push(AgentStep {
                agent: "self_reflection".into(),
                action: "reflect".into(),
                result_summary: resp.chars().take(150).collect(),
            });

            if let Some(json_str) = extract_json_object(&resp) {
                if json_str.contains("\"revise\"") {
                    #[derive(Deserialize)]
                    struct Revision {
                        #[serde(default)]
                        false_positive: bool,
                        #[serde(default = "rev_default_conf")]
                        confidence: f32,
                        #[serde(default)]
                        reasoning: String,
                    }
                    fn rev_default_conf() -> f32 { 0.5 }

                    if let Ok(rev) = serde_json::from_str::<Revision>(&json_str) {
                        return Some(AiAnalysis {
                            is_false_positive: rev.false_positive,
                            confidence: rev.confidence.clamp(0.0, 1.0),
                            reasoning: format!("[revised after reflection] {}", rev.reasoning)
                                .chars().take(500).collect(),
                            suggested_fix: candidate.suggested_fix.clone(),
                        });
                    }
                }
            }
            return None;
        }
    }
    None
}

// ── Prompt construction ──

fn build_react_system_prompt(
    finding: &Finding,
    file_ctx: &super::agents::FileContext,
    dataflow: &super::agents::DataflowTrace,
    memory: &str,
) -> String {
    let sources_str = dataflow.sources.iter()
        .map(|s| format!("  L{}: {}", s.line, s.expression))
        .collect::<Vec<_>>().join("\n");
    let sinks_str = dataflow.sinks.iter()
        .map(|s| format!("  L{}: {}", s.line, s.expression))
        .collect::<Vec<_>>().join("\n");
    let sanitizers_str = dataflow.sanitizers.iter()
        .map(|s| format!("  L{}: {}", s.line, s.expression))
        .collect::<Vec<_>>().join("\n");

    format!(
        r#"You are an expert security analyst investigating a potential vulnerability. You have tools to explore the codebase and must gather enough evidence before making a judgment.

## The Finding
Rule: {rule_id} — {title}
Severity: {severity}
File: {file}:{line}
Description: {desc}
Matched: {matched}

## Initial Context (gathered automatically)
Language: {lang}
Test file: {is_test}
Generated: {is_gen}
Function: {func_sig}
Callers: {callers}

## Static Dataflow Analysis
Sources (user input): {sources}
Sanitizers: {sanitizers}
Sinks (dangerous ops): {sinks}

## Project Knowledge
{memory}

## Your Tools
{tools}

## How to Work
1. THINK about what information you need to make a confident judgment
2. USE TOOLS to gather that information (read files, search code, trace data flow)
3. After each tool result, REASON about what you learned and what you still need
4. When you have enough evidence, call the "done" tool with your verdict

IMPORTANT RULES:
- Always investigate before judging. Never call "done" as your first action.
- If you're unsure, use more tools to gather evidence.
- Consider the FULL picture: is this reachable? is input sanitized? is it in test code?
- Respond with a JSON tool call: {{"tool": "tool_name", "args": {{...}}}}
- For your final answer: {{"tool": "done", "args": {{"verdict": "true_positive/false_positive", "confidence": "0.85", "reasoning": "...", "suggested_fix": "..." or null}}}}

Begin your investigation."#,
        rule_id = finding.rule_id,
        title = finding.title,
        severity = finding.severity,
        file = finding.file_path.display(),
        line = finding.line_number,
        desc = finding.description,
        matched = &finding.matched_text[..finding.matched_text.len().min(100)],
        lang = file_ctx.language,
        is_test = file_ctx.is_test_file,
        is_gen = file_ctx.is_generated,
        func_sig = file_ctx.function_signature,
        callers = if file_ctx.callers.is_empty() { "(none found)".to_string() } else { file_ctx.callers.join(", ") },
        sources = if sources_str.is_empty() { "(none detected)".to_string() } else { sources_str },
        sanitizers = if sanitizers_str.is_empty() { "(none detected)".to_string() } else { sanitizers_str },
        sinks = if sinks_str.is_empty() { "(none detected)".to_string() } else { sinks_str },
        memory = memory,
        tools = ToolBox::available_tools(),
    )
}

fn format_conversation(turns: &[ReActTurn]) -> String {
    turns.iter()
        .map(|t| format!("[{}]\n{}", t.role, t.content))
        .collect::<Vec<_>>()
        .join("\n\n")
}

fn parse_agent_action(response: &str) -> AgentAction {
    if let Some(json_str) = extract_json_object(response) {
        if let Ok(call) = serde_json::from_str::<ToolCall>(&json_str) {
            if call.tool == "done" {
                if let Ok(verdict) = serde_json::from_value::<DoneVerdict>(
                    serde_json::Value::Object(
                        call.args.iter()
                            .map(|(k, v)| (k.clone(), serde_json::Value::String(v.clone())))
                            .collect()
                    )
                ) {
                    return AgentAction::Done(verdict);
                }
            }
            return AgentAction::ToolUse(call);
        }

        if json_str.contains("\"verdict\"") {
            if let Ok(verdict) = serde_json::from_str::<DoneVerdict>(&json_str) {
                return AgentAction::Done(verdict);
            }
        }
    }

    AgentAction::Thinking(response.chars().take(200).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_tool_call() {
        let resp = r#"Let me check the file. {"tool": "read_file", "args": {"path": "src/app.py"}}"#;
        match parse_agent_action(resp) {
            AgentAction::ToolUse(call) => {
                assert_eq!(call.tool, "read_file");
                assert_eq!(call.args.get("path").unwrap(), "src/app.py");
            }
            _ => panic!("Expected ToolUse"),
        }
    }

    #[test]
    fn test_parse_done_action() {
        let resp = r#"{"tool": "done", "args": {"verdict": "true_positive", "confidence": "0.9", "reasoning": "SQL injection confirmed"}}"#;
        match parse_agent_action(resp) {
            AgentAction::Done(v) => {
                assert_eq!(v.verdict, "true_positive");
                assert_eq!(v.confidence, "0.9");
            }
            _ => panic!("Expected Done"),
        }
    }

    #[test]
    fn test_parse_thinking() {
        let resp = "I need to think about this more carefully. The code seems suspicious.";
        match parse_agent_action(resp) {
            AgentAction::Thinking(_) => {}
            _ => panic!("Expected Thinking"),
        }
    }

    #[test]
    fn test_should_reflect_low_confidence() {
        let analysis = AiAnalysis {
            is_false_positive: false,
            confidence: 0.4,
            reasoning: "not sure".into(),
            suggested_fix: None,
        };
        let ctx = super::super::agents::FileContext::default();
        let df = super::super::agents::DataflowTrace::default();
        assert!(should_reflect(&analysis, &ctx, &df));
    }

    #[test]
    fn test_should_not_reflect_high_confidence() {
        let analysis = AiAnalysis {
            is_false_positive: true,
            confidence: 0.9,
            reasoning: "clearly a test".into(),
            suggested_fix: None,
        };
        let ctx = super::super::agents::FileContext { is_test_file: true, ..Default::default() };
        let df = super::super::agents::DataflowTrace::default();
        assert!(!should_reflect(&analysis, &ctx, &df));
    }

    #[test]
    fn test_should_reflect_contradiction_fp_with_taint() {
        let analysis = AiAnalysis {
            is_false_positive: true,
            confidence: 0.8,
            reasoning: "seems fine".into(),
            suggested_fix: None,
        };
        let ctx = super::super::agents::FileContext::default();
        let df = super::super::agents::DataflowTrace {
            is_user_controlled: true,
            has_sanitization: false,
            sinks: vec![super::super::agents::DataflowNode {
                kind: "sink".into(), expression: "execute(q)".into(), file: String::new(), line: 10,
            }],
            ..Default::default()
        };
        assert!(should_reflect(&analysis, &ctx, &df));
    }

    #[test]
    fn test_project_memory_learn() {
        let mut mem = ProjectMemory::default();
        mem.learn_from_response("This is a Flask application using SQLAlchemy ORM");
        assert_eq!(mem.framework.as_deref(), Some("Flask"));
        assert_eq!(mem.orm_used.as_deref(), Some("SQLAlchemy"));
    }

    #[test]
    fn test_project_memory_summary() {
        let mem = ProjectMemory {
            framework: Some("Flask".into()),
            orm_used: Some("SQLAlchemy".into()),
            ..Default::default()
        };
        let summary = mem.summary();
        assert!(summary.contains("Flask"));
        assert!(summary.contains("SQLAlchemy"));
    }
}
