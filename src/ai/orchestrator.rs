use anyhow::Result;
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Semaphore;

use crate::scanner::Finding;
use super::agents::*;
use super::agent_prompts;
use super::{AiConfig, AiAnalysis, call_with_retry};

#[derive(Debug, Clone, serde::Deserialize, Default)]
#[allow(dead_code)]
struct ContextAgentResponse {
    #[serde(default)]
    is_dead_code: bool,
    #[serde(default)]
    is_reachable_from_user_input: bool,
    #[serde(default)]
    framework_detected: String,
    #[serde(default)]
    auth_protected: bool,
    #[serde(default)]
    additional_context: String,
}

#[derive(Debug, Clone, serde::Deserialize, Default)]
#[allow(dead_code)]
struct DataflowAgentResponse {
    #[serde(default)]
    taint_reaches_sink: bool,
    #[serde(default)]
    sanitization_adequate: bool,
    #[serde(default)]
    data_flow_description: String,
    #[serde(default)]
    missing_sanitization: Option<String>,
}

#[derive(Debug, Clone, serde::Deserialize, Default)]
struct ExploitAgentResponse {
    #[serde(default)]
    exploitable: bool,
    #[serde(default)]
    attack_vector: String,
    #[serde(default)]
    prerequisites: Vec<String>,
    #[serde(default)]
    impact: String,
    #[serde(default)]
    cvss_estimate: Option<f32>,
    #[serde(default)]
    poc_sketch: Option<String>,
}

#[derive(Debug, Clone, serde::Deserialize)]
struct SynthesisResponse {
    #[serde(default)]
    false_positive: bool,
    #[serde(default = "default_confidence")]
    confidence: f32,
    #[serde(default)]
    reasoning: String,
    #[serde(default)]
    suggested_fix: Option<String>,
    #[serde(default)]
    attack_narrative: Option<String>,
}

fn default_confidence() -> f32 { 0.5 }

pub async fn run_agent_pipeline(
    findings: &[Finding],
    config: &AiConfig,
    file_contents: &HashMap<PathBuf, String>,
) -> Result<Vec<(usize, AiAnalysis, VulnContext)>> {
    let client = reqwest::Client::builder()
        .timeout(config.timeout)
        .build()?;

    let semaphore = Arc::new(Semaphore::new(config.max_concurrency));
    let client = Arc::new(client);
    let config = Arc::new(config.clone());

    let mp = MultiProgress::new();
    let overall_pb = mp.add(ProgressBar::new(findings.len() as u64));
    overall_pb.set_style(
        ProgressStyle::default_bar()
            .template("  {spinner:.green} Agent pipeline [{bar:30.green/dim}] {pos}/{len} findings")
            .unwrap()
            .progress_chars("━╸─"),
    );

    let mut handles = Vec::new();

    for (idx, finding) in findings.iter().enumerate() {
        let sem = semaphore.clone();
        let cli = client.clone();
        let cfg = config.clone();
        let pb = overall_pb.clone();
        let mp = mp.clone();

        let finding = finding.clone();
        let file_contents = file_contents.clone();

        let handle = tokio::spawn(async move {
            let _permit = sem.acquire().await.unwrap();

            let agent_pb = mp.add(ProgressBar::new_spinner());
            agent_pb.set_style(
                ProgressStyle::default_spinner()
                    .template("    {spinner:.cyan} #{idx} {msg}")
                    .unwrap(),
            );

            let result = analyze_single_finding(
                idx, &finding, &cfg, &cli, &file_contents, &agent_pb,
            ).await;

            agent_pb.finish_and_clear();
            pb.inc(1);

            result
        });

        handles.push(handle);
    }

    let mut results = Vec::new();
    for handle in handles {
        if let Ok(Ok(result)) = handle.await {
            results.push(result);
        }
    }

    overall_pb.finish_and_clear();
    results.sort_by_key(|(idx, _, _)| *idx);
    Ok(results)
}

async fn analyze_single_finding(
    idx: usize,
    finding: &Finding,
    config: &AiConfig,
    client: &reqwest::Client,
    file_contents: &HashMap<PathBuf, String>,
    pb: &ProgressBar,
) -> Result<(usize, AiAnalysis, VulnContext)> {
    let strategy = AnalysisStrategy::from_rule_id(&finding.rule_id);
    let agents = strategy.required_agents();

    let mut vuln_ctx = VulnContext::default();

    // Phase 1: Static analysis (no LLM)
    pb.set_message(format!("{} gathering context...", finding.title));
    let file_ctx = gather_static_context(finding, file_contents);
    vuln_ctx.file_context = file_ctx.clone();

    let dataflow = if agents.iter().any(|a| matches!(a, AgentRole::DataflowTracer)) {
        let df = trace_static_dataflow(finding, file_contents, &file_ctx);
        vuln_ctx.dataflow = df.clone();
        df
    } else {
        DataflowTrace::default()
    };

    // Quick exit: test files with secrets are almost always false positives
    if file_ctx.is_test_file && matches!(strategy, AnalysisStrategy::SecretTriage) {
        vuln_ctx.agent_trace.push(AgentStep {
            agent: "orchestrator".to_string(),
            action: "quick_exit".to_string(),
            result_summary: "Test file with secret pattern — skipping LLM, marking as false positive".to_string(),
        });

        return Ok((idx, AiAnalysis {
            is_false_positive: true,
            confidence: 0.95,
            reasoning: format!(
                "Secret pattern found in test/fixture file ({}). Test files commonly contain example credentials for testing purposes.",
                finding.file_path.display()
            ),
            suggested_fix: None,
        }, vuln_ctx));
    }

    // Phase 2: LLM agents
    let mut agent_results: Vec<(String, String)> = Vec::new();

    // Agent 1: Context Gatherer
    if agents.iter().any(|a| matches!(a, AgentRole::ContextGatherer)) {
        pb.set_message(format!("{} [1/{}] context agent...", finding.title, agents.len()));
        let prompt = agent_prompts::build_context_gatherer_prompt(finding, &file_ctx);
        match call_with_retry(client, config, &prompt).await {
            Ok(resp) => {
                vuln_ctx.agent_trace.push(AgentStep {
                    agent: "context_gatherer".to_string(),
                    action: "analyze_context".to_string(),
                    result_summary: resp.chars().take(200).collect(),
                });
                agent_results.push(("Context".to_string(), resp));
            }
            Err(_) => {
                agent_results.push(("Context".to_string(), "(agent failed)".to_string()));
            }
        }
    }

    // Agent 2: Dataflow Tracer
    if agents.iter().any(|a| matches!(a, AgentRole::DataflowTracer)) {
        pb.set_message(format!("{} [2/{}] dataflow agent...", finding.title, agents.len()));
        let prompt = agent_prompts::build_dataflow_prompt(finding, &file_ctx, &dataflow);
        match call_with_retry(client, config, &prompt).await {
            Ok(resp) => {
                vuln_ctx.agent_trace.push(AgentStep {
                    agent: "dataflow_tracer".to_string(),
                    action: "trace_dataflow".to_string(),
                    result_summary: resp.chars().take(200).collect(),
                });
                agent_results.push(("Dataflow".to_string(), resp));
            }
            Err(_) => {
                agent_results.push(("Dataflow".to_string(), "(agent failed)".to_string()));
            }
        }
    }

    // Agent 3: Exploit Validator
    if agents.iter().any(|a| matches!(a, AgentRole::ExploitValidator)) {
        pb.set_message(format!("{} [3/{}] exploit agent...", finding.title, agents.len()));
        let ctx_result = agent_results.iter()
            .find(|(n, _)| n == "Context")
            .map(|(_, r)| r.as_str())
            .unwrap_or("(not available)");
        let df_result = agent_results.iter()
            .find(|(n, _)| n == "Dataflow")
            .map(|(_, r)| r.as_str())
            .unwrap_or("(not available)");

        let prompt = agent_prompts::build_exploit_prompt(
            finding, &file_ctx, &dataflow, ctx_result, df_result,
        );
        match call_with_retry(client, config, &prompt).await {
            Ok(resp) => {
                if let Some(exploit) = parse_exploit_response(&resp) {
                    vuln_ctx.exploit_assessment = ExploitAssessment {
                        is_exploitable: exploit.exploitable,
                        attack_vector: exploit.attack_vector.clone(),
                        prerequisites: exploit.prerequisites.clone(),
                        impact: exploit.impact.clone(),
                        cvss_estimate: exploit.cvss_estimate,
                        poc_sketch: exploit.poc_sketch.clone(),
                    };
                }
                vuln_ctx.agent_trace.push(AgentStep {
                    agent: "exploit_validator".to_string(),
                    action: "assess_exploitability".to_string(),
                    result_summary: resp.chars().take(200).collect(),
                });
                agent_results.push(("Exploit".to_string(), resp));
            }
            Err(_) => {
                agent_results.push(("Exploit".to_string(), "(agent failed)".to_string()));
            }
        }
    }

    // Agent 4: Synthesizer (final verdict)
    pb.set_message(format!("{} synthesizing...", finding.title));

    let synthesis_prompt = match strategy {
        AnalysisStrategy::SecretTriage => {
            let ctx_result = agent_results.iter()
                .find(|(n, _)| n == "Context")
                .map(|(_, r)| r.as_str())
                .unwrap_or("(not available)");
            agent_prompts::build_secret_synthesis_prompt(finding, &file_ctx, ctx_result)
        }
        _ => {
            let refs: Vec<(&str, &str)> = agent_results.iter()
                .map(|(n, r)| (n.as_str(), r.as_str()))
                .collect();
            agent_prompts::build_synthesis_prompt(finding, &file_ctx, &dataflow, &refs)
        }
    };

    let analysis = match call_with_retry(client, config, &synthesis_prompt).await {
        Ok(resp) => {
            vuln_ctx.agent_trace.push(AgentStep {
                agent: "synthesizer".to_string(),
                action: "final_verdict".to_string(),
                result_summary: resp.chars().take(200).collect(),
            });
            parse_synthesis_response(&resp)
        }
        Err(_) => {
            AiAnalysis {
                is_false_positive: false,
                confidence: 0.3,
                reasoning: "AI synthesis agent failed — defaulting to scanner verdict".to_string(),
                suggested_fix: None,
            }
        }
    };

    Ok((idx, analysis, vuln_ctx))
}

fn parse_exploit_response(text: &str) -> Option<ExploitAgentResponse> {
    let json_str = super::extract_json_object(text)?;
    serde_json::from_str(&json_str).ok()
}

fn parse_synthesis_response(text: &str) -> AiAnalysis {
    if let Some(json_str) = super::extract_json_object(text) {
        if let Ok(resp) = serde_json::from_str::<SynthesisResponse>(&json_str) {
            return AiAnalysis {
                is_false_positive: resp.false_positive,
                confidence: resp.confidence.clamp(0.0, 1.0),
                reasoning: if let Some(narrative) = &resp.attack_narrative {
                    format!("{} | Attack: {}", resp.reasoning, narrative)
                } else {
                    resp.reasoning
                }.chars().take(500).collect(),
                suggested_fix: resp.suggested_fix.filter(|s| !s.is_empty()),
            };
        }
    }

    super::parse_ai_response(text)
}
