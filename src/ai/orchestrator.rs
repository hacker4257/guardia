use anyhow::Result;
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tokio::sync::Semaphore;

use crate::scanner::Finding;
use super::agents::{VulnContext, AgentStep, AnalysisStrategy};
use super::evidence::EvidenceBoard;
use super::judge;
use super::react::ProjectMemory;
use super::specialist_agents;
use super::{AiConfig, AiAnalysis};

pub async fn run_agent_pipeline(
    findings: &[Finding],
    config: &AiConfig,
    file_contents: &HashMap<PathBuf, String>,
) -> Result<Vec<(usize, AiAnalysis, VulnContext)>> {
    let client = reqwest::Client::builder()
        .timeout(config.timeout)
        .build()?;

    let finding_semaphore = Arc::new(Semaphore::new(config.max_concurrency));
    let llm_semaphore = Arc::new(Semaphore::new(config.max_concurrency * 3));
    let client = Arc::new(client);
    let config = Arc::new(config.clone());
    let memory = Arc::new(Mutex::new(ProjectMemory::default()));

    let multi_pb = MultiProgress::new();
    let main_pb = multi_pb.add(ProgressBar::new(findings.len() as u64));
    main_pb.set_style(
        ProgressStyle::default_bar()
            .template("  {spinner:.green} Findings [{bar:30.green/dim}] {pos}/{len} {msg}")
            .unwrap()
            .progress_chars("━╸─"),
    );

    let mut handles = Vec::new();

    for (idx, finding) in findings.iter().enumerate() {
        let f_sem = finding_semaphore.clone();
        let l_sem = llm_semaphore.clone();
        let cli = client.clone();
        let cfg = config.clone();
        let pb = main_pb.clone();
        let mem = memory.clone();
        let finding = finding.clone();
        let file_contents = file_contents.clone();
        let multi = multi_pb.clone();

        let handle = tokio::spawn(async move {
            let _finding_permit = f_sem.acquire().await.unwrap();
            pb.set_message(format!("#{} {}", idx + 1, &finding.title[..finding.title.len().min(30)]));

            let result = analyze_single_finding(
                idx, &finding, &cfg, &cli, &file_contents, mem, l_sem, &multi,
            ).await;

            pb.inc(1);
            result
        });

        handles.push(handle);
    }

    let mut results = Vec::new();
    for handle in handles {
        if let Ok(result) = handle.await {
            results.push(result);
        }
    }

    main_pb.finish_and_clear();
    results.sort_by_key(|(idx, _, _)| *idx);
    Ok(results)
}

async fn analyze_single_finding(
    idx: usize,
    finding: &Finding,
    config: &AiConfig,
    client: &reqwest::Client,
    file_contents: &HashMap<PathBuf, String>,
    memory: Arc<Mutex<ProjectMemory>>,
    llm_semaphore: Arc<Semaphore>,
    _multi: &MultiProgress,
) -> (usize, AiAnalysis, VulnContext) {
    let board = EvidenceBoard::new_shared();
    let strategy = AnalysisStrategy::from_rule_id(&finding.rule_id);
    let roles = strategy.required_agents();

    let mut agent_handles = Vec::new();

    for role in roles {
        let finding = finding.clone();
        let config = config.clone();
        let client = client.clone();
        let file_contents = file_contents.clone();
        let board = board.clone();
        let memory = memory.clone();
        let sem = llm_semaphore.clone();
        let role = *role;

        let handle = tokio::spawn(async move {
            let _permit = sem.acquire().await.unwrap();

            let result = match role {
                super::agents::AgentRole::ContextGatherer => {
                    specialist_agents::run_context_agent(
                        &finding, &config, &client, &file_contents, board, memory,
                    ).await
                }
                super::agents::AgentRole::DataflowTracer => {
                    specialist_agents::run_dataflow_agent(
                        &finding, &config, &client, &file_contents, board, memory,
                    ).await
                }
                super::agents::AgentRole::ExploitValidator => {
                    specialist_agents::run_exploit_agent(
                        &finding, &config, &client, &file_contents, board, memory,
                    ).await
                }
                super::agents::AgentRole::Synthesizer => {
                    Ok(())
                }
            };

            if let Err(e) = result {
                eprintln!("  Agent {:?} failed for finding #{}: {}", role, finding.rule_id, e);
            }
        });

        agent_handles.push(handle);
    }

    for handle in agent_handles {
        let _ = handle.await;
    }

    let analysis = match judge::run_judge(finding, config, client, board.clone()).await {
        Ok(a) => a,
        Err(_) => AiAnalysis {
            is_false_positive: false,
            confidence: 0.3,
            reasoning: "Judge agent failed — defaulting to scanner verdict".into(),
            suggested_fix: None,
        },
    };

    let board_data = board.lock().unwrap();
    let mut vuln_ctx = VulnContext::default();

    for entry in &board_data.entries {
        vuln_ctx.agent_trace.push(AgentStep {
            agent: entry.source_agent.clone(),
            action: format!("{:?}", entry.category),
            result_summary: entry.content.chars().take(150).collect(),
        });
    }
    for verdict in &board_data.agent_verdicts {
        vuln_ctx.agent_trace.push(AgentStep {
            agent: verdict.agent.clone(),
            action: "verdict".into(),
            result_summary: format!(
                "fp={} conf={:.2}: {}",
                verdict.is_false_positive, verdict.confidence,
                verdict.reasoning.chars().take(100).collect::<String>(),
            ),
        });
    }
    vuln_ctx.agent_trace.push(AgentStep {
        agent: "judge".into(),
        action: "final_verdict".into(),
        result_summary: format!(
            "fp={} conf={:.2}: {}",
            analysis.is_false_positive, analysis.confidence,
            analysis.reasoning.chars().take(100).collect::<String>(),
        ),
    });

    (idx, analysis, vuln_ctx)
}
