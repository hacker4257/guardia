use anyhow::Result;
use indicatif::{ProgressBar, ProgressStyle};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tokio::sync::Semaphore;

use crate::scanner::Finding;
use super::agents::VulnContext;
use super::react::{self, ProjectMemory};
use super::{AiConfig, AiAnalysis};

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
    let memory = Arc::new(Mutex::new(ProjectMemory::default()));

    let pb = ProgressBar::new(findings.len() as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("  {spinner:.green} AI Agent [{bar:30.green/dim}] {pos}/{len} {msg}")
            .unwrap()
            .progress_chars("━╸─"),
    );

    let mut handles = Vec::new();

    for (idx, finding) in findings.iter().enumerate() {
        let sem = semaphore.clone();
        let cli = client.clone();
        let cfg = config.clone();
        let pb = pb.clone();
        let mem = memory.clone();
        let finding = finding.clone();
        let file_contents = file_contents.clone();

        let handle = tokio::spawn(async move {
            let _permit = sem.acquire().await.unwrap();
            pb.set_message(format!("#{} {}", idx + 1, finding.title));

            let result = react::react_analyze(
                &finding, &cfg, &cli, &file_contents, mem,
            ).await;

            pb.inc(1);

            match result {
                Ok((analysis, ctx)) => Some((idx, analysis, ctx)),
                Err(_) => Some((idx, AiAnalysis {
                    is_false_positive: false,
                    confidence: 0.3,
                    reasoning: "Agent pipeline failed — defaulting to scanner verdict".into(),
                    suggested_fix: None,
                }, VulnContext::default()))
            }
        });

        handles.push(handle);
    }

    let mut results = Vec::new();
    for handle in handles {
        if let Ok(Some(result)) = handle.await {
            results.push(result);
        }
    }

    pb.finish_and_clear();
    results.sort_by_key(|(idx, _, _)| *idx);
    Ok(results)
}
