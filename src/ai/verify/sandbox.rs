use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::scanner::Finding;
use crate::ai::agents::VulnContext;
use crate::ai::{AiConfig, call_with_retry};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxResult {
    pub status: VerifyStatus,
    pub output_summary: String,
    pub poc_script: Option<String>,
    pub execution_time_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VerifyStatus {
    Verified,
    Disproved,
    Inconclusive,
    Failed,
}

pub async fn run_sandbox_verification(
    finding: &Finding,
    vuln_ctx: &VulnContext,
    config: &AiConfig,
    client: &reqwest::Client,
    timeout_secs: u64,
) -> Result<SandboxResult> {
    let poc_script = generate_poc_script(finding, vuln_ctx, config, client).await?;

    if poc_script.trim().is_empty() {
        return Ok(SandboxResult {
            status: VerifyStatus::Failed,
            output_summary: "LLM could not generate a PoC script".into(),
            poc_script: None,
            execution_time_ms: 0,
        });
    }

    match execute_in_docker(&poc_script, timeout_secs).await {
        Ok(result) => Ok(result),
        Err(e) => Ok(SandboxResult {
            status: VerifyStatus::Failed,
            output_summary: format!("Docker sandbox failed: {}. Install Docker for PoC verification.", e),
            poc_script: Some(poc_script),
            execution_time_ms: 0,
        }),
    }
}

async fn generate_poc_script(
    finding: &Finding,
    vuln_ctx: &VulnContext,
    config: &AiConfig,
    client: &reqwest::Client,
) -> Result<String> {
    let exploit_info = vuln_ctx.exploit_assessment.poc_sketch
        .as_deref()
        .unwrap_or("(no PoC sketch available)");

    let prompt = format!(
        r#"Generate a minimal Python PoC script to verify this vulnerability.
The script should:
1. Be self-contained (no external dependencies beyond requests/urllib)
2. Print "VULNERABLE" to stdout if the vulnerability is confirmed
3. Print "NOT_VULNERABLE" if the test fails
4. Exit with code 0 on success, 1 on failure
5. Include a timeout of 5 seconds for any network requests

## Vulnerability
Rule: {rule_id} — {title}
Severity: {severity}
File: {file}:{line}
Description: {desc}

## Exploit Assessment
{exploit_info}

## Attack Vector
{attack_vector}

Respond with ONLY the Python script, no markdown fences or explanation."#,
        rule_id = finding.rule_id,
        title = finding.title,
        severity = finding.severity,
        file = finding.file_path.display(),
        line = finding.line_number,
        desc = &finding.description[..finding.description.len().min(300)],
        exploit_info = exploit_info,
        attack_vector = vuln_ctx.exploit_assessment.attack_vector,
    );

    let response = call_with_retry(client, config, &prompt).await?;

    let script = response
        .trim()
        .trim_start_matches("```python")
        .trim_start_matches("```")
        .trim_end_matches("```")
        .trim()
        .to_string();

    Ok(script)
}

async fn execute_in_docker(poc_script: &str, timeout_secs: u64) -> Result<SandboxResult> {
    use std::process::Command;

    let docker_check = Command::new("docker")
        .arg("version")
        .output();

    if docker_check.is_err() || !docker_check.unwrap().status.success() {
        anyhow::bail!("Docker is not available");
    }

    let start = std::time::Instant::now();

    let script_b64 = base64_encode(poc_script);

    let output = Command::new("docker")
        .args([
            "run",
            "--rm",
            "--network=none",
            "--memory=256m",
            "--cpus=1",
            "--read-only",
            "--tmpfs", "/tmp:rw,noexec,nosuid,size=64m",
            "--security-opt", "no-new-privileges",
            &format!("--stop-timeout={}", timeout_secs),
            "python:3.11-slim",
            "sh", "-c",
            &format!(
                "echo '{}' | python3 -c \"import base64,sys; exec(base64.b64decode(sys.stdin.read()).decode())\"",
                script_b64,
            ),
        ])
        .output()?;

    let elapsed = start.elapsed().as_millis() as u64;
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    let status = if stdout.contains("VULNERABLE") {
        VerifyStatus::Verified
    } else if stdout.contains("NOT_VULNERABLE") {
        VerifyStatus::Disproved
    } else if output.status.success() {
        VerifyStatus::Inconclusive
    } else {
        VerifyStatus::Inconclusive
    };

    let output_summary = format!(
        "exit={}, stdout={}, stderr={}",
        output.status.code().unwrap_or(-1),
        stdout.chars().take(200).collect::<String>(),
        stderr.chars().take(200).collect::<String>(),
    );

    Ok(SandboxResult {
        status,
        output_summary,
        poc_script: Some(poc_script.to_string()),
        execution_time_ms: elapsed,
    })
}

fn base64_encode(input: &str) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(input.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base64_encode() {
        let encoded = base64_encode("print('hello')");
        assert!(!encoded.is_empty());
        assert!(encoded.len() > 10);
    }

    #[test]
    fn test_verify_status_variants() {
        let verified = SandboxResult {
            status: VerifyStatus::Verified,
            output_summary: "VULNERABLE found".into(),
            poc_script: Some("print('VULNERABLE')".into()),
            execution_time_ms: 100,
        };
        assert!(matches!(verified.status, VerifyStatus::Verified));
    }
}
