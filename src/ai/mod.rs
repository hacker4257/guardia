mod prompt;

use anyhow::Result;
use indicatif::{ProgressBar, ProgressStyle};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;

use crate::scanner::Finding;

#[derive(Debug, Clone)]
pub struct AiConfig {
    pub provider: AiProvider,
    pub model: String,
    pub base_url: String,
    pub api_key: Option<String>,
    pub timeout: Duration,
    pub max_concurrency: usize,
    pub max_retries: u32,
}

#[derive(Debug, Clone)]
pub enum AiProvider {
    Ollama,
    OpenAI,
    Anthropic,
}

impl AiConfig {
    pub fn new(provider_str: &str, model: &str, custom_url: Option<&str>, timeout_secs: u64, concurrency: usize) -> Self {
        let (provider, default_url, api_key) = match provider_str {
            "openai" => (
                AiProvider::OpenAI,
                "https://api.openai.com/v1",
                std::env::var("OPENAI_API_KEY").ok(),
            ),
            "anthropic" | "claude" => (
                AiProvider::Anthropic,
                "https://api.anthropic.com/v1",
                std::env::var("ANTHROPIC_API_KEY").ok(),
            ),
            _ => (
                AiProvider::Ollama,
                "http://localhost:11434",
                None,
            ),
        };

        Self {
            provider,
            model: model.to_string(),
            base_url: custom_url.unwrap_or(default_url).to_string(),
            api_key,
            timeout: Duration::from_secs(timeout_secs),
            max_concurrency: concurrency,
            max_retries: 2,
        }
    }

    pub fn missing_api_key(&self) -> bool {
        matches!(self.provider, AiProvider::OpenAI | AiProvider::Anthropic) && self.api_key.is_none()
    }

    pub fn provider_name(&self) -> &str {
        match self.provider {
            AiProvider::Ollama => "Ollama",
            AiProvider::OpenAI => "OpenAI",
            AiProvider::Anthropic => "Anthropic",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiAnalysis {
    pub is_false_positive: bool,
    pub confidence: f32,
    pub reasoning: String,
    pub suggested_fix: Option<String>,
}

pub async fn analyze_findings(
    findings: &[Finding],
    config: &AiConfig,
    file_contents: &HashMap<PathBuf, String>,
) -> Result<Vec<(usize, AiAnalysis)>> {
    let client = reqwest::Client::builder()
        .timeout(config.timeout)
        .build()?;

    let semaphore = Arc::new(Semaphore::new(config.max_concurrency));
    let client = Arc::new(client);
    let config = Arc::new(config.clone());

    let pb = ProgressBar::new(findings.len() as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("  {spinner:.green} AI analyzing [{bar:30.green/dim}] {pos}/{len} {msg}")
            .unwrap()
            .progress_chars("━╸─"),
    );

    let mut handles = Vec::new();

    for (idx, finding) in findings.iter().enumerate() {
        let context = file_contents
            .get(&finding.file_path)
            .map(|c| extract_context(c, finding.line_number, 5))
            .unwrap_or_default();

        let user_prompt = prompt::build_analysis_prompt(finding, &context);
        let sem = semaphore.clone();
        let cli = client.clone();
        let cfg = config.clone();
        let pb = pb.clone();
        let title = finding.title.clone();

        let handle = tokio::spawn(async move {
            let _permit = sem.acquire().await.unwrap();
            pb.set_message(format!("#{} {}", idx + 1, title));

            let result = call_with_retry(&cli, &cfg, &user_prompt).await;
            pb.inc(1);

            match result {
                Ok(text) => Some((idx, parse_ai_response(&text))),
                Err(_) => None,
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
    results.sort_by_key(|(idx, _)| *idx);
    Ok(results)
}

async fn call_with_retry(
    client: &reqwest::Client,
    config: &AiConfig,
    prompt: &str,
) -> Result<String> {
    let mut last_err = anyhow::anyhow!("no attempts made");

    for attempt in 0..=config.max_retries {
        if attempt > 0 {
            tokio::time::sleep(Duration::from_millis(500 * attempt as u64)).await;
        }

        let result = match &config.provider {
            AiProvider::Ollama => call_ollama(client, config, prompt).await,
            AiProvider::OpenAI => call_openai(client, config, prompt).await,
            AiProvider::Anthropic => call_anthropic(client, config, prompt).await,
        };

        match result {
            Ok(text) if !text.trim().is_empty() => return Ok(text),
            Ok(_) => last_err = anyhow::anyhow!("empty response"),
            Err(e) => last_err = e,
        }
    }

    Err(last_err)
}

pub fn apply_ai_filter(
    findings: &mut Vec<Finding>,
    analyses: &[(usize, AiAnalysis)],
) -> usize {
    let false_positive_indices: std::collections::HashSet<usize> = analyses
        .iter()
        .filter(|(_, a)| a.is_false_positive && a.confidence > 0.7)
        .map(|(idx, _)| *idx)
        .collect();

    let count = false_positive_indices.len();

    let mut idx = 0;
    findings.retain(|_| {
        let keep = !false_positive_indices.contains(&idx);
        idx += 1;
        keep
    });

    count
}

pub fn build_ai_annotations(
    _findings: &[Finding],
    analyses: &[(usize, AiAnalysis)],
) -> HashMap<usize, AiAnalysis> {
    let mut map = HashMap::new();
    for (idx, analysis) in analyses {
        if !analysis.is_false_positive {
            map.insert(*idx, analysis.clone());
        }
    }
    map
}

fn extract_context(content: &str, line: usize, radius: usize) -> String {
    let lines: Vec<&str> = content.lines().collect();
    let start = line.saturating_sub(radius + 1);
    let end = (line + radius).min(lines.len());
    lines[start..end]
        .iter()
        .enumerate()
        .map(|(i, l)| format!("{:>4} | {}", start + i + 1, l))
        .collect::<Vec<_>>()
        .join("\n")
}

// ── Ollama ──

#[derive(Serialize)]
struct OllamaRequest {
    model: String,
    prompt: String,
    stream: bool,
}

#[derive(Deserialize)]
struct OllamaResponse {
    response: String,
}

async fn call_ollama(client: &reqwest::Client, config: &AiConfig, prompt: &str) -> Result<String> {
    let full_prompt = format!("{}\n\n{}", prompt::SYSTEM_PROMPT, prompt);
    let resp = client
        .post(format!("{}/api/generate", config.base_url))
        .json(&OllamaRequest {
            model: config.model.clone(),
            prompt: full_prompt,
            stream: false,
        })
        .send()
        .await?;

    if !resp.status().is_success() {
        anyhow::bail!("Ollama returned {}: {}", resp.status(), resp.text().await.unwrap_or_default());
    }

    Ok(resp.json::<OllamaResponse>().await?.response)
}

// ── OpenAI (and compatible) ──

#[derive(Serialize)]
struct OpenAIRequest {
    model: String,
    messages: Vec<OpenAIMessage>,
    temperature: f32,
}

#[derive(Serialize, Deserialize)]
struct OpenAIMessage {
    role: String,
    content: String,
}

#[derive(Deserialize)]
struct OpenAIResponse {
    choices: Vec<OpenAIChoice>,
}

#[derive(Deserialize)]
struct OpenAIChoice {
    message: OpenAIMessage,
}

async fn call_openai(client: &reqwest::Client, config: &AiConfig, prompt: &str) -> Result<String> {
    let mut req = client
        .post(format!("{}/chat/completions", config.base_url))
        .json(&OpenAIRequest {
            model: config.model.clone(),
            messages: vec![
                OpenAIMessage {
                    role: "system".to_string(),
                    content: prompt::SYSTEM_PROMPT.to_string(),
                },
                OpenAIMessage {
                    role: "user".to_string(),
                    content: prompt.to_string(),
                },
            ],
            temperature: 0.1,
        });

    if let Some(key) = &config.api_key {
        req = req.header("Authorization", format!("Bearer {}", key));
    }

    let resp = req.send().await?;

    if !resp.status().is_success() {
        anyhow::bail!("OpenAI returned {}: {}", resp.status(), resp.text().await.unwrap_or_default());
    }

    let data = resp.json::<OpenAIResponse>().await?;
    Ok(data.choices.first().map(|c| c.message.content.clone()).unwrap_or_default())
}

// ── Anthropic ──

#[derive(Serialize)]
struct AnthropicRequest {
    model: String,
    max_tokens: u32,
    system: String,
    messages: Vec<AnthropicMessage>,
}

#[derive(Serialize, Deserialize)]
struct AnthropicMessage {
    role: String,
    content: String,
}

#[derive(Deserialize)]
struct AnthropicResponse {
    content: Vec<AnthropicContent>,
}

#[derive(Deserialize)]
struct AnthropicContent {
    text: String,
}

async fn call_anthropic(client: &reqwest::Client, config: &AiConfig, prompt: &str) -> Result<String> {
    let resp = client
        .post(format!("{}/messages", config.base_url))
        .header("x-api-key", config.api_key.as_deref().unwrap_or(""))
        .header("anthropic-version", "2023-06-01")
        .json(&AnthropicRequest {
            model: config.model.clone(),
            max_tokens: 1024,
            system: prompt::SYSTEM_PROMPT.to_string(),
            messages: vec![AnthropicMessage {
                role: "user".to_string(),
                content: prompt.to_string(),
            }],
        })
        .send()
        .await?;

    if !resp.status().is_success() {
        anyhow::bail!("Anthropic returned {}: {}", resp.status(), resp.text().await.unwrap_or_default());
    }

    let data = resp.json::<AnthropicResponse>().await?;
    Ok(data.content.first().map(|c| c.text.clone()).unwrap_or_default())
}

// ── Response parsing ──

fn parse_ai_response(text: &str) -> AiAnalysis {
    let lower = text.to_lowercase();

    let is_false_positive = lower.contains("false_positive: true")
        || lower.contains("false positive: true")
        || lower.contains("\"false_positive\": true")
        || lower.contains("is_false_positive: true")
        || (lower.contains("this is a false positive") && !lower.contains("not a false positive"));

    let confidence = if lower.contains("confidence: high") || lower.contains("confidence: 0.9") {
        0.9
    } else if lower.contains("confidence: medium") || lower.contains("confidence: 0.7") || lower.contains("confidence: 0.6") {
        0.7
    } else if lower.contains("confidence: low") || lower.contains("confidence: 0.3") {
        0.3
    } else {
        0.5
    };

    let reasoning = extract_field(text, "REASONING:")
        .unwrap_or_else(|| text.lines().take(3).collect::<Vec<_>>().join(" "))
        .chars()
        .take(300)
        .collect();

    let suggested_fix = extract_code_block(text);

    AiAnalysis {
        is_false_positive,
        confidence,
        reasoning,
        suggested_fix,
    }
}

fn extract_field(text: &str, field: &str) -> Option<String> {
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix(field) {
            let val = rest.trim().to_string();
            if !val.is_empty() {
                return Some(val);
            }
        }
    }
    None
}

fn extract_code_block(text: &str) -> Option<String> {
    let start = text.find("```")?;
    let after = &text[start + 3..];
    let nl = after.find('\n')?;
    let code_start = &after[nl + 1..];
    let end = code_start.find("```")?;
    let code = code_start[..end].trim();
    if code.is_empty() { None } else { Some(code.to_string()) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_true_positive() {
        let resp = "FALSE_POSITIVE: false\nCONFIDENCE: high\nREASONING: This is a real SQL injection.\nSUGGESTED_FIX:\n```python\ncursor.execute('SELECT * FROM users WHERE id = ?', (uid,))\n```";
        let analysis = parse_ai_response(resp);
        assert!(!analysis.is_false_positive);
        assert!(analysis.confidence > 0.8);
        assert!(analysis.reasoning.contains("SQL injection"));
        assert!(analysis.suggested_fix.is_some());
    }

    #[test]
    fn test_parse_false_positive() {
        let resp = "FALSE_POSITIVE: true\nCONFIDENCE: high\nREASONING: This is a test file with example data, not a real secret.";
        let analysis = parse_ai_response(resp);
        assert!(analysis.is_false_positive);
        assert!(analysis.confidence > 0.8);
    }

    #[test]
    fn test_parse_messy_response() {
        let resp = "I think this is a false positive because the value is clearly a placeholder.\nconfidence: medium\nNo fix needed.";
        let analysis = parse_ai_response(resp);
        assert!(analysis.confidence >= 0.5);
        assert!(!analysis.reasoning.is_empty());
    }

    #[test]
    fn test_extract_code_block() {
        let text = "Here is the fix:\n```python\nprint('hello')\n```\nDone.";
        assert_eq!(extract_code_block(text), Some("print('hello')".to_string()));
    }

    #[test]
    fn test_extract_code_block_none() {
        assert_eq!(extract_code_block("no code here"), None);
    }
}
