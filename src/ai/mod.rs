mod prompt;

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::scanner::Finding;

#[derive(Debug, Clone)]
pub struct AiConfig {
    pub provider: AiProvider,
    pub model: String,
    pub base_url: String,
    pub api_key: Option<String>,
}

#[derive(Debug, Clone)]
pub enum AiProvider {
    Ollama,
    OpenAI,
    Anthropic,
}

impl AiConfig {
    pub fn ollama(model: &str) -> Self {
        Self {
            provider: AiProvider::Ollama,
            model: model.to_string(),
            base_url: "http://localhost:11434".to_string(),
            api_key: None,
        }
    }

    pub fn openai(model: &str, api_key: &str) -> Self {
        Self {
            provider: AiProvider::OpenAI,
            model: model.to_string(),
            base_url: "https://api.openai.com/v1".to_string(),
            api_key: Some(api_key.to_string()),
        }
    }

    pub fn anthropic(model: &str, api_key: &str) -> Self {
        Self {
            provider: AiProvider::Anthropic,
            model: model.to_string(),
            base_url: "https://api.anthropic.com/v1".to_string(),
            api_key: Some(api_key.to_string()),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AiAnalysis {
    pub is_false_positive: bool,
    pub confidence: f32,
    pub reasoning: String,
    pub suggested_fix: Option<String>,
}

pub async fn analyze_findings(
    findings: &[Finding],
    config: &AiConfig,
    file_contents: &std::collections::HashMap<std::path::PathBuf, String>,
) -> Result<Vec<(usize, AiAnalysis)>> {
    let client = reqwest::Client::new();
    let mut results = Vec::new();

    for (idx, finding) in findings.iter().enumerate() {
        let context = file_contents
            .get(&finding.file_path)
            .map(|c| extract_context(c, finding.line_number, 5))
            .unwrap_or_default();

        let user_prompt = prompt::build_analysis_prompt(finding, &context);

        let response = match &config.provider {
            AiProvider::Ollama => call_ollama(&client, config, &user_prompt).await,
            AiProvider::OpenAI => call_openai(&client, config, &user_prompt).await,
            AiProvider::Anthropic => call_anthropic(&client, config, &user_prompt).await,
        };

        match response {
            Ok(text) => {
                let analysis = parse_ai_response(&text);
                results.push((idx, analysis));
            }
            Err(e) => {
                eprintln!("  AI analysis failed for finding #{}: {}", idx + 1, e);
            }
        }
    }

    Ok(results)
}

pub fn apply_ai_filter(
    findings: &mut Vec<Finding>,
    analyses: &[(usize, AiAnalysis)],
) {
    let false_positive_indices: std::collections::HashSet<usize> = analyses
        .iter()
        .filter(|(_, a)| a.is_false_positive && a.confidence > 0.7)
        .map(|(idx, _)| *idx)
        .collect();

    let mut idx = 0;
    findings.retain(|_| {
        let keep = !false_positive_indices.contains(&idx);
        idx += 1;
        keep
    });
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
    let resp = client
        .post(format!("{}/api/generate", config.base_url))
        .json(&OllamaRequest {
            model: config.model.clone(),
            prompt: prompt.to_string(),
            stream: false,
        })
        .send()
        .await?
        .json::<OllamaResponse>()
        .await?;
    Ok(resp.response)
}

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
    let resp = client
        .post(format!("{}/chat/completions", config.base_url))
        .header("Authorization", format!("Bearer {}", config.api_key.as_deref().unwrap_or("")))
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
        })
        .send()
        .await?
        .json::<OpenAIResponse>()
        .await?;

    Ok(resp.choices.first().map(|c| c.message.content.clone()).unwrap_or_default())
}

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
        .await?
        .json::<AnthropicResponse>()
        .await?;

    Ok(resp.content.first().map(|c| c.text.clone()).unwrap_or_default())
}

fn parse_ai_response(text: &str) -> AiAnalysis {
    let lower = text.to_lowercase();

    let is_false_positive = lower.contains("false positive: true")
        || lower.contains("\"false_positive\": true")
        || lower.contains("is_false_positive: true")
        || (lower.contains("false positive") && !lower.contains("not a false positive"));

    let confidence = if lower.contains("confidence: high") || lower.contains("confidence: 0.9") {
        0.9
    } else if lower.contains("confidence: medium") || lower.contains("confidence: 0.7") {
        0.7
    } else {
        0.5
    };

    let suggested_fix = if let Some(start) = text.find("```") {
        let after = &text[start + 3..];
        if let Some(nl) = after.find('\n') {
            let code_start = &after[nl + 1..];
            if let Some(end) = code_start.find("```") {
                Some(code_start[..end].trim().to_string())
            } else {
                None
            }
        } else {
            None
        }
    } else {
        None
    };

    AiAnalysis {
        is_false_positive,
        confidence,
        reasoning: text.lines().take(3).collect::<Vec<_>>().join(" ").chars().take(200).collect(),
        suggested_fix,
    }
}
