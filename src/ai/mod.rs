pub mod agents;
mod agent_prompts;
pub mod orchestrator;
mod prompt;

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::time::Duration;

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

pub(crate) async fn call_with_retry(
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

#[derive(Deserialize)]
struct RawJsonResponse {
    false_positive: Option<bool>,
    confidence: Option<f32>,
    reasoning: Option<String>,
    suggested_fix: Option<String>,
    #[allow(dead_code)]
    fix_description: Option<String>,
}

pub(crate) fn parse_ai_response(text: &str) -> AiAnalysis {
    if let Some(analysis) = try_parse_json(text) {
        return analysis;
    }
    parse_text_fallback(text)
}

fn try_parse_json(text: &str) -> Option<AiAnalysis> {
    let json_str = extract_json_object(text)?;
    let raw: RawJsonResponse = serde_json::from_str(&json_str).ok()?;

    Some(AiAnalysis {
        is_false_positive: raw.false_positive.unwrap_or(false),
        confidence: raw.confidence.unwrap_or(0.5).clamp(0.0, 1.0),
        reasoning: raw.reasoning
            .unwrap_or_default()
            .chars()
            .take(500)
            .collect(),
        suggested_fix: raw.suggested_fix.filter(|s| !s.is_empty()),
    })
}

pub(crate) fn extract_json_object(text: &str) -> Option<String> {
    let start = text.find('{')?;
    let mut depth = 0;
    let mut in_string = false;
    let mut escape_next = false;

    for (i, ch) in text[start..].char_indices() {
        if escape_next {
            escape_next = false;
            continue;
        }
        match ch {
            '\\' if in_string => escape_next = true,
            '"' => in_string = !in_string,
            '{' if !in_string => depth += 1,
            '}' if !in_string => {
                depth -= 1;
                if depth == 0 {
                    return Some(text[start..start + i + 1].to_string());
                }
            }
            _ => {}
        }
    }
    None
}

fn parse_text_fallback(text: &str) -> AiAnalysis {
    let lower = text.to_lowercase();

    let is_false_positive = lower.contains("false_positive: true")
        || lower.contains("false positive: true")
        || lower.contains("\"false_positive\": true")
        || lower.contains("is_false_positive: true")
        || (lower.contains("this is a false positive") && !lower.contains("not a false positive"));

    let confidence = extract_confidence_number(&lower)
        .unwrap_or_else(|| {
            if lower.contains("confidence: high") || lower.contains("high confidence") {
                0.9
            } else if lower.contains("confidence: medium") || lower.contains("medium confidence") {
                0.7
            } else if lower.contains("confidence: low") || lower.contains("low confidence") {
                0.3
            } else {
                0.5
            }
        });

    let reasoning = extract_field(text, "REASONING:")
        .or_else(|| extract_field(text, "reasoning:"))
        .unwrap_or_else(|| text.lines()
            .filter(|l| !l.trim().is_empty())
            .take(3)
            .collect::<Vec<_>>()
            .join(" "))
        .chars()
        .take(500)
        .collect();

    let suggested_fix = extract_code_block(text);

    AiAnalysis {
        is_false_positive,
        confidence: confidence.clamp(0.0, 1.0),
        reasoning,
        suggested_fix,
    }
}

fn extract_confidence_number(text: &str) -> Option<f32> {
    let patterns = ["confidence: ", "confidence\":", "\"confidence\":"];
    for pat in &patterns {
        if let Some(pos) = text.find(pat) {
            let after = &text[pos + pat.len()..];
            let num_str: String = after.trim().chars()
                .take_while(|c| c.is_ascii_digit() || *c == '.')
                .collect();
            if let Ok(val) = num_str.parse::<f32>() {
                return Some(if val > 1.0 { val / 100.0 } else { val });
            }
        }
    }
    None
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
    fn test_parse_json_true_positive() {
        let resp = r#"{"false_positive": false, "confidence": 0.9, "reasoning": "This is a real SQL injection vulnerability.", "suggested_fix": "cursor.execute('SELECT * FROM users WHERE id = ?', (uid,))"}"#;
        let analysis = parse_ai_response(resp);
        assert!(!analysis.is_false_positive);
        assert!(analysis.confidence > 0.8);
        assert!(analysis.reasoning.contains("SQL injection"));
        assert!(analysis.suggested_fix.is_some());
    }

    #[test]
    fn test_parse_json_false_positive() {
        let resp = r#"{"false_positive": true, "confidence": 0.95, "reasoning": "This is AWS's example key AKIAIOSFODNN7EXAMPLE, not a real credential.", "suggested_fix": null}"#;
        let analysis = parse_ai_response(resp);
        assert!(analysis.is_false_positive);
        assert!(analysis.confidence > 0.9);
        assert!(analysis.suggested_fix.is_none());
    }

    #[test]
    fn test_parse_json_with_markdown_wrapper() {
        let resp = "Sure, here's my analysis:\n\n```json\n{\"false_positive\": false, \"confidence\": 0.85, \"reasoning\": \"Command injection via os.system\", \"suggested_fix\": \"subprocess.run(cmd, shell=False)\"}\n```\n";
        let analysis = parse_ai_response(resp);
        assert!(!analysis.is_false_positive);
        assert!(analysis.confidence > 0.8);
    }

    #[test]
    fn test_parse_text_fallback_true_positive() {
        let resp = "FALSE_POSITIVE: false\nCONFIDENCE: high\nREASONING: This is a real SQL injection.\nSUGGESTED_FIX:\n```python\ncursor.execute('SELECT * FROM users WHERE id = ?', (uid,))\n```";
        let analysis = parse_ai_response(resp);
        assert!(!analysis.is_false_positive);
        assert!(analysis.confidence > 0.8);
        assert!(analysis.suggested_fix.is_some());
    }

    #[test]
    fn test_parse_text_fallback_false_positive() {
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
    fn test_parse_numeric_confidence() {
        let resp = r#"{"false_positive": false, "confidence": 0.73, "reasoning": "Moderate risk.", "suggested_fix": null}"#;
        let analysis = parse_ai_response(resp);
        assert!((analysis.confidence - 0.73).abs() < 0.01);
    }

    #[test]
    fn test_confidence_clamped() {
        let resp = r#"{"false_positive": false, "confidence": 1.5, "reasoning": "Over-confident.", "suggested_fix": null}"#;
        let analysis = parse_ai_response(resp);
        assert!(analysis.confidence <= 1.0);
    }

    #[test]
    fn test_extract_json_nested() {
        let json = r#"blah {"false_positive": true, "reasoning": "has \"quotes\" inside"} blah"#;
        let extracted = extract_json_object(json);
        assert!(extracted.is_some());
        assert!(extracted.unwrap().starts_with('{'));
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
