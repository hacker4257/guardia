use anyhow::{Result, bail};
use serde::Serialize;
use sha2::{Sha256, Digest};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};

use super::AiProvider;

static REMOTE_WARNING_SHOWN: AtomicBool = AtomicBool::new(false);

#[derive(Debug, Clone)]
pub struct PrivacyConfig {
    pub mode: PrivacyMode,
    pub audit_log_path: Option<PathBuf>,
    pub sanitize_variables: bool,
    pub sanitize_strings: bool,
    pub strip_comments: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub enum PrivacyMode {
    LocalOnly,
    SanitizedRemote,
    Unrestricted,
}

impl Default for PrivacyConfig {
    fn default() -> Self {
        Self {
            mode: PrivacyMode::SanitizedRemote,
            audit_log_path: Some(PathBuf::from("guardia-audit.jsonl")),
            sanitize_variables: true,
            sanitize_strings: true,
            strip_comments: true,
        }
    }
}

impl PrivacyConfig {
    pub fn from_mode_str(mode: &str) -> Self {
        let mode = match mode {
            "local-only" => PrivacyMode::LocalOnly,
            "unrestricted" => PrivacyMode::Unrestricted,
            _ => PrivacyMode::SanitizedRemote,
        };
        Self { mode, ..Default::default() }
    }
}

// ── Data Classification ──

#[derive(Debug, Clone, PartialEq, Serialize)]
pub enum DataClass {
    Public,
    Internal,
    Confidential,
    Restricted,
}

pub fn classify_content(text: &str) -> DataClass {
    let lower = text.to_lowercase();

    let restricted_patterns = [
        "password", "secret_key", "private_key", "-----begin",
        "api_key", "access_token", "refresh_token", "ssn",
        "credit_card", "social_security",
    ];
    if restricted_patterns.iter().any(|p| lower.contains(p)) {
        return DataClass::Restricted;
    }

    let confidential_patterns = [
        "database_url", "connection_string", "smtp_",
        "aws_", "azure_", "gcp_", "jwt", "bearer",
        "authorization", "cookie", "session",
    ];
    if confidential_patterns.iter().any(|p| lower.contains(p)) {
        return DataClass::Confidential;
    }

    let internal_patterns = [
        "internal", "proprietary", "copyright",
        "trade secret", "do not distribute",
    ];
    if internal_patterns.iter().any(|p| lower.contains(p)) {
        return DataClass::Internal;
    }

    DataClass::Public
}

// ── Code Sanitizer ──

pub fn sanitize_code(text: &str, config: &PrivacyConfig) -> String {
    if config.mode == PrivacyMode::Unrestricted {
        return text.to_string();
    }

    let mut result = text.to_string();

    if config.strip_comments {
        result = strip_comments(&result);
    }
    if config.sanitize_strings {
        result = sanitize_string_literals(&result);
    }
    if config.sanitize_variables {
        result = sanitize_variable_names(&result);
    }

    result
}

fn strip_comments(text: &str) -> String {
    let mut result = Vec::new();
    let mut in_block_comment = false;

    for line in text.lines() {
        let trimmed = line.trim();

        if in_block_comment {
            if trimmed.contains("*/") {
                in_block_comment = false;
            }
            continue;
        }

        if trimmed.starts_with("/*") {
            in_block_comment = true;
            if trimmed.contains("*/") {
                in_block_comment = false;
            }
            continue;
        }

        if trimmed.starts_with("//") || trimmed.starts_with('#') && !trimmed.starts_with("#include") && !trimmed.starts_with("#!") {
            continue;
        }

        if let Some(pos) = line.find("//") {
            result.push(line[..pos].trim_end().to_string());
        } else if let Some(pos) = line.find(" #") {
            if !line[..pos].contains('"') && !line[..pos].contains('\'') {
                result.push(line[..pos].trim_end().to_string());
            } else {
                result.push(line.to_string());
            }
        } else {
            result.push(line.to_string());
        }
    }

    result.join("\n")
}

fn sanitize_string_literals(text: &str) -> String {
    let mut result = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    let mut string_count = 0u32;

    while let Some(ch) = chars.next() {
        if ch == '"' || ch == '\'' {
            let quote = ch;
            result.push(quote);
            let mut content_len = 0;
            let mut escaped = false;
            loop {
                match chars.next() {
                    Some('\\') if !escaped => {
                        escaped = true;
                        content_len += 1;
                    }
                    Some(c) if c == quote && !escaped => {
                        string_count += 1;
                        result.push_str(&format!("<STR_{},len={}>", string_count, content_len));
                        result.push(quote);
                        break;
                    }
                    Some(_) => {
                        escaped = false;
                        content_len += 1;
                    }
                    None => break,
                }
            }
        } else {
            result.push(ch);
        }
    }

    result
}

fn sanitize_variable_names(text: &str) -> String {
    let mut mapping: HashMap<String, String> = HashMap::new();
    let mut counter = 0u32;

    let preserved_keywords = [
        "def", "class", "import", "from", "return", "if", "else", "elif",
        "for", "while", "try", "except", "finally", "with", "as", "in",
        "not", "and", "or", "is", "None", "True", "False", "self", "cls",
        "function", "const", "let", "var", "async", "await", "new", "this",
        "public", "private", "protected", "static", "void", "int", "string",
        "bool", "float", "double", "char", "null", "undefined", "typeof",
        "fn", "pub", "use", "mod", "struct", "enum", "impl", "trait", "mut",
        "func", "package", "type", "interface", "go", "defer", "chan",
        "request", "response", "req", "res", "app", "db", "cursor", "conn",
        "query", "execute", "system", "eval", "exec", "open", "read", "write",
        "send", "render", "redirect", "url", "path", "file", "os", "subprocess",
        "sql", "html", "json", "xml", "http", "https", "get", "post", "put",
        "delete", "route", "api", "auth", "login", "user", "admin", "config",
        "escape", "sanitize", "encode", "decode", "validate", "filter", "clean",
        "print", "println", "fmt", "log", "error", "warn", "info", "debug",
    ];

    let mut result = String::with_capacity(text.len());
    let mut word = String::new();

    for ch in text.chars() {
        if ch.is_alphanumeric() || ch == '_' {
            word.push(ch);
        } else {
            if !word.is_empty() {
                let lower = word.to_lowercase();
                if preserved_keywords.contains(&lower.as_str())
                    || word.starts_with(|c: char| c.is_uppercase()) && word.len() <= 3
                    || word.chars().all(|c| c.is_uppercase() || c == '_')
                    || word.parse::<f64>().is_ok()
                {
                    result.push_str(&word);
                } else {
                    let replacement = mapping.entry(word.clone()).or_insert_with(|| {
                        counter += 1;
                        format!("v{}", counter)
                    });
                    result.push_str(replacement);
                }
                word.clear();
            }
            result.push(ch);
        }
    }
    if !word.is_empty() {
        let lower = word.to_lowercase();
        if preserved_keywords.contains(&lower.as_str()) {
            result.push_str(&word);
        } else {
            let replacement = mapping.entry(word.clone()).or_insert_with(|| {
                counter += 1;
                format!("v{}", counter)
            });
            result.push_str(replacement);
        }
    }

    result
}

// ── Privacy Gate: check before LLM call ──

pub fn check_privacy_gate(provider: &AiProvider, config: &PrivacyConfig) -> Result<()> {
    let is_remote = matches!(provider, AiProvider::OpenAI | AiProvider::Anthropic);

    if config.mode == PrivacyMode::LocalOnly && is_remote {
        bail!(
            "Privacy mode is 'local-only' but provider is remote ({}). \
             Use --privacy sanitized or --privacy unrestricted to allow remote calls.",
            match provider {
                AiProvider::OpenAI => "OpenAI",
                AiProvider::Anthropic => "Anthropic",
                _ => "unknown",
            }
        );
    }

    if is_remote && !REMOTE_WARNING_SHOWN.swap(true, Ordering::Relaxed) {
        eprintln!(
            "  \x1b[33m⚠\x1b[0m Code snippets will be sent to remote LLM provider. \
             Use --privacy local-only for offline mode."
        );
    }

    Ok(())
}

pub fn prepare_prompt(prompt: &str, config: &PrivacyConfig, provider: &AiProvider) -> String {
    let is_remote = matches!(provider, AiProvider::OpenAI | AiProvider::Anthropic);

    if is_remote && config.mode == PrivacyMode::SanitizedRemote {
        sanitize_code(prompt, config)
    } else {
        prompt.to_string()
    }
}

// ── Audit Logger ──

#[derive(Serialize)]
struct AuditEntry {
    timestamp: String,
    provider: String,
    data_class: DataClass,
    token_estimate: usize,
    content_hash: String,
    privacy_mode: String,
    sanitized: bool,
}

pub fn write_audit_log(
    config: &PrivacyConfig,
    provider_name: &str,
    prompt: &str,
    sanitized: bool,
) {
    let path = match &config.audit_log_path {
        Some(p) => p,
        None => return,
    };

    let mut hasher = Sha256::new();
    hasher.update(prompt.as_bytes());
    let hash = format!("{:x}", hasher.finalize());

    let entry = AuditEntry {
        timestamp: chrono::Utc::now().to_rfc3339(),
        provider: provider_name.to_string(),
        data_class: classify_content(prompt),
        token_estimate: prompt.len() / 4,
        content_hash: hash[..16].to_string(),
        privacy_mode: format!("{:?}", config.mode),
        sanitized,
    };

    if let Ok(json) = serde_json::to_string(&entry) {
        use std::io::Write;
        if let Ok(mut file) = std::fs::OpenOptions::new()
            .create(true).append(true).open(path)
        {
            let _ = writeln!(file, "{}", json);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_classify_public() {
        assert_eq!(classify_content("def hello(): print('hi')"), DataClass::Public);
    }

    #[test]
    fn test_classify_restricted() {
        assert_eq!(classify_content("password = 'secret123'"), DataClass::Restricted);
    }

    #[test]
    fn test_classify_confidential() {
        assert_eq!(classify_content("DATABASE_URL = 'postgres://...'"), DataClass::Confidential);
    }

    #[test]
    fn test_strip_comments() {
        let code = "x = 1  // assign\n// full line comment\ny = 2";
        let result = strip_comments(code);
        assert!(!result.contains("assign"));
        assert!(!result.contains("full line"));
        assert!(result.contains("x = 1"));
        assert!(result.contains("y = 2"));
    }

    #[test]
    fn test_sanitize_strings() {
        let code = r#"name = "John Doe""#;
        let result = sanitize_string_literals(code);
        assert!(!result.contains("John Doe"));
        assert!(result.contains("STR_"));
    }

    #[test]
    fn test_sanitize_preserves_keywords() {
        let code = "def get_user(request):\n    return query(sql)";
        let config = PrivacyConfig::default();
        let result = sanitize_code(code, &config);
        assert!(result.contains("def"));
        assert!(result.contains("request"));
        assert!(result.contains("return"));
        assert!(result.contains("query"));
    }

    #[test]
    fn test_unrestricted_no_sanitize() {
        let config = PrivacyConfig {
            mode: PrivacyMode::Unrestricted,
            ..Default::default()
        };
        let code = "secret_password = 'hunter2'";
        assert_eq!(sanitize_code(code, &config), code);
    }

    #[test]
    fn test_privacy_gate_local_only_blocks_remote() {
        let config = PrivacyConfig {
            mode: PrivacyMode::LocalOnly,
            ..Default::default()
        };
        assert!(check_privacy_gate(&AiProvider::OpenAI, &config).is_err());
        assert!(check_privacy_gate(&AiProvider::Ollama, &config).is_ok());
    }

    #[test]
    fn test_privacy_gate_sanitized_allows_remote() {
        let config = PrivacyConfig {
            mode: PrivacyMode::SanitizedRemote,
            ..Default::default()
        };
        assert!(check_privacy_gate(&AiProvider::OpenAI, &config).is_ok());
    }
}
