use regex::Regex;
use std::path::PathBuf;
use std::sync::LazyLock;

use super::{Finding, Severity};

struct SecretRule {
    id: &'static str,
    title: &'static str,
    description: &'static str,
    severity: Severity,
    pattern: &'static str,
    suggestion: &'static str,
}

static SECRET_RULES: &[SecretRule] = &[
    // === Cloud Provider Keys ===
    SecretRule {
        id: "SEC001",
        title: "AWS Access Key ID",
        description: "Hardcoded AWS Access Key ID detected. This can grant unauthorized access to AWS services.",
        severity: Severity::Critical,
        pattern: r"(?i)(AKIA[0-9A-Z]{16})",
        suggestion: "Use environment variables or AWS IAM roles instead. Store keys in AWS Secrets Manager.",
    },
    SecretRule {
        id: "SEC002",
        title: "AWS Secret Access Key",
        description: "Hardcoded AWS Secret Access Key detected.",
        severity: Severity::Critical,
        pattern: r#"(?i)(?:aws_secret_access_key|aws_secret|secret_key)\s*[:=]\s*["']?([A-Za-z0-9/+=]{40})["']?"#,
        suggestion: "Use environment variables or AWS IAM roles. Never commit AWS secrets to source control.",
    },
    SecretRule {
        id: "SEC003",
        title: "Google Cloud API Key",
        description: "Hardcoded Google Cloud API key detected.",
        severity: Severity::High,
        pattern: r"AIza[0-9A-Za-z\-_]{35}",
        suggestion: "Use Google Cloud Secret Manager or environment variables.",
    },
    SecretRule {
        id: "SEC004",
        title: "Azure Storage Key",
        description: "Hardcoded Azure storage account key detected.",
        severity: Severity::Critical,
        pattern: r#"(?i)(?:AccountKey|azure_storage_key)\s*[:=]\s*["']?([A-Za-z0-9+/=]{88})["']?"#,
        suggestion: "Use Azure Key Vault or Managed Identity instead.",
    },

    // === API Keys & Tokens ===
    SecretRule {
        id: "SEC010",
        title: "Generic API Key",
        description: "Potential API key assignment detected in code.",
        severity: Severity::High,
        pattern: r#"(?i)(?:api_key|apikey|api_secret|api_token)\s*[:=]\s*["']([a-zA-Z0-9_\-]{20,})["']"#,
        suggestion: "Move API keys to environment variables or a secrets manager.",
    },
    SecretRule {
        id: "SEC011",
        title: "Generic Secret/Password",
        description: "Potential hardcoded password or secret detected.",
        severity: Severity::High,
        pattern: r#"(?i)(?:password|passwd|pwd|secret|token)\s*[:=]\s*["']([^"'\s]{8,})["']"#,
        suggestion: "Never hardcode passwords. Use a secrets manager or environment variables.",
    },
    SecretRule {
        id: "SEC012",
        title: "Bearer Token",
        description: "Hardcoded Bearer authentication token detected.",
        severity: Severity::High,
        pattern: r#"(?i)["']Bearer\s+[a-zA-Z0-9_\-\.]{20,}["']"#,
        suggestion: "Load Bearer tokens from environment variables at runtime.",
    },
    SecretRule {
        id: "SEC013",
        title: "Basic Auth Credentials",
        description: "Hardcoded Basic authentication credentials detected.",
        severity: Severity::High,
        pattern: r#"(?i)["']Basic\s+[A-Za-z0-9+/=]{10,}["']"#,
        suggestion: "Never hardcode authentication credentials. Use a credential store.",
    },

    // === Version Control & CI/CD ===
    SecretRule {
        id: "SEC020",
        title: "GitHub Token",
        description: "Hardcoded GitHub personal access token or OAuth token detected.",
        severity: Severity::Critical,
        pattern: r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}",
        suggestion: "Use GitHub Actions secrets or environment variables.",
    },
    SecretRule {
        id: "SEC021",
        title: "GitLab Token",
        description: "Hardcoded GitLab token detected.",
        severity: Severity::Critical,
        pattern: r"glpat-[A-Za-z0-9\-_]{20,}",
        suggestion: "Use GitLab CI/CD variables instead.",
    },

    // === Communication Platforms ===
    SecretRule {
        id: "SEC030",
        title: "Slack Token",
        description: "Hardcoded Slack API token detected.",
        severity: Severity::High,
        pattern: r"xox[bpors]-[0-9]{10,}-[0-9]{10,}-[a-zA-Z0-9]{24,}",
        suggestion: "Store Slack tokens in environment variables.",
    },
    SecretRule {
        id: "SEC031",
        title: "Slack Webhook URL",
        description: "Hardcoded Slack webhook URL detected.",
        severity: Severity::Medium,
        pattern: r"https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[a-zA-Z0-9]{24,}",
        suggestion: "Store webhook URLs in environment variables or a config service.",
    },
    SecretRule {
        id: "SEC032",
        title: "Discord Webhook URL",
        description: "Hardcoded Discord webhook URL detected.",
        severity: Severity::Medium,
        pattern: r"https://discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_\-]+",
        suggestion: "Store webhook URLs in environment variables.",
    },

    // === Database ===
    SecretRule {
        id: "SEC040",
        title: "Database Connection String",
        description: "Database connection string with embedded credentials detected.",
        severity: Severity::Critical,
        pattern: r#"(?i)(?:mysql|postgres|postgresql|mongodb|redis|mssql)://[^:]+:[^@]+@[^\s"']+"#,
        suggestion: "Use environment variables for database connection strings. Separate credentials from connection config.",
    },

    // === Private Keys ===
    SecretRule {
        id: "SEC050",
        title: "RSA Private Key",
        description: "RSA private key detected in source code.",
        severity: Severity::Critical,
        pattern: r"-----BEGIN RSA PRIVATE KEY-----",
        suggestion: "Never commit private keys. Use a key management service.",
    },
    SecretRule {
        id: "SEC051",
        title: "SSH Private Key",
        description: "SSH private key detected in source code.",
        severity: Severity::Critical,
        pattern: r"-----BEGIN (?:OPENSSH|EC|DSA) PRIVATE KEY-----",
        suggestion: "Never commit SSH keys. Use ssh-agent or a secrets manager.",
    },
    SecretRule {
        id: "SEC052",
        title: "PGP Private Key",
        description: "PGP private key block detected.",
        severity: Severity::Critical,
        pattern: r"-----BEGIN PGP PRIVATE KEY BLOCK-----",
        suggestion: "Never commit PGP private keys to source control.",
    },

    // === Payment & Financial ===
    SecretRule {
        id: "SEC060",
        title: "Stripe API Key",
        description: "Hardcoded Stripe API key detected.",
        severity: Severity::Critical,
        pattern: r"(?:sk|pk)_(?:live|test)_[0-9a-zA-Z]{24,}",
        suggestion: "Use environment variables for Stripe keys. Never use live keys in code.",
    },
    SecretRule {
        id: "SEC061",
        title: "Square Access Token",
        description: "Hardcoded Square access token detected.",
        severity: Severity::High,
        pattern: r"sq0atp-[0-9A-Za-z\-_]{22,}",
        suggestion: "Store Square tokens in environment variables.",
    },

    // === AI/LLM Provider Keys ===
    SecretRule {
        id: "SEC070",
        title: "OpenAI API Key",
        description: "Hardcoded OpenAI API key detected.",
        severity: Severity::High,
        pattern: r"sk-[a-zA-Z0-9]{20,}T3BlbkFJ[a-zA-Z0-9]{20,}",
        suggestion: "Use environment variables for LLM API keys.",
    },
    SecretRule {
        id: "SEC071",
        title: "Anthropic API Key",
        description: "Hardcoded Anthropic (Claude) API key detected.",
        severity: Severity::High,
        pattern: r"sk-ant-[a-zA-Z0-9\-_]{40,}",
        suggestion: "Use environment variables for LLM API keys.",
    },

    // === JWT ===
    SecretRule {
        id: "SEC080",
        title: "JSON Web Token",
        description: "Hardcoded JWT detected. JWTs may contain sensitive claims.",
        severity: Severity::Medium,
        pattern: r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_\-]{10,}",
        suggestion: "JWTs should be generated at runtime, not hardcoded.",
    },

    // === .env file patterns ===
    SecretRule {
        id: "SEC090",
        title: "Environment Variable with Secret",
        description: "Sensitive value assigned in environment configuration.",
        severity: Severity::Medium,
        pattern: r#"(?i)^(?:export\s+)?(?:DB_PASSWORD|DATABASE_URL|SECRET_KEY|PRIVATE_KEY|AUTH_TOKEN|ACCESS_TOKEN|ENCRYPTION_KEY)\s*=\s*["']?[A-Za-z0-9+/=@:_\-\.]{8,}["']?\s*$"#,
        suggestion: "Use a .env.example with placeholder values. Never commit real .env files.",
    },
];

struct CompiledRule {
    rule: &'static SecretRule,
    regex: Regex,
}

static COMPILED_RULES: LazyLock<Vec<CompiledRule>> = LazyLock::new(|| {
    SECRET_RULES
        .iter()
        .map(|rule| CompiledRule {
            rule,
            regex: Regex::new(rule.pattern).unwrap_or_else(|e| {
                panic!("Invalid regex for rule {}: {}", rule.id, e);
            }),
        })
        .collect()
});

pub fn scan_secrets(file_path: &PathBuf, content: &str, findings: &mut Vec<Finding>) {
    if is_likely_test_or_example(file_path) {
        return;
    }

    for (line_number, line) in content.lines().enumerate() {
        if is_comment_or_example(line) {
            continue;
        }

        for compiled in COMPILED_RULES.iter() {
            if let Some(mat) = compiled.regex.find(line) {
                let matched_text = mat.as_str().to_string();

                if is_placeholder(&matched_text) {
                    continue;
                }

                findings.push(Finding {
                    rule_id: compiled.rule.id.to_string(),
                    severity: compiled.rule.severity.clone(),
                    title: compiled.rule.title.to_string(),
                    description: compiled.rule.description.to_string(),
                    file_path: file_path.clone(),
                    line_number: line_number + 1,
                    line_content: line.to_string(),
                    matched_text: redact(&matched_text),
                    suggestion: compiled.rule.suggestion.to_string(),
                });
            }
        }

        check_high_entropy(file_path, line, line_number + 1, findings);
    }
}

fn check_high_entropy(file_path: &PathBuf, line: &str, line_number: usize, findings: &mut Vec<Finding>) {
    static ENTROPY_RE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r#"["']([A-Za-z0-9+/=_\-]{32,})["']"#).unwrap()
    });

    for cap in ENTROPY_RE.captures_iter(line) {
        let candidate = &cap[1];

        if is_placeholder(candidate) {
            continue;
        }

        let entropy = shannon_entropy(candidate);

        if entropy > 4.5 && candidate.len() >= 32 {
            let already_found = !findings.is_empty()
                && findings.last().map_or(false, |f| f.line_number == line_number && f.file_path == *file_path);

            if already_found {
                continue;
            }

            findings.push(Finding {
                rule_id: "SEC100".to_string(),
                severity: Severity::Medium,
                title: "High Entropy String".to_string(),
                description: format!(
                    "High entropy string detected (entropy: {:.2}). This may be a hardcoded secret or key.",
                    entropy
                ),
                file_path: file_path.clone(),
                line_number,
                line_content: line.to_string(),
                matched_text: redact(candidate),
                suggestion: "Review this string. If it's a secret, move it to environment variables or a secrets manager.".to_string(),
            });
        }
    }
}

fn shannon_entropy(s: &str) -> f64 {
    let mut freq = [0u32; 256];
    for byte in s.bytes() {
        freq[byte as usize] += 1;
    }

    let len = s.len() as f64;
    freq.iter()
        .filter(|&&count| count > 0)
        .map(|&count| {
            let p = count as f64 / len;
            -p * p.log2()
        })
        .sum()
}

fn redact(s: &str) -> String {
    if s.len() <= 8 {
        return "*".repeat(s.len());
    }
    let visible = 4.min(s.len() / 4);
    format!("{}...{}", &s[..visible], "*".repeat(8))
}

fn is_placeholder(s: &str) -> bool {
    let lower = s.to_lowercase();
    let placeholders = [
        "example", "placeholder", "your_", "your-", "xxx", "todo",
        "changeme", "replace", "insert", "dummy", "fake", "test",
        "sample", "demo", "aaaa", "0000", "1234",
    ];
    placeholders.iter().any(|p| lower.contains(p))
}

fn is_comment_or_example(line: &str) -> bool {
    let trimmed = line.trim();
    if trimmed.starts_with("//") && trimmed.contains("example") {
        return true;
    }
    if trimmed.starts_with('#') && trimmed.contains("example") {
        return true;
    }
    let lower = trimmed.to_lowercase();
    if lower.contains("os.environ") || lower.contains("os.getenv") || lower.contains("env::var") || lower.contains("process.env") {
        return true;
    }
    false
}

fn is_likely_test_or_example(path: &PathBuf) -> bool {
    let path_str = path.to_string_lossy().to_lowercase();
    let test_indicators = [
        "test_fixture", "testdata", "mock_data",
        "__snapshots__", "example_config",
    ];
    test_indicators.iter().any(|t| path_str.contains(t))
}

pub fn get_rules_info() -> Vec<(&'static str, &'static str, &'static str, &'static Severity)> {
    SECRET_RULES
        .iter()
        .map(|r| (r.id, r.title, r.description, &r.severity))
        .collect()
}
