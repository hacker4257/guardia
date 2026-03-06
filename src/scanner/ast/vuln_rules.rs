use regex::Regex;
use std::path::PathBuf;
use std::sync::LazyLock;
use tree_sitter::Node;

use super::languages::LangId;
use crate::scanner::{Finding, Severity};

fn line_number_at(source: &[u8], byte_offset: usize) -> usize {
    source[..byte_offset].iter().filter(|&&b| b == b'\n').count() + 1
}

fn line_content_at(source: &[u8], byte_offset: usize) -> String {
    let start = source[..byte_offset]
        .iter()
        .rposition(|&b| b == b'\n')
        .map(|p| p + 1)
        .unwrap_or(0);
    let end = source[byte_offset..]
        .iter()
        .position(|&b| b == b'\n')
        .map(|p| byte_offset + p)
        .unwrap_or(source.len());
    String::from_utf8_lossy(&source[start..end]).to_string()
}

fn walk_tree<F>(node: &Node, source: &[u8], callback: &mut F)
where
    F: FnMut(&Node, &[u8]),
{
    callback(node, source);
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        walk_tree(&child, source, callback);
    }
}

// ── SQL Injection ──

static SQL_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:execute|exec|query|raw|cursor\.execute|prepare)\s*\("#).unwrap()
});

static SQL_CONCAT_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE)\s+.*(?:\+|%s|%d|\{|\$\{|f["'])"#).unwrap()
});

pub fn check_sql_injection(
    root: &Node,
    source: &[u8],
    file_path: &PathBuf,
    _lang: LangId,
    findings: &mut Vec<Finding>,
) {
    walk_tree(root, source, &mut |node, src| {
        if node.kind() == "string" || node.kind() == "string_literal" || node.kind() == "template_string" {
            let text = node.utf8_text(src).unwrap_or("");
            if SQL_CONCAT_PATTERN.is_match(text) {
                if let Some(parent) = node.parent() {
                    let parent_text = parent.utf8_text(src).unwrap_or("");
                    if parent.kind() == "binary_expression"
                        || parent.kind() == "concatenated_string"
                        || parent_text.contains("format")
                        || parent_text.contains("f\"")
                        || parent_text.contains("${")
                    {
                        findings.push(Finding {
                            rule_id: "VULN001".to_string(),
                            severity: Severity::Critical,
                            title: "SQL Injection".to_string(),
                            description: "SQL query constructed with string concatenation or formatting. Use parameterized queries instead.".to_string(),
                            file_path: file_path.clone(),
                            line_number: line_number_at(src, node.start_byte()),
                            line_content: line_content_at(src, node.start_byte()),
                            matched_text: text.chars().take(60).collect(),
                            suggestion: "Use parameterized queries (e.g., cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,)))".to_string(),
                        });
                    }
                }
            }
        }

        if node.kind() == "call" || node.kind() == "call_expression" || node.kind() == "method_invocation" {
            let text = node.utf8_text(src).unwrap_or("");
            if SQL_PATTERN.is_match(text) && (text.contains('+') || text.contains("format") || text.contains("f\"") || text.contains("${")) {
                findings.push(Finding {
                    rule_id: "VULN001".to_string(),
                    severity: Severity::Critical,
                    title: "SQL Injection".to_string(),
                    description: "Dynamic SQL query with potential user input concatenation.".to_string(),
                    file_path: file_path.clone(),
                    line_number: line_number_at(src, node.start_byte()),
                    line_content: line_content_at(src, node.start_byte()),
                    matched_text: text.chars().take(80).collect(),
                    suggestion: "Use parameterized queries or prepared statements.".to_string(),
                });
            }
        }
    });
}

// ── Command Injection ──

static CMD_FUNCTIONS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:os\.system|os\.popen|subprocess\.call|subprocess\.run|subprocess\.Popen|Runtime\.getRuntime\(\)\.exec|exec\(|child_process|eval\(|Function\()"#).unwrap()
});

pub fn check_command_injection(
    root: &Node,
    source: &[u8],
    file_path: &PathBuf,
    _lang: LangId,
    findings: &mut Vec<Finding>,
) {
    walk_tree(root, source, &mut |node, src| {
        if node.kind() == "call" || node.kind() == "call_expression" || node.kind() == "method_invocation" {
            let text = node.utf8_text(src).unwrap_or("");
            if CMD_FUNCTIONS.is_match(text) && (text.contains('+') || text.contains("format") || text.contains("f\"") || text.contains("${") || text.contains("%s")) {
                findings.push(Finding {
                    rule_id: "VULN002".to_string(),
                    severity: Severity::Critical,
                    title: "Command Injection".to_string(),
                    description: "System command executed with dynamic input. An attacker could inject arbitrary commands.".to_string(),
                    file_path: file_path.clone(),
                    line_number: line_number_at(src, node.start_byte()),
                    line_content: line_content_at(src, node.start_byte()),
                    matched_text: text.chars().take(80).collect(),
                    suggestion: "Avoid passing user input to system commands. Use subprocess with a list of arguments instead of shell=True.".to_string(),
                });
            }
        }
    });
}

// ── Path Traversal ──

static PATH_FUNCTIONS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:open\(|readFile|readFileSync|createReadStream|Path\.join|os\.path\.join|File\(|FileInputStream)"#).unwrap()
});

pub fn check_path_traversal(
    root: &Node,
    source: &[u8],
    file_path: &PathBuf,
    _lang: LangId,
    findings: &mut Vec<Finding>,
) {
    walk_tree(root, source, &mut |node, src| {
        if node.kind() == "call" || node.kind() == "call_expression" || node.kind() == "method_invocation" {
            let text = node.utf8_text(src).unwrap_or("");
            if PATH_FUNCTIONS.is_match(text) && (text.contains("request") || text.contains("req.") || text.contains("params") || text.contains("query") || text.contains("user_input") || text.contains("input")) {
                findings.push(Finding {
                    rule_id: "VULN003".to_string(),
                    severity: Severity::High,
                    title: "Path Traversal".to_string(),
                    description: "File operation uses potentially user-controlled input without sanitization.".to_string(),
                    file_path: file_path.clone(),
                    line_number: line_number_at(src, node.start_byte()),
                    line_content: line_content_at(src, node.start_byte()),
                    matched_text: text.chars().take(80).collect(),
                    suggestion: "Validate and sanitize file paths. Use a whitelist of allowed paths or os.path.realpath() to resolve symlinks.".to_string(),
                });
            }
        }
    });
}

// ── XSS ──

static XSS_PATTERNS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:innerHTML|outerHTML|document\.write|\.html\(|dangerouslySetInnerHTML|v-html)"#).unwrap()
});

pub fn check_xss(
    root: &Node,
    source: &[u8],
    file_path: &PathBuf,
    _lang: LangId,
    findings: &mut Vec<Finding>,
) {
    walk_tree(root, source, &mut |node, src| {
        let text = node.utf8_text(src).unwrap_or("");
        if node.kind() == "assignment_expression"
            || node.kind() == "expression_statement"
            || node.kind() == "call_expression"
            || node.kind() == "member_expression"
        {
            if XSS_PATTERNS.is_match(text) {
                findings.push(Finding {
                    rule_id: "VULN004".to_string(),
                    severity: Severity::High,
                    title: "Cross-Site Scripting (XSS)".to_string(),
                    description: "Unsafe DOM manipulation that may allow script injection.".to_string(),
                    file_path: file_path.clone(),
                    line_number: line_number_at(src, node.start_byte()),
                    line_content: line_content_at(src, node.start_byte()),
                    matched_text: text.chars().take(80).collect(),
                    suggestion: "Use textContent instead of innerHTML, or sanitize HTML with a library like DOMPurify.".to_string(),
                });
            }
        }
    });
}

// ── Insecure Crypto ──

static WEAK_CRYPTO: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:md5|sha1|DES|RC4|Math\.random|random\.random)\s*[\(.]"#).unwrap()
});

pub fn check_insecure_crypto(
    root: &Node,
    source: &[u8],
    file_path: &PathBuf,
    _lang: LangId,
    findings: &mut Vec<Finding>,
) {
    walk_tree(root, source, &mut |node, src| {
        if node.kind() == "call" || node.kind() == "call_expression" || node.kind() == "method_invocation" {
            let text = node.utf8_text(src).unwrap_or("");
            if WEAK_CRYPTO.is_match(text) {
                let is_security_context = text.contains("password")
                    || text.contains("token")
                    || text.contains("secret")
                    || text.contains("hash")
                    || text.contains("digest")
                    || text.contains("encrypt")
                    || text.contains("key");

                if is_security_context || text.contains("md5") || text.contains("MD5") || text.contains("sha1") || text.contains("SHA1") {
                    findings.push(Finding {
                        rule_id: "VULN005".to_string(),
                        severity: Severity::Medium,
                        title: "Insecure Cryptography".to_string(),
                        description: "Use of weak or broken cryptographic algorithm (MD5, SHA1, DES, RC4) or insecure random number generator.".to_string(),
                        file_path: file_path.clone(),
                        line_number: line_number_at(src, node.start_byte()),
                        line_content: line_content_at(src, node.start_byte()),
                        matched_text: text.chars().take(60).collect(),
                        suggestion: "Use SHA-256/SHA-3 for hashing, AES-256-GCM for encryption, and a CSPRNG for random values.".to_string(),
                    });
                }
            }
        }
    });
}

// ── Hardcoded IP ──

static IP_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"["']\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}["']"#).unwrap()
});

pub fn check_hardcoded_ip(
    root: &Node,
    source: &[u8],
    file_path: &PathBuf,
    _lang: LangId,
    findings: &mut Vec<Finding>,
) {
    walk_tree(root, source, &mut |node, src| {
        if node.kind() == "string" || node.kind() == "string_literal" {
            let text = node.utf8_text(src).unwrap_or("");
            if IP_PATTERN.is_match(text) {
                let inner = text.trim_matches(|c| c == '"' || c == '\'');
                if inner == "127.0.0.1" || inner == "0.0.0.0" || inner == "255.255.255.255" {
                    return;
                }
                findings.push(Finding {
                    rule_id: "VULN006".to_string(),
                    severity: Severity::Low,
                    title: "Hardcoded IP Address".to_string(),
                    description: "IP address is hardcoded. This reduces portability and may expose internal infrastructure.".to_string(),
                    file_path: file_path.clone(),
                    line_number: line_number_at(src, node.start_byte()),
                    line_content: line_content_at(src, node.start_byte()),
                    matched_text: text.to_string(),
                    suggestion: "Use configuration files or environment variables for IP addresses.".to_string(),
                });
            }
        }
    });
}
