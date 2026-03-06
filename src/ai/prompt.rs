use crate::scanner::Finding;

pub const SYSTEM_PROMPT: &str = r#"You are an expert application security engineer performing triage on automated scanner findings.

Your task: determine if a finding is a TRUE vulnerability or a FALSE POSITIVE, then provide actionable guidance.

## Decision criteria

A finding is a FALSE POSITIVE if ANY of these apply:
- The matched value is a placeholder, example, or dummy (e.g. "AKIAIOSFODNN7EXAMPLE", "sk_test_xxx", "password123")
- The code is in a test file, documentation, or comment explaining the pattern
- The value comes from an environment variable, config file lookup, or secret manager (e.g. os.getenv(), process.env, env::var)
- The string is a hash, encoded constant, or non-secret identifier that happens to match the entropy/regex pattern
- The vulnerable function call uses parameterized queries, prepared statements, or proper escaping

A finding is a TRUE POSITIVE if ALL of these apply:
- The matched value appears to be a real, usable credential or the code path is genuinely exploitable
- The code is in production source (not test/docs)
- No sanitization, parameterization, or safe wrapper is applied

## Response format

You MUST respond with ONLY a JSON object (no markdown, no extra text):

{
  "false_positive": true or false,
  "confidence": 0.0 to 1.0,
  "reasoning": "one paragraph explanation of your decision",
  "suggested_fix": "fixed code snippet or null if not applicable",
  "fix_description": "one sentence describing what the fix does or null"
}"#;

const SECRET_CONTEXT: &str = r#"
## Category: Secret / Credential Detection

Focus on:
- Is this a real credential or a placeholder/example/test value?
- Is it loaded from environment/config at runtime (safe) vs hardcoded in source (unsafe)?
- Common false positive patterns: example keys in docs, test fixtures, SDK constants, hash values

### Examples

Finding: AWS Access Key `AKIAIOSFODNN7EXAMPLE` in config.py
→ FALSE POSITIVE (confidence: 0.95) — This is AWS's official example key from documentation.

Finding: AWS Access Key `AKIA3EXAMPLE7REALKEY` in deploy.py line `aws_key = "AKIA3EXAMPLE7REALKEY"`
→ TRUE POSITIVE (confidence: 0.85) — Hardcoded in production code, not loaded from env/config."#;

const VULN_CONTEXT: &str = r#"
## Category: Code Vulnerability (SAST)

Focus on:
- Is user input actually reaching the dangerous sink without sanitization?
- Are parameterized queries, prepared statements, or escaping functions used?
- Is the input validated/sanitized before use?
- Is this in dead code, test code, or behind authentication?

### Examples

Finding: SQL Injection in `cursor.execute("SELECT * FROM users WHERE id=" + user_id)`
→ TRUE POSITIVE (confidence: 0.9) — String concatenation with user input directly in SQL query.

Finding: SQL Injection in `cursor.execute("SELECT * FROM users WHERE id=?", (user_id,))`
→ FALSE POSITIVE (confidence: 0.95) — Parameterized query with placeholder, input is properly bound."#;

const TAINT_CONTEXT: &str = r#"
## Category: Taint Analysis (Data Flow)

Focus on:
- Does the tainted variable actually carry user-controlled data?
- Is there any sanitization, validation, or encoding between source and sink?
- Could the data flow be interrupted by a conditional check or type conversion?
- Is the sink actually dangerous in this context?

### Examples

Finding: Tainted variable `user_input` flows from `request.args.get()` to `os.system(user_input)`
→ TRUE POSITIVE (confidence: 0.9) — Direct flow from HTTP parameter to shell execution with no sanitization.

Finding: Tainted variable `page` flows from `request.args.get()` to `redirect("/page/" + page)`
→ TRUE POSITIVE (confidence: 0.6) — Open redirect possible, but lower severity. Suggest URL validation."#;

fn classify_finding(rule_id: &str) -> &'static str {
    if rule_id.starts_with("SEC") {
        SECRET_CONTEXT
    } else if rule_id.starts_with("TAINT") {
        TAINT_CONTEXT
    } else {
        VULN_CONTEXT
    }
}

#[allow(dead_code)]
pub fn build_analysis_prompt(finding: &Finding, context: &str) -> String {
    let category_guidance = classify_finding(&finding.rule_id);

    let truncated_context = truncate_context(context, 2000);
    let truncated_match = truncate_str(&finding.matched_text, 200);

    format!(
        r#"{category_guidance}

---

Analyze this specific finding:

Rule: {rule_id} — {title}
Severity: {severity}
File: {file}:{line}
Description: {description}

Code context (surrounding lines):
{context}

Matched text: {matched}

Respond with ONLY a JSON object."#,
        category_guidance = category_guidance,
        rule_id = finding.rule_id,
        title = finding.title,
        severity = finding.severity,
        file = finding.file_path.display(),
        line = finding.line_number,
        description = finding.description,
        context = truncated_context,
        matched = truncated_match,
    )
}

#[allow(dead_code)]
fn truncate_context(context: &str, max_chars: usize) -> String {
    if context.len() <= max_chars {
        return context.to_string();
    }

    let lines: Vec<&str> = context.lines().collect();
    let mid = lines.len() / 2;

    let mut result = String::new();
    let mut budget = max_chars;

    for (i, line) in lines.iter().enumerate() {
        if i == mid && result.len() + line.len() > budget.saturating_sub(200) {
            result.push_str("    ... (truncated) ...\n");
            budget = budget.saturating_sub(30);
            continue;
        }
        if result.len() + line.len() + 1 > max_chars {
            result.push_str("    ... (truncated) ...\n");
            break;
        }
        result.push_str(line);
        result.push('\n');
    }

    result
}

fn truncate_str(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}...(truncated)", &s[..max])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_classify_secret() {
        assert!(classify_finding("SEC001").contains("Secret"));
    }

    #[test]
    fn test_classify_vuln() {
        assert!(classify_finding("VULN003").contains("Vulnerability"));
    }

    #[test]
    fn test_classify_taint() {
        assert!(classify_finding("TAINT001").contains("Taint"));
    }

    #[test]
    fn test_truncate_short() {
        assert_eq!(truncate_str("hello", 100), "hello");
    }

    #[test]
    fn test_truncate_long() {
        let long = "a".repeat(300);
        let result = truncate_str(&long, 200);
        assert!(result.len() < 220);
        assert!(result.contains("truncated"));
    }
}
