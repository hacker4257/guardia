use crate::scanner::Finding;

pub const SYSTEM_PROMPT: &str = r#"You are a senior application security engineer reviewing code for vulnerabilities.
Your job is to analyze security scanner findings and determine:
1. Whether each finding is a TRUE positive or FALSE positive
2. If true positive, provide a specific code fix

Respond in this exact format:
FALSE_POSITIVE: true/false
CONFIDENCE: high/medium/low
REASONING: <one paragraph explanation>
SUGGESTED_FIX:
```
<fixed code if applicable>
```"#;

pub fn build_analysis_prompt(finding: &Finding, context: &str) -> String {
    format!(
        r#"Analyze this security finding:

**Rule:** {} - {}
**Severity:** {}
**File:** {}:{}
**Description:** {}

**Code Context:**
{}

**Matched:** {}

Is this a true security vulnerability or a false positive? If true, suggest a fix."#,
        finding.rule_id,
        finding.title,
        finding.severity,
        finding.file_path.display(),
        finding.line_number,
        finding.description,
        context,
        finding.matched_text,
    )
}
