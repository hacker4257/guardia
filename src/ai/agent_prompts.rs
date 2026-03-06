use crate::scanner::Finding;
use super::agents::*;

pub fn build_context_gatherer_prompt(finding: &Finding, file_ctx: &FileContext) -> String {
    format!(
        r#"You are a code context analyst. Given a security finding and its surrounding code, provide deeper context analysis.

## Finding
Rule: {rule_id} — {title}
Severity: {severity}
File: {file}:{line}
Language: {language}
Is test file: {is_test}
Is generated: {is_generated}

## Function containing the finding
```
{func_body}
```

## Imports in this file
{imports}

## Known callers
{callers}

## Task
Analyze the code context and respond with ONLY a JSON object:
{{
  "is_dead_code": true/false,
  "is_reachable_from_user_input": true/false,
  "framework_detected": "flask/django/express/spring/none/...",
  "auth_protected": true/false,
  "additional_context": "one paragraph of relevant observations"
}}"#,
        rule_id = finding.rule_id,
        title = finding.title,
        severity = finding.severity,
        file = finding.file_path.display(),
        line = finding.line_number,
        language = file_ctx.language,
        is_test = file_ctx.is_test_file,
        is_generated = file_ctx.is_generated,
        func_body = truncate(&file_ctx.function_body_snippet, 1500),
        imports = file_ctx.imports.join("\n"),
        callers = if file_ctx.callers.is_empty() {
            "(none found)".to_string()
        } else {
            file_ctx.callers.join("\n")
        },
    )
}

pub fn build_dataflow_prompt(finding: &Finding, file_ctx: &FileContext, dataflow: &DataflowTrace) -> String {
    let sources_str = dataflow.sources.iter()
        .map(|s| format!("  L{}: {}", s.line, s.expression))
        .collect::<Vec<_>>()
        .join("\n");

    let sanitizers_str = dataflow.sanitizers.iter()
        .map(|s| format!("  L{}: {}", s.line, s.expression))
        .collect::<Vec<_>>()
        .join("\n");

    let sinks_str = dataflow.sinks.iter()
        .map(|s| format!("  L{}: {}", s.line, s.expression))
        .collect::<Vec<_>>()
        .join("\n");

    format!(
        r#"You are a dataflow analysis expert. Trace how data flows from user input to dangerous operations.

## Finding
Rule: {rule_id} — {title}
File: {file}:{line}
Language: {language}

## Code
```
{func_body}
```

## Static analysis found these data flow points

Sources (user input entry points):
{sources}

Sanitizers (validation/encoding/escaping):
{sanitizers}

Sinks (dangerous operations):
{sinks}

## Task
Trace the complete data flow path. Determine if user-controlled data reaches the dangerous operation without adequate sanitization.

Respond with ONLY a JSON object:
{{
  "taint_reaches_sink": true/false,
  "sanitization_adequate": true/false,
  "data_flow_description": "step by step description of how data flows",
  "missing_sanitization": "what sanitization is missing, or null",
  "variable_chain": ["var1", "var2", "..."]
}}"#,
        rule_id = finding.rule_id,
        title = finding.title,
        file = finding.file_path.display(),
        line = finding.line_number,
        language = file_ctx.language,
        func_body = truncate(&file_ctx.function_body_snippet, 1500),
        sources = if sources_str.is_empty() { "  (none detected)".to_string() } else { sources_str },
        sanitizers = if sanitizers_str.is_empty() { "  (none detected)".to_string() } else { sanitizers_str },
        sinks = if sinks_str.is_empty() { "  (none detected)".to_string() } else { sinks_str },
    )
}

pub fn build_exploit_prompt(
    finding: &Finding,
    file_ctx: &FileContext,
    dataflow: &DataflowTrace,
    context_analysis: &str,
    dataflow_analysis: &str,
) -> String {
    format!(
        r#"You are a penetration testing expert. Assess whether this vulnerability is exploitable in practice.

## Finding
Rule: {rule_id} — {title}
Severity: {severity}
File: {file}:{line}
Language: {language}

## Previous agent findings

### Context Agent said:
{context_analysis}

### Dataflow Agent said:
{dataflow_analysis}

## Data flow summary
User-controlled input: {user_controlled}
Sanitization present: {has_sanitization}
Taint path: {taint_path}

## Task
Based on all evidence, assess exploitability. Consider:
1. Can an attacker actually reach this code path?
2. What input would trigger the vulnerability?
3. What is the real-world impact?

Respond with ONLY a JSON object:
{{
  "exploitable": true/false,
  "attack_vector": "description of how to exploit",
  "prerequisites": ["list of conditions needed"],
  "impact": "what damage can be done",
  "cvss_estimate": 0.0 to 10.0,
  "poc_sketch": "conceptual proof-of-concept or null"
}}"#,
        rule_id = finding.rule_id,
        title = finding.title,
        severity = finding.severity,
        file = finding.file_path.display(),
        line = finding.line_number,
        language = file_ctx.language,
        context_analysis = truncate(context_analysis, 500),
        dataflow_analysis = truncate(dataflow_analysis, 500),
        user_controlled = dataflow.is_user_controlled,
        has_sanitization = dataflow.has_sanitization,
        taint_path = dataflow.taint_path.join(" → "),
    )
}

pub fn build_synthesis_prompt(
    finding: &Finding,
    file_ctx: &FileContext,
    dataflow: &DataflowTrace,
    agent_results: &[(&str, &str)],
) -> String {
    let evidence = agent_results.iter()
        .map(|(agent, result)| format!("### {} Agent:\n{}", agent, truncate(result, 400)))
        .collect::<Vec<_>>()
        .join("\n\n");

    format!(
        r#"You are a senior security engineer making the FINAL verdict on a scanner finding.

## Finding
Rule: {rule_id} — {title}
Severity: {severity}
File: {file}:{line}
Language: {language}
Is test file: {is_test}

## Evidence from analysis agents

{evidence}

## Data flow summary
Sources found: {source_count}
Sanitizers found: {sanitizer_count}
Sinks found: {sink_count}
User-controlled: {user_controlled}
Has sanitization: {has_sanitization}

## Task
Synthesize ALL evidence into a final verdict. Weight the evidence:
- Test/generated files strongly suggest false positive
- Presence of sanitization reduces true positive confidence
- Confirmed exploitability increases true positive confidence
- Multiple agents agreeing increases confidence

Respond with ONLY a JSON object:
{{
  "false_positive": true/false,
  "confidence": 0.0 to 1.0,
  "severity_adjustment": "unchanged/upgrade/downgrade",
  "reasoning": "comprehensive paragraph synthesizing all agent findings",
  "suggested_fix": "specific code fix or null",
  "fix_description": "what the fix does or null",
  "attack_narrative": "if true positive, describe the full attack chain or null"
}}"#,
        rule_id = finding.rule_id,
        title = finding.title,
        severity = finding.severity,
        file = finding.file_path.display(),
        line = finding.line_number,
        language = file_ctx.language,
        is_test = file_ctx.is_test_file,
        evidence = evidence,
        source_count = dataflow.sources.len(),
        sanitizer_count = dataflow.sanitizers.len(),
        sink_count = dataflow.sinks.len(),
        user_controlled = dataflow.is_user_controlled,
        has_sanitization = dataflow.has_sanitization,
    )
}

pub fn build_secret_synthesis_prompt(
    finding: &Finding,
    file_ctx: &FileContext,
    context_analysis: &str,
) -> String {
    format!(
        r#"You are a senior security engineer making the FINAL verdict on a secret detection finding.

## Finding
Rule: {rule_id} — {title}
Severity: {severity}
File: {file}:{line}
Matched: {matched}

## Context
Language: {language}
Is test file: {is_test}
Is generated: {is_generated}

## Context Agent analysis:
{context_analysis}

## Common false positive patterns
- AWS example key: AKIAIOSFODNN7EXAMPLE
- Placeholder values: xxx, test, example, dummy, fake, sample, placeholder
- Environment variable reads: os.getenv(), process.env, env::var()
- Config file lookups: config.get(), settings.SECRET_KEY
- Hash values that match key patterns

## Task
Make the final call. Is this a real leaked secret or a false positive?

Respond with ONLY a JSON object:
{{
  "false_positive": true/false,
  "confidence": 0.0 to 1.0,
  "reasoning": "explain your decision with specific evidence",
  "suggested_fix": "how to fix if true positive, or null",
  "secret_type": "what kind of secret this appears to be"
}}"#,
        rule_id = finding.rule_id,
        title = finding.title,
        severity = finding.severity,
        file = finding.file_path.display(),
        line = finding.line_number,
        matched = truncate(&finding.matched_text, 100),
        language = file_ctx.language,
        is_test = file_ctx.is_test_file,
        is_generated = file_ctx.is_generated,
        context_analysis = truncate(context_analysis, 500),
    )
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}...", &s[..max])
    }
}
