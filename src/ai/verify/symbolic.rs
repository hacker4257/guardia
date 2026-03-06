use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

use crate::scanner::Finding;
use crate::ai::agents::VulnContext;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymbolicResult {
    pub reachable: bool,
    pub taint_complete: bool,
    pub sanitizer_effective: bool,
    pub config_safe: bool,
    pub overall_confidence_adjustment: f32,
    pub details: Vec<String>,
}

impl Default for SymbolicResult {
    fn default() -> Self {
        Self {
            reachable: true,
            taint_complete: false,
            sanitizer_effective: false,
            config_safe: true,
            overall_confidence_adjustment: 0.0,
            details: Vec::new(),
        }
    }
}

pub fn run_symbolic_verification(
    finding: Option<&Finding>,
    vuln_ctx: &VulnContext,
    file_contents: &HashMap<PathBuf, String>,
) -> SymbolicResult {
    let finding = match finding {
        Some(f) => f,
        None => return SymbolicResult::default(),
    };

    let content = file_contents
        .get(&finding.file_path)
        .map(|s| s.as_str())
        .unwrap_or("");

    let lines: Vec<&str> = content.lines().collect();

    let mut result = SymbolicResult::default();

    check_reachability(finding, &lines, file_contents, &mut result);
    check_taint_completeness(vuln_ctx, &mut result);
    check_sanitizer_effectiveness(finding, vuln_ctx, &lines, &mut result);
    check_config_safety(finding, &lines, file_contents, &mut result);

    compute_confidence_adjustment(&mut result);

    result
}

fn check_reachability(
    finding: &Finding,
    lines: &[&str],
    file_contents: &HashMap<PathBuf, String>,
    result: &mut SymbolicResult,
) {
    if finding.rule_id.starts_with("SEC") {
        result.reachable = true;
        result.details.push("Secret finding — reachability check skipped".into());
        return;
    }

    let has_route = lines.iter().any(|l| {
        let t = l.trim();
        t.contains("@app.route") || t.contains("@router.") || t.contains("@api_view")
            || t.contains("app.get(") || t.contains("app.post(") || t.contains("router.get(")
            || t.contains("@RequestMapping") || t.contains("@GetMapping") || t.contains("@PostMapping")
            || t.contains("func ") && t.contains("http.") || t.contains("HandleFunc")
    });

    if has_route {
        result.reachable = true;
        result.details.push("HTTP route/endpoint found in same file".into());
        return;
    }

    let func_name = extract_function_name(lines, finding.line_number);
    if func_name.is_empty() {
        result.reachable = true;
        result.details.push("Could not determine function — assuming reachable".into());
        return;
    }

    let mut caller_found = false;
    for (path, content) in file_contents {
        if *path == finding.file_path { continue; }
        for line in content.lines() {
            if line.contains(&func_name) && line.contains('(') {
                caller_found = true;
                break;
            }
        }
        if caller_found { break; }
    }

    if caller_found {
        result.reachable = true;
        result.details.push(format!("Function '{}' is called from other files", func_name));
    } else {
        let is_exported = lines.iter().any(|l| {
            l.contains("__all__") && l.contains(&func_name)
                || l.trim().starts_with("pub ") && l.contains(&func_name)
                || l.contains("module.exports") && l.contains(&func_name)
                || l.contains("export ") && l.contains(&func_name)
        });

        if is_exported {
            result.reachable = true;
            result.details.push(format!("Function '{}' is exported — potentially reachable", func_name));
        } else {
            result.reachable = false;
            result.details.push(format!("Function '{}' has no callers and is not exported — unreachable", func_name));
        }
    }
}

fn check_taint_completeness(
    vuln_ctx: &VulnContext,
    result: &mut SymbolicResult,
) {
    let df = &vuln_ctx.dataflow;

    if df.sources.is_empty() && df.sinks.is_empty() {
        result.taint_complete = false;
        result.details.push("No sources or sinks found — taint path incomplete".into());
        return;
    }

    if !df.sources.is_empty() && !df.sinks.is_empty() {
        let source_line = df.sources.first().map(|s| s.line).unwrap_or(0);
        let sink_line = df.sinks.first().map(|s| s.line).unwrap_or(0);

        if source_line > 0 && sink_line > 0 && sink_line > source_line {
            result.taint_complete = true;
            result.details.push(format!(
                "Taint path: source at L{} → sink at L{} (forward flow)",
                source_line, sink_line,
            ));
        } else if source_line > 0 && sink_line > 0 {
            result.taint_complete = true;
            result.details.push(format!(
                "Taint path: source at L{} → sink at L{} (reverse order — may cross functions)",
                source_line, sink_line,
            ));
        }
    } else if !df.sinks.is_empty() {
        result.taint_complete = false;
        result.details.push("Sink found but no user-controlled source identified".into());
    }
}

fn check_sanitizer_effectiveness(
    finding: &Finding,
    vuln_ctx: &VulnContext,
    _lines: &[&str],
    result: &mut SymbolicResult,
) {
    let df = &vuln_ctx.dataflow;

    if df.sanitizers.is_empty() {
        result.sanitizer_effective = false;
        result.details.push("No sanitizers found".into());
        return;
    }

    let vuln_type = categorize_vuln_type(&finding.rule_id);

    for san in &df.sanitizers {
        let san_lower = san.expression.to_lowercase();
        let effective = match vuln_type {
            VulnType::SqlInjection => {
                san_lower.contains("parameterize") || san_lower.contains("prepared")
                    || san_lower.contains("?") || san_lower.contains("%s")
                    || san_lower.contains("setstring") || san_lower.contains("setint")
            }
            VulnType::Xss => {
                san_lower.contains("escape") || san_lower.contains("encode")
                    || san_lower.contains("dompurify") || san_lower.contains("bleach")
                    || san_lower.contains("sanitize")
            }
            VulnType::CommandInjection => {
                san_lower.contains("shlex") || san_lower.contains("quote")
                    || san_lower.contains("shell=false")
            }
            VulnType::PathTraversal => {
                san_lower.contains("realpath") || san_lower.contains("canonicalize")
                    || san_lower.contains("abspath")
            }
            VulnType::Other => {
                san_lower.contains("sanitize") || san_lower.contains("escape")
                    || san_lower.contains("validate")
            }
        };

        if effective {
            result.sanitizer_effective = true;
            result.details.push(format!(
                "Effective sanitizer for {:?} at L{}: {}",
                vuln_type, san.line, san.expression,
            ));
            return;
        } else {
            result.details.push(format!(
                "Sanitizer at L{} ({}) may not be effective for {:?}",
                san.line, san.expression, vuln_type,
            ));
        }
    }

    result.sanitizer_effective = false;
}

fn check_config_safety(
    finding: &Finding,
    lines: &[&str],
    file_contents: &HashMap<PathBuf, String>,
    result: &mut SymbolicResult,
) {
    if finding.rule_id.starts_with("SEC") {
        result.config_safe = true;
        return;
    }

    let all_lines: Vec<&str> = file_contents.values()
        .flat_map(|c| c.lines())
        .chain(lines.iter().copied())
        .collect();

    let dangerous_configs: Vec<(&str, &str)> = vec![
        ("DEBUG = True", "Debug mode enabled in production"),
        ("DEBUG=True", "Debug mode enabled"),
        ("debug: true", "Debug mode enabled"),
        ("TESTING = True", "Testing mode may disable security"),
        ("ENV = 'development'", "Development environment config"),
        ("NODE_ENV=development", "Development environment"),
    ];

    for (pattern, description) in &dangerous_configs {
        if all_lines.iter().any(|l| l.contains(pattern)) {
            result.config_safe = false;
            result.details.push(format!("Dangerous config: {}", description));
        }
    }
}

fn compute_confidence_adjustment(result: &mut SymbolicResult) {
    let mut adj = 0.0f32;

    if !result.reachable {
        adj -= 0.25;
    }

    if result.taint_complete {
        adj += 0.05;
    } else {
        adj -= 0.1;
    }

    if result.sanitizer_effective {
        adj -= 0.2;
    }

    if !result.config_safe {
        adj += 0.05;
    }

    result.overall_confidence_adjustment = adj.clamp(-0.5, 0.3);
}

fn extract_function_name(lines: &[&str], target_line: usize) -> String {
    if target_line == 0 || lines.is_empty() {
        return String::new();
    }

    let idx = (target_line - 1).min(lines.len() - 1);

    for i in (0..=idx).rev() {
        let trimmed = lines[i].trim();
        if trimmed.starts_with("def ") || trimmed.starts_with("async def ")
            || trimmed.starts_with("function ") || trimmed.starts_with("async function ")
            || trimmed.starts_with("fn ") || trimmed.starts_with("pub fn ")
            || trimmed.starts_with("func ")
        {
            return trimmed.split('(').next()
                .unwrap_or("")
                .split_whitespace()
                .last()
                .unwrap_or("")
                .to_string();
        }
    }

    String::new()
}

#[derive(Debug)]
enum VulnType {
    SqlInjection,
    Xss,
    CommandInjection,
    PathTraversal,
    Other,
}

fn categorize_vuln_type(rule_id: &str) -> VulnType {
    match rule_id {
        "VULN001" | "TAINT001" => VulnType::SqlInjection,
        "VULN002" | "VULN016" | "TAINT002" => VulnType::CommandInjection,
        "VULN003" | "TAINT003" => VulnType::Xss,
        "VULN004" => VulnType::PathTraversal,
        _ => VulnType::Other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ai::agents::{DataflowTrace, DataflowNode};

    fn make_finding(rule_id: &str) -> Finding {
        Finding {
            rule_id: rule_id.to_string(),
            severity: crate::scanner::Severity::High,
            title: "Test".to_string(),
            description: "Test finding".to_string(),
            file_path: PathBuf::from("test.py"),
            line_number: 5,
            line_content: "execute(q)".to_string(),
            matched_text: "execute".to_string(),
            suggestion: "fix it".to_string(),
        }
    }

    #[test]
    fn test_reachable_with_route() {
        let finding = make_finding("VULN001");
        let lines = vec![
            "@app.route('/users')",
            "def get_users():",
            "    q = request.args.get('q')",
            "    cursor.execute(q)",
        ];
        let mut result = SymbolicResult::default();
        let files = HashMap::new();
        check_reachability(&finding, &lines, &files, &mut result);
        assert!(result.reachable);
    }

    #[test]
    fn test_unreachable_no_callers() {
        let finding = make_finding("VULN001");
        let lines = vec![
            "def internal_helper():",
            "    q = build_query()",
            "    cursor.execute(q)",
        ];
        let mut result = SymbolicResult::default();
        let files = HashMap::new();
        check_reachability(&finding, &lines, &files, &mut result);
        assert!(!result.reachable);
    }

    #[test]
    fn test_taint_complete() {
        let vuln_ctx = VulnContext {
            dataflow: DataflowTrace {
                sources: vec![DataflowNode { kind: "source".into(), expression: "request.args".into(), file: String::new(), line: 3 }],
                sinks: vec![DataflowNode { kind: "sink".into(), expression: "execute(q)".into(), file: String::new(), line: 5 }],
                sanitizers: vec![],
                taint_path: vec![],
                is_user_controlled: true,
                has_sanitization: false,
            },
            ..Default::default()
        };
        let mut result = SymbolicResult::default();
        check_taint_completeness(&vuln_ctx, &mut result);
        assert!(result.taint_complete);
    }

    #[test]
    fn test_sanitizer_effective_for_sqli() {
        let finding = make_finding("VULN001");
        let vuln_ctx = VulnContext {
            dataflow: DataflowTrace {
                sources: vec![],
                sinks: vec![],
                sanitizers: vec![DataflowNode {
                    kind: "sanitizer".into(),
                    expression: "cursor.execute(q, (param,))  # parameterized".into(),
                    file: String::new(), line: 5,
                }],
                taint_path: vec![],
                is_user_controlled: true,
                has_sanitization: true,
            },
            ..Default::default()
        };
        let mut result = SymbolicResult::default();
        check_sanitizer_effectiveness(&finding, &vuln_ctx, &[], &mut result);
        assert!(result.sanitizer_effective);
    }

    #[test]
    fn test_html_escape_not_effective_for_sqli() {
        let finding = make_finding("VULN001");
        let vuln_ctx = VulnContext {
            dataflow: DataflowTrace {
                sources: vec![],
                sinks: vec![],
                sanitizers: vec![DataflowNode {
                    kind: "sanitizer".into(),
                    expression: "html.escape(user_input)".into(),
                    file: String::new(), line: 4,
                }],
                taint_path: vec![],
                is_user_controlled: true,
                has_sanitization: true,
            },
            ..Default::default()
        };
        let mut result = SymbolicResult::default();
        check_sanitizer_effectiveness(&finding, &vuln_ctx, &[], &mut result);
        assert!(!result.sanitizer_effective);
    }

    #[test]
    fn test_confidence_adjustment_unreachable() {
        let mut result = SymbolicResult {
            reachable: false,
            taint_complete: false,
            sanitizer_effective: false,
            config_safe: true,
            overall_confidence_adjustment: 0.0,
            details: vec![],
        };
        compute_confidence_adjustment(&mut result);
        assert!(result.overall_confidence_adjustment < 0.0);
    }

    #[test]
    fn test_confidence_adjustment_sanitized() {
        let mut result = SymbolicResult {
            reachable: true,
            taint_complete: true,
            sanitizer_effective: true,
            config_safe: true,
            overall_confidence_adjustment: 0.0,
            details: vec![],
        };
        compute_confidence_adjustment(&mut result);
        assert!(result.overall_confidence_adjustment < 0.0);
    }

    #[test]
    fn test_full_symbolic_verification() {
        let finding = make_finding("VULN001");
        let mut files = HashMap::new();
        files.insert(PathBuf::from("test.py"), "@app.route('/test')\ndef test():\n    q = request.args.get('q')\n    cursor.execute(q)\n".to_string());

        let vuln_ctx = VulnContext {
            dataflow: DataflowTrace {
                sources: vec![DataflowNode { kind: "source".into(), expression: "request.args".into(), file: String::new(), line: 3 }],
                sinks: vec![DataflowNode { kind: "sink".into(), expression: "cursor.execute(q)".into(), file: String::new(), line: 4 }],
                sanitizers: vec![],
                taint_path: vec![],
                is_user_controlled: true,
                has_sanitization: false,
            },
            ..Default::default()
        };

        let result = run_symbolic_verification(Some(&finding), &vuln_ctx, &files);
        assert!(result.reachable);
        assert!(result.taint_complete);
        assert!(!result.sanitizer_effective);
    }
}
