use std::collections::HashSet;
use std::path::PathBuf;
use tree_sitter::Node;

use super::languages::LangId;
use crate::scanner::{Finding, Severity};

pub struct TaintAnalyzer {
    lang: LangId,
    tainted_vars: HashSet<String>,
}

impl TaintAnalyzer {
    pub fn new(lang: LangId) -> Self {
        Self {
            lang,
            tainted_vars: HashSet::new(),
        }
    }

    pub fn analyze(
        &mut self,
        root: &Node,
        source: &[u8],
        file_path: &PathBuf,
        findings: &mut Vec<Finding>,
    ) {
        self.collect_sources(root, source);

        if !self.tainted_vars.is_empty() {
            self.check_sinks(root, source, file_path, findings);
        }
    }

    fn collect_sources(&mut self, node: &Node, source: &[u8]) {
        let text = node.utf8_text(source).unwrap_or("");

        match self.lang {
            LangId::Python => {
                if node.kind() == "assignment" || node.kind() == "expression_statement" {
                    if text.contains("request.") || text.contains("input(") || text.contains("sys.argv") || text.contains("os.environ") {
                        if let Some(first_child) = node.child(0) {
                            let var_name = first_child.utf8_text(source).unwrap_or("").to_string();
                            if !var_name.is_empty() && var_name.len() < 50 {
                                self.tainted_vars.insert(var_name);
                            }
                        }
                    }
                }
                if node.kind() == "parameters" || node.kind() == "typed_parameter" || node.kind() == "identifier" {
                    if let Some(parent) = node.parent() {
                        if parent.kind() == "function_definition" || parent.kind() == "parameters" {
                            let param = text.trim().to_string();
                            if !param.is_empty() && param.len() < 50 && param != "self" {
                                self.tainted_vars.insert(param);
                            }
                        }
                    }
                }
            }
            LangId::JavaScript => {
                if text.contains("req.body") || text.contains("req.params") || text.contains("req.query")
                    || text.contains("document.getElementById") || text.contains("window.location")
                    || text.contains("process.argv")
                {
                    if let Some(first_child) = node.child(0) {
                        let var_name = first_child.utf8_text(source).unwrap_or("").to_string();
                        if !var_name.is_empty() && var_name.len() < 50 {
                            self.tainted_vars.insert(var_name);
                        }
                    }
                }
            }
            LangId::Java => {
                if text.contains("getParameter") || text.contains("getHeader") || text.contains("getInputStream") || text.contains("Scanner") {
                    if let Some(first_child) = node.child(0) {
                        let var_name = first_child.utf8_text(source).unwrap_or("").to_string();
                        if !var_name.is_empty() && var_name.len() < 50 {
                            self.tainted_vars.insert(var_name);
                        }
                    }
                }
            }
            _ => {}
        }

        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            self.collect_sources(&child, source);
        }
    }

    fn check_sinks(
        &self,
        node: &Node,
        source: &[u8],
        file_path: &PathBuf,
        findings: &mut Vec<Finding>,
    ) {
        let text = node.utf8_text(source).unwrap_or("");

        let is_sink = match self.lang {
            LangId::Python => {
                text.contains("execute(") || text.contains("os.system(") || text.contains("subprocess")
                    || text.contains("eval(") || text.contains("open(")
            }
            LangId::JavaScript => {
                text.contains("query(") || text.contains("exec(") || text.contains("eval(")
                    || text.contains("innerHTML") || text.contains("document.write")
            }
            LangId::Java => {
                text.contains("executeQuery") || text.contains("exec(") || text.contains("ProcessBuilder")
            }
            _ => false,
        };

        if is_sink {
            for var in &self.tainted_vars {
                if text.contains(var.as_str()) {
                    let line_num = source[..node.start_byte()]
                        .iter()
                        .filter(|&&b| b == b'\n')
                        .count()
                        + 1;

                    let line_start = source[..node.start_byte()]
                        .iter()
                        .rposition(|&b| b == b'\n')
                        .map(|p| p + 1)
                        .unwrap_or(0);
                    let line_end = source[node.start_byte()..]
                        .iter()
                        .position(|&b| b == b'\n')
                        .map(|p| node.start_byte() + p)
                        .unwrap_or(source.len());

                    findings.push(Finding {
                        rule_id: "TAINT001".to_string(),
                        severity: Severity::High,
                        title: "Tainted Data Flow".to_string(),
                        description: format!(
                            "Variable '{}' from user input flows into a dangerous sink without sanitization.",
                            var
                        ),
                        file_path: file_path.clone(),
                        line_number: line_num,
                        line_content: String::from_utf8_lossy(&source[line_start..line_end]).to_string(),
                        matched_text: text.chars().take(80).collect(),
                        suggestion: "Validate and sanitize all user input before passing to sensitive operations.".to_string(),
                    });
                    break;
                }
            }
        }

        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            self.check_sinks(&child, source, file_path, findings);
        }
    }
}
