use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCall {
    pub tool: String,
    pub args: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolResult {
    pub tool: String,
    pub success: bool,
    pub output: String,
}

pub struct ToolBox {
    file_contents: HashMap<PathBuf, String>,
}

impl ToolBox {
    pub fn new(file_contents: HashMap<PathBuf, String>) -> Self {
        Self { file_contents }
    }

    pub fn available_tools() -> &'static str {
        r#"You have access to these tools. Call them by responding with a JSON object with "tool" and "args" fields.

## read_file
Read a specific file's content (or a range of lines).
Args: { "path": "src/app.py", "start_line": "1", "end_line": "50" }
(start_line and end_line are optional)

## search_code
Search for a pattern across all scanned files. Returns matching lines with file paths and line numbers.
Args: { "pattern": "cursor.execute" }

## find_function
Find the definition of a function by name across all files.
Args: { "function_name": "get_user" }

## find_callers
Find all call sites of a function.
Args: { "function_name": "get_user" }

## read_imports
Get all import/require/use statements from a file.
Args: { "path": "src/app.py" }

## check_sanitization
Check if a variable is sanitized between two line numbers in a file.
Args: { "path": "src/app.py", "variable": "user_id", "from_line": "10", "to_line": "25" }

## list_routes
Find HTTP route/endpoint definitions in a file (Flask, Express, Spring, etc).
Args: { "path": "src/app.py" }

## get_config
Look for configuration files and security-related settings.
Args: { "pattern": "database" }

## done
Signal that you have enough information to make your assessment.
Args: { "verdict": "true_positive" or "false_positive", "confidence": "0.85", "reasoning": "...", "suggested_fix": "..." or null }
"#
    }

    pub fn execute(&self, call: &ToolCall) -> ToolResult {
        match call.tool.as_str() {
            "read_file" => self.read_file(&call.args),
            "search_code" => self.search_code(&call.args),
            "find_function" => self.find_function(&call.args),
            "find_callers" => self.find_callers(&call.args),
            "read_imports" => self.read_imports(&call.args),
            "check_sanitization" => self.check_sanitization(&call.args),
            "list_routes" => self.list_routes(&call.args),
            "get_config" => self.get_config(&call.args),
            "done" => ToolResult {
                tool: "done".to_string(),
                success: true,
                output: "Analysis complete.".to_string(),
            },
            other => ToolResult {
                tool: other.to_string(),
                success: false,
                output: format!("Unknown tool: {}. Available: read_file, search_code, find_function, find_callers, read_imports, check_sanitization, list_routes, get_config, done", other),
            },
        }
    }

    fn read_file(&self, args: &HashMap<String, String>) -> ToolResult {
        let path = match args.get("path") {
            Some(p) => p,
            None => return ToolResult { tool: "read_file".into(), success: false, output: "Missing 'path' argument".into() },
        };

        let target = PathBuf::from(path);
        let content = self.file_contents.iter()
            .find(|(p, _)| p.ends_with(&target) || p.to_str().map_or(false, |s| s.contains(path)))
            .map(|(_, c)| c.as_str());

        match content {
            Some(text) => {
                let start: usize = args.get("start_line").and_then(|s| s.parse().ok()).unwrap_or(1);
                let end: usize = args.get("end_line").and_then(|s| s.parse().ok()).unwrap_or(usize::MAX);

                let output: String = text.lines()
                    .enumerate()
                    .filter(|(i, _)| *i + 1 >= start && *i + 1 <= end)
                    .map(|(i, l)| format!("{:>4} | {}", i + 1, l))
                    .collect::<Vec<_>>()
                    .join("\n");

                let truncated = if output.len() > 3000 {
                    format!("{}...\n(truncated, {} total lines)", &output[..3000], text.lines().count())
                } else {
                    output
                };

                ToolResult { tool: "read_file".into(), success: true, output: truncated }
            }
            None => ToolResult { tool: "read_file".into(), success: false, output: format!("File not found: {}", path) },
        }
    }

    fn search_code(&self, args: &HashMap<String, String>) -> ToolResult {
        let pattern = match args.get("pattern") {
            Some(p) => p,
            None => return ToolResult { tool: "search_code".into(), success: false, output: "Missing 'pattern' argument".into() },
        };

        let pattern_lower = pattern.to_lowercase();
        let mut matches = Vec::new();

        for (path, content) in &self.file_contents {
            for (i, line) in content.lines().enumerate() {
                if line.to_lowercase().contains(&pattern_lower) {
                    matches.push(format!("{}:{} | {}", path.display(), i + 1, line.trim()));
                    if matches.len() >= 30 {
                        matches.push("... (truncated, too many results)".to_string());
                        return ToolResult { tool: "search_code".into(), success: true, output: matches.join("\n") };
                    }
                }
            }
        }

        if matches.is_empty() {
            ToolResult { tool: "search_code".into(), success: true, output: format!("No matches found for '{}'", pattern) }
        } else {
            ToolResult { tool: "search_code".into(), success: true, output: format!("{} matches:\n{}", matches.len(), matches.join("\n")) }
        }
    }

    fn find_function(&self, args: &HashMap<String, String>) -> ToolResult {
        let name = match args.get("function_name") {
            Some(n) => n,
            None => return ToolResult { tool: "find_function".into(), success: false, output: "Missing 'function_name' argument".into() },
        };

        let def_patterns = [
            format!("def {}(", name),
            format!("async def {}(", name),
            format!("function {}(", name),
            format!("async function {}(", name),
            format!("fn {}(", name),
            format!("pub fn {}(", name),
            format!("func {}(", name),
        ];

        let mut results = Vec::new();

        for (path, content) in &self.file_contents {
            for (i, line) in content.lines().enumerate() {
                let trimmed = line.trim();
                if def_patterns.iter().any(|p| trimmed.contains(p.as_str())) {
                    let start = i;
                    let end = (i + 20).min(content.lines().count());
                    let snippet: String = content.lines()
                        .enumerate()
                        .skip(start)
                        .take(end - start)
                        .map(|(j, l)| format!("{:>4} | {}", j + 1, l))
                        .collect::<Vec<_>>()
                        .join("\n");

                    results.push(format!("Found in {}:{}\n{}", path.display(), i + 1, snippet));
                }
            }
        }

        if results.is_empty() {
            ToolResult { tool: "find_function".into(), success: true, output: format!("Function '{}' not found", name) }
        } else {
            ToolResult { tool: "find_function".into(), success: true, output: results.join("\n\n") }
        }
    }

    fn find_callers(&self, args: &HashMap<String, String>) -> ToolResult {
        let name = match args.get("function_name") {
            Some(n) => n,
            None => return ToolResult { tool: "find_callers".into(), success: false, output: "Missing 'function_name' argument".into() },
        };

        let call_pattern = format!("{}(", name);
        let def_patterns = [
            format!("def {}(", name),
            format!("function {}(", name),
            format!("fn {}(", name),
            format!("func {}(", name),
        ];

        let mut callers = Vec::new();

        for (path, content) in &self.file_contents {
            for (i, line) in content.lines().enumerate() {
                let trimmed = line.trim();
                if trimmed.contains(&call_pattern) && !def_patterns.iter().any(|p| trimmed.contains(p.as_str())) {
                    callers.push(format!("{}:{} | {}", path.display(), i + 1, trimmed));
                    if callers.len() >= 20 {
                        return ToolResult { tool: "find_callers".into(), success: true, output: callers.join("\n") };
                    }
                }
            }
        }

        if callers.is_empty() {
            ToolResult { tool: "find_callers".into(), success: true, output: format!("No callers found for '{}'", name) }
        } else {
            ToolResult { tool: "find_callers".into(), success: true, output: format!("{} call sites:\n{}", callers.len(), callers.join("\n")) }
        }
    }

    fn read_imports(&self, args: &HashMap<String, String>) -> ToolResult {
        let path = match args.get("path") {
            Some(p) => p,
            None => return ToolResult { tool: "read_imports".into(), success: false, output: "Missing 'path' argument".into() },
        };

        let target = PathBuf::from(path);
        let content = self.file_contents.iter()
            .find(|(p, _)| p.ends_with(&target) || p.to_str().map_or(false, |s| s.contains(path)))
            .map(|(_, c)| c.as_str());

        match content {
            Some(text) => {
                let imports: Vec<String> = text.lines()
                    .enumerate()
                    .filter(|(_, l)| {
                        let t = l.trim();
                        t.starts_with("import ") || t.starts_with("from ") || t.starts_with("use ")
                            || t.starts_with("require(") || (t.starts_with("const ") && t.contains("require("))
                            || t.starts_with("#include") || t.starts_with("package ")
                    })
                    .map(|(i, l)| format!("{:>4} | {}", i + 1, l.trim()))
                    .collect();

                if imports.is_empty() {
                    ToolResult { tool: "read_imports".into(), success: true, output: "No imports found".into() }
                } else {
                    ToolResult { tool: "read_imports".into(), success: true, output: imports.join("\n") }
                }
            }
            None => ToolResult { tool: "read_imports".into(), success: false, output: format!("File not found: {}", path) },
        }
    }

    fn check_sanitization(&self, args: &HashMap<String, String>) -> ToolResult {
        let path = match args.get("path") {
            Some(p) => p,
            None => return ToolResult { tool: "check_sanitization".into(), success: false, output: "Missing 'path' argument".into() },
        };
        let variable = match args.get("variable") {
            Some(v) => v,
            None => return ToolResult { tool: "check_sanitization".into(), success: false, output: "Missing 'variable' argument".into() },
        };
        let from: usize = args.get("from_line").and_then(|s| s.parse().ok()).unwrap_or(1);
        let to: usize = args.get("to_line").and_then(|s| s.parse().ok()).unwrap_or(usize::MAX);

        let target = PathBuf::from(path);
        let content = self.file_contents.iter()
            .find(|(p, _)| p.ends_with(&target) || p.to_str().map_or(false, |s| s.contains(path)))
            .map(|(_, c)| c.as_str());

        let sanitize_keywords = [
            "escape", "sanitize", "encode", "clean", "validate", "filter",
            "prepared", "parameterize", "bind", "quote", "htmlspecialchars",
            "parseInt", "Number(", "int(", "str(", ".strip(", ".trim(",
        ];

        match content {
            Some(text) => {
                let mut findings = Vec::new();
                for (i, line) in text.lines().enumerate() {
                    let line_num = i + 1;
                    if line_num < from || line_num > to { continue; }
                    if !line.contains(variable) { continue; }

                    let has_sanitize = sanitize_keywords.iter().any(|k| line.contains(k));
                    if has_sanitize {
                        findings.push(format!("SANITIZED at L{}: {}", line_num, line.trim()));
                    } else {
                        findings.push(format!("UNSANITIZED use at L{}: {}", line_num, line.trim()));
                    }
                }

                if findings.is_empty() {
                    ToolResult { tool: "check_sanitization".into(), success: true, output: format!("Variable '{}' not found between lines {}-{}", variable, from, to) }
                } else {
                    ToolResult { tool: "check_sanitization".into(), success: true, output: findings.join("\n") }
                }
            }
            None => ToolResult { tool: "check_sanitization".into(), success: false, output: format!("File not found: {}", path) },
        }
    }

    fn list_routes(&self, args: &HashMap<String, String>) -> ToolResult {
        let path = match args.get("path") {
            Some(p) => p,
            None => return ToolResult { tool: "list_routes".into(), success: false, output: "Missing 'path' argument".into() },
        };

        let target = PathBuf::from(path);
        let content = self.file_contents.iter()
            .find(|(p, _)| p.ends_with(&target) || p.to_str().map_or(false, |s| s.contains(path)))
            .map(|(_, c)| c.as_str());

        let route_patterns = [
            "@app.route", "@router.", "@blueprint.",
            "app.get(", "app.post(", "app.put(", "app.delete(", "router.get(", "router.post(",
            "@GetMapping", "@PostMapping", "@RequestMapping",
            "http.HandleFunc(", "r.HandleFunc(",
            "#[get(", "#[post(",
        ];

        match content {
            Some(text) => {
                let routes: Vec<String> = text.lines()
                    .enumerate()
                    .filter(|(_, l)| route_patterns.iter().any(|p| l.contains(p)))
                    .map(|(i, l)| format!("{:>4} | {}", i + 1, l.trim()))
                    .collect();

                if routes.is_empty() {
                    ToolResult { tool: "list_routes".into(), success: true, output: "No route definitions found".into() }
                } else {
                    ToolResult { tool: "list_routes".into(), success: true, output: routes.join("\n") }
                }
            }
            None => ToolResult { tool: "list_routes".into(), success: false, output: format!("File not found: {}", path) },
        }
    }

    fn get_config(&self, args: &HashMap<String, String>) -> ToolResult {
        let pattern = args.get("pattern").map(|s| s.as_str()).unwrap_or("config");
        let pattern_lower = pattern.to_lowercase();

        let config_extensions = ["yml", "yaml", "toml", "ini", "cfg", "conf", "json", "env"];
        let config_names = ["config", "settings", "application", ".env", "database"];

        let mut results = Vec::new();

        for (path, content) in &self.file_contents {
            let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");

            let is_config = config_extensions.contains(&ext) || config_names.iter().any(|n| file_name.contains(n));

            if !is_config { continue; }

            let relevant_lines: Vec<String> = content.lines()
                .enumerate()
                .filter(|(_, l)| l.to_lowercase().contains(&pattern_lower))
                .map(|(i, l)| format!("{:>4} | {}", i + 1, l.trim()))
                .take(10)
                .collect();

            if !relevant_lines.is_empty() {
                results.push(format!("{}:\n{}", path.display(), relevant_lines.join("\n")));
            }
        }

        if results.is_empty() {
            ToolResult { tool: "get_config".into(), success: true, output: format!("No config entries found matching '{}'", pattern) }
        } else {
            ToolResult { tool: "get_config".into(), success: true, output: results.join("\n\n") }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_toolbox() -> ToolBox {
        let mut files = HashMap::new();
        files.insert(PathBuf::from("src/app.py"), r#"from flask import Flask, request
import sqlite3

app = Flask(__name__)

@app.route('/user')
def get_user():
    uid = request.args.get('id')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id=" + uid)
    return cursor.fetchone()
"#.to_string());
        files.insert(PathBuf::from("src/utils.py"), r#"from src.app import get_user

def admin_view():
    return get_user()
"#.to_string());
        ToolBox::new(files)
    }

    #[test]
    fn test_read_file() {
        let tb = make_toolbox();
        let result = tb.execute(&ToolCall {
            tool: "read_file".into(),
            args: HashMap::from([("path".into(), "src/app.py".into())]),
        });
        assert!(result.success);
        assert!(result.output.contains("flask"));
    }

    #[test]
    fn test_read_file_range() {
        let tb = make_toolbox();
        let result = tb.execute(&ToolCall {
            tool: "read_file".into(),
            args: HashMap::from([
                ("path".into(), "src/app.py".into()),
                ("start_line".into(), "6".into()),
                ("end_line".into(), "12".into()),
            ]),
        });
        assert!(result.success);
        assert!(result.output.contains("get_user"));
        assert!(!result.output.contains("import sqlite3"));
    }

    #[test]
    fn test_search_code() {
        let tb = make_toolbox();
        let result = tb.execute(&ToolCall {
            tool: "search_code".into(),
            args: HashMap::from([("pattern".into(), "cursor.execute".into())]),
        });
        assert!(result.success);
        assert!(result.output.contains("app.py"));
    }

    #[test]
    fn test_find_function() {
        let tb = make_toolbox();
        let result = tb.execute(&ToolCall {
            tool: "find_function".into(),
            args: HashMap::from([("function_name".into(), "get_user".into())]),
        });
        assert!(result.success);
        assert!(result.output.contains("def get_user"));
    }

    #[test]
    fn test_find_callers() {
        let tb = make_toolbox();
        let result = tb.execute(&ToolCall {
            tool: "find_callers".into(),
            args: HashMap::from([("function_name".into(), "get_user".into())]),
        });
        assert!(result.success);
        assert!(result.output.contains("utils.py"));
    }

    #[test]
    fn test_check_sanitization() {
        let tb = make_toolbox();
        let result = tb.execute(&ToolCall {
            tool: "check_sanitization".into(),
            args: HashMap::from([
                ("path".into(), "src/app.py".into()),
                ("variable".into(), "uid".into()),
                ("from_line".into(), "8".into()),
                ("to_line".into(), "12".into()),
            ]),
        });
        assert!(result.success);
        assert!(result.output.contains("UNSANITIZED"));
    }

    #[test]
    fn test_list_routes() {
        let tb = make_toolbox();
        let result = tb.execute(&ToolCall {
            tool: "list_routes".into(),
            args: HashMap::from([("path".into(), "src/app.py".into())]),
        });
        assert!(result.success);
        assert!(result.output.contains("/user"));
    }

    #[test]
    fn test_unknown_tool() {
        let tb = make_toolbox();
        let result = tb.execute(&ToolCall {
            tool: "hack_the_planet".into(),
            args: HashMap::new(),
        });
        assert!(!result.success);
    }
}
