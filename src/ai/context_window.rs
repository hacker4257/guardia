use std::collections::VecDeque;

const CHARS_PER_TOKEN: usize = 4;

#[derive(Debug, Clone)]
pub struct ContextWindow {
    max_tokens: usize,
    system_prompt: String,
    turns: VecDeque<Turn>,
    summaries: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct Turn {
    pub role: TurnRole,
    pub content: String,
    token_estimate: usize,
}

#[derive(Debug, Clone, PartialEq)]
pub enum TurnRole {
    Assistant,
    ToolResult,
    Nudge,
}

impl ContextWindow {
    pub fn new(max_tokens: usize, system_prompt: String) -> Self {
        Self {
            max_tokens,
            system_prompt,
            turns: VecDeque::new(),
            summaries: Vec::new(),
        }
    }

    pub fn add_assistant(&mut self, content: String) {
        self.push_turn(TurnRole::Assistant, content);
    }

    pub fn add_tool_result(&mut self, tool_name: &str, output: String) {
        let truncated = budget_truncate(&output, self.per_turn_budget());
        let content = format!("[Tool Result: {}]\n{}", tool_name, truncated);
        self.push_turn(TurnRole::ToolResult, content);
    }

    pub fn add_nudge(&mut self, content: String) {
        self.push_turn(TurnRole::Nudge, content);
    }

    pub fn render(&self) -> String {
        let mut parts = Vec::with_capacity(3 + self.turns.len());
        parts.push(self.system_prompt.clone());

        if !self.summaries.is_empty() {
            parts.push(format!(
                "\n[Previous context summary]\n{}",
                self.summaries.join("\n")
            ));
        }

        for turn in &self.turns {
            let prefix = match turn.role {
                TurnRole::Assistant => "[assistant]",
                TurnRole::ToolResult => "[observation]",
                TurnRole::Nudge => "[user]",
            };
            parts.push(format!("{}\n{}", prefix, turn.content));
        }

        parts.join("\n\n")
    }

    pub fn current_tokens(&self) -> usize {
        let system_tokens = estimate_tokens(&self.system_prompt);
        let summary_tokens: usize = self.summaries.iter().map(|s| estimate_tokens(s)).sum();
        let turn_tokens: usize = self.turns.iter().map(|t| t.token_estimate).sum();
        system_tokens + summary_tokens + turn_tokens
    }

    #[allow(dead_code)]
    pub fn remaining_tokens(&self) -> usize {
        self.max_tokens.saturating_sub(self.current_tokens())
    }

    fn per_turn_budget(&self) -> usize {
        (self.max_tokens / 8).max(500)
    }

    fn push_turn(&mut self, role: TurnRole, content: String) {
        let token_estimate = estimate_tokens(&content);
        self.turns.push_back(Turn { role, content, token_estimate });
        self.evict_if_needed();
    }

    fn evict_if_needed(&mut self) {
        let reserve = self.max_tokens / 4;
        while self.current_tokens() > self.max_tokens.saturating_sub(reserve) && self.turns.len() > 2 {
            let evicted = self.compress_oldest();
            if let Some(summary) = evicted {
                if self.summaries.len() >= 3 {
                    self.summaries = vec![merge_summaries(&self.summaries)];
                }
                self.summaries.push(summary);
            }
        }
    }

    fn compress_oldest(&mut self) -> Option<String> {
        let mut evicted_content = Vec::new();

        while evicted_content.len() < 3 && self.turns.len() > 2 {
            if let Some(turn) = self.turns.pop_front() {
                evicted_content.push(summarize_turn(&turn));
            }
        }

        if evicted_content.is_empty() {
            None
        } else {
            Some(evicted_content.join(" | "))
        }
    }
}

fn estimate_tokens(text: &str) -> usize {
    (text.len() / CHARS_PER_TOKEN).max(1)
}

fn budget_truncate(text: &str, max_tokens: usize) -> String {
    let max_chars = max_tokens * CHARS_PER_TOKEN;
    if text.len() <= max_chars {
        text.to_string()
    } else {
        let head = max_chars * 3 / 4;
        let tail = max_chars / 4;
        let tail_start = text.len().saturating_sub(tail);
        format!(
            "{}...\n[{} chars omitted]\n...{}",
            &text[..head.min(text.len())],
            text.len() - head - tail,
            &text[tail_start..],
        )
    }
}

fn summarize_turn(turn: &Turn) -> String {
    let prefix = match turn.role {
        TurnRole::Assistant => "Agent said",
        TurnRole::ToolResult => "Tool returned",
        TurnRole::Nudge => "Prompted",
    };

    let content_preview: String = turn.content
        .lines()
        .filter(|l| !l.trim().is_empty())
        .take(2)
        .map(|l| l.chars().take(80).collect::<String>())
        .collect::<Vec<_>>()
        .join("; ");

    format!("{}: {}", prefix, content_preview)
}

fn merge_summaries(summaries: &[String]) -> String {
    let combined: String = summaries.iter()
        .map(|s| s.chars().take(100).collect::<String>())
        .collect::<Vec<_>>()
        .join(" → ");
    format!("[compressed history] {}", combined)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_render() {
        let mut cw = ContextWindow::new(4000, "You are a security analyst.".into());
        cw.add_tool_result("read_file", "def get_user(uid):\n  return db.query(uid)".into());
        cw.add_assistant("I see the function. Let me check sanitization.".into());

        let rendered = cw.render();
        assert!(rendered.contains("security analyst"));
        assert!(rendered.contains("[observation]"));
        assert!(rendered.contains("[assistant]"));
        assert!(rendered.contains("get_user"));
    }

    #[test]
    fn test_token_estimation() {
        assert_eq!(estimate_tokens("hello world!"), 3);
        assert_eq!(estimate_tokens(""), 1);
    }

    #[test]
    fn test_budget_truncate_short() {
        let result = budget_truncate("short text", 1000);
        assert_eq!(result, "short text");
    }

    #[test]
    fn test_budget_truncate_long() {
        let long = "x".repeat(10000);
        let result = budget_truncate(&long, 500);
        assert!(result.len() < 10000);
        assert!(result.contains("chars omitted"));
    }

    #[test]
    fn test_eviction_under_pressure() {
        let mut cw = ContextWindow::new(200, "sys".into());
        for i in 0..20 {
            cw.add_tool_result("search", format!("result line {} with some padding text here", i));
        }
        assert!(cw.current_tokens() <= 200);
        assert!(!cw.summaries.is_empty());
    }

    #[test]
    fn test_remaining_tokens() {
        let cw = ContextWindow::new(1000, "system prompt here".into());
        assert!(cw.remaining_tokens() > 0);
        assert!(cw.remaining_tokens() < 1000);
    }

    #[test]
    fn test_summary_merge() {
        let mut cw = ContextWindow::new(100, "s".into());
        for i in 0..30 {
            cw.add_assistant(format!("step {} analysis with details", i));
        }
        assert!(cw.summaries.len() <= 4);
    }

    #[test]
    fn test_summarize_turn() {
        let turn = Turn {
            role: TurnRole::ToolResult,
            content: "Found 5 matches:\nsrc/app.py:10 | cursor.execute(q)\nsrc/db.py:20 | execute(sql)".into(),
            token_estimate: 20,
        };
        let summary = summarize_turn(&turn);
        assert!(summary.starts_with("Tool returned"));
        assert!(summary.contains("cursor.execute"));
    }
}
