use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct EvidenceBoard {
    pub entries: Vec<Evidence>,
    pub agent_verdicts: Vec<AgentVerdict>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    pub source_agent: String,
    pub category: EvidenceCategory,
    pub content: String,
    pub confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum EvidenceCategory {
    FileContext,
    DataflowPath,
    SanitizationCheck,
    ExploitAssessment,
    CodePattern,
    ConfigFinding,
    CallerAnalysis,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentVerdict {
    pub agent: String,
    pub is_false_positive: bool,
    pub confidence: f32,
    pub reasoning: String,
    pub suggested_fix: Option<String>,
}

pub type SharedBoard = Arc<Mutex<EvidenceBoard>>;

impl EvidenceBoard {
    pub fn new_shared() -> SharedBoard {
        Arc::new(Mutex::new(Self::default()))
    }

    pub fn add_evidence(&mut self, evidence: Evidence) {
        self.entries.push(evidence);
    }

    pub fn add_verdict(&mut self, verdict: AgentVerdict) {
        self.agent_verdicts.push(verdict);
    }

    pub fn summary_for_judge(&self) -> String {
        let mut parts = Vec::new();

        let grouped = self.entries_by_category();
        for (cat, entries) in grouped {
            parts.push(format!("## {:?}", cat));
            for e in entries {
                parts.push(format!("  [{}] (conf={:.2}) {}", e.source_agent, e.confidence, 
                    truncate(&e.content, 300)));
            }
        }

        if !self.agent_verdicts.is_empty() {
            parts.push("\n## Agent Verdicts".to_string());
            for v in &self.agent_verdicts {
                parts.push(format!(
                    "  [{}] {} (conf={:.2}): {}",
                    v.agent,
                    if v.is_false_positive { "FALSE_POSITIVE" } else { "TRUE_POSITIVE" },
                    v.confidence,
                    truncate(&v.reasoning, 200),
                ));
            }
        }

        parts.join("\n")
    }

    fn entries_by_category(&self) -> Vec<(EvidenceCategory, Vec<&Evidence>)> {
        use EvidenceCategory::*;
        let order = [FileContext, DataflowPath, SanitizationCheck, 
                     ExploitAssessment, CodePattern, ConfigFinding, CallerAnalysis];
        let mut result = Vec::new();
        for cat in &order {
            let entries: Vec<&Evidence> = self.entries.iter()
                .filter(|e| e.category == *cat)
                .collect();
            if !entries.is_empty() {
                result.push((cat.clone(), entries));
            }
        }
        result
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max { s.to_string() } else { format!("{}...", &s[..max]) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_evidence_board_add_and_summary() {
        let mut board = EvidenceBoard::default();
        board.add_evidence(Evidence {
            source_agent: "context".into(),
            category: EvidenceCategory::FileContext,
            content: "Python Flask app, not a test file".into(),
            confidence: 0.95,
        });
        board.add_evidence(Evidence {
            source_agent: "dataflow".into(),
            category: EvidenceCategory::DataflowPath,
            content: "request.args → uid → cursor.execute (no sanitization)".into(),
            confidence: 0.9,
        });
        board.add_verdict(AgentVerdict {
            agent: "exploit".into(),
            is_false_positive: false,
            confidence: 0.88,
            reasoning: "SQL injection confirmed".into(),
            suggested_fix: Some("Use parameterized query".into()),
        });

        let summary = board.summary_for_judge();
        assert!(summary.contains("FileContext"));
        assert!(summary.contains("DataflowPath"));
        assert!(summary.contains("TRUE_POSITIVE"));
    }

    #[test]
    fn test_shared_board_thread_safe() {
        let board = EvidenceBoard::new_shared();
        let b1 = board.clone();
        let b2 = board.clone();

        std::thread::spawn(move || {
            b1.lock().unwrap().add_evidence(Evidence {
                source_agent: "a1".into(),
                category: EvidenceCategory::FileContext,
                content: "test".into(),
                confidence: 0.5,
            });
        }).join().unwrap();

        std::thread::spawn(move || {
            b2.lock().unwrap().add_evidence(Evidence {
                source_agent: "a2".into(),
                category: EvidenceCategory::DataflowPath,
                content: "test2".into(),
                confidence: 0.6,
            });
        }).join().unwrap();

        assert_eq!(board.lock().unwrap().entries.len(), 2);
    }
}
