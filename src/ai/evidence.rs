use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct EvidenceBoard {
    pub entries: Vec<Evidence>,
    pub agent_verdicts: Vec<AgentVerdict>,
    pub conflicts: Vec<Conflict>,
    #[serde(skip)]
    #[allow(dead_code)]
    created_at: Option<std::time::SystemTime>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    pub source_agent: String,
    pub category: EvidenceCategory,
    pub content: String,
    pub confidence: f32,
    pub source_type: EvidenceSource,
    #[serde(skip)]
    #[allow(dead_code)]
    pub timestamp_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum EvidenceSource {
    StaticAnalysis,
    LlmReasoning,
    ToolOutput,
    CachedResult,
}

impl Default for EvidenceSource {
    fn default() -> Self { Self::LlmReasoning }
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Conflict {
    pub agent_a: String,
    pub agent_b: String,
    pub description: String,
    pub severity: ConflictSeverity,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ConflictSeverity {
    Minor,
    Major,
    Critical,
}

pub type SharedBoard = Arc<Mutex<EvidenceBoard>>;

const SOURCE_WEIGHT: [(EvidenceSource, f32); 4] = [
    (EvidenceSource::StaticAnalysis, 1.0),
    (EvidenceSource::ToolOutput, 0.9),
    (EvidenceSource::LlmReasoning, 0.7),
    (EvidenceSource::CachedResult, 0.6),
];

impl EvidenceBoard {
    pub fn new_shared() -> SharedBoard {
        Arc::new(Mutex::new(Self {
            created_at: Some(std::time::SystemTime::now()),
            ..Default::default()
        }))
    }

    pub fn add_evidence(&mut self, evidence: Evidence) {
        self.entries.push(evidence);
    }

    #[allow(dead_code)]
    pub fn add_evidence_weighted(&mut self, mut evidence: Evidence) {
        let weight = SOURCE_WEIGHT.iter()
            .find(|(src, _)| *src == evidence.source_type)
            .map(|(_, w)| *w)
            .unwrap_or(0.7);
        evidence.confidence *= weight;
        evidence.confidence = evidence.confidence.clamp(0.0, 1.0);
        self.entries.push(evidence);
    }

    pub fn add_verdict(&mut self, verdict: AgentVerdict) {
        self.detect_verdict_conflicts(&verdict);
        self.agent_verdicts.push(verdict);
    }

    pub fn weighted_confidence(&self, category: &EvidenceCategory) -> f32 {
        let entries: Vec<&Evidence> = self.entries.iter()
            .filter(|e| e.category == *category)
            .collect();
        if entries.is_empty() { return 0.0; }

        let total_weight: f32 = entries.iter().map(|e| {
            let source_w = SOURCE_WEIGHT.iter()
                .find(|(src, _)| *src == e.source_type)
                .map(|(_, w)| *w)
                .unwrap_or(0.7);
            source_w
        }).sum();

        let weighted_sum: f32 = entries.iter().map(|e| {
            let source_w = SOURCE_WEIGHT.iter()
                .find(|(src, _)| *src == e.source_type)
                .map(|(_, w)| *w)
                .unwrap_or(0.7);
            e.confidence * source_w
        }).sum();

        (weighted_sum / total_weight).clamp(0.0, 1.0)
    }

    pub fn has_critical_conflicts(&self) -> bool {
        self.conflicts.iter().any(|c| c.severity == ConflictSeverity::Critical)
    }

    pub fn summary_for_judge(&self) -> String {
        let mut parts = Vec::new();

        let grouped = self.entries_by_category();
        for (cat, entries) in grouped {
            let cat_conf = self.weighted_confidence(&cat);
            parts.push(format!("## {:?} (weighted confidence: {:.2})", cat, cat_conf));
            for e in entries {
                let source_tag = match e.source_type {
                    EvidenceSource::StaticAnalysis => "static",
                    EvidenceSource::LlmReasoning => "llm",
                    EvidenceSource::ToolOutput => "tool",
                    EvidenceSource::CachedResult => "cached",
                };
                parts.push(format!("  [{}|{}] (conf={:.2}) {}", 
                    e.source_agent, source_tag, e.confidence, 
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

        if !self.conflicts.is_empty() {
            parts.push("\n## ⚠ Detected Conflicts".to_string());
            for c in &self.conflicts {
                parts.push(format!(
                    "  [{:?}] {} vs {}: {}",
                    c.severity, c.agent_a, c.agent_b, c.description,
                ));
            }
        }

        parts.join("\n")
    }

    fn detect_verdict_conflicts(&mut self, new_verdict: &AgentVerdict) {
        for existing in &self.agent_verdicts {
            if existing.is_false_positive != new_verdict.is_false_positive {
                let severity = if existing.confidence > 0.7 && new_verdict.confidence > 0.7 {
                    ConflictSeverity::Critical
                } else if existing.confidence > 0.5 && new_verdict.confidence > 0.5 {
                    ConflictSeverity::Major
                } else {
                    ConflictSeverity::Minor
                };

                self.conflicts.push(Conflict {
                    agent_a: existing.agent.clone(),
                    agent_b: new_verdict.agent.clone(),
                    description: format!(
                        "{} says {} but {} says {}",
                        existing.agent,
                        if existing.is_false_positive { "FP" } else { "TP" },
                        new_verdict.agent,
                        if new_verdict.is_false_positive { "FP" } else { "TP" },
                    ),
                    severity,
                });
            }
        }
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

    fn evidence(agent: &str, cat: EvidenceCategory, content: &str, conf: f32, src: EvidenceSource) -> Evidence {
        Evidence {
            source_agent: agent.into(), category: cat, content: content.into(),
            confidence: conf, source_type: src, timestamp_ms: 0,
        }
    }

    #[test]
    fn test_evidence_board_add_and_summary() {
        let mut board = EvidenceBoard::default();
        board.add_evidence(evidence("context", EvidenceCategory::FileContext,
            "Python Flask app, not a test file", 0.95, EvidenceSource::StaticAnalysis));
        board.add_evidence(evidence("dataflow", EvidenceCategory::DataflowPath,
            "request.args -> uid -> cursor.execute (no sanitization)", 0.9, EvidenceSource::ToolOutput));
        board.add_verdict(AgentVerdict {
            agent: "exploit".into(), is_false_positive: false,
            confidence: 0.88, reasoning: "SQL injection confirmed".into(),
            suggested_fix: Some("Use parameterized query".into()),
        });

        let summary = board.summary_for_judge();
        assert!(summary.contains("FileContext"));
        assert!(summary.contains("DataflowPath"));
        assert!(summary.contains("TRUE_POSITIVE"));
        assert!(summary.contains("static"));
        assert!(summary.contains("tool"));
    }

    #[test]
    fn test_weighted_confidence() {
        let mut board = EvidenceBoard::default();
        board.add_evidence(evidence("a", EvidenceCategory::DataflowPath,
            "static result", 0.9, EvidenceSource::StaticAnalysis));
        board.add_evidence(evidence("b", EvidenceCategory::DataflowPath,
            "llm result", 0.9, EvidenceSource::LlmReasoning));

        let conf = board.weighted_confidence(&EvidenceCategory::DataflowPath);
        assert!(conf > 0.7);
        assert!(conf < 0.95);
    }

    #[test]
    fn test_conflict_detection() {
        let mut board = EvidenceBoard::default();
        board.add_verdict(AgentVerdict {
            agent: "context".into(), is_false_positive: true,
            confidence: 0.9, reasoning: "test file".into(), suggested_fix: None,
        });
        board.add_verdict(AgentVerdict {
            agent: "exploit".into(), is_false_positive: false,
            confidence: 0.85, reasoning: "exploitable".into(), suggested_fix: None,
        });

        assert_eq!(board.conflicts.len(), 1);
        assert!(board.has_critical_conflicts());
        assert!(board.conflicts[0].description.contains("context"));
    }

    #[test]
    fn test_no_conflict_when_agree() {
        let mut board = EvidenceBoard::default();
        board.add_verdict(AgentVerdict {
            agent: "a".into(), is_false_positive: false,
            confidence: 0.9, reasoning: "real".into(), suggested_fix: None,
        });
        board.add_verdict(AgentVerdict {
            agent: "b".into(), is_false_positive: false,
            confidence: 0.8, reasoning: "confirmed".into(), suggested_fix: None,
        });
        assert!(board.conflicts.is_empty());
    }

    #[test]
    fn test_evidence_weighted_add() {
        let mut board = EvidenceBoard::default();
        board.add_evidence_weighted(Evidence {
            source_agent: "a".into(), category: EvidenceCategory::FileContext,
            content: "test".into(), confidence: 1.0,
            source_type: EvidenceSource::CachedResult, timestamp_ms: 0,
        });
        assert!(board.entries[0].confidence < 1.0);
        assert!(board.entries[0].confidence >= 0.5);
    }

    #[test]
    fn test_shared_board_thread_safe() {
        let board = EvidenceBoard::new_shared();
        let b1 = board.clone();
        let b2 = board.clone();

        std::thread::spawn(move || {
            b1.lock().unwrap().add_evidence(evidence("a1", EvidenceCategory::FileContext,
                "test", 0.5, EvidenceSource::StaticAnalysis));
        }).join().unwrap();

        std::thread::spawn(move || {
            b2.lock().unwrap().add_evidence(evidence("a2", EvidenceCategory::DataflowPath,
                "test2", 0.6, EvidenceSource::ToolOutput));
        }).join().unwrap();

        assert_eq!(board.lock().unwrap().entries.len(), 2);
    }

    #[test]
    fn test_summary_includes_conflicts() {
        let mut board = EvidenceBoard::default();
        board.add_verdict(AgentVerdict {
            agent: "a".into(), is_false_positive: true,
            confidence: 0.8, reasoning: "fp".into(), suggested_fix: None,
        });
        board.add_verdict(AgentVerdict {
            agent: "b".into(), is_false_positive: false,
            confidence: 0.8, reasoning: "tp".into(), suggested_fix: None,
        });
        let summary = board.summary_for_judge();
        assert!(summary.contains("Conflicts"));
    }
}
