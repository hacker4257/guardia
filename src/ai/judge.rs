use anyhow::Result;
use serde::Deserialize;

use crate::scanner::Finding;
use super::evidence::{SharedBoard, AgentVerdict};
use super::{AiConfig, AiAnalysis, call_with_retry, extract_json_object};

#[derive(Deserialize)]
struct JudgeDecision {
    #[serde(default)]
    verdict: String,
    #[serde(default = "default_conf")]
    confidence: String,
    #[serde(default)]
    reasoning: String,
    #[serde(default)]
    suggested_fix: Option<String>,
    #[serde(default)]
    dissenting_note: Option<String>,
}

fn default_conf() -> String { "0.5".to_string() }

pub async fn run_judge(
    finding: &Finding,
    config: &AiConfig,
    client: &reqwest::Client,
    board: SharedBoard,
) -> Result<AiAnalysis> {
    let evidence_summary = board.lock().unwrap().summary_for_judge();
    let verdicts = board.lock().unwrap().agent_verdicts.clone();

    if let Some(quick) = try_quick_consensus(&verdicts) {
        return Ok(quick);
    }

    let prompt = format!(
        r#"You are the Judge Agent — the final decision maker for a security finding.
Multiple specialist agents have independently analyzed this finding and submitted evidence.
Your job: synthesize ALL evidence, resolve conflicts, and deliver a final verdict.

## The Finding
Rule: {rule_id} — {title}
Severity: {severity}
File: {file}:{line}
Description: {desc}

## Evidence Board (from specialist agents)
{evidence}

## Decision Rules
1. If ALL agents agree → adopt their consensus but verify reasoning
2. If agents DISAGREE → weigh evidence quality, not just vote count
3. Dataflow evidence (sanitization, taint path) outweighs context-only evidence
4. Exploit assessment is the strongest signal for true positives
5. Test/fixture file context is the strongest signal for false positives
6. When uncertain, lean toward TRUE POSITIVE (security-conservative)

## Your Response
Respond with a single JSON object:
{{
  "verdict": "true_positive" or "false_positive",
  "confidence": "0.0-1.0",
  "reasoning": "synthesized explanation citing specific agent evidence",
  "suggested_fix": "code fix or null",
  "dissenting_note": "if any agent disagreed, note why you overruled them, or null"
}}"#,
        rule_id = finding.rule_id,
        title = finding.title,
        severity = finding.severity,
        file = finding.file_path.display(),
        line = finding.line_number,
        desc = &finding.description[..finding.description.len().min(200)],
        evidence = evidence_summary,
    );

    let response = call_with_retry(client, config, &prompt).await
        .unwrap_or_else(|_| build_fallback_from_verdicts(&verdicts));

    let analysis = parse_judge_response(&response, &verdicts);

    if should_self_check(&analysis, &verdicts) {
        if let Some(refined) = self_check(&analysis, &evidence_summary, finding, config, client).await {
            return Ok(refined);
        }
    }

    Ok(analysis)
}

fn try_quick_consensus(verdicts: &[AgentVerdict]) -> Option<AiAnalysis> {
    if verdicts.is_empty() {
        return None;
    }

    let all_fp = verdicts.iter().all(|v| v.is_false_positive);
    let all_tp = verdicts.iter().all(|v| !v.is_false_positive);
    let avg_conf: f32 = verdicts.iter().map(|v| v.confidence).sum::<f32>() / verdicts.len() as f32;

    if avg_conf > 0.85 && verdicts.len() >= 2 {
        if all_fp {
            let reasons: Vec<&str> = verdicts.iter().map(|v| v.reasoning.as_str()).collect();
            return Some(AiAnalysis {
                is_false_positive: true,
                confidence: avg_conf,
                reasoning: format!("[consensus] {}", reasons.join("; ")),
                suggested_fix: verdicts.iter().find_map(|v| v.suggested_fix.clone()),
            });
        }
        if all_tp {
            let reasons: Vec<&str> = verdicts.iter().map(|v| v.reasoning.as_str()).collect();
            return Some(AiAnalysis {
                is_false_positive: false,
                confidence: avg_conf,
                reasoning: format!("[consensus] {}", reasons.join("; ")),
                suggested_fix: verdicts.iter().find_map(|v| v.suggested_fix.clone()),
            });
        }
    }

    None
}

fn parse_judge_response(response: &str, verdicts: &[AgentVerdict]) -> AiAnalysis {
    if let Some(json_str) = extract_json_object(response) {
        if let Ok(decision) = serde_json::from_str::<JudgeDecision>(&json_str) {
            let confidence: f32 = decision.confidence.parse().unwrap_or(0.5);
            let is_fp = decision.verdict.contains("false");

            let mut reasoning = decision.reasoning;
            if let Some(note) = decision.dissenting_note {
                if !note.is_empty() && note != "null" {
                    reasoning = format!("{} [dissent: {}]", reasoning, note);
                }
            }

            return AiAnalysis {
                is_false_positive: is_fp,
                confidence: confidence.clamp(0.0, 1.0),
                reasoning: reasoning.chars().take(500).collect(),
                suggested_fix: decision.suggested_fix.filter(|s| !s.is_empty() && s != "null"),
            };
        }
    }

    build_analysis_from_verdicts(verdicts)
}

fn build_fallback_from_verdicts(verdicts: &[AgentVerdict]) -> String {
    let analysis = build_analysis_from_verdicts(verdicts);
    format!(
        r#"{{"verdict": "{}", "confidence": "{:.2}", "reasoning": "{}", "suggested_fix": null}}"#,
        if analysis.is_false_positive { "false_positive" } else { "true_positive" },
        analysis.confidence,
        analysis.reasoning.replace('"', "'"),
    )
}

fn build_analysis_from_verdicts(verdicts: &[AgentVerdict]) -> AiAnalysis {
    if verdicts.is_empty() {
        return AiAnalysis {
            is_false_positive: false,
            confidence: 0.3,
            reasoning: "No agent verdicts available — defaulting to scanner verdict".into(),
            suggested_fix: None,
        };
    }

    let fp_votes = verdicts.iter().filter(|v| v.is_false_positive).count();
    let tp_votes = verdicts.len() - fp_votes;
    let is_fp = fp_votes > tp_votes;
    let avg_conf: f32 = verdicts.iter().map(|v| v.confidence).sum::<f32>() / verdicts.len() as f32;

    let reasons: Vec<String> = verdicts.iter()
        .map(|v| format!("[{}] {}", v.agent, v.reasoning))
        .collect();

    AiAnalysis {
        is_false_positive: is_fp,
        confidence: avg_conf.clamp(0.0, 1.0),
        reasoning: format!("[vote {}/{}] {}", 
            if is_fp { fp_votes } else { tp_votes }, verdicts.len(),
            reasons.join("; ")).chars().take(500).collect(),
        suggested_fix: verdicts.iter().find_map(|v| v.suggested_fix.clone()),
    }
}

fn should_self_check(analysis: &AiAnalysis, verdicts: &[AgentVerdict]) -> bool {
    if analysis.confidence < 0.6 {
        return true;
    }

    let fp_count = verdicts.iter().filter(|v| v.is_false_positive).count();
    let tp_count = verdicts.len() - fp_count;
    if fp_count > 0 && tp_count > 0 {
        return true;
    }

    false
}

async fn self_check(
    candidate: &AiAnalysis,
    evidence: &str,
    finding: &Finding,
    config: &AiConfig,
    client: &reqwest::Client,
) -> Option<AiAnalysis> {
    let prompt = format!(
        r#"You are reviewing a security verdict for potential errors.

## Finding
{rule_id}: {title} in {file}:{line}

## Current Verdict
- {verdict} (confidence: {conf:.2})
- Reasoning: {reasoning}

## Full Evidence
{evidence}

## Self-Check Questions
1. Does the evidence actually support this verdict?
2. Did the judge miss or misweigh any critical evidence?
3. Are there contradictions between agents that weren't resolved?
4. Would a senior security engineer agree?

If the verdict is correct:
{{"action": "confirm"}}

If it should change:
{{"action": "revise", "false_positive": true/false, "confidence": 0.0-1.0, "reasoning": "..."}}"#,
        rule_id = finding.rule_id,
        title = finding.title,
        file = finding.file_path.display(),
        line = finding.line_number,
        verdict = if candidate.is_false_positive { "FALSE_POSITIVE" } else { "TRUE_POSITIVE" },
        conf = candidate.confidence,
        reasoning = candidate.reasoning,
        evidence = if evidence.len() > 2000 { &evidence[..2000] } else { evidence },
    );

    let response = call_with_retry(client, config, &prompt).await.ok()?;

    if let Some(json_str) = extract_json_object(&response) {
        if json_str.contains("\"revise\"") {
            #[derive(Deserialize)]
            struct Revision {
                #[serde(default)]
                false_positive: bool,
                #[serde(default = "rev_default_conf")]
                confidence: f32,
                #[serde(default)]
                reasoning: String,
            }
            fn rev_default_conf() -> f32 { 0.5 }

            if let Ok(rev) = serde_json::from_str::<Revision>(&json_str) {
                return Some(AiAnalysis {
                    is_false_positive: rev.false_positive,
                    confidence: rev.confidence.clamp(0.0, 1.0),
                    reasoning: format!("[revised by self-check] {}", rev.reasoning)
                        .chars().take(500).collect(),
                    suggested_fix: candidate.suggested_fix.clone(),
                });
            }
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_quick_consensus_all_fp() {
        let verdicts = vec![
            AgentVerdict {
                agent: "context".into(), is_false_positive: true,
                confidence: 0.9, reasoning: "test file".into(), suggested_fix: None,
            },
            AgentVerdict {
                agent: "dataflow".into(), is_false_positive: true,
                confidence: 0.88, reasoning: "no real data flow".into(), suggested_fix: None,
            },
        ];
        let result = try_quick_consensus(&verdicts);
        assert!(result.is_some());
        let analysis = result.unwrap();
        assert!(analysis.is_false_positive);
        assert!(analysis.confidence > 0.85);
    }

    #[test]
    fn test_quick_consensus_disagreement() {
        let verdicts = vec![
            AgentVerdict {
                agent: "context".into(), is_false_positive: true,
                confidence: 0.9, reasoning: "test file".into(), suggested_fix: None,
            },
            AgentVerdict {
                agent: "exploit".into(), is_false_positive: false,
                confidence: 0.85, reasoning: "exploitable".into(), suggested_fix: None,
            },
        ];
        let result = try_quick_consensus(&verdicts);
        assert!(result.is_none());
    }

    #[test]
    fn test_build_analysis_from_verdicts_majority() {
        let verdicts = vec![
            AgentVerdict {
                agent: "a".into(), is_false_positive: false,
                confidence: 0.8, reasoning: "real".into(), suggested_fix: Some("fix".into()),
            },
            AgentVerdict {
                agent: "b".into(), is_false_positive: false,
                confidence: 0.7, reasoning: "confirmed".into(), suggested_fix: None,
            },
            AgentVerdict {
                agent: "c".into(), is_false_positive: true,
                confidence: 0.6, reasoning: "maybe not".into(), suggested_fix: None,
            },
        ];
        let analysis = build_analysis_from_verdicts(&verdicts);
        assert!(!analysis.is_false_positive);
        assert!(analysis.suggested_fix.is_some());
    }

    #[test]
    fn test_should_self_check_low_confidence() {
        let analysis = AiAnalysis {
            is_false_positive: false, confidence: 0.4,
            reasoning: "unsure".into(), suggested_fix: None,
        };
        assert!(should_self_check(&analysis, &[]));
    }

    #[test]
    fn test_should_self_check_disagreement() {
        let analysis = AiAnalysis {
            is_false_positive: false, confidence: 0.8,
            reasoning: "real".into(), suggested_fix: None,
        };
        let verdicts = vec![
            AgentVerdict {
                agent: "a".into(), is_false_positive: false,
                confidence: 0.8, reasoning: "real".into(), suggested_fix: None,
            },
            AgentVerdict {
                agent: "b".into(), is_false_positive: true,
                confidence: 0.7, reasoning: "fake".into(), suggested_fix: None,
            },
        ];
        assert!(should_self_check(&analysis, &verdicts));
    }

    #[test]
    fn test_parse_judge_response_valid() {
        let resp = r#"{"verdict": "true_positive", "confidence": "0.88", "reasoning": "SQL injection confirmed by dataflow", "suggested_fix": "Use parameterized query", "dissenting_note": null}"#;
        let analysis = parse_judge_response(resp, &[]);
        assert!(!analysis.is_false_positive);
        assert!((analysis.confidence - 0.88).abs() < 0.01);
        assert!(analysis.suggested_fix.is_some());
    }

    #[test]
    fn test_parse_judge_response_with_dissent() {
        let resp = r#"{"verdict": "true_positive", "confidence": "0.75", "reasoning": "Confirmed vuln", "suggested_fix": null, "dissenting_note": "Context agent said FP but evidence is weak"}"#;
        let analysis = parse_judge_response(resp, &[]);
        assert!(analysis.reasoning.contains("dissent"));
    }

    #[test]
    fn test_parse_judge_response_fallback() {
        let resp = "I think this is a true positive because...";
        let verdicts = vec![
            AgentVerdict {
                agent: "a".into(), is_false_positive: false,
                confidence: 0.8, reasoning: "real".into(), suggested_fix: None,
            },
        ];
        let analysis = parse_judge_response(resp, &verdicts);
        assert!(!analysis.is_false_positive);
    }
}
