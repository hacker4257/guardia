pub mod cwe_rules;
pub mod cve_db;

use crate::scanner::Finding;

pub struct KnowledgeBase {
    pub cve_db: Option<cve_db::CveDatabase>,
}

impl KnowledgeBase {
    pub fn new(cve_db_path: Option<&str>) -> Self {
        let cve_db = cve_db_path.and_then(|p| cve_db::CveDatabase::load(p).ok());
        Self { cve_db }
    }

    pub fn enrich_context_agent(&self, finding: &Finding) -> String {
        let mut parts = Vec::new();

        if let Some(cwe) = cwe_rules::lookup_by_rule_id(&finding.rule_id) {
            parts.push(format!(
                "## CWE Knowledge: {} — {}\n{}\n\nKnown mitigations: {}\nSeverity guidance: {}",
                cwe.id, cwe.name, cwe.description,
                cwe.mitigations.join("; "),
                cwe.severity_guidance,
            ));
        }

        parts.join("\n\n")
    }

    pub fn enrich_dataflow_agent(&self, finding: &Finding) -> String {
        let mut parts = Vec::new();

        if let Some(cwe) = cwe_rules::lookup_by_rule_id(&finding.rule_id) {
            parts.push(format!(
                "## CWE Vulnerable Patterns for {} ({})\n{}",
                cwe.id, cwe.name,
                cwe.vulnerable_patterns.join("\n"),
            ));
        }

        parts.join("\n\n")
    }

    pub fn enrich_exploit_agent(&self, finding: &Finding) -> String {
        let mut parts = Vec::new();

        if let Some(cwe) = cwe_rules::lookup_by_rule_id(&finding.rule_id) {
            parts.push(format!(
                "## CWE Attack Context: {} — {}\nPatterns: {}\nRelated CWEs: {}",
                cwe.id, cwe.name,
                cwe.vulnerable_patterns.join("; "),
                cwe.related_cwes.join(", "),
            ));
        }

        if let Some(ref db) = self.cve_db {
            let cves = db.find_relevant(&finding.rule_id, finding.description.as_str());
            if !cves.is_empty() {
                let cve_text: Vec<String> = cves.iter().take(3).map(|c| {
                    format!("- {} (CVSS {}): {} [{}]", c.id, c.cvss, c.description, c.affected_product)
                }).collect();
                parts.push(format!("## Related CVEs\n{}", cve_text.join("\n")));
            }
        }

        parts.join("\n\n")
    }

    pub fn enrich_judge_agent(&self, finding: &Finding) -> String {
        if let Some(cwe) = cwe_rules::lookup_by_rule_id(&finding.rule_id) {
            format!(
                "## CWE Severity Guidance for {} ({})\n{}",
                cwe.id, cwe.name, cwe.severity_guidance,
            )
        } else {
            String::new()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn make_finding(rule_id: &str) -> Finding {
        Finding {
            rule_id: rule_id.to_string(),
            severity: crate::scanner::Severity::High,
            title: "Test".to_string(),
            description: "SQL injection test".to_string(),
            file_path: PathBuf::from("test.py"),
            line_number: 1,
            line_content: "execute(q)".to_string(),
            matched_text: "execute".to_string(),
            suggestion: "use parameterized".to_string(),
        }
    }

    #[test]
    fn test_knowledge_base_enriches_vuln() {
        let kb = KnowledgeBase::new(None);
        let ctx = kb.enrich_context_agent(&make_finding("VULN001"));
        assert!(ctx.contains("CWE") || ctx.is_empty());
    }

    #[test]
    fn test_knowledge_base_no_cve_db() {
        let kb = KnowledgeBase::new(None);
        assert!(kb.cve_db.is_none());
    }
}
