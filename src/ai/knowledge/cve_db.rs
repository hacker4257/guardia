use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct CveEntry {
    pub id: String,
    pub affected_product: String,
    pub description: String,
    pub cvss: f32,
    pub cwe_ids: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct CveDatabase {
    entries: Vec<CveEntry>,
}

impl CveDatabase {
    pub fn load(path: &str) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let entries: Vec<CveEntry> = serde_json::from_str(&content)?;
        Ok(Self { entries })
    }

    pub fn find_relevant(&self, rule_id: &str, description: &str) -> Vec<&CveEntry> {
        let target_cwe = super::cwe_rules::lookup_by_rule_id(rule_id)
            .map(|e| e.id.to_string());

        let desc_lower = description.to_lowercase();
        let keywords: Vec<&str> = desc_lower.split_whitespace()
            .filter(|w| w.len() > 3)
            .take(5)
            .collect();

        let mut scored: Vec<(f32, &CveEntry)> = self.entries.iter()
            .map(|cve| {
                let mut score = 0.0f32;

                if let Some(ref cwe_id) = target_cwe {
                    if cve.cwe_ids.iter().any(|c| c == cwe_id) {
                        score += 5.0;
                    }
                }

                let cve_desc_lower = cve.description.to_lowercase();
                for kw in &keywords {
                    if cve_desc_lower.contains(kw) {
                        score += 1.0;
                    }
                }

                score += cve.cvss / 10.0;

                (score, cve)
            })
            .filter(|(score, _)| *score > 2.0)
            .collect();

        scored.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));
        scored.into_iter().take(5).map(|(_, e)| e).collect()
    }

    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cve_database_load_nonexistent() {
        assert!(CveDatabase::load("/nonexistent/path.json").is_err());
    }

    #[test]
    fn test_find_relevant_empty_db() {
        let db = CveDatabase { entries: vec![] };
        let results = db.find_relevant("VULN001", "SQL injection");
        assert!(results.is_empty());
    }

    #[test]
    fn test_find_relevant_with_entries() {
        let db = CveDatabase {
            entries: vec![
                CveEntry {
                    id: "CVE-2024-1234".into(),
                    affected_product: "TestApp".into(),
                    description: "SQL injection in user login endpoint".into(),
                    cvss: 9.8,
                    cwe_ids: vec!["CWE-89".into()],
                },
                CveEntry {
                    id: "CVE-2024-5678".into(),
                    affected_product: "OtherApp".into(),
                    description: "Buffer overflow in image parser".into(),
                    cvss: 7.5,
                    cwe_ids: vec!["CWE-119".into()],
                },
            ],
        };

        let results = db.find_relevant("VULN001", "SQL injection vulnerability");
        assert!(!results.is_empty());
        assert_eq!(results[0].id, "CVE-2024-1234");
    }
}
