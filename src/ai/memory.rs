use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

pub type SharedMemory = Arc<Mutex<ProjectMemory>>;

// ── Structured Project Memory ──

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProjectMemory {
    pub project_profile: ProjectProfile,
    pub security_posture: SecurityPosture,
    pub knowledge_entries: Vec<KnowledgeEntry>,
    pub finding_conclusions: Vec<FindingConclusion>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProjectProfile {
    pub framework: Option<String>,
    pub language: Option<String>,
    pub orm: Option<String>,
    pub auth_mechanism: Option<String>,
    pub template_engine: Option<String>,
    pub package_manager: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SecurityPosture {
    pub has_csrf_protection: Option<bool>,
    pub has_rate_limiting: Option<bool>,
    pub has_input_validation_layer: Option<bool>,
    pub has_waf: Option<bool>,
    pub known_sanitizers: Vec<String>,
    pub known_auth_decorators: Vec<String>,
    pub security_headers_configured: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KnowledgeEntry {
    pub category: KnowledgeCategory,
    pub key: String,
    pub value: String,
    pub confidence: f32,
    pub source_finding: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum KnowledgeCategory {
    Framework,
    SecurityConfig,
    CodePattern,
    DataflowPattern,
    FileStructure,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingConclusion {
    pub rule_id: String,
    pub file_path: String,
    pub function_name: String,
    pub is_false_positive: bool,
    pub confidence: f32,
    pub key_reason: String,
    pub file_hash: u64,
}

impl ProjectMemory {
    pub fn new_shared() -> SharedMemory {
        Arc::new(Mutex::new(Self::default()))
    }

    pub fn learn_from_response(&mut self, text: &str) {
        let lower = text.to_lowercase();

        self.detect_framework(&lower);
        self.detect_orm(&lower);
        self.detect_security_features(&lower);
        self.detect_sanitizers(&lower);
    }

    #[allow(dead_code)]
    pub fn learn_structured(&mut self, category: KnowledgeCategory, key: String, value: String, confidence: f32, source: Option<String>) {
        if self.knowledge_entries.iter().any(|e| e.key == key && e.category == category) {
            return;
        }
        self.knowledge_entries.push(KnowledgeEntry {
            category, key, value, confidence, source_finding: source,
        });

        if self.knowledge_entries.len() > 100 {
            self.knowledge_entries.sort_by(|a, b| b.confidence.partial_cmp(&a.confidence).unwrap_or(std::cmp::Ordering::Equal));
            self.knowledge_entries.truncate(80);
        }
    }

    pub fn record_conclusion(&mut self, conclusion: FindingConclusion) {
        self.finding_conclusions.push(conclusion);
        if self.finding_conclusions.len() > 200 {
            self.finding_conclusions.drain(0..50);
        }
    }

    // ── Recall: query relevant knowledge for a new finding ──

    pub fn recall_for_finding(&self, rule_id: &str, file_path: &str, function_name: &str) -> RecalledContext {
        let mut ctx = RecalledContext::default();

        ctx.project_summary = self.project_summary();

        ctx.similar_conclusions = self.find_similar_conclusions(rule_id, file_path, function_name);

        ctx.relevant_knowledge = self.recall_by_relevance(rule_id, file_path);

        ctx.security_summary = self.security_summary();

        ctx
    }

    pub fn project_summary(&self) -> String {
        let mut parts = Vec::new();
        let p = &self.project_profile;
        if let Some(fw) = &p.framework { parts.push(format!("Framework: {}", fw)); }
        if let Some(lang) = &p.language { parts.push(format!("Language: {}", lang)); }
        if let Some(orm) = &p.orm { parts.push(format!("ORM: {}", orm)); }
        if let Some(auth) = &p.auth_mechanism { parts.push(format!("Auth: {}", auth)); }
        if let Some(tmpl) = &p.template_engine { parts.push(format!("Templates: {}", tmpl)); }

        if parts.is_empty() { "(no project profile yet)".into() } else { parts.join(", ") }
    }

    pub fn security_summary(&self) -> String {
        let s = &self.security_posture;
        let mut parts = Vec::new();

        if let Some(csrf) = s.has_csrf_protection {
            parts.push(format!("CSRF protection: {}", if csrf { "YES" } else { "NO" }));
        }
        if let Some(rate) = s.has_rate_limiting {
            parts.push(format!("Rate limiting: {}", if rate { "YES" } else { "NO" }));
        }
        if let Some(val) = s.has_input_validation_layer {
            parts.push(format!("Input validation layer: {}", if val { "YES" } else { "NO" }));
        }
        if !s.known_sanitizers.is_empty() {
            parts.push(format!("Known sanitizers: {}", s.known_sanitizers.join(", ")));
        }
        if !s.known_auth_decorators.is_empty() {
            parts.push(format!("Auth decorators: {}", s.known_auth_decorators.join(", ")));
        }

        if parts.is_empty() { "(no security posture data yet)".into() } else { parts.join("\n") }
    }

    fn find_similar_conclusions(&self, rule_id: &str, file_path: &str, function_name: &str) -> Vec<String> {
        let rule_prefix = &rule_id[..rule_id.len().min(4)];
        let file_dir = PathBuf::from(file_path)
            .parent()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_default();

        let mut scored: Vec<(f32, &FindingConclusion)> = self.finding_conclusions.iter()
            .map(|c| {
                let mut score = 0.0f32;
                if c.rule_id.starts_with(rule_prefix) { score += 3.0; }
                if c.rule_id == rule_id { score += 2.0; }
                if c.file_path == file_path { score += 2.0; }
                if !file_dir.is_empty() && c.file_path.starts_with(&file_dir) { score += 1.0; }
                if !function_name.is_empty() && c.function_name == function_name { score += 1.5; }
                score *= c.confidence;
                (score, c)
            })
            .filter(|(score, _)| *score > 1.0)
            .collect();

        scored.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));

        scored.iter()
            .take(3)
            .map(|(score, c)| format!(
                "[rel={:.1}] {} in {}::{} → {} (conf={:.2}): {}",
                score, c.rule_id, c.file_path, c.function_name,
                if c.is_false_positive { "FP" } else { "TP" },
                c.confidence, c.key_reason,
            ))
            .collect()
    }

    fn recall_by_relevance(&self, rule_id: &str, file_path: &str) -> Vec<String> {
        let is_secret = rule_id.starts_with("SEC");
        let is_taint = rule_id.starts_with("TAINT");

        let mut relevant: Vec<&KnowledgeEntry> = self.knowledge_entries.iter()
            .filter(|e| {
                match e.category {
                    KnowledgeCategory::SecurityConfig => true,
                    KnowledgeCategory::DataflowPattern => is_taint || !is_secret,
                    KnowledgeCategory::CodePattern => true,
                    KnowledgeCategory::Framework => true,
                    KnowledgeCategory::FileStructure => {
                        e.key.contains(file_path) || file_path.contains(&e.key)
                    }
                }
            })
            .collect();

        relevant.sort_by(|a, b| b.confidence.partial_cmp(&a.confidence).unwrap_or(std::cmp::Ordering::Equal));

        relevant.iter()
            .take(5)
            .map(|e| format!("[{:?}] {}: {} (conf={:.2})", e.category, e.key, e.value, e.confidence))
            .collect()
    }

    fn detect_framework(&mut self, lower: &str) {
        if self.project_profile.framework.is_some() { return; }
        let frameworks = [
            ("flask", "Flask"), ("django", "Django"), ("fastapi", "FastAPI"),
            ("express", "Express"), ("next.js", "Next.js"), ("nestjs", "NestJS"),
            ("spring boot", "Spring Boot"), ("spring", "Spring"),
            ("gin", "Gin"), ("actix", "Actix"), ("rails", "Rails"),
            ("laravel", "Laravel"), ("asp.net", "ASP.NET"),
        ];
        for (pat, name) in &frameworks {
            if lower.contains(pat) {
                self.project_profile.framework = Some(name.to_string());
                return;
            }
        }
    }

    fn detect_orm(&mut self, lower: &str) {
        if self.project_profile.orm.is_some() { return; }
        let orms = [
            ("sqlalchemy", "SQLAlchemy"), ("django orm", "Django ORM"),
            ("sequelize", "Sequelize"), ("prisma", "Prisma"),
            ("hibernate", "Hibernate"), ("gorm", "GORM"),
            ("typeorm", "TypeORM"), ("active record", "ActiveRecord"),
            ("entity framework", "Entity Framework"),
        ];
        for (pat, name) in &orms {
            if lower.contains(pat) {
                self.project_profile.orm = Some(name.to_string());
                return;
            }
        }
    }

    fn detect_security_features(&mut self, lower: &str) {
        if lower.contains("csrf") && (lower.contains("protect") || lower.contains("token") || lower.contains("middleware")) {
            if self.security_posture.has_csrf_protection.is_none() {
                self.security_posture.has_csrf_protection = Some(true);
            }
        }
        if lower.contains("rate limit") || lower.contains("throttle") {
            if self.security_posture.has_rate_limiting.is_none() {
                self.security_posture.has_rate_limiting = Some(true);
            }
        }
        if lower.contains("waf") || lower.contains("web application firewall") {
            if self.security_posture.has_waf.is_none() {
                self.security_posture.has_waf = Some(true);
            }
        }
        if lower.contains("helmet") || lower.contains("security headers") || lower.contains("content-security-policy") {
            if self.security_posture.security_headers_configured.is_none() {
                self.security_posture.security_headers_configured = Some(true);
            }
        }
    }

    fn detect_sanitizers(&mut self, lower: &str) {
        let sanitizer_patterns = [
            "bleach", "dompurify", "html.escape", "markupsafe",
            "xss-clean", "sanitize-html", "validator.escape",
            "esapi", "owasp encoder",
        ];
        for pat in &sanitizer_patterns {
            if lower.contains(pat) && !self.security_posture.known_sanitizers.contains(&pat.to_string()) {
                self.security_posture.known_sanitizers.push(pat.to_string());
            }
        }
    }
}

// ── Recalled context for a finding ──

#[derive(Debug, Clone, Default)]
pub struct RecalledContext {
    pub project_summary: String,
    pub security_summary: String,
    pub similar_conclusions: Vec<String>,
    pub relevant_knowledge: Vec<String>,
    pub knowledge_context: String,
}

impl RecalledContext {
    pub fn format_for_prompt(&self) -> String {
        let mut parts = Vec::new();

        parts.push(format!("## Project Profile\n{}", self.project_summary));
        parts.push(format!("## Security Posture\n{}", self.security_summary));

        if !self.similar_conclusions.is_empty() {
            parts.push(format!(
                "## Similar Findings Already Analyzed\n{}",
                self.similar_conclusions.join("\n"),
            ));
        }

        if !self.relevant_knowledge.is_empty() {
            parts.push(format!(
                "## Relevant Knowledge\n{}",
                self.relevant_knowledge.join("\n"),
            ));
        }

        if !self.knowledge_context.is_empty() {
            parts.push(self.knowledge_context.clone());
        }

        parts.join("\n\n")
    }

    #[allow(dead_code)]
    pub fn has_similar_conclusion(&self) -> bool {
        !self.similar_conclusions.is_empty()
    }
}

// ── Finding Cache: dedup similar findings ──

#[derive(Debug, Clone, Default)]
pub struct FindingCache {
    entries: HashMap<String, CacheEntry>,
}

#[derive(Debug, Clone)]
struct CacheEntry {
    #[allow(dead_code)]
    pub rule_id: String,
    pub file_path: String,
    pub is_false_positive: bool,
    pub confidence: f32,
    pub reasoning: String,
    pub suggested_fix: Option<String>,
    pub hit_count: u32,
}

impl FindingCache {
    pub fn new() -> Self {
        Self { entries: HashMap::new() }
    }

    pub fn lookup(&mut self, rule_id: &str, file_path: &str, function_name: &str) -> Option<CachedResult> {
        let key = Self::cache_key(rule_id, file_path, function_name);
        if let Some(entry) = self.entries.get_mut(&key) {
            entry.hit_count += 1;
            return Some(CachedResult {
                is_false_positive: entry.is_false_positive,
                confidence: (entry.confidence * 0.9).clamp(0.0, 1.0),
                reasoning: format!("[cached from {}::{}] {}", entry.file_path, function_name, entry.reasoning),
                suggested_fix: entry.suggested_fix.clone(),
            });
        }

        let file_key = Self::file_rule_key(rule_id, file_path);
        if let Some(entry) = self.entries.get_mut(&file_key) {
            entry.hit_count += 1;
            return Some(CachedResult {
                is_false_positive: entry.is_false_positive,
                confidence: (entry.confidence * 0.75).clamp(0.0, 1.0),
                reasoning: format!("[cached from same file] {}", entry.reasoning),
                suggested_fix: entry.suggested_fix.clone(),
            });
        }

        None
    }

    pub fn store(&mut self, rule_id: &str, file_path: &str, function_name: &str,
                 is_false_positive: bool, confidence: f32, reasoning: &str, suggested_fix: Option<String>) {
        let key = Self::cache_key(rule_id, file_path, function_name);
        self.entries.insert(key, CacheEntry {
            rule_id: rule_id.to_string(),
            file_path: file_path.to_string(),
            is_false_positive,
            confidence,
            reasoning: reasoning.chars().take(200).collect(),
            suggested_fix,
            hit_count: 0,
        });

        let file_key = Self::file_rule_key(rule_id, file_path);
        if !self.entries.contains_key(&file_key) {
            self.entries.insert(file_key, CacheEntry {
                rule_id: rule_id.to_string(),
                file_path: file_path.to_string(),
                is_false_positive,
                confidence,
                reasoning: reasoning.chars().take(200).collect(),
                suggested_fix: None,
                hit_count: 0,
            });
        }
    }

    fn cache_key(rule_id: &str, file_path: &str, function_name: &str) -> String {
        format!("{}:{}:{}", rule_id, file_path, function_name)
    }

    fn file_rule_key(rule_id: &str, file_path: &str) -> String {
        format!("{}:{}", rule_id, file_path)
    }
}

#[derive(Debug, Clone)]
pub struct CachedResult {
    pub is_false_positive: bool,
    pub confidence: f32,
    pub reasoning: String,
    pub suggested_fix: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_learn_framework() {
        let mut mem = ProjectMemory::default();
        mem.learn_from_response("This is a Flask application using SQLAlchemy");
        assert_eq!(mem.project_profile.framework.as_deref(), Some("Flask"));
        assert_eq!(mem.project_profile.orm.as_deref(), Some("SQLAlchemy"));
    }

    #[test]
    fn test_learn_security_features() {
        let mut mem = ProjectMemory::default();
        mem.learn_from_response("The app uses CSRF protection middleware and rate limiting");
        assert_eq!(mem.security_posture.has_csrf_protection, Some(true));
        assert_eq!(mem.security_posture.has_rate_limiting, Some(true));
    }

    #[test]
    fn test_learn_sanitizers() {
        let mut mem = ProjectMemory::default();
        mem.learn_from_response("Input is cleaned with bleach and DOMPurify");
        assert!(mem.security_posture.known_sanitizers.contains(&"bleach".to_string()));
        assert!(mem.security_posture.known_sanitizers.contains(&"dompurify".to_string()));
    }

    #[test]
    fn test_structured_knowledge() {
        let mut mem = ProjectMemory::default();
        mem.learn_structured(
            KnowledgeCategory::SecurityConfig,
            "global_csrf".into(), "CSRF enabled via Flask-WTF".into(),
            0.9, Some("VULN001".into()),
        );
        assert_eq!(mem.knowledge_entries.len(), 1);

        mem.learn_structured(
            KnowledgeCategory::SecurityConfig,
            "global_csrf".into(), "duplicate".into(),
            0.9, None,
        );
        assert_eq!(mem.knowledge_entries.len(), 1);
    }

    #[test]
    fn test_record_and_recall_conclusion() {
        let mut mem = ProjectMemory::default();
        mem.record_conclusion(FindingConclusion {
            rule_id: "VULN001".into(),
            file_path: "src/app.py".into(),
            function_name: "get_user".into(),
            is_false_positive: false,
            confidence: 0.9,
            key_reason: "SQL injection confirmed".into(),
            file_hash: 12345,
        });

        let recalled = mem.recall_for_finding("VULN002", "src/app.py", "get_admin");
        assert!(!recalled.similar_conclusions.is_empty());
        assert!(recalled.similar_conclusions[0].contains("VULN001"));
    }

    #[test]
    fn test_recall_relevance_scoring() {
        let mut mem = ProjectMemory::default();
        mem.record_conclusion(FindingConclusion {
            rule_id: "VULN001".into(),
            file_path: "src/app.py".into(),
            function_name: "get_user".into(),
            is_false_positive: false,
            confidence: 0.9,
            key_reason: "SQL injection in same file".into(),
            file_hash: 111,
        });
        mem.record_conclusion(FindingConclusion {
            rule_id: "SEC001".into(),
            file_path: "tests/test_app.py".into(),
            function_name: "test_func".into(),
            is_false_positive: true,
            confidence: 0.8,
            key_reason: "test file secret".into(),
            file_hash: 222,
        });

        let recalled = mem.recall_for_finding("VULN002", "src/app.py", "delete_user");
        assert!(!recalled.similar_conclusions.is_empty());
        assert!(recalled.similar_conclusions[0].contains("VULN001"));
    }

    #[test]
    fn test_finding_cache_exact_match() {
        let mut cache = FindingCache::new();
        cache.store("VULN001", "src/app.py", "get_user", false, 0.9, "SQL injection", None);

        let result = cache.lookup("VULN001", "src/app.py", "get_user");
        assert!(result.is_some());
        let r = result.unwrap();
        assert!(!r.is_false_positive);
        assert!(r.confidence > 0.7);
    }

    #[test]
    fn test_finding_cache_file_level_match() {
        let mut cache = FindingCache::new();
        cache.store("VULN001", "src/app.py", "get_user", false, 0.9, "SQL injection", None);

        let result = cache.lookup("VULN001", "src/app.py", "delete_user");
        assert!(result.is_some());
        let r = result.unwrap();
        assert!(r.confidence < 0.9);
        assert!(r.reasoning.contains("same file"));
    }

    #[test]
    fn test_finding_cache_miss() {
        let mut cache = FindingCache::new();
        cache.store("VULN001", "src/app.py", "get_user", false, 0.9, "SQL injection", None);

        let result = cache.lookup("SEC001", "src/config.py", "load_config");
        assert!(result.is_none());
    }

    #[test]
    fn test_project_summary() {
        let mut mem = ProjectMemory::default();
        mem.project_profile.framework = Some("Flask".into());
        mem.project_profile.orm = Some("SQLAlchemy".into());
        let summary = mem.project_summary();
        assert!(summary.contains("Flask"));
        assert!(summary.contains("SQLAlchemy"));
    }

    #[test]
    fn test_security_summary() {
        let mut mem = ProjectMemory::default();
        mem.security_posture.has_csrf_protection = Some(true);
        mem.security_posture.known_sanitizers = vec!["bleach".into()];
        let summary = mem.security_summary();
        assert!(summary.contains("CSRF"));
        assert!(summary.contains("bleach"));
    }

    #[test]
    fn test_recalled_context_format() {
        let ctx = RecalledContext {
            project_summary: "Flask + SQLAlchemy".into(),
            security_summary: "CSRF: YES".into(),
            similar_conclusions: vec!["[rel=5.0] VULN001 → TP".into()],
            relevant_knowledge: vec!["[SecurityConfig] csrf: enabled".into()],
            knowledge_context: String::new(),
        };
        let formatted = ctx.format_for_prompt();
        assert!(formatted.contains("Project Profile"));
        assert!(formatted.contains("Security Posture"));
        assert!(formatted.contains("Similar Findings"));
        assert!(formatted.contains("Relevant Knowledge"));
    }

    #[test]
    fn test_knowledge_entry_limit() {
        let mut mem = ProjectMemory::default();
        for i in 0..120 {
            mem.learn_structured(
                KnowledgeCategory::CodePattern,
                format!("pattern_{}", i), format!("value_{}", i),
                (i as f32) / 120.0, None,
            );
        }
        assert!(mem.knowledge_entries.len() <= 100);
    }
}
