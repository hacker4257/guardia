pub mod ast;
pub mod rules;
mod secret;

use anyhow::Result;
use ignore::WalkBuilder;
use indicatif::{ProgressBar, ProgressStyle};
use rayon::prelude::*;
use serde::Serialize;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use crate::config::ScanConfig;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Low => write!(f, "LOW"),
            Severity::Medium => write!(f, "MEDIUM"),
            Severity::High => write!(f, "HIGH"),
            Severity::Critical => write!(f, "CRITICAL"),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub rule_id: String,
    pub severity: Severity,
    pub title: String,
    pub description: String,
    pub file_path: PathBuf,
    pub line_number: usize,
    pub line_content: String,
    pub matched_text: String,
    pub suggestion: String,
}

pub fn run_scan(config: &ScanConfig) -> Result<Vec<Finding>> {
    if config.threads > 0 {
        rayon::ThreadPoolBuilder::new()
            .num_threads(config.threads)
            .build_global()
            .ok();
    }

    let files = collect_files(&config.path)?;

    let pb = if config.show_progress {
        let pb = ProgressBar::new(files.len() as u64);
        pb.set_style(
            ProgressStyle::default_bar()
                .template("  {spinner:.cyan} Scanning [{bar:40.cyan/dim}] {pos}/{len} files")
                .unwrap()
                .progress_chars("━╸─"),
        );
        Some(pb)
    } else {
        None
    };

    let findings: Arc<Mutex<Vec<Finding>>> = Arc::new(Mutex::new(Vec::new()));

    files.par_iter().for_each(|file| {
        if let Ok(content) = std::fs::read_to_string(file) {
            let mut file_findings = Vec::new();

            secret::scan_secrets(file, &content, &mut file_findings);

            if !config.secret_only {
                ast::scan_ast(file, &content, &mut file_findings);
            }

            let mut locked = findings.lock().unwrap();
            locked.extend(file_findings);
        }

        if let Some(ref pb) = pb {
            pb.inc(1);
        }
    });

    if let Some(pb) = pb {
        pb.finish_and_clear();
    }

    let mut results = Arc::try_unwrap(findings)
        .unwrap()
        .into_inner()
        .unwrap();

    results.retain(|f| f.severity >= config.min_severity);
    results.sort_by(|a, b| b.severity.cmp(&a.severity));

    dedup_findings(&mut results);

    Ok(results)
}

fn dedup_findings(findings: &mut Vec<Finding>) {
    let mut seen = std::collections::HashSet::new();
    findings.retain(|f| {
        let key = format!("{}:{}:{}", f.rule_id, f.file_path.display(), f.line_number);
        seen.insert(key)
    });
}

fn collect_files(path: &PathBuf) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();

    if path.is_file() {
        files.push(path.clone());
        return Ok(files);
    }

    let walker = WalkBuilder::new(path)
        .hidden(false)
        .git_ignore(true)
        .git_global(true)
        .git_exclude(true)
        .build();

    for entry in walker {
        let entry = entry?;
        let path = entry.path();

        if !path.is_file() {
            continue;
        }

        if should_skip(path) {
            continue;
        }

        files.push(path.to_path_buf());
    }

    Ok(files)
}

fn should_skip(path: &std::path::Path) -> bool {
    let skip_extensions = [
        "png", "jpg", "jpeg", "gif", "bmp", "ico", "svg", "webp",
        "mp3", "mp4", "avi", "mov", "wav", "flac",
        "zip", "tar", "gz", "bz2", "xz", "7z", "rar",
        "exe", "dll", "so", "dylib", "bin",
        "pdf", "doc", "docx", "xls", "xlsx",
        "woff", "woff2", "ttf", "eot", "otf",
        "lock", "sum",
    ];

    let skip_dirs = [
        "node_modules", ".git", "target", "dist", "build",
        "__pycache__", ".venv", "venv", ".tox",
        "vendor", ".bundle",
    ];

    if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
        if skip_extensions.contains(&ext.to_lowercase().as_str()) {
            return true;
        }
    }

    for component in path.components() {
        if let std::path::Component::Normal(name) = component {
            if let Some(name_str) = name.to_str() {
                if skip_dirs.contains(&name_str) {
                    return true;
                }
            }
        }
    }

    if let Ok(metadata) = std::fs::metadata(path) {
        if metadata.len() > 5 * 1024 * 1024 {
            return true;
        }
    }

    false
}
