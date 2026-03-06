use std::path::PathBuf;

use crate::scanner::Severity;

#[allow(dead_code)]
pub struct ScanConfig {
    pub path: PathBuf,
    pub secret_only: bool,
    pub min_severity: Severity,
    pub show_progress: bool,
    pub threads: usize,
}
