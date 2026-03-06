pub mod symbolic;
pub mod sandbox;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationStatus {
    pub symbolic: symbolic::SymbolicResult,
    pub sandbox: Option<sandbox::SandboxResult>,
}

impl VerificationStatus {
    pub fn confidence_adjustment(&self) -> f32 {
        let mut adj = self.symbolic.overall_confidence_adjustment;
        if let Some(ref sb) = self.sandbox {
            match sb.status {
                sandbox::VerifyStatus::Verified => adj += 0.15,
                sandbox::VerifyStatus::Disproved => adj -= 0.3,
                sandbox::VerifyStatus::Inconclusive | sandbox::VerifyStatus::Failed => {}
            }
        }
        adj.clamp(-0.5, 0.3)
    }

    pub fn summary(&self) -> String {
        let mut parts = vec![format!(
            "Symbolic: reachable={}, taint_complete={}, sanitizer_effective={}, config_safe={} (adj={:+.2})",
            self.symbolic.reachable,
            self.symbolic.taint_complete,
            self.symbolic.sanitizer_effective,
            self.symbolic.config_safe,
            self.symbolic.overall_confidence_adjustment,
        )];

        if let Some(ref sb) = self.sandbox {
            parts.push(format!("Sandbox: {:?} — {}", sb.status, sb.output_summary));
        }

        parts.join(" | ")
    }
}
