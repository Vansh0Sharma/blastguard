//! Offline readiness snapshot, not a Codex runtime compatibility check.

use std::path::Path;

use serde::Serialize;

use crate::{claude_doctor, error::BlastguardError, render::safe_text};

pub const SCHEMA: &str = "blastguard.codex.doctor/1.0";
pub const PREREQUISITE_EXIT: u8 = 30;

#[derive(Serialize)]
pub struct Installation {
    pub found: bool,
    pub path: Option<String>,
    pub version: Option<String>,
    pub discovery: &'static str,
}

#[derive(Serialize)]
pub struct Report {
    pub schema_version: &'static str,
    pub prerequisites_passed: bool,
    pub compatibility: &'static str,
    pub repository: String,
    pub checks: Vec<claude_doctor::Check>,
    pub codex: Installation,
    pub limitations: &'static str,
}

pub fn inspect(repo: Option<&Path>) -> Result<Report, BlastguardError> {
    let checks = claude_doctor::inspect_for(repo, "codex")?;
    Ok(Report {
        schema_version: SCHEMA,
        prerequisites_passed: checks.ready,
        compatibility: "unverified",
        repository: checks.repository,
        checks: checks.checks,
        codex: Installation {
            found: checks.claude.path.is_some(),
            path: checks.claude.path,
            version: None,
            discovery: "Filesystem discovery only; Codex was not executed, including help/version queries.",
        },
        limitations: "Experimental offline foundation only. No Codex launcher, installed hook, configuration writes, network access, or runtime enforcement test. Git must be trusted. Passing prerequisites does not establish Codex compatibility or protection. See docs/integrations/codex.md.",
    })
}

pub fn json(report: &Report) -> Result<String, BlastguardError> {
    // Dynamic strings were sanitized before serialization, preserving JSON.
    serde_json::to_string_pretty(report)
        .map_err(|_| BlastguardError::Serialization("Codex doctor report".to_owned()))
}

pub fn human(report: &Report) -> String {
    let mut output = format!(
        "Codex doctor (experimental): {}\nCompatibility: unverified\nRepository: {}",
        if report.prerequisites_passed {
            "local prerequisites passed"
        } else {
            "prerequisites failed"
        },
        report.repository
    );
    for check in &report.checks {
        output.push_str(&format!(
            "\n[{}] {}: {}",
            if check.passed { "ok" } else { "fail" },
            check.id,
            check.detail
        ));
    }
    if let Some(path) = &report.codex.path {
        output.push_str(&format!("\nCodex executable: {path}"));
    }
    output.push_str(&format!(
        "\n{}\n{}",
        report.codex.discovery, report.limitations
    ));
    safe_text(&output)
}
