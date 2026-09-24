use std::{fs, path::Path};

use globset::Glob;
use serde::Deserialize;

use crate::{
    error::BlastguardError,
    model::{Decision, Finding, Severity},
    redaction,
};

#[derive(Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub overrides: Vec<Override>,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Override {
    pub pattern: String,
    pub decision: Decision,
    pub reason: String,
}

impl Config {
    pub fn load(explicit: Option<&Path>, cwd: &Path) -> Result<Self, BlastguardError> {
        let path = explicit.map(Path::to_path_buf).or_else(|| {
            let candidate = cwd.join("blastguard.toml");
            candidate.is_file().then_some(candidate)
        });

        let Some(path) = path else {
            return Ok(Self::default());
        };
        let redacted_path = redaction::redact(&path.display().to_string()).text;
        let source = fs::read_to_string(&path).map_err(|source| BlastguardError::ConfigRead {
            path: redacted_path.clone(),
            source,
        })?;
        toml::from_str(&source).map_err(|source: toml::de::Error| BlastguardError::ConfigParse {
            path: redacted_path,
            message: redaction::redact(&source.to_string()).text,
        })
    }

    /// Returns the strongest matching override. This prevents a broad allow rule from
    /// shadowing a narrower ask or block rule.
    pub fn matching_override(
        &self,
        command: &str,
    ) -> Result<Option<(Decision, Finding)>, BlastguardError> {
        let mut matches = Vec::new();
        for entry in &self.overrides {
            let glob =
                Glob::new(&entry.pattern).map_err(|error| BlastguardError::InvalidPattern {
                    pattern: redaction::redact(&entry.pattern).text,
                    message: error.to_string(),
                })?;
            if glob.compile_matcher().is_match(command) {
                matches.push(entry);
            }
        }
        let Some(entry) = matches.into_iter().max_by_key(|entry| entry.decision) else {
            return Ok(None);
        };
        let severity = match entry.decision {
            Decision::Allow => Severity::Info,
            Decision::Ask => Severity::Medium,
            Decision::Block => Severity::High,
        };
        Ok(Some((
            entry.decision,
            Finding {
                rule_id: format!("config.override.{}", entry.decision.as_str()),
                severity,
                explanation: redaction::redact(&entry.reason).text,
                affected_paths: Vec::new(),
                recommendation: "Review blastguard.toml if this override is no longer intended."
                    .to_owned(),
            },
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strongest_matching_override_wins() {
        let config = Config {
            overrides: vec![
                Override {
                    pattern: "cargo *".into(),
                    decision: Decision::Allow,
                    reason: "developer tools".into(),
                },
                Override {
                    pattern: "cargo publish*".into(),
                    decision: Decision::Block,
                    reason: "publishing is controlled".into(),
                },
            ],
        };
        let result = config.matching_override("cargo publish");
        assert!(matches!(result, Ok(Some((Decision::Block, _)))));
    }
}
