use crate::{error::BlastguardError, model::Analysis, redaction};

pub fn json(analysis: &Analysis) -> Result<String, BlastguardError> {
    let serialized = serde_json::to_string_pretty(analysis)
        .map_err(|error| BlastguardError::Serialization(error.to_string()))?;
    Ok(redaction::redact(&serialized).text)
}

pub fn human(analysis: &Analysis) -> String {
    let paths = if analysis.affected_paths.is_empty() {
        "none identified".to_owned()
    } else {
        analysis.affected_paths.join(", ")
    };
    let network = if analysis.network_activity.detected {
        format!("yes ({})", analysis.network_activity.commands.join(", "))
    } else {
        "no".to_owned()
    };
    let rollback = if analysis.rollback.available {
        "available".to_owned()
    } else {
        format!("unavailable — {}", analysis.rollback.reason)
    };
    let mut output = format!(
        "╭─ Blast Radius ──────────────────────────────────────────\n\
         │ Requested  {}\n\
         │ Decision   {}\n\
         │ Risk       {}\n\
         │ Paths      {}\n\
         │ Network    {}\n\
         │ Rollback   {}\n\
         ╰──────────────────────────────────────────────────",
        one_line(&analysis.command),
        analysis.decision.as_str().to_ascii_uppercase(),
        one_line(&analysis.summary),
        one_line(&paths),
        network,
        one_line(&rollback),
    );
    for finding in &analysis.findings {
        output.push_str(&format!(
            "\n\n[{}] {}: {}\n  Recommendation: {}",
            format!("{:?}", finding.severity).to_ascii_uppercase(),
            finding.rule_id,
            one_line(&finding.explanation),
            one_line(&finding.recommendation)
        ));
    }
    redaction::redact(&output).text
}

fn one_line(value: &str) -> String {
    value.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use crate::model::{Analysis, Finding, Severity};

    #[test]
    fn card_has_required_fields() {
        let card = super::human(&Analysis::new("cargo test".into(), Path::new("/repo")));
        for label in [
            "Requested",
            "Decision",
            "Risk",
            "Paths",
            "Network",
            "Rollback",
        ] {
            assert!(card.contains(label));
        }
    }

    #[test]
    fn every_rendered_field_is_redacted() {
        let token = ["ghp_", "abcdefghijklmnopqrstuvwxyz123456"].concat();
        let mut analysis = Analysis::new(token.clone(), Path::new("/repo"));
        analysis.cwd = token.clone();
        analysis.summary = token.clone();
        analysis.affected_paths = vec![token.clone()];
        analysis.network_activity.commands = vec![token.clone()];
        analysis.rollback.reason = token.clone();
        analysis.parser.engine = token.clone();
        analysis.findings.push(Finding {
            rule_id: token.clone(),
            severity: Severity::High,
            explanation: token.clone(),
            affected_paths: vec![token.clone()],
            recommendation: token.clone(),
        });

        let human = super::human(&analysis);
        let json = super::json(&analysis);
        assert!(!human.contains(&token));
        assert!(matches!(json, Ok(ref output) if !output.contains(&token)));
    }
}
