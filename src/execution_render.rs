use crate::{
    error::BlastguardError,
    execution::{ExecutionReport, PreparedExecution, StreamResult},
    redaction,
};

pub fn decision_card(value: &PreparedExecution) -> String {
    let mut lines = vec![
        "BlastGuard execution decision".to_owned(),
        format!("Session: {}", value.session_id),
        format!("Worktree: {}", value.worktree_path),
        format!("Command: {}", value.safe_command),
        format!("Policy decision: {}", value.analysis.decision.as_str()),
        format!(
            "Approval: {}",
            if value.approval_provided {
                "provided"
            } else {
                "not provided"
            }
        ),
        format!(
            "Execution: {}",
            if value.will_execute() {
                "will start"
            } else {
                "will not start"
            }
        ),
        format!(
            "Limits: {} seconds, {} total output bytes",
            value.limits.timeout_seconds, value.limits.max_output_bytes
        ),
        "Rollback scope: Git-tracked and non-ignored worktree changes only.".to_owned(),
        "Scope warning: Git-isolated, not OS-sandboxed. External effects, runtime path resolution, network access, and escaped processes are not contained.".to_owned(),
    ];
    if !value.analysis.findings.is_empty() {
        lines.push("Findings:".to_owned());
        for finding in &value.analysis.findings {
            lines.push(format!(
                "  - [{}] {}: {}",
                severity_label(finding.severity),
                finding.rule_id,
                finding.explanation
            ));
        }
    }
    redaction::redact(&lines.join("\n")).text
}

pub fn result(value: &ExecutionReport) -> String {
    let mut lines = vec![
        "BlastGuard execution result".to_owned(),
        format!("Session: {}", value.session_id),
        format!("State: {}", value.execution_state.as_str()),
    ];
    if let Some(process) = &value.process {
        lines.push(format!(
            "Child: exit={}, signal={}, duration={} ms",
            process
                .exit_code
                .map_or_else(|| "none".to_owned(), |code| code.to_string()),
            process
                .signal
                .map_or_else(|| "none".to_owned(), |signal| signal.to_string()),
            process.duration_milliseconds
        ));
        lines.push(format!(
            "Cleanup: complete={} ({})",
            process.termination_complete, process.termination_scope
        ));
        push_stream(&mut lines, "stdout", &process.stdout);
        push_stream(&mut lines, "stderr", &process.stderr);
    }
    lines.push(value.rollback_scope.clone());
    lines.push(value.boundary_warning.clone());
    lines.push(value.next_step.clone());
    redaction::redact(&lines.join("\n")).text
}

pub fn json(value: &ExecutionReport) -> Result<String, BlastguardError> {
    let serialized = serde_json::to_string_pretty(value)
        .map_err(|error| BlastguardError::Serialization(error.to_string()))?;
    Ok(redaction::redact(&serialized).text)
}

fn push_stream(lines: &mut Vec<String>, label: &str, value: &StreamResult) {
    lines.push(format!(
        "{label}: observed={} captured={} truncated={} redactions={} terminal_sequences_removed={}",
        value.bytes_observed,
        value.bytes_captured,
        value.truncated,
        value
            .redactions
            .iter()
            .map(|item| item.replacements)
            .sum::<usize>(),
        value.terminal_sequences_removed
    ));
    if !value.text.is_empty() {
        lines.push(format!("--- {label} ---"));
        lines.push(value.text.clone());
    }
}

fn severity_label(value: crate::model::Severity) -> &'static str {
    match value {
        crate::model::Severity::Info => "info",
        crate::model::Severity::Low => "low",
        crate::model::Severity::Medium => "medium",
        crate::model::Severity::High => "high",
        crate::model::Severity::Critical => "critical",
    }
}
