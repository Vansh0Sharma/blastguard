use std::sync::OnceLock;

use regex::{Captures, Regex};
use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RedactionMatch {
    pub rule_id: String,
    pub replacements: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RedactedText {
    pub text: String,
    pub matches: Vec<RedactionMatch>,
}

struct Rule {
    id: &'static str,
    regex: Regex,
    replacement: Replacement,
}

enum Replacement {
    Literal(&'static str),
    Assignment,
}

/// Redact common high-confidence secret shapes without retaining matched values.
pub fn redact(input: &str) -> RedactedText {
    let mut text = input.to_owned();
    let mut matches = Vec::new();
    for rule in rules() {
        let count = rule.regex.find_iter(&text).count();
        if count == 0 {
            continue;
        }
        text = match rule.replacement {
            Replacement::Literal(value) => rule.regex.replace_all(&text, value).into_owned(),
            Replacement::Assignment => rule
                .regex
                .replace_all(&text, |captures: &Captures<'_>| {
                    let prefix = captures.name("prefix").map_or("secret=", |m| m.as_str());
                    format!("{prefix}[REDACTED]")
                })
                .into_owned(),
        };
        matches.push(RedactionMatch {
            rule_id: rule.id.to_owned(),
            replacements: count,
        });
    }
    RedactedText { text, matches }
}

fn rules() -> &'static [Rule] {
    static RULES: OnceLock<Vec<Rule>> = OnceLock::new();
    RULES.get_or_init(|| {
        [
            (
                "secret.private_key",
                r"(?s)-----BEGIN(?: [A-Z0-9]+)? PRIVATE KEY-----.*?-----END(?: [A-Z0-9]+)? PRIVATE KEY-----",
                Replacement::Literal("[REDACTED PRIVATE KEY]"),
            ),
            (
                "secret.assignment",
                r#"(?i)(?P<prefix>[\"']?(?:[a-z0-9_]*(?:api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|secret(?:_access)?_key|token|password|passwd))[\"']?\s*[:=]\s*[\"']?)[^\s\"',;}{]{8,}"#,
                Replacement::Assignment,
            ),
            (
                "secret.bearer_token",
                r"(?i)(?P<prefix>\b(?:authorization\s*:\s*)?bearer\s+)[A-Za-z0-9._~+/-]{12,}={0,2}",
                Replacement::Assignment,
            ),
            (
                "secret.aws_access_key",
                r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b",
                Replacement::Literal("[REDACTED AWS ACCESS KEY]"),
            ),
            (
                "secret.github_token",
                r"\b(?:gh[pousr]_[A-Za-z0-9]{20,255}|github_pat_[A-Za-z0-9_]{20,255})\b",
                Replacement::Literal("[REDACTED GITHUB TOKEN]"),
            ),
            (
                "secret.jwt",
                r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b",
                Replacement::Literal("[REDACTED JWT]"),
            ),
        ]
        .into_iter()
        .filter_map(|(id, pattern, replacement)| {
            Regex::new(pattern).ok().map(|regex| Rule { id, regex, replacement })
        })
        .collect()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_supported_secret_classes() {
        let aws = ["AKIA", "1234567890ABCDEF"].concat();
        let github = ["ghp_", "abcdefghijklmnopqrstuvwxyz123456"].concat();
        let jwt = [
            "eyJhbGciOiJIUzI1NiJ9",
            "eyJzdWIiOiIxMjM0NTY3ODkwIn0",
            "abcdefghijklmnopqrstuvwxyz",
        ]
        .join(".");
        let private_key = [
            "-----BEGIN PRIVATE KEY-----",
            "not-a-real-key-body",
            "-----END PRIVATE KEY-----",
        ]
        .join("\n");
        let input = format!("{aws} {github} {jwt}\n{private_key}\napi_key=abcdefghijk");
        let output = redact(&input);
        assert_eq!(output.matches.len(), 5);
        assert!(!output.text.contains("1234567890ABCDEF"));
        assert!(!output.text.contains("not-a-real-key-body"));
        assert!(output.text.contains("api_key=[REDACTED]"));
    }

    #[test]
    fn leaves_ordinary_output_unchanged() {
        let output = redact("cargo test: 12 passed");
        assert_eq!(output.text, "cargo test: 12 passed");
        assert!(output.matches.is_empty());
    }

    #[test]
    fn redacts_assignment_secrets_in_nested_json_and_bearer_headers() {
        let secret = ["nested", "-value-", "123456789"].concat();
        let bearer = ["bearer", "credential", "123456"].concat();
        let input = format!(
            r#"{{"outer":{{"api_key":"{secret}"}},"header":"Authorization: Bearer {bearer}"}}"#
        );
        let output = redact(&input);
        assert!(!output.text.contains(&secret));
        assert!(!output.text.contains(&bearer));
        assert!(output
            .matches
            .iter()
            .any(|item| item.rule_id == "secret.assignment"));
        assert!(output
            .matches
            .iter()
            .any(|item| item.rule_id == "secret.bearer_token"));
    }
}
