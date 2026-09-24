use std::path::Path;

use serde::{Deserialize, Serialize};

pub const SCHEMA_VERSION: &str = "1.0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Decision {
    Allow,
    Ask,
    Block,
}

impl Decision {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Ask => "ask",
            Self::Block => "block",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    pub rule_id: String,
    pub severity: Severity,
    pub explanation: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub affected_paths: Vec<String>,
    pub recommendation: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkActivity {
    pub detected: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub commands: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RollbackStatus {
    pub available: bool,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParserStatus {
    pub engine: String,
    pub complete: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Analysis {
    pub schema_version: String,
    pub command: String,
    pub cwd: String,
    pub decision: Decision,
    pub summary: String,
    pub findings: Vec<Finding>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub affected_paths: Vec<String>,
    pub network_activity: NetworkActivity,
    pub rollback: RollbackStatus,
    pub parser: ParserStatus,
}

impl Analysis {
    pub fn new(command: String, cwd: &Path) -> Self {
        Self {
            schema_version: SCHEMA_VERSION.to_owned(),
            command,
            cwd: cwd.display().to_string(),
            decision: Decision::Allow,
            summary: "No material command-level risks detected.".to_owned(),
            findings: Vec::new(),
            affected_paths: Vec::new(),
            network_activity: NetworkActivity {
                detected: false,
                commands: Vec::new(),
            },
            rollback: RollbackStatus {
                available: false,
                reason: "No sandbox session is attached to analysis; the requested command is not executed."
                    .to_owned(),
            },
            parser: ParserStatus {
                engine: "tree-sitter-bash".to_owned(),
                complete: true,
            },
        }
    }
}
