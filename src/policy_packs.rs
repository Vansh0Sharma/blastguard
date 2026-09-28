//! Embedded, offline configuration assets. Packs use only existing override rules.

use clap::ValueEnum;
use serde::Serialize;

use crate::{config::Config, error::BlastguardError, model::Decision};

pub const VERSION: &str = "1.0.0";

#[derive(Clone, Copy, Debug, Serialize, ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum PolicyPack {
    Balanced,
    Strict,
    Ci,
}

#[derive(Serialize)]
pub struct Description {
    pub name: PolicyPack,
    pub version: &'static str,
    pub recommended: bool,
    pub summary: &'static str,
}

impl PolicyPack {
    pub fn description(self) -> Description {
        Description {
            name: self,
            version: VERSION,
            recommended: matches!(self, Self::Balanced),
            summary: match self {
                Self::Balanced => "Built-in decisions with no extra overrides; recommended starting point.",
                Self::Strict => "Ask for every command; block matching Cargo/npm publication text.",
                Self::Ci => "Block selected transfer/publication text; automation must reject all nonzero analysis exits.",
            },
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Balanced => "balanced",
            Self::Strict => "strict",
            Self::Ci => "ci",
        }
    }

    pub fn source(self) -> &'static str {
        match self {
            Self::Balanced => include_str!("../policy-packs/v1/balanced.toml"),
            Self::Strict => include_str!("../policy-packs/v1/strict.toml"),
            Self::Ci => include_str!("../policy-packs/v1/ci.toml"),
        }
    }

    pub fn config(self) -> Result<Config, BlastguardError> {
        let config: Config = toml::from_str(self.source()).map_err(|_| invalid_asset())?;
        // An embedded pack is never allowed to introduce an allow override.
        if config
            .overrides
            .iter()
            .any(|entry| entry.decision == Decision::Allow)
        {
            return Err(invalid_asset());
        }
        config.matching_override("")?;
        Ok(config)
    }
}

fn invalid_asset() -> BlastguardError {
    BlastguardError::ConfigParse {
        path: "embedded policy pack".to_owned(),
        message: "invalid embedded pack; packs must contain only ask/block overrides".to_owned(),
    }
}

pub fn list_json() -> Result<String, BlastguardError> {
    serialize(&serde_json::json!({
        "schema_version": "blastguard.policy.list/1.0",
        "packs": all().map(PolicyPack::description),
    }))
}

pub fn show_json(pack: PolicyPack) -> Result<String, BlastguardError> {
    pack.config()?;
    serialize(&serde_json::json!({
        "schema_version": "blastguard.policy.show/1.0",
        "pack": pack.description(),
        "config_toml": pack.source(),
    }))
}

pub fn all() -> [PolicyPack; 3] {
    [PolicyPack::Balanced, PolicyPack::Strict, PolicyPack::Ci]
}

fn serialize(value: &impl Serialize) -> Result<String, BlastguardError> {
    serde_json::to_string_pretty(value)
        .map_err(|error| BlastguardError::Serialization(error.to_string()))
}
