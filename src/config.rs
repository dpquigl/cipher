use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CipherKey {
    pub permutation: String,
}

#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("Invalid cipher key length: expected 26 characters, got {0}")]
    InvalidKeyLength(String),

    #[error("Failed to parse YAML config: {0}")]
    ParseError(#[from] serde_yaml::Error),

    #[error("Config file not found: {0}")]
    FileNotFound(String),
}

pub fn load_key_file(path: &str) -> Result<CipherKey, ConfigError> {
    std::fs::read_to_string(path)
        .map_err(|e| ConfigError::FileNotFound(e.to_string()))?;
    // Actually read and parse - see below for validation
    let yaml = std::fs::read_to_string(path)
        .map_err(|e| ConfigError::FileNotFound(e.to_string()))?;
    serde_yaml::from_str::<CipherKey>(&yaml)
        .map_err(ConfigError::ParseError)
}
