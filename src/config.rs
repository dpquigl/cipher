use serde::{Deserialize, Serialize};
use crate::AppError;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CipherKey {
    pub permutation: String,
}

pub fn load_key_file(path: &str) -> Result<CipherKey, AppError> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| AppError::FileNotFound(format!("{}", e)))?;

    let config: CipherKey = serde_yaml::from_str(&content)?;

    if config.permutation.len() != 26 {
        return Err(AppError::InvalidKeyLength(config.permutation.len().to_string()));
    }

    Ok(config)
}