use thiserror::Error;

#[derive(Error, Debug)]
pub enum AppError {
    #[error("Invalid permutation string length: expected 26 characters, got {0}")]
    InvalidPermutationLength(usize),
    #[error("Duplicate character in permutation: '{0}' (each letter must appear exactly once)")]
    DuplicateCharacter(char),
    #[error("Invalid cipher key length: expected 26 characters, got {0}")]
    InvalidKeyLength(String),
    #[error("Failed to parse YAML config: {0}")]
    ParseError(serde_yaml::Error),
    #[error("Config file not found: {0}")]
    FileNotFound(String),
    #[error("{0}")]
    Any(Box<dyn std::error::Error>),
}

impl From<serde_yaml::Error> for AppError {
    fn from(err: serde_yaml::Error) -> Self {
        AppError::ParseError(err)
    }
}

pub type CipherResult<T> = Result<T, AppError>;