use clap::{Parser, Subcommand};
use anyhow::Result;

use cipher::cipher::SubstitutionCipher;
use cipher::config::load_key_file;

mod cipher;
mod config;

#[derive(Parser)]
#[command(name = "cipher")]
#[command(about = "A substitution cipher CLI tool")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Encrypt text using a substitution cipher
    Encrypt {
        /// The text to encrypt
        text: String,
        /// Cipher permutation string (26 chars)
        #[arg(short = 'k', long = "cipher-key")]
        cipher_key: Option<String>,
        /// Path to YAML config file containing cipher key
        #[arg(short = 'f', long = "key-file")]
        key_file: Option<String>,
    },

    /// Decrypt text using a substitution cipher
    Decrypt {
        /// The text to decrypt
        text: String,
        /// Cipher permutation string (26 chars)
        #[arg(short = 'k', long = "cipher-key")]
        cipher_key: Option<String>,
        /// Path to YAML config file containing cipher key
        #[arg(short = 'f', long = "key-file")]
        key_file: Option<String>,
    },

    /// Show current cipher key from config file (for debugging)
    Status {
        /// Path to YAML config file
        key_file: String,
    },
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Encrypt { text, cipher_key, key_file } => {
            run_encrypt(&text, &cipher_key, &key_file)
        }
        Commands::Decrypt { text, cipher_key, key_file } => {
            run_decrypt(&text, &cipher_key, &key_file)
        }
        Commands::Status { key_file } => {
            run_status(&key_file)
        }
    }
}

fn run_encrypt(text: &str, cli_key: &Option<String>, key_file: &Option<String>) -> Result<(), Box<dyn std::error::Error>> {
    let cipher = build_cipher(cli_key, key_file)?;
    println!("{}", cipher.encrypt(text));
    Ok(())
}

fn run_decrypt(text: &str, cli_key: &Option<String>, key_file: &Option<String>) -> Result<(), Box<dyn std::error::Error>> {
    let cipher = build_cipher(cli_key, key_file)?;
    println!("{}", cipher.decrypt(text));
    Ok(())
}

fn run_status(key_file: &str) -> Result<(), Box<dyn std::error::Error>> {
    let key = load_key_file(key_file)?;
    println!("cipher_key: {}", key.permutation);
    Ok(())
}

fn build_cipher(cli_key: &Option<String>, key_file: &Option<String>) -> Result<SubstitutionCipher, Box<dyn std::error::Error>> {
    match (cli_key.as_ref(), key_file.as_ref()) {
        (Some(key), None) => {
            SubstitutionCipher::from_permutation(&key)?
                .map_err(|e| e.into())
        }
        (None, Some(file)) => {
            let config = load_key_file(file).map_err(|e| e.into())?;
            SubstitutionCipher::from_permutation(&config.permutation)?
        }
        _ => {
            anyhow::bail("Provide either --cipher-key or --key-file");
        }
    }
}
