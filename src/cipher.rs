use thiserror::Error;

#[derive(Error, Debug)]
pub enum CipherError {
    #[error("Invalid permutation string length: expected 26 characters, got {0}")]
    InvalidPermutationLength(usize),
    #[error("Duplicate character in permutation: '{0}' (each letter must appear exactly once)")]
    DuplicateCharacter(char),
}

/// Substitution cipher using a permutation string for encryption/decryption
#[derive(Clone)]
pub struct SubstitutionCipher {
    forward_map: Vec<char>,   // Plaintext letter -> encrypted character
    reverse_map: Vec<u8>,     // Encrypted char index (0-25) -> plaintext letter index (0-25)
}

impl SubstitutionCipher {
    pub fn from_permutation(permutation: &str) -> Result<Self, CipherError> {
        if permutation.len() != 26 {
            return Err(CipherError::InvalidPermutationLength(permutation.len()));
        }

        // Check for duplicate characters
        let mut seen = std::collections::HashSet::new();
        let forward_map: Vec<char> = permutation.chars()
            .map(|c| {
                if !seen.insert(c) {
                    Err(CipherError::DuplicateCharacter(c))
                } else {
                    Ok(c)
                }
            })
            .collect::<Result<Vec<_>, _>>()?;

        let reverse_map = build_reverse_map(&forward_map);

        Ok(Self { forward_map, reverse_map })
    }

    /// Encrypt plaintext using the substitution cipher
    pub fn encrypt(&self, text: &str) -> String {
        text.chars().map(|c| self.encrypt_char(c)).collect()
    }

    /// Decrypt ciphertext to recover original plaintext
    pub fn decrypt(&self, text: &str) -> String {
        text.chars().map(|c| self.decrypt_char(c)).collect()
    }

    fn encrypt_char(&self, c: char) -> char {
        match c {
            'a'..='z' => self.encrypt_lowercase(c),
            'A'..='Z' => self.encrypt_uppercase(c),
            _ => c,  // Non-alphabetic characters pass through unchanged
        }
    }

    fn decrypt_char(&self, c: char) -> char {
        match c.to_ascii_lowercase() {
            'a'..='z' => self.decrypt_lowercase(c),
            _ => c,  // Non-alphabetic characters pass through unchanged
        }
    }

    fn encrypt_lowercase(&self, c: char) -> char {
        let idx = (c as u8) - b'a';
        self.forward_map[idx as usize]
    }

    fn encrypt_uppercase(&self, c: char) -> char {
        let idx = (c as u8) - b'A';
        let mapped_char = self.forward_map[idx as usize];
        if mapped_char >= 'a' && mapped_char <= 'z' {
            (mapped_char as u8 + b'A' - b'a') as char
        } else {
            c
        }
    }

    fn decrypt_lowercase(&self, c: char) -> char {
        let cipher_char = c.to_ascii_lowercase();
        let idx = (cipher_char as u8) - b'a';
        let plaintext_idx = self.reverse_map.get(idx as usize).copied().unwrap_or(0);
        (plaintext_idx + b'a') as char
    }
}

fn build_forward_map(permutation: &str) -> Vec<char> {
    permutation.chars().collect()
}

fn build_reverse_map(forward_map: &[char]) -> Vec<u8> {
    let mut reverse_map = vec![0u8; 26];
    for (plaintext_idx, &cipher_char) in forward_map.iter().enumerate() {
        if cipher_char >= 'a' && cipher_char <= 'z' {
            let cipher_byte = cipher_char as u8;
            if cipher_byte >= b'a' && cipher_byte <= b'z' {
                reverse_map[cipher_byte - b'a'] = plaintext_idx as u8;
            }
        } else if cipher_char >= 'A' && cipher_char <= 'Z' {
            let cipher_byte = cipher_char as u8;
            if cipher_byte >= b'A' && cipher_byte <= b'Z' {
                reverse_map[cipher_byte - b'A'] = plaintext_idx as u8;
            }
        }
    }
    reverse_map
}
