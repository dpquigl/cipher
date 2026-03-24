use thiserror::Error;

#[derive(Error, Debug)]
pub enum CipherError {
    #[error("Invalid permutation string length: expected 26 characters")]
    InvalidPermutationLength,
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
            return Err(CipherError::InvalidPermutationLength);
        }

        let forward_map = build_forward_map(permutation);
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
            'a'..='z' => encrypt_lowercase(c),
            'A'..='Z' => encrypt_uppercase(c),
            _ => c,  // Non-alphabetic characters pass through unchanged
        }
    }

    fn decrypt_char(&self, c: char) -> char {
        match c.to_ascii_lowercase() {
            'a'..='z' => decrypt_lowercase(c),
            _ => c,  // Non-alphabetic characters pass through unchanged
        }
    }

    fn encrypt_lowercase(&self, c: char) -> char {
        let idx = c as u8 - b'a';
        self.forward_map[idx as usize]
    }

    fn encrypt_uppercase(&self, c: char) -> char {
        let idx = c as u8 - b'A';
        (self.forward_map[idx as usize] as u8 + b'A' - b'a') as char
    }

    fn decrypt_lowercase(&self, c: char) -> char {
        let cipher_char = c.to_ascii_lowercase();
        let idx = cipher_char as u8 - b'a';
        if idx >= self.reverse_map.len() as u8 {
            return c;
        }
        let plaintext_idx = self.reverse_map[idx as usize];
        (plaintext_idx + b'a') as char
    }
}

fn build_forward_map(permutation: &str) -> Vec<char> {
    permutation.chars().collect::<Vec<_>>()
}

fn build_reverse_map(forward_map: &[char]) -> Vec<u8> {
    let mut reverse_map = vec![0u8; 26];
    for (i, &cipher_char) in forward_map.iter().enumerate() {
        if cipher_char >= b'a' && cipher_char <= b'z' {
            let plaintext_idx = cipher_char as usize - b'a' as usize;
            reverse_map[plaintext_idx] = i as u8;
        }
    }
    reverse_map
}
