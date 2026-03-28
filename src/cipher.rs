use crate::AppError;
use std::collections::HashSet;

#[derive(Debug)]
pub struct SubstitutionCipher {
    forward_map: Vec<char>,   // Plaintext letter -> encrypted character
    reverse_map: Vec<u8>,     // Encrypted char index (0-25) -> plaintext letter index (0-25)
}

impl SubstitutionCipher {
    pub fn from_permutation(permutation: &str) -> Result<Self, AppError> {
        if permutation.len() != 26 {
            return Err(AppError::InvalidPermutationLength(permutation.len()));
        }

        let forward_map = build_forward_map(permutation)?;
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
        if c.is_ascii_uppercase() {
            self.decrypt_uppercase(c)
        } else {
            self.decrypt_lowercase(c)
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
        if c < 'a' || c > 'z' {
            return c;
        }
        let idx = (c as u8) - b'a';
        let plaintext_idx = self.reverse_map.get(idx as usize).copied().unwrap_or(0);
        (plaintext_idx + b'a') as char
    }

    fn decrypt_uppercase(&self, c: char) -> char {
        if c < 'A' || c > 'Z' {
            return c;
        }
        let idx = (c as u8) - b'A';
        let plaintext_idx = self.reverse_map.get(idx as usize).copied().unwrap_or(0);
        (plaintext_idx + b'a') as char
    }
}

fn build_forward_map(permutation: &str) -> Result<Vec<char>, AppError> {
    let mut seen = HashSet::new();
    permutation.chars()
    .map(|c| {
        if !seen.insert(c) {
            Err(AppError::DuplicateCharacter(c))
        } else {
            Ok(c)
        }
    })
    .collect::<Result<Vec<_>, AppError>>()
}

fn build_reverse_map(forward_map: &[char]) -> Vec<u8> {
    let mut reverse_map = vec![0u8; 26];
    for (plaintext_idx, &cipher_char) in forward_map.iter().enumerate() {
        if cipher_char >= 'a' && cipher_char <= 'z' {
            let cipher_byte = cipher_char as u8;
            if cipher_byte >= b'a' && cipher_byte <= b'z' {
                reverse_map[(cipher_byte - b'a') as usize] = plaintext_idx as u8;
            }
        } else if cipher_char >= 'A' && cipher_char <= 'Z' {
            let cipher_byte = cipher_char as u8;
            if cipher_byte >= b'A' && cipher_byte <= b'Z' {
                reverse_map[(cipher_byte - b'A') as usize] = plaintext_idx as u8;
            }
        }
    }
    reverse_map
}

#[cfg(test)]
mod tests {
    use super::*;

const TEST_PERMUTATION: &str = "qwertyuiopasdfghjklzxcvbnm";

    #[test]
    fn test_encrypt_lowercase() {
        let cipher = SubstitutionCipher::from_permutation(TEST_PERMUTATION).unwrap();
        assert_eq!(cipher.encrypt("hello"), "itssg");
    }

    #[test]
    fn test_decrypt() {
        let cipher = SubstitutionCipher::from_permutation(TEST_PERMUTATION).unwrap();
        let encrypted = cipher.encrypt("Hello World!");
        assert_eq!(cipher.decrypt(&encrypted), "hello world!");
    }

    #[test]
    fn test_empty_string() {
        let cipher = SubstitutionCipher::from_permutation(TEST_PERMUTATION).unwrap();
        assert_eq!(cipher.encrypt(""), "");
    }

    #[test]
    fn test_special_characters_preserved() {
        let cipher = SubstitutionCipher::from_permutation(TEST_PERMUTATION).unwrap();
        let result = cipher.encrypt("Hello, World! 123 @#$");
        assert_eq!(result, "Itssg, Vgksr! 123 @#$"); // non-alpha unchanged, case converted to uppercase output
    }

    #[test]
    fn test_invalid_permutation_length() {
        let result = SubstitutionCipher::from_permutation("abc");
        assert!(result.is_err());
    }
}