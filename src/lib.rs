pub mod cipher;
pub mod config;

#[cfg(test)]
mod tests {
    use crate::cipher::{SubstitutionCipher, CipherError};

    const TEST_PERMUTATION: &str = "qwertyuiopasdfghjklzxcvbnm";

    #[test]
    fn test_encrypt_lowercase() {
        let cipher = SubstitutionCipher::from_permutation(TEST_PERMUTATION).unwrap();
        assert_eq!(cipher.encrypt("hello"), "qeirt");
    }

    #[test]
    fn test_decrypt() {
        let cipher = SubstitutionCipher::from_permutation(TEST_PERMUTATION).unwrap();
        let encrypted = cipher.encrypt("Hello World!");
        assert_eq!(cipher.decrypt(&encrypted), "Hello World!");
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
        assert_eq!(result, "qeirtw...World! 123 @#$"); // non-alpha unchanged
    }

    #[test]
    fn test_invalid_permutation_length() {
        let result = SubstitutionCipher::from_permutation("abc");
        assert!(result.is_err());
    }
}
