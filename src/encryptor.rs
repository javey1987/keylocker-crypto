use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum EncryptionError {
    #[error("Encryption failed: {0}")]
    EncryptError(String),
    #[error("Decryption failed: {0}")]
    DecryptError(String),
    #[error("Invalid key length")]
    InvalidKeyLength,
}

/// Encrypts plaintext using AES-256-GCM.
/// Returns base64-encoded ciphertext (nonce + ciphertext + tag).
pub fn encrypt(plaintext: &str, hex_key: &str) -> Result<String, EncryptionError> {
    let key_bytes = hex::decode(hex_key)
        .map_err(|_| EncryptionError::InvalidKeyLength)?;

    let key = aes_gcm::Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);

    let nonce_bytes = rand::Rng::r#gen::<[u8; 12]>(&mut OsRng);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_bytes())
        .map_err(|e| EncryptionError::EncryptError(e.to_string()))?;

    let mut combined = nonce_bytes.to_vec();
    combined.extend_from_slice(&ciphertext);

    Ok(base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &combined))
}

/// Decrypts base64-encoded ciphertext using AES-256-GCM.
pub fn decrypt(encrypted_base64: &str, hex_key: &str) -> Result<String, EncryptionError> {
    let key_bytes = hex::decode(hex_key)
        .map_err(|_| EncryptionError::InvalidKeyLength)?;

    let combined = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, encrypted_base64)
        .map_err(|e| EncryptionError::DecryptError(e.to_string()))?;

    if combined.len() < 12 {
        return Err(EncryptionError::DecryptError("Ciphertext too short".to_string()));
    }

    let (nonce_bytes, ciphertext) = combined.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);

    let key = aes_gcm::Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);

    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| EncryptionError::DecryptError(e.to_string()))?;

    String::from_utf8(plaintext)
        .map_err(|e| EncryptionError::DecryptError(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let hex_key = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let plaintext = "sk-proj-OpenAIApiKey123456789";
        let encrypted = encrypt(plaintext, hex_key).unwrap();
        let decrypted = decrypt(&encrypted, hex_key).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_wrong_key_fails() {
        let key1 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let key2 = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let encrypted = encrypt("secret", key1).unwrap();
        assert!(decrypt(&encrypted, key2).is_err());
    }
}
