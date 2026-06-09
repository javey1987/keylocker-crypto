use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use crate::types::{Argon2Params, MasterPasswordHash};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum KeyDerivationError {
    #[error("Argon2 error: {0}")]
    Argon2Error(String),
    #[error("Password verification failed")]
    VerificationFailed,
}

/// Derives an encryption key from the master password.
/// Returns (encryption_key_hex, master_password_hash_for_verification)
pub fn derive_master_key(
    master_password: &str,
    salt: Option<&str>,
) -> Result<(String, MasterPasswordHash), KeyDerivationError> {
    let salt = match salt {
        Some(s) => SaltString::from_b64(s)
            .map_err(|e| KeyDerivationError::Argon2Error(e.to_string()))?,
        None => SaltString::generate(&mut OsRng),
    };

    let params = Argon2Params::default();
    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2::Params::new(params.m_cost, params.t_cost, params.p_cost, None)
            .map_err(|e| KeyDerivationError::Argon2Error(e.to_string()))?,
    );

    let hash = argon2
        .hash_password(master_password.as_bytes(), &salt)
        .map_err(|e| KeyDerivationError::Argon2Error(e.to_string()))?;

    let hash_bytes = hash.hash.unwrap().as_bytes().to_vec();
    let encryption_key = hex::encode(&hash_bytes);

    let master_hash = MasterPasswordHash {
        hash: hash.to_string(),
        salt: salt.as_str().to_string(),
        params,
    };

    Ok((encryption_key, master_hash))
}

/// Verifies the master password against the stored hash.
pub fn verify_master_password(
    master_password: &str,
    stored_hash: &MasterPasswordHash,
) -> Result<String, KeyDerivationError> {
    let parsed_hash = PasswordHash::new(&stored_hash.hash)
        .map_err(|e| KeyDerivationError::Argon2Error(e.to_string()))?;

    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2::Params::new(stored_hash.params.m_cost, stored_hash.params.t_cost, stored_hash.params.p_cost, None)
            .map_err(|e| KeyDerivationError::Argon2Error(e.to_string()))?,
    );

    argon2
        .verify_password(master_password.as_bytes(), &parsed_hash)
        .map_err(|_| KeyDerivationError::VerificationFailed)?;

    let salt = SaltString::from_b64(&stored_hash.salt)
        .map_err(|e| KeyDerivationError::Argon2Error(e.to_string()))?;

    let hash = argon2
        .hash_password(master_password.as_bytes(), &salt)
        .map_err(|e| KeyDerivationError::Argon2Error(e.to_string()))?;

    let hash_bytes = hash.hash.unwrap().as_bytes().to_vec();
    Ok(hex::encode(&hash_bytes))
}

/// Generates a hex-encoded recovery key
pub fn generate_recovery_key() -> String {
    use rand::Rng;
    let mut rng = OsRng;
    let mut bytes = [0u8; 32];
    rng.fill(&mut bytes);
    hex::encode(&bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_derivation_roundtrip() {
        let (key, hash) = derive_master_key("MySecurePassword123!", None).unwrap();
        assert_eq!(key.len(), 64);
        let derived = verify_master_password("MySecurePassword123!", &hash).unwrap();
        assert_eq!(key, derived);
    }

    #[test]
    fn test_wrong_password_fails() {
        let (_, hash) = derive_master_key("correct", None).unwrap();
        assert!(verify_master_password("wrong", &hash).is_err());
    }

    #[test]
    fn test_recovery_key_generation() {
        let key = generate_recovery_key();
        assert_eq!(key.len(), 64);
    }
}
