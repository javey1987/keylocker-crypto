//! KeyLocker Crypto — Encryption Library
//!
//! AES-256-GCM authenticated encryption with Argon2id key derivation.
//! Open source for independent security audit.
//! Part of the KeyLocker project.

mod encryptor;
mod key_derivation;

pub use encryptor::{encrypt, decrypt, EncryptionError};
pub use key_derivation::{derive_master_key, verify_master_password, generate_recovery_key, KeyDerivationError};

/// Re-export the data structures
pub mod types {
    use serde::{Deserialize, Serialize};

    /// Master password hash (stored for verification)
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct MasterPasswordHash {
        pub hash: String,
        pub salt: String,
        pub params: Argon2Params,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct Argon2Params {
        pub m_cost: u32,
        pub t_cost: u32,
        pub p_cost: u32,
    }

    impl Default for Argon2Params {
        fn default() -> Self {
            Self { m_cost: 19456, t_cost: 2, p_cost: 1 }
        }
    }
}
