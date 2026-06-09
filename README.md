# 🔐 KeyLocker Crypto

KeyLocker's encryption layer — open source for independent security audit.

## Encryption

- **Symmetric encryption**: AES-256-GCM (authenticated encryption)
- **Key derivation**: Argon2id (memory-hard KDF, 19MB memory cost)
- **Key wrapping**: RSA-4096 for shared vaults (team feature)

## Usage

```rust
use keylocker_crypto::{encrypt, decrypt, derive_master_key, verify_master_password};

// Set up master password
let (encryption_key, hash) = derive_master_key("your master password", None)?;

// Encrypt
let ciphertext = encrypt("sk-proj-openai-key-xxx", &encryption_key)?;

// Decrypt
let plaintext = decrypt(&ciphertext, &encryption_key)?;
```

## Audit

This library is designed for independent security review.  
If you find a vulnerability, please open an issue.
