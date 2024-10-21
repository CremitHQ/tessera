use std::borrow::Cow;

use tessera_policy::error::PolicyError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ABEError<'a> {
    #[error("Policy error: {0}")]
    PolicyError(#[from] PolicyError),

    #[error("Does not satisfy the policy")]
    PolicyNotSatisfied,

    #[error("Invalid Policy: {0}")]
    InvalidPolicy(Cow<'a, str>),

    #[error("AES-GCM module error: {0}")]
    AESGCMError(#[from] AESGCMError),

    #[error("ABE encryption error: {0}")]
    EncryptionError(Cow<'a, str>),

    #[error("ABE decryption error: {0}")]
    DecryptionError(Cow<'a, str>),
}

#[derive(Error, Debug)]
pub enum AESGCMError {
    #[error("AES-GCM encryption error: {0}")]
    EncryptionError(aes_gcm::Error),

    #[error("AES-GCM decryption error: {0}")]
    DecryptionError(aes_gcm::Error),

    #[error("AES-GCM nonce size mismatch")]
    NonceSizeMismatch,
}
