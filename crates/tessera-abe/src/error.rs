use tessera_policy::error::PolicyParserError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ABEError {
    #[error("invalid policy: {0}")]
    InvalidPolicy(#[from] InvalidPolicyErrorKind),

    #[error("invalid attribute: {0}")]
    InvalidAttribute(#[from] InvalidAttributeKind),

    #[error("aes-gcm error: {0}")]
    AESGCMError(#[from] AESGCMErrorKind),
}

#[derive(Error, Debug)]
pub enum InvalidPolicyErrorKind {
    #[error("does not satisfy the policy")]
    PolicyNotSatisfied,

    #[error(transparent)]
    ParsePolicy(#[from] PolicyParserError),
}

#[derive(Error, Debug)]
pub enum InvalidAttributeKind {
    #[error("attribute `{0}` not found")]
    AttributeNotFound(String),
}

#[derive(Error, Debug)]
pub enum AESGCMErrorKind {
    #[error("failed to encrypt data ({0})")]
    Encryption(aes_gcm::Error),

    #[error("failed to decrypt data ({0})")]
    Decryption(aes_gcm::Error),

    #[error("invalid nonce size (expected {expected} bytes, got {actual} bytes)")]
    NonceSizeMismatch { expected: usize, actual: usize },
}
