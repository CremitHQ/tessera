use std::fmt::Debug;
use std::str::Utf8Error;

use base64::DecodeError;
use josekit::JoseError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum JWTError {
    #[error("error decoding b64 jwt part")]
    DecodeBase64(#[from] DecodeError),
    #[error("JWT has an invalid format '{0}'")]
    InvalidJwtFormat(String),
    #[error("Unable to parse jwt to json")]
    SerDeParseError(#[from] serde_json::Error),
    #[error("Unable to parse jwt header from json")]
    HeaderParseError(#[source] JoseError),
    #[error("Error creating JWT")]
    JoseCreationError(#[from] JoseError),
    #[error("Missing algorithm in JWT")]
    JWTAlgorithmNotFound,
    #[error("Invalid algorithm '{}',", .0)]
    InvalidJWTAlgorithm(String),
    #[error("Error parsing JWK to signer")]
    SignerCreationError(JoseError),
    #[error("Error parsing JWK to verifier")]
    VerifierCreationError(JoseError),
    #[error("Error parsing JWK to decrypter")]
    DecrypterCreationError(JoseError),
    #[error("Error parsing JWK to encrypter")]
    EncrypterCreationError(JoseError),
    #[error("Error decrypting JWE")]
    DecryptError(JoseError),
    #[error("Error encrypting JWE")]
    EncryptError(JoseError),
    #[error("Invalid JWS Signature")]
    InvalidSignature(JoseError),
    #[error("Invalid encoding of payload")]
    NoUTF8(#[from] Utf8Error),
    #[error("Error getting client keystore")]
    KeystoreCreation(#[source] anyhow::Error),
    #[error("Could not find JWK Key to perform ")]
    KeyNotFound,
}
