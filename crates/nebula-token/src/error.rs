use std::fmt::Debug;
use std::str::Utf8Error;

use base64::DecodeError;
use josekit::JoseError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum JWTError {
    #[error("error while decoding b64 jwt part")]
    DecodeBase64(#[from] DecodeError),

    #[error("invalid JWT format '{0}'")]
    InvalidJwtFormat(String),

    #[error("unable to parse jwt to json")]
    SerdeError(#[from] serde_json::Error),

    #[error("error while creating JWT")]
    JoseCreationError(#[from] JoseError),

    #[error("error while parsing JWK to verifier")]
    VerifierCreationError(JoseError),

    #[error("invalid JWS Signature")]
    InvalidSignature(JoseError),

    #[error("missing claim '{0}'")]
    MissingClaim(&'static str),
}
