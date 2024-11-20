use base64::engine::general_purpose::URL_SAFE_NO_PAD as base64_engine;
use base64::Engine;
use josekit::jwk::Jwk;
use sha3::{Digest, Sha3_256 as Sha256, Sha3_384 as Sha384, Sha3_512 as Sha512};
use thiserror::Error;

pub trait Hashable {
    fn identifier(&self) -> String;
}

#[derive(Debug, Error)]
pub enum HashingError {
    #[error("Invalid JWK used to hash a token")]
    InvalidKey,
    #[error("Invalid hashing algorithm in JWK. {:?}", .0)]
    InvalidHashAlgorithm(String),
    #[error("Error ascii encoding identifier. {:?}", .0)]
    Ascii(String),
}

pub trait TokenHasher {
    fn hash(&self, key: &Jwk) -> Result<String, HashingError>;
}

impl<T> TokenHasher for T
where
    T: Hashable,
{
    fn hash(&self, key: &Jwk) -> Result<String, HashingError> {
        let id = self.identifier();
        let algorithm = key.algorithm().ok_or(HashingError::InvalidKey)?.to_uppercase();
        let hash = match &algorithm[..] {
            "ES256" | "RS256" | "HS256" | "PS256" => Sha256::digest(id.as_bytes()).to_vec(),
            "ES384" | "RS384" | "HS384" | "PS384" => Sha384::digest(id.as_bytes()).to_vec(),
            "ES512" | "RS512" | "HS512" | "PS512" => Sha512::digest(id.as_bytes()).to_vec(),
            _ => {
                return Err(HashingError::InvalidHashAlgorithm(algorithm));
            }
        };
        let first_half = &hash[..hash.len() / 2];
        Ok(base64_engine.encode(first_half))
    }
}
