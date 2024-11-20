use josekit::jwk::Jwk;
use std::fmt;
use std::fmt::Formatter;
use std::hash::{Hash, Hasher};
use std::prelude::v1::Result::Err;
use std::str::FromStr;

use super::Algorithm;
use josekit::jws::JwsAlgorithm;
use josekit::jws::*;
use josekit::jwt::alg::unsecured::UnsecuredJwsAlgorithm;
use serde::de::{Error, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;

#[derive(Debug, Clone)]
pub struct SigningAlgorithm(Box<dyn JwsAlgorithm>);

impl SigningAlgorithm {
    pub fn new(jws_algorithm: Box<dyn JwsAlgorithm>) -> Self {
        SigningAlgorithm(jws_algorithm)
    }
}

impl Algorithm for SigningAlgorithm {
    fn is_symmetric(&self) -> bool {
        self.0.name().starts_with("HS")
    }

    fn name(&self) -> &str {
        self.0.name()
    }
}

impl Hash for SigningAlgorithm {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.name().hash(state)
    }
}

impl<A> From<A> for SigningAlgorithm
where
    A: JwsAlgorithm + 'static,
{
    fn from(alg: A) -> Self {
        SigningAlgorithm::new(Box::new(alg))
    }
}

impl PartialEq for SigningAlgorithm {
    fn eq(&self, other: &Self) -> bool {
        self.0.name() == other.0.name()
    }
}

impl Eq for SigningAlgorithm {}

impl Serialize for SigningAlgorithm {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.0.name())
    }
}

impl<'de> Deserialize<'de> for SigningAlgorithm {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct AlgVisitor;

        impl<'de> Visitor<'de> for AlgVisitor {
            type Value = SigningAlgorithm;

            fn expecting(&self, formatter: &mut Formatter) -> fmt::Result {
                formatter.write_str("a valid jws algorithm.")
            }

            fn visit_str<E>(self, alg: &str) -> Result<Self::Value, E>
            where
                E: Error,
            {
                SigningAlgorithm::from_str(alg).map_err(|err| Error::custom(err.to_string()))
            }
        }
        deserializer.deserialize_str(AlgVisitor)
    }
}

#[derive(Debug, Error)]
#[error("unsupported algorithm {}", .0)]
pub struct ParseAlgError(String);

impl FromStr for SigningAlgorithm {
    type Err = ParseAlgError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "HS256" => Ok(SigningAlgorithm::new(Box::new(HS256))),
            "HS384" => Ok(SigningAlgorithm::new(Box::new(HS384))),
            "HS512" => Ok(SigningAlgorithm::new(Box::new(HS512))),
            "RS256" => Ok(SigningAlgorithm::new(Box::new(RS256))),
            "RS384" => Ok(SigningAlgorithm::new(Box::new(RS384))),
            "RS512" => Ok(SigningAlgorithm::new(Box::new(RS512))),
            "PS256" => Ok(SigningAlgorithm::new(Box::new(PS256))),
            "PS384" => Ok(SigningAlgorithm::new(Box::new(PS384))),
            "PS512" => Ok(SigningAlgorithm::new(Box::new(PS512))),
            "ES256" => Ok(SigningAlgorithm::new(Box::new(ES256))),
            "ES256K" => Ok(SigningAlgorithm::new(Box::new(ES256K))),
            "ES384" => Ok(SigningAlgorithm::new(Box::new(ES384))),
            "ES512" => Ok(SigningAlgorithm::new(Box::new(ES512))),
            "EdDSA" => Ok(SigningAlgorithm::new(Box::new(EdDSA))),
            "none" => Ok(SigningAlgorithm::new(Box::new(UnsecuredJwsAlgorithm::None))),
            _ => Err(ParseAlgError(s.to_string())),
        }
    }
}
