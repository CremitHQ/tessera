use std::fmt::Formatter;
use std::time::SystemTime;

use base64::engine::general_purpose::URL_SAFE_NO_PAD as base64_engine;
use base64::Engine;
use josekit::jwk::Jwk;
use josekit::jws::JwsHeader;
use josekit::jwt;
use josekit::jwt::JwtPayload;
use serde::de::{Error, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{Map, Value};

use super::error::JWTError;
use super::jwk::jwk_ext::JwkExt;

#[derive(Debug, Clone)]
pub struct Jwt {
    header: JwsHeader,
    payload: JwtPayload,
    pub serialized_repr: String,
}

impl Jwt {
    pub fn new(header: JwsHeader, payload: JwtPayload, key: &Jwk) -> Result<Self, JWTError> {
        let signer = key.get_signer()?;
        let result = jwt::encode_with_signer(&payload, &header, &*signer).map_err(JWTError::JoseCreationError)?;
        Ok(Jwt { header, payload, serialized_repr: result })
    }

    pub fn verify(&self, key: &Jwk) -> Result<(), JWTError> {
        let verifier = key.get_verifier().map_err(JWTError::VerifierCreationError)?;
        let jwt_bytes = self.serialized_repr.as_bytes();
        let indexes: Vec<usize> =
            jwt_bytes.iter().enumerate().filter(|(_, b)| **b == b'.').map(|(pos, _)| pos).collect();
        debug_assert_eq!(indexes.len(), 2);

        let header_and_payload = &jwt_bytes[..indexes[1]];
        let signature = &jwt_bytes[(indexes[1] + 1)..];
        let decoded_signature = base64_engine.decode(signature)?;
        verifier.verify(header_and_payload, &decoded_signature).map_err(JWTError::InvalidSignature)
    }

    pub fn decode(input: impl AsRef<str>, key: &Jwk) -> Result<Self, JWTError> {
        let jwt = Jwt::decode_without_verification(input)?;
        jwt.verify(key)?;
        Ok(jwt)
    }

    pub fn decode_without_verification(input: impl AsRef<str>) -> Result<Self, JWTError> {
        let str_jwt = input.as_ref();
        let parts: Vec<&str> = str_jwt.split('.').collect();

        if parts.len() != 3 {
            return Err(JWTError::InvalidJwtFormat(str_jwt.to_owned()));
        }

        let header_b64 = base64_engine.decode(parts[0])?;
        let header: Map<String, Value> = serde_json::from_slice(&header_b64)?;
        let header = JwsHeader::from_map(header)?;

        let payload_b64 = base64_engine.decode(parts[1])?;
        let payload: Map<String, Value> = serde_json::from_slice(&payload_b64)?;
        let payload = JwtPayload::from_map(payload)?;

        Ok(Jwt { header, payload, serialized_repr: str_jwt.to_owned() })
    }

    pub fn is_expired(&self) -> bool {
        self.payload.expires_at().map_or(true, |exp| exp < SystemTime::now())
    }

    pub fn kid(&self) -> Option<&str> {
        self.header.key_id()
    }

    pub fn payload(&self) -> &JwtPayload {
        &self.payload
    }
}

impl Serialize for Jwt {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.serialized_repr)
    }
}

impl<'de> Deserialize<'de> for Jwt {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct JWSVisitor;
        impl Visitor<'_> for JWSVisitor {
            type Value = Jwt;

            fn expecting(&self, formatter: &mut Formatter) -> std::fmt::Result {
                formatter.write_str("an signed jws string")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: Error,
            {
                Jwt::decode_without_verification(v).map_err(|err| E::custom(err))
            }
        }
        deserializer.deserialize_str(JWSVisitor)
    }
}
