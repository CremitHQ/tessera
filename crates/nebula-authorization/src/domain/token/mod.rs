use anyhow::Result;
use josekit::jwt::JwtPayload;
use serde_json::Value;
use std::collections::HashMap;

pub mod error;
pub mod jwk;
pub mod jws;
pub mod jwt;

pub trait Algorithm {
    fn is_symmetric(&self) -> bool;

    fn name(&self) -> &str;
}

pub trait SizableAlgorithm: Algorithm {
    fn length(&self) -> Option<usize>;
}

pub trait JwtPayloadExt {
    fn from_hash_map(map: HashMap<&str, Value>) -> Result<JwtPayload>;
}

impl JwtPayloadExt for JwtPayload {
    fn from_hash_map(map: HashMap<&str, Value>) -> Result<JwtPayload> {
        let mut payload = JwtPayload::new();
        for (k, v) in map {
            payload.set_claim(k, Some(v))?;
        }
        Ok(payload)
    }
}
