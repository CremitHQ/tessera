use std::collections::HashMap;

use josekit::{jwt::JwtPayload, Value};

use crate::error::JWTError;

pub const WORKSPACE_NAME_CLAIM: &str = "wmn";
pub const ATTRIBUTES_CLAIM: &str = "attributes";

#[derive(Debug, Clone)]
pub struct NebulaClaim {
    pub gid: String,
    pub workspace_name: String,
    pub attributes: HashMap<String, String>,
}

impl TryFrom<&JwtPayload> for NebulaClaim {
    type Error = JWTError;

    fn try_from(payload: &JwtPayload) -> Result<Self, Self::Error> {
        let gid = payload.subject().ok_or(JWTError::MissingClaim("sub"))?.to_string();
        let workspace_name =
            match payload.claim(WORKSPACE_NAME_CLAIM).ok_or(JWTError::MissingClaim(WORKSPACE_NAME_CLAIM))? {
                Value::String(ref s) => s.clone(),
                _ => return Err(JWTError::InvalidJwtFormat("wnm is not a string".to_string())),
            };
        let attributes = match payload.claim(ATTRIBUTES_CLAIM).ok_or(JWTError::MissingClaim(ATTRIBUTES_CLAIM))? {
            Value::Object(ref map) => map.clone(),
            _ => return Err(JWTError::InvalidJwtFormat("attributes is not a map".to_string())),
        };

        Ok(NebulaClaim {
            gid,
            workspace_name,
            attributes: attributes.into_iter().map(|(k, v)| (k, v.to_string())).collect(),
        })
    }
}
