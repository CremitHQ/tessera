use std::collections::HashMap;

use josekit::{jwt::JwtPayload, Value};
use serde::{Deserialize, Serialize};

use crate::error::JWTError;

pub const WORKSPACE_NAME_CLAIM: &str = "wmn";
pub const ATTRIBUTES_CLAIM: &str = "attributes";
pub const ROLE_CLAIM: &str = "role";

#[derive(Debug, Clone)]
pub struct NebulaClaim {
    pub gid: String,
    pub workspace_name: String,
    pub attributes: HashMap<String, String>,
    pub role: Role,
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
        let role = match payload.claim(ROLE_CLAIM).ok_or(JWTError::MissingClaim(ROLE_CLAIM))? {
            Value::String(ref s) => Role::from(s.clone()),
            _ => return Err(JWTError::InvalidJwtFormat("role is not a string".to_string())),
        };

        Ok(NebulaClaim {
            gid,
            workspace_name,
            attributes: attributes
                .into_iter()
                .map(|(k, v)| {
                    let v = v.as_str()?.to_string();
                    Some((k, v))
                })
                .collect::<Option<_>>()
                .ok_or(JWTError::InvalidJwtFormat("attributes is not a map of strings".to_string()))?,
            role,
        })
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum Role {
    #[serde(rename = "admin")]
    Admin,
    #[serde(rename = "member")]
    Member,
}

impl From<String> for Role {
    fn from(s: String) -> Self {
        match s.as_str() {
            "admin" => Role::Admin,
            "member" => Role::Member,
            _ => Role::Member,
        }
    }
}

impl From<Role> for String {
    fn from(role: Role) -> Self {
        match role {
            Role::Admin => "admin".to_string(),
            Role::Member => "member".to_string(),
        }
    }
}
