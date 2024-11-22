use std::time::{Duration, SystemTime};

use anyhow::Result;
use nebula_token::{
    claim::{ATTRIBUTES_CLAIM, ROLE_CLAIM, WORKSPACE_NAME_CLAIM},
    jwk::jwk_set::JwkSet,
    jwt::Jwt,
    JwsHeader, JwtPayload, Map, Value,
};
use url::Url;

use super::connector::Identity;

pub struct TokenService {
    pub base_url: Url,
    pub lifetime: u64,
    pub jwks: JwkSet,
    pub jwk_kid: String,
}

const DEFAULT_ALGORITHM: &'static str = "ES256";
const ISSUER: &'static str = "nebula-authorization";

impl TokenService {
    pub fn new(base_url: Url, lifetime: u64, jwks: JwkSet, jwk_kid: String) -> Self {
        Self { base_url, lifetime, jwks, jwk_kid }
    }

    pub fn create_jwt(&self, identity: &Identity) -> Result<Jwt> {
        let mut jws_header = JwsHeader::new();
        jws_header.set_jwk_set_url(self.base_url.join("/jwks").expect("failed to create jwks url"));
        jws_header.set_key_id(&self.jwk_kid);
        jws_header.set_algorithm(DEFAULT_ALGORITHM);

        let mut jwt_payload = JwtPayload::new();
        jwt_payload.set_claim(
            ATTRIBUTES_CLAIM,
            Some(Value::Object(
                identity.claims.iter().map(|(k, v)| (k.to_string(), v.to_string().into())).collect::<Map<_, _>>(),
            )),
        )?;
        jwt_payload.set_subject(&identity.user_id);
        jwt_payload.set_issuer(ISSUER);
        jwt_payload.set_claim(WORKSPACE_NAME_CLAIM, Some(identity.workspace_name.clone().into())).unwrap();
        jwt_payload.set_claim(ROLE_CLAIM, Some(String::from(identity.role.clone()).into())).unwrap();

        let now = SystemTime::now();
        let expires_at = now + Duration::from_secs(self.lifetime);
        jwt_payload.set_expires_at(&expires_at);
        jwt_payload.set_issued_at(&now);

        let jwt =
            Jwt::new(jws_header, jwt_payload, self.jwks.get(&self.jwk_kid).expect("failed to get jwk from jwk set"))?;

        Ok(jwt)
    }
}
