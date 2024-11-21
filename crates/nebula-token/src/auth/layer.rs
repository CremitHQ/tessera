use std::sync::Arc;

use bon::Builder;
use tower::Layer;

use crate::{jwk::jwk_set::JWK_SET_DEFAULT_KEY_ID, jwt::Jwt};

use super::{
    error::AuthError,
    extractor::{AuthHeaderTokenExtractor, TokenExtractor},
    jwks_discovery::JwksDiscovery,
    service::NebulaAuthService,
};

#[derive(Builder, Clone)]
pub struct NebulaAuthLayer {
    pub jwk_discovery: Arc<dyn JwksDiscovery + Send + Sync>,

    #[builder(default = Arc::new(AuthHeaderTokenExtractor))]
    pub token_extractor: Arc<dyn TokenExtractor + Send + Sync>,
}

impl NebulaAuthLayer {
    pub async fn validate_token(&self, token: &str) -> Result<Jwt, AuthError> {
        let jwks = self.jwk_discovery.jwks().await?;
        let jwt = Jwt::decode_without_verification(token).map_err(AuthError::DecodeJwt)?;
        let jwk = jwks.get(jwt.kid().unwrap_or(JWK_SET_DEFAULT_KEY_ID)).ok_or(AuthError::NoJwk)?;
        jwt.verify(jwk).map_err(AuthError::VerifyJwt)?;
        match jwt.is_expired() {
            true => Err(AuthError::ExpiredJwt),
            false => Ok(jwt),
        }
    }
}

impl<S> Layer<S> for NebulaAuthLayer {
    type Service = NebulaAuthService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        NebulaAuthService::new(inner, self)
    }
}
