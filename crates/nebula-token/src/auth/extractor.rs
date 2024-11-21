use axum::extract::Request;
use std::{borrow::Cow, sync::Arc};

use super::error::AuthError;

pub type ExtractedToken<'a> = Cow<'a, str>;
pub trait TokenExtractor: Send + Sync + std::fmt::Debug {
    fn extract<'a>(&self, request: &'a Request) -> Result<ExtractedToken<'a>, AuthError>;
}
#[derive(Debug, Clone, Default)]
pub struct AuthHeaderTokenExtractor;

impl TokenExtractor for AuthHeaderTokenExtractor {
    fn extract<'a>(&self, request: &'a Request) -> Result<ExtractedToken<'a>, AuthError> {
        request
            .headers()
            .get("authorization")
            .ok_or(AuthError::MissingAuthorizationHeader)?
            .to_str()
            .map_err(|err| AuthError::InvalidAuthorizationHeader(err.to_string()))?
            .strip_prefix("Bearer ")
            .ok_or(AuthError::MissingBearerToken)
            .map(Cow::Borrowed)
    }
}

pub(crate) fn extract_jwt(
    request: &Request<axum::body::Body>,
    extractor: Arc<dyn TokenExtractor>,
) -> Option<ExtractedToken<'_>> {
    match extractor.extract(request) {
        Ok(jwt) => Some(jwt),
        Err(err) => {
            tracing::debug!(?extractor, ?err, "Extractor failed");
            None
        }
    }
}
