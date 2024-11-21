use std::task::{Context, Poll};

use axum::{body::Body, extract::Request, response::IntoResponse};
use futures_util::future::BoxFuture;

use crate::claim::NebulaClaim;

use super::{error::AuthError, extractor, layer::NebulaAuthLayer};

#[derive(Clone)]
pub struct NebulaAuthService<S> {
    inner: S,
    layer: NebulaAuthLayer,
}

impl<S> NebulaAuthService<S> {
    pub fn new(inner: S, layer: &NebulaAuthLayer) -> Self {
        Self { inner, layer: layer.clone() }
    }
}

impl<S> tower::Service<Request<Body>> for NebulaAuthService<S>
where
    S: tower::Service<Request<Body>, Response = axum::response::Response> + Send + Clone + 'static,
    S::Future: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut request: Request<Body>) -> Self::Future {
        let mut inner = self.inner.clone();
        let layer = self.layer.clone();
        Box::pin(async move {
            let result = match extractor::extract_jwt(&request, layer.token_extractor.clone()) {
                Some(token) => layer.validate_token(&token).await,
                None => Err(AuthError::MissingToken),
            };

            match result {
                Ok(token) => {
                    let claim: Result<NebulaClaim, _> = token.payload().try_into().map_err(AuthError::ParseClaim);
                    match claim {
                        Ok(claim) => {
                            request.extensions_mut().insert(claim);
                            request.extensions_mut().insert(token);
                            inner.call(request).await
                        }
                        Err(err) => Ok(err.into_response()),
                    }
                }
                Err(err) => Ok(err.into_response()),
            }
        })
    }
}
