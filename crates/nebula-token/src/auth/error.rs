use axum::http::StatusCode;
use axum_thiserror::ErrorStatus;
use thiserror::Error;

use crate::error::JWTError;

#[derive(Debug, Error, ErrorStatus)]
pub enum AuthError {
    #[error("Could not retrieve the JWK from the JWK set")]
    #[status(StatusCode::INTERNAL_SERVER_ERROR)]
    NoJwk,

    #[error("Could not fetch the JWK set. Reason: {0}")]
    #[status(StatusCode::INTERNAL_SERVER_ERROR)]
    JwkSetFetchError(#[from] reqwest::Error),

    #[error("The 'Authorization' header was not present on a request")]
    #[status(StatusCode::INTERNAL_SERVER_ERROR)]
    MissingAuthorizationHeader,

    #[error("The 'Authorization' header was present on a request but its value could not be parsed. Reason: {0}")]
    #[status(StatusCode::INTERNAL_SERVER_ERROR)]
    InvalidAuthorizationHeader(String),

    #[error("The 'Authorization' header did not contain the expected 'Bearer ...token' format")]
    #[status(StatusCode::INTERNAL_SERVER_ERROR)]
    MissingBearerToken,

    #[error("JWT could be extracted from the request")]
    #[status(StatusCode::INTERNAL_SERVER_ERROR)]
    MissingToken,

    #[error("The token could not be decoded. Reason: {0}")]
    #[status(StatusCode::INTERNAL_SERVER_ERROR)]
    JwtDecodeError(#[source] JWTError),

    #[error("The token could not be verified. Reason: {0}")]
    #[status(StatusCode::UNAUTHORIZED)]
    JwtVerificationError(#[source] JWTError),

    #[error("The token has expired")]
    #[status(StatusCode::UNAUTHORIZED)]
    JwtExpired,
}
