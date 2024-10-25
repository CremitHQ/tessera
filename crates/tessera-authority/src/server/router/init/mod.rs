use std::sync::Arc;

use axum::{extract::State, http::StatusCode, response::IntoResponse, routing::post, Json, Router};
use axum_thiserror::ErrorStatus;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::Deserialize;
use thiserror::Error;

use crate::application::Application;

pub(crate) fn router(application: Arc<Application>) -> axum::Router {
    Router::new().route("/init", post(handle_initializing_authority)).with_state(application)
}

async fn handle_initializing_authority(
    State(application): State<Arc<Application>>,
    Json(InitRequest { secret_shares: share, secret_threshold: threshold }): Json<InitRequest>,
) -> Result<impl IntoResponse, InitAuthorityError> {
    let shares = application
        .authority
        .init_key_pair_storage(share as usize, threshold as usize)
        .await
        .inspect_err(|e| eprintln!("Error initializing authority key pair: {}", e))
        .map_err(|_| InitAuthorityError::InitializationError)?;
    let shares = shares
        .iter()
        .map(|share| bincode::serialize(&share))
        .collect::<Result<Vec<_>, _>>()
        .map_err(InitAuthorityError::SerializationError)?;
    let shares = shares.iter().map(|share| STANDARD.encode(share)).collect::<Vec<_>>();
    Ok(Json(shares))
}

#[derive(Deserialize)]
pub struct InitRequest {
    secret_shares: u8,
    secret_threshold: u8,
}

#[derive(Error, Debug, ErrorStatus)]
pub enum InitAuthorityError {
    #[error("Unable to initialize the authority key pair")]
    #[status(StatusCode::INTERNAL_SERVER_ERROR)]
    InitializationError,

    #[error("Unable to serialize the shares")]
    #[status(StatusCode::INTERNAL_SERVER_ERROR)]
    SerializationError(#[from] bincode::Error),
}
