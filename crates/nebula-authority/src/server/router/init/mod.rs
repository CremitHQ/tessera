use std::sync::Arc;

use axum::{extract::State, http::StatusCode, response::IntoResponse, routing::post, Json, Router};
use axum_thiserror::ErrorStatus;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::Deserialize;
use thiserror::Error;
use zeroize::Zeroizing;

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
        .map_err(|_| InitAuthorityError::KeyPairInitialization)?;

    let shares = Zeroizing::new(
        shares
            .iter()
            .map(|share| {
                let share = Zeroizing::new(rmp_serde::to_vec(&share)?);
                Ok(Zeroizing::new(STANDARD.encode(&share)))
            })
            .collect::<Result<Vec<_>, _>>()
            .map_err(InitAuthorityError::Serialization)?,
    );
    Ok(Json(shares))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InitRequest {
    secret_shares: u8,
    secret_threshold: u8,
}

#[derive(Error, Debug, ErrorStatus)]
pub enum InitAuthorityError {
    #[error("Unable to initialize the authority key pair")]
    #[status(StatusCode::INTERNAL_SERVER_ERROR)]
    KeyPairInitialization,

    #[error("Unable to serialize the shares")]
    #[status(StatusCode::INTERNAL_SERVER_ERROR)]
    Serialization(#[from] rmp_serde::encode::Error),
}
