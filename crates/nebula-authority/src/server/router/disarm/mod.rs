use std::sync::Arc;

use axum::{extract::State, http::StatusCode, response::IntoResponse, routing::post, Json, Router};
use axum_thiserror::ErrorStatus;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use nebula_secret_sharing::shamir::Share;
use serde::Deserialize;
use thiserror::Error;
use zeroize::Zeroizing;

use crate::application::Application;

pub(crate) fn router(application: Arc<Application>) -> axum::Router {
    Router::new().route("/disarm", post(handle_disarm_authority)).with_state(application)
}

async fn handle_disarm_authority(
    State(application): State<Arc<Application>>,
    Json(DisarmRequest { shares }): Json<DisarmRequest>,
) -> Result<impl IntoResponse, DisarmError> {
    let shares: Vec<Share> = shares
        .iter()
        .map(|share| {
            let share = Zeroizing::new(STANDARD.decode(share).map_err(DisarmError::Decode)?);
            let share = rmp_serde::from_slice(&share).map_err(DisarmError::Deserialize)?;
            Ok(share)
        })
        .collect::<Result<_, DisarmError>>()?;

    application.authority.disarm_key_pair_storage(&shares).await.map_err(|_| DisarmError::FailedToDisarm)?;

    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DisarmRequest {
    shares: Zeroizing<Vec<String>>,
}

#[derive(Error, Debug, ErrorStatus)]
pub enum DisarmError {
    #[error("Unable to decode the shares")]
    #[status(StatusCode::INTERNAL_SERVER_ERROR)]
    Decode(#[from] base64::DecodeError),

    #[error("Unable to deserialize the shares")]
    #[status(StatusCode::INTERNAL_SERVER_ERROR)]
    Deserialize(#[from] rmp_serde::decode::Error),

    #[error("Unable to disarm the authority key pair")]
    #[status(StatusCode::INTERNAL_SERVER_ERROR)]
    FailedToDisarm,
}
