use std::sync::Arc;

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::patch,
    Json, Router,
};
use axum_thiserror::ErrorStatus;

use nebula_abe::random::miracl::MiraclRng;

use rand::{rngs::OsRng, Rng as _};
use serde::Serialize;
use thiserror::Error;

use crate::application::Application;

pub(crate) fn router(application: Arc<Application>) -> axum::Router {
    Router::new().route("/key-pair", patch(handle_key_pair_rolling)).with_state(application)
}

async fn handle_key_pair_rolling(
    Path(workspace_name): Path<String>,
    State(application): State<Arc<Application>>,
) -> Result<impl IntoResponse, KeyPairRollingError> {
    let gp = application
        .authority
        .backbone_service
        .global_params(&workspace_name)
        .await
        .map_err(|_| KeyPairRollingError::GetGlobalParams)?;

    let mut rng = MiraclRng::new();
    let mut seed = [0u8; 64];
    OsRng.fill(&mut seed);
    rng.seed(&seed);

    let version = application
        .authority
        .key_pair_rolling(&gp, &workspace_name)
        .await
        .map_err(|_| KeyPairRollingError::FailedToRollKeyPair)?;

    Ok(Json(KeyPairRollingResponse { version }))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyPairRollingResponse {
    version: u64,
}

#[derive(Error, Debug, ErrorStatus)]
pub enum KeyPairRollingError {
    #[error("Unable to get the global params")]
    #[status(StatusCode::INTERNAL_SERVER_ERROR)]
    GetGlobalParams,

    #[error("Unable to roll the key pair")]
    #[status(StatusCode::INTERNAL_SERVER_ERROR)]
    FailedToRollKeyPair,
}
