use std::sync::Arc;

use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::IntoResponse,
    routing::get,
    Json, Router,
};
use axum_thiserror::ErrorStatus;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::application::Application;

pub(crate) fn router(application: Arc<Application>) -> axum::Router {
    Router::new().route("/public-key", get(handle_get_public_key)).with_state(application)
}

async fn handle_get_public_key(
    Query(query_params): Query<GetPublicKeyQueryParam>,
    State(application): State<Arc<Application>>,
) -> Result<impl IntoResponse, GetPublicKeyError> {
    let key_pair = if let Some(version) = query_params.version {
        application.authority.key_pair_by_version(version).await
    } else {
        application.authority.key_pair().await
    }
    .map_err(|_| GetPublicKeyError::GetPublicKey)?;

    let public_key = rmp_serde::to_vec(&key_pair.pk).map_err(GetPublicKeyError::Serialization)?;
    let public_key = STANDARD.encode(&public_key);

    Ok(Json(GetPublicKeyResponse { public_key }))
}

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct GetPublicKeyQueryParam {
    version: Option<u64>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetPublicKeyResponse {
    public_key: String,
}

#[derive(Error, Debug, ErrorStatus)]
pub enum GetPublicKeyError {
    #[error("Unable to get the public key")]
    #[status(StatusCode::INTERNAL_SERVER_ERROR)]
    GetPublicKey,

    #[error("Unable to serialize the public key")]
    #[status(StatusCode::INTERNAL_SERVER_ERROR)]
    Serialization(#[from] rmp_serde::encode::Error),
}
