use std::sync::Arc;

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    routing::get,
    Extension, Json, Router,
};
use axum_thiserror::ErrorStatus;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use nebula_abe::{random::miracl::MiraclRng, schemes::isabella24::UserSecretKey};
use nebula_token::claim::NebulaClaim;
use rand::{rngs::OsRng, Rng as _};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::application::Application;

pub(crate) fn router(application: Arc<Application>) -> axum::Router {
    Router::new().route("/user-key", get(handle_get_user_key)).with_state(application)
}

async fn handle_get_user_key(
    Path(workspace_name): Path<String>,
    Query(query_params): Query<GetUserKeyQueryParam>,
    State(application): State<Arc<Application>>,
    Extension(claim): Extension<NebulaClaim>,
) -> Result<impl IntoResponse, GetUserKeyError> {
    let key_pair = if let Some(version) = query_params.version {
        application.authority.key_pair_by_version(&workspace_name, version).await
    } else {
        application.authority.key_pair(&workspace_name).await
    }
    .map_err(|_| GetUserKeyError::GetUserKey)?;

    let gp = application
        .authority
        .backbone_service
        .global_params(&workspace_name)
        .await
        .map_err(|_| GetUserKeyError::GetGlobalParams)?;

    let mut rng = MiraclRng::new();
    let mut seed = [0u8; 64];
    OsRng.fill(&mut seed);
    rng.seed(&seed);

    let user_key = UserSecretKey::new(
        &mut rng,
        &gp,
        &key_pair.mk,
        &claim.gid,
        &claim.attributes.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>(),
    );

    let user_key = rmp_serde::to_vec(&user_key).map_err(GetUserKeyError::Serialization)?;
    let user_key = STANDARD.encode(&user_key);

    Ok(Json(GetUserKeyResponse { user_key }))
}

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct GetUserKeyQueryParam {
    version: Option<u64>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetUserKeyResponse {
    user_key: String,
}

#[derive(Error, Debug, ErrorStatus)]
pub enum GetUserKeyError {
    #[error("Unable to get the user key")]
    #[status(StatusCode::INTERNAL_SERVER_ERROR)]
    GetUserKey,

    #[error("Unable to get the global params")]
    #[status(StatusCode::INTERNAL_SERVER_ERROR)]
    GetGlobalParams,

    #[error("Unable to serialize the user key")]
    #[status(StatusCode::INTERNAL_SERVER_ERROR)]
    Serialization(#[from] rmp_serde::encode::Error),
}
