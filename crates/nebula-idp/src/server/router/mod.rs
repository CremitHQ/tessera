use std::sync::Arc;

use axum::{extract::State, http::StatusCode, response::IntoResponse, routing::post, Json, Router};
use axum_thiserror::ErrorStatus;
use serde::Deserialize;
use thiserror::Error;

use crate::application::Application;

pub(crate) fn router(application: Arc<Application>) -> axum::Router {
    Router::new().route("/login", post(handle_provider_login)).with_state(application)
}

async fn handle_provider_login(
    State(application): State<Arc<Application>>,
    Json(payload): Json<ProviderLoginRequest>,
) -> Result<impl IntoResponse, ProviderLoginError> {
    Ok(Json(()))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderLoginRequest {}

#[derive(Error, Debug, ErrorStatus)]
pub enum ProviderLoginError {}
