use std::sync::Arc;

use axum::{
    debug_handler,
    extract::{Path, Query, State},
    response::IntoResponse,
    routing::get,
    Json, Router,
};
use serde::Deserialize;

use crate::application::{
    self,
    secret::{SecretData, SecretUseCase},
    Application,
};

use self::response::SecretResponse;

mod response;

pub(crate) fn router(application: Arc<Application>) -> axum::Router {
    Router::new()
        .route("/workspaces/:workspace_name/secrets", get(handle_get_secrets))
        .route("/workspaces/:workspace_name/secrets/:secret_identifier", get(handle_get_secret))
        .with_state(application)
}

#[derive(Deserialize)]
struct GetSecretsApiQueryParam {
    path: Option<String>,
}

#[debug_handler]
async fn handle_get_secrets(
    Path(workspace_name): Path<String>,
    Query(query_params): Query<GetSecretsApiQueryParam>,
    State(application): State<Arc<Application>>,
) -> Result<impl IntoResponse, application::secret::Error> {
    let secrets =
        application.with_workspace(&workspace_name).secret().list(query_params.path.as_deref().unwrap_or("/")).await?;
    let response: Vec<SecretResponse> = secrets.into_iter().map(SecretResponse::from).collect();

    Ok(Json(response))
}

#[debug_handler]
async fn handle_get_secret(
    Path((workspace_name, secret_identifier)): Path<(String, String)>,
    State(application): State<Arc<Application>>,
) -> Result<impl IntoResponse, application::secret::Error> {
    let secret = application.with_workspace(&workspace_name).secret().get(&secret_identifier).await?;

    Ok(Json(SecretResponse::from(secret)))
}

impl From<SecretData> for SecretResponse {
    fn from(value: SecretData) -> Self {
        Self {
            key: value.key,
            path: value.path,
            reader_policy_ids: value.reader_policy_ids,
            writer_policy_ids: value.writer_policy_ids,
        }
    }
}
