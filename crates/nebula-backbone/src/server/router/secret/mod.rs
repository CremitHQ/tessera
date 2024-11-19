use std::sync::Arc;

use axum::{
    debug_handler,
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    routing::get,
    Json, Router,
};
use base64::{prelude::BASE64_STANDARD, Engine};
use serde::Deserialize;

use crate::application::{
    self,
    secret::{SecretData, SecretRegisterCommand, SecretUpdate, SecretUseCase},
    Application,
};

use self::{
    request::{PatchSecretRequest, PostSecretRequest},
    response::{InvalidSecretCipherResponse, SecretResponse},
};

mod request;
mod response;

pub(crate) fn router(application: Arc<Application>) -> axum::Router {
    Router::new()
        .route("/workspaces/:workspace_name/secrets", get(handle_get_secrets).post(handle_post_secret))
        .route(
            "/workspaces/:workspace_name/secrets/*secret_identifier",
            get(handle_get_secret).delete(handle_delete_secret).patch(handle_patch_secret),
        )
        .with_state(application)
}

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case")]
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
async fn handle_post_secret(
    Path(workspace_name): Path<String>,
    State(application): State<Arc<Application>>,
    Json(payload): Json<PostSecretRequest>,
) -> Result<impl IntoResponse, application::secret::Error> {
    let cipher = if let Ok(cipher) = BASE64_STANDARD.decode(payload.cipher) {
        cipher
    } else {
        return Ok(InvalidSecretCipherResponse {}.into_response());
    };

    application
        .with_workspace(&workspace_name)
        .secret()
        .register(SecretRegisterCommand {
            path: payload.path,
            key: payload.key,
            cipher,
            access_condition_ids: payload.access_condition_ids,
        })
        .await?;

    Ok(StatusCode::CREATED.into_response())
}

#[debug_handler]
async fn handle_get_secret(
    Path((workspace_name, secret_identifier)): Path<(String, String)>,
    State(application): State<Arc<Application>>,
) -> Result<impl IntoResponse, application::secret::Error> {
    let secret = application.with_workspace(&workspace_name).secret().get(&format!("/{secret_identifier}")).await?;

    Ok(Json(SecretResponse::from(secret)))
}

#[debug_handler]
async fn handle_delete_secret(
    Path((workspace_name, secret_identifier)): Path<(String, String)>,
    State(application): State<Arc<Application>>,
) -> Result<impl IntoResponse, application::secret::Error> {
    application.with_workspace(&workspace_name).secret().delete(&format!("/{secret_identifier}")).await?;

    Ok(StatusCode::NO_CONTENT)
}

#[debug_handler]
async fn handle_patch_secret(
    Path((workspace_name, secret_identifier)): Path<(String, String)>,
    State(application): State<Arc<Application>>,
    Json(payload): Json<PatchSecretRequest>,
) -> Result<impl IntoResponse, application::secret::Error> {
    let cipher = match payload.cipher.map(|cipher| BASE64_STANDARD.decode(cipher)) {
        Some(Ok(cipher)) => Some(cipher),
        Some(Err(_)) => return Ok(InvalidSecretCipherResponse {}.into_response()),
        None => None,
    };

    application
        .with_workspace(&workspace_name)
        .secret()
        .update(
            &format!("/{secret_identifier}"),
            SecretUpdate { path: payload.path, cipher, access_condition_ids: payload.access_condition_ids },
        )
        .await?;

    Ok(StatusCode::NO_CONTENT.into_response())
}

impl From<SecretData> for SecretResponse {
    fn from(value: SecretData) -> Self {
        Self {
            key: value.key,
            path: value.path,
            cipher: BASE64_STANDARD.encode(value.cipher),
            access_condition_ids: value.access_condition_ids,
        }
    }
}
