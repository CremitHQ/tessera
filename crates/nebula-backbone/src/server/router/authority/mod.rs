use std::sync::Arc;

use axum::{
    debug_handler,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::get,
    Json, Router,
};
use ulid::Ulid;

use crate::{
    application::{
        self,
        authority::{AuthorityData, AuthorityUseCase},
        Application,
    },
    server::response::handle_internal_server_error,
};

use self::{request::PostAuthorityRequest, response::AuthorityResponse};

mod request;
mod response;

pub(crate) fn router(application: Arc<Application>) -> axum::Router {
    Router::new()
        .route("/workspaces/:workspace_name/authorities", get(handle_get_authorities).post(handle_post_authority))
        .route("/workspaces/:workspace_name/authorities/:authority_id", get(handle_get_authority))
        .with_state(application)
}

impl IntoResponse for application::authority::Error {
    fn into_response(self) -> axum::response::Response {
        match self {
            application::authority::Error::Anyhow(e) => handle_internal_server_error(&*e).into_response(),
            application::authority::Error::NameAlreadyInUse { entered_authority_name } => {
                response::AuthorityNameAlreadyInUseErrorResponse { entered_authority_name }.into_response()
            }
            application::authority::Error::AuthorityNotExists { entered_authority_id } => {
                response::AuthorityNotFoundResponse { entered_authority_id }.into_response()
            }
        }
    }
}

impl From<AuthorityData> for response::AuthorityResponse {
    fn from(value: AuthorityData) -> Self {
        Self { id: value.id, name: value.name, host: value.host, public_key: value.public_key }
    }
}

#[debug_handler]
async fn handle_post_authority(
    Path(workspace_name): Path<String>,
    State(application): State<Arc<Application>>,
    Json(payload): Json<PostAuthorityRequest>,
) -> application::authority::Result<impl IntoResponse> {
    application.with_workspace(&workspace_name).authority().register_authority(&payload.name, &payload.host).await?;
    Ok(StatusCode::CREATED)
}

#[debug_handler]
async fn handle_get_authorities(
    Path(workspace_name): Path<String>,
    State(application): State<Arc<Application>>,
) -> application::authority::Result<impl IntoResponse> {
    let authorities = application.with_workspace(&workspace_name).authority().get_authorities().await?;

    let payload: Vec<_> = authorities.into_iter().map(response::AuthorityResponse::from).collect();

    Ok(Json(payload))
}

#[debug_handler]
async fn handle_get_authority(
    Path((workspace_name, authority_id)): Path<(String, Ulid)>,
    State(application): State<Arc<Application>>,
) -> application::authority::Result<impl IntoResponse> {
    let authority = application.with_workspace(&workspace_name).authority().get_authority(&authority_id).await?;

    let payload = AuthorityResponse::from(authority);

    Ok(Json(payload))
}
