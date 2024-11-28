use std::sync::Arc;

use axum::{
    debug_handler,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::post,
    Json, Router,
};

use crate::{
    application::{self, authority::AuthorityUseCase, Application},
    server::response::handle_internal_server_error,
};

use self::request::PostAuthorityRequest;

mod request;
mod response;

pub(crate) fn router(application: Arc<Application>) -> axum::Router {
    Router::new().route("/workspaces/:workspace_name/authorities", post(handle_post_authority)).with_state(application)
}

#[debug_handler]
async fn handle_post_authority(
    Path(workspace_name): Path<String>,
    State(application): State<Arc<Application>>,
    Json(payload): Json<PostAuthorityRequest>,
) -> application::authority::Result<impl IntoResponse> {
    application.with_workspace(&workspace_name).authority().register_authority(&payload.name, &payload.host).await?;
    Ok(StatusCode::OK)
}

impl IntoResponse for application::authority::Error {
    fn into_response(self) -> axum::response::Response {
        match self {
            application::authority::Error::Anyhow(e) => handle_internal_server_error(&*e).into_response(),
            application::authority::Error::NameAlreadyInUse { entered_authority_name } => {
                response::AuthorityNameAlreadyInUseErrorResponse { entered_authority_name }.into_response()
            }
        }
    }
}
