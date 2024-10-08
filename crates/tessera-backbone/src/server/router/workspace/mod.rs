use std::sync::Arc;

use axum::{debug_handler, extract::State, http::StatusCode, response::IntoResponse, routing::post, Json, Router};

use crate::{
    application::{
        workspace::{self, command::CreatingWorkspaceCommand, WorkspaceUseCase},
        Application,
    },
    server::response::handle_internal_server_error,
};

use self::request::PostWorkspaceRequest;

mod request;
mod response;

pub(crate) fn router(application: Arc<Application>) -> axum::Router {
    Router::new().route("/", post(handle_post_workspace)).with_state(application)
}

#[debug_handler]
async fn handle_post_workspace(
    State(application): State<Arc<Application>>,
    Json(payload): Json<PostWorkspaceRequest>,
) -> Result<impl IntoResponse, workspace::Error> {
    application.workspace().create(payload.into()).await?;

    Ok(StatusCode::OK)
}

impl From<PostWorkspaceRequest> for CreatingWorkspaceCommand {
    fn from(value: PostWorkspaceRequest) -> Self {
        Self { name: value.name }
    }
}

impl IntoResponse for workspace::Error {
    fn into_response(self) -> axum::response::Response {
        match self {
            workspace::Error::Anyhow(e) => handle_internal_server_error(&*e).into_response(),
            workspace::Error::WorkspaceNameConflicted => response::WorkspaceNameConflictedErrorResponse.into_response(),
        }
    }
}
