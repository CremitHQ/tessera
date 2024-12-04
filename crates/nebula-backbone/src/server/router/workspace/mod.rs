use std::sync::Arc;

use axum::{
    debug_handler,
    extract::{Path, State},
    http::StatusCode,
    middleware,
    response::IntoResponse,
    routing::{delete, get},
    Json, Router,
};

use crate::{
    application::{
        workspace::{self, command::CreatingWorkspaceCommand, data::WorkspaceData, WorkspaceUseCase},
        Application,
    },
    server::{check_admin_role, check_workspace_name, response::handle_internal_server_error},
};

use self::{request::PostWorkspaceRequest, response::GetWorkspacesResponse};

mod request;
mod response;

pub(crate) fn public_router(application: Arc<Application>) -> axum::Router {
    Router::new().route("/workspaces", get(handle_get_workspaces).post(handle_post_workspace)).with_state(application)
}

pub(crate) fn router(application: Arc<Application>) -> axum::Router {
    let admin_routers = Router::new()
        .route("/:workspace_name", delete(handle_delete_workspace))
        .route_layer(middleware::from_fn(check_admin_role))
        .route_layer(middleware::from_fn(check_workspace_name));
    Router::new().merge(admin_routers).with_state(application)
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
            workspace::Error::WorkspaceNotExists => response::WorkspaceNotExistsErrorResponse.into_response(),
        }
    }
}

#[debug_handler]
async fn handle_get_workspaces(
    State(application): State<Arc<Application>>,
) -> Result<impl IntoResponse, workspace::Error> {
    let workspaces = application.workspace().get_all().await?;

    let payload: Vec<GetWorkspacesResponse> = workspaces.into_iter().map(|data| data.into()).collect();

    Ok((StatusCode::OK, Json(payload)))
}

impl From<WorkspaceData> for GetWorkspacesResponse {
    fn from(value: WorkspaceData) -> Self {
        Self { name: value.name }
    }
}

#[debug_handler]
async fn handle_delete_workspace(
    Path(workspace_name): Path<String>,
    State(application): State<Arc<Application>>,
) -> Result<impl IntoResponse, workspace::Error> {
    application.workspace().delete_by_name(&workspace_name).await?;

    Ok(StatusCode::NO_CONTENT)
}
