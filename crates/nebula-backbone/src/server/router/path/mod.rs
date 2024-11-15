use std::sync::Arc;

use axum::{
    debug_handler,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::get,
    Json, Router,
};

use crate::{
    application::{self, path::PathUseCase, Application},
    server::router::path::request::PatchPathRequest,
};

use self::request::PostPathRequest;

mod model;
mod request;
mod response;

pub(crate) fn router(application: Arc<Application>) -> axum::Router {
    Router::new()
        .route("/workspaces/:workspace_name/paths", get(handle_get_paths).post(handle_post_path))
        .route(
            "/workspaces/:workspace_name/paths/*path",
            get(handle_get_path).delete(handle_delete_path).patch(handle_patch_path),
        )
        .with_state(application)
}

#[debug_handler]
async fn handle_post_path(
    Path(workspace_name): Path<String>,
    State(application): State<Arc<Application>>,
    Json(payload): Json<PostPathRequest>,
) -> Result<impl IntoResponse, application::path::Error> {
    application.with_workspace(&workspace_name).path().register(&payload.path).await?;

    Ok(StatusCode::NO_CONTENT)
}

#[debug_handler]
async fn handle_get_paths(
    Path(workspace_name): Path<String>,
    State(application): State<Arc<Application>>,
) -> Result<impl IntoResponse, application::path::Error> {
    let paths = application.with_workspace(&workspace_name).path().get_all().await?;

    Ok(Json(paths.into_iter().map(response::PathResponse::from).collect::<Vec<_>>()))
}

#[debug_handler]
async fn handle_delete_path(
    Path((workspace_name, path)): Path<(String, String)>,
    State(application): State<Arc<Application>>,
) -> Result<impl IntoResponse, application::path::Error> {
    application.with_workspace(&workspace_name).path().delete(&normalize_path(path)).await?;

    Ok(StatusCode::NO_CONTENT)
}

#[debug_handler]
async fn handle_patch_path(
    Path((workspace_name, path)): Path<(String, String)>,
    State(application): State<Arc<Application>>,
    Json(payload): Json<PatchPathRequest>,
) -> Result<impl IntoResponse, application::path::Error> {
    application.with_workspace(&workspace_name).path().update(&normalize_path(path), &payload.path).await?;

    Ok(StatusCode::NO_CONTENT)
}
#[debug_handler]
async fn handle_get_path(
    Path((workspace_name, path)): Path<(String, String)>,
    State(application): State<Arc<Application>>,
) -> Result<impl IntoResponse, application::path::Error> {
    let path = application.with_workspace(&workspace_name).path().get(&normalize_path(path)).await?;

    Ok(Json(response::PathResponse::from(path)))
}

fn normalize_path(path: String) -> String {
    if path.starts_with("/") {
        path
    } else {
        format!("/{path}")
    }
}

impl From<application::path::PathData> for response::PathResponse {
    fn from(value: application::path::PathData) -> Self {
        Self { path: value.path }
    }
}
