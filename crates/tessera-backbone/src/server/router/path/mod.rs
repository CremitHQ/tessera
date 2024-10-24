use std::sync::Arc;

use axum::{
    debug_handler,
    extract::{Path, State},
    response::IntoResponse,
    routing::get,
    Json, Router,
};

use crate::application::{self, path::PathUseCase, Application};

mod response;

pub(crate) fn router(application: Arc<Application>) -> axum::Router {
    Router::new().route("/workspaces/:workspace_name/paths", get(handle_get_paths)).with_state(application)
}

#[debug_handler]
async fn handle_get_paths(
    Path(workspace_name): Path<String>,
    State(application): State<Arc<Application>>,
) -> Result<impl IntoResponse, application::path::Error> {
    let paths = application.with_workspace(&workspace_name).path().get_all().await?;

    Ok(Json(paths.into_iter().map(response::PathResponse::from).collect::<Vec<_>>()))
}

impl From<application::path::PathData> for response::PathResponse {
    fn from(value: application::path::PathData) -> Self {
        Self { path: value.path }
    }
}
