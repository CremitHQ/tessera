use std::sync::Arc;

use axum::{
    debug_handler,
    extract::{Path, State},
    response::IntoResponse,
    routing::get,
    Json, Router,
};

use crate::application::{self, policy::PolicyUseCase, Application};

mod response;

pub(crate) fn router(application: Arc<Application>) -> axum::Router {
    Router::new().route("/workspaces/:workspace_name/policies", get(handle_get_policies)).with_state(application)
}

#[debug_handler]
async fn handle_get_policies(
    Path(workspace_name): Path<String>,
    State(application): State<Arc<Application>>,
) -> Result<impl IntoResponse, application::policy::Error> {
    let policies = application.with_workspace(&workspace_name).policy().get_all().await?;

    Ok(Json(policies.into_iter().map(response::PolicyResponse::from).collect::<Vec<_>>()))
}

impl From<application::policy::PolicyData> for response::PolicyResponse {
    fn from(value: application::policy::PolicyData) -> Self {
        Self { id: value.id, name: value.name, expression: value.expression }
    }
}
