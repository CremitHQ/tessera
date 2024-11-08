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

use crate::application::{self, policy::PolicyUseCase, Application};

use self::response::PolicyResponse;

mod request;
mod response;

pub(crate) fn router(application: Arc<Application>) -> axum::Router {
    Router::new()
        .route("/workspaces/:workspace_name/policies", get(handle_get_policies).post(handle_post_policy))
        .route("/workspaces/:workspace_name/policies/:policy_id", get(handle_get_policy).patch(handle_patch_policy))
        .with_state(application)
}

#[debug_handler]
async fn handle_get_policies(
    Path(workspace_name): Path<String>,
    State(application): State<Arc<Application>>,
) -> Result<impl IntoResponse, application::policy::Error> {
    let policies = application.with_workspace(&workspace_name).policy().get_all().await?;

    Ok(Json(policies.into_iter().map(response::PolicyResponse::from).collect::<Vec<_>>()))
}
#[debug_handler]

async fn handle_post_policy(
    Path(workspace_name): Path<String>,
    State(application): State<Arc<Application>>,
    Json(payload): Json<request::PostPolicyRequest>,
) -> Result<impl IntoResponse, application::policy::Error> {
    application.with_workspace(&workspace_name).policy().register(&payload.name, &payload.expression).await?;

    Ok(StatusCode::CREATED)
}

#[debug_handler]
async fn handle_get_policy(
    Path((workspace_name, policy_id)): Path<(String, Ulid)>,
    State(application): State<Arc<Application>>,
) -> Result<impl IntoResponse, application::policy::Error> {
    let policy = application.with_workspace(&workspace_name).policy().get_policy(policy_id).await?;

    Ok(Json(PolicyResponse::from(policy)))
}

#[debug_handler]
async fn handle_patch_policy(
    Path((workspace_name, policy_id)): Path<(String, Ulid)>,
    State(application): State<Arc<Application>>,
    Json(payload): Json<request::PatchPolicyRequest>,
) -> Result<impl IntoResponse, application::policy::Error> {
    application
        .with_workspace(&workspace_name)
        .policy()
        .update(&policy_id, payload.name.as_deref(), payload.expression.as_deref())
        .await?;

    Ok(StatusCode::NO_CONTENT)
}

impl From<application::policy::PolicyData> for response::PolicyResponse {
    fn from(value: application::policy::PolicyData) -> Self {
        Self { id: value.id, name: value.name, expression: value.expression }
    }
}
