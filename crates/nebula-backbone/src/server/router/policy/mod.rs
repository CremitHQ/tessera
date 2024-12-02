use std::sync::Arc;

use axum::{
    debug_handler,
    extract::{Path, State},
    http::StatusCode,
    middleware,
    response::IntoResponse,
    routing::{get, patch, post},
    Json, Router,
};
use ulid::Ulid;

use crate::{
    application::{self, policy::PolicyUseCase, Application},
    server::{check_admin_role, check_member_role, check_workspace_name},
};

use self::response::PolicyResponse;

mod request;
mod response;

pub(crate) fn router(application: Arc<Application>) -> axum::Router {
    let member_router = Router::new()
        .route("/workspaces/:workspace_name/policies", get(handle_get_policies))
        .route("/workspaces/:workspace_name/policies/:policy_id", get(handle_get_policy))
        .route_layer(middleware::from_fn(check_member_role))
        .route_layer(middleware::from_fn(check_workspace_name));
    let admin_router = Router::new()
        .route("/workspaces/:workspace_name/policies", post(handle_post_policy))
        .route(
            "/workspaces/:workspace_name/policies/:policy_id",
            patch(handle_patch_policy).delete(handle_delete_policy),
        )
        .route_layer(middleware::from_fn(check_admin_role))
        .route_layer(middleware::from_fn(check_workspace_name));

    Router::new().merge(member_router).merge(admin_router).with_state(application)
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

#[debug_handler]
async fn handle_delete_policy(
    Path((workspace_name, policy_id)): Path<(String, Ulid)>,
    State(application): State<Arc<Application>>,
) -> Result<impl IntoResponse, application::policy::Error> {
    application.with_workspace(&workspace_name).policy().delete(&policy_id).await?;

    Ok(StatusCode::NO_CONTENT)
}

impl From<application::policy::PolicyData> for response::PolicyResponse {
    fn from(value: application::policy::PolicyData) -> Self {
        Self { id: value.id, name: value.name, expression: value.expression }
    }
}
