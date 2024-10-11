use axum::{http::StatusCode, response::IntoResponse};
use serde::Serialize;

use crate::server::response::error_payload;

pub(super) struct WorkspaceNameConflictedErrorResponse;

impl IntoResponse for WorkspaceNameConflictedErrorResponse {
    fn into_response(self) -> axum::response::Response {
        (StatusCode::CONFLICT, error_payload("WORKSPACE_NAME_CONFLICTED", "workspace is already exists."))
            .into_response()
    }
}

#[derive(Serialize)]
pub(super) struct GetWorkspacesResponse {
    pub name: String,
}
