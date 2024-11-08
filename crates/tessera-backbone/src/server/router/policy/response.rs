use crate::{
    application::policy,
    server::response::{error_payload, error_payload_with_data, handle_internal_server_error},
};
use axum::{http::StatusCode, response::IntoResponse};
use serde::Serialize;
use ulid::Ulid;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct PolicyResponse {
    pub id: Ulid,
    pub name: String,
    pub expression: String,
}

struct PolicyNotExistsResponse {
    entered_policy_id: Ulid,
}

impl IntoResponse for PolicyNotExistsResponse {
    fn into_response(self) -> axum::response::Response {
        (
            StatusCode::NOT_FOUND,
            error_payload_with_data(
                "POLICY_NOT_EXISTS",
                "policy is not exists.",
                EnteredPolicyIdData { entered_policy_id: self.entered_policy_id },
            ),
        )
            .into_response()
    }
}

struct InvalidPolicyResponse {}

impl IntoResponse for InvalidPolicyResponse {
    fn into_response(self) -> axum::response::Response {
        (StatusCode::BAD_REQUEST, error_payload("INVALID_POLICY_EXPRESSION", "entered expression is invalid."))
            .into_response()
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct EnteredPolicyIdData {
    entered_policy_id: Ulid,
}

impl IntoResponse for policy::Error {
    fn into_response(self) -> axum::response::Response {
        match self {
            policy::Error::Anyhow(e) => handle_internal_server_error(&*e).into_response(),
            policy::Error::PolicyNotExists { entered_policy_id } => {
                PolicyNotExistsResponse { entered_policy_id }.into_response()
            }
            policy::Error::InvalidExpression(_) => InvalidPolicyResponse {}.into_response(),
        }
    }
}
