use crate::{
    application,
    server::response::{error_payload, error_payload_with_data, handle_internal_server_error},
};
use axum::{http::StatusCode, response::IntoResponse};
use serde::Serialize;
use ulid::Ulid;

impl IntoResponse for application::secret::Error {
    fn into_response(self) -> axum::response::Response {
        match self {
            application::secret::Error::Anyhow(e) => handle_internal_server_error(&*e).into_response(),
            application::secret::Error::InvalidSecretIdentifier { entered_identifier } => {
                InvalidSecretIdentifierErrorResponse { entered_identifier }.into_response()
            }
            application::secret::Error::SecretNotExists => SecretNotExistsErrorRespone {}.into_response(),
            application::secret::Error::PolicyNotExists { entered_policy_id } => {
                PolicyNotExistsErrorResponse { entered_policy_id }.into_response()
            }
            application::secret::Error::PathNotExists { entered_path } => {
                PathNotExistsErrorResponse { entered_path }.into_response()
            }
        }
    }
}

struct SecretNotExistsErrorRespone {}

impl IntoResponse for SecretNotExistsErrorRespone {
    fn into_response(self) -> axum::response::Response {
        (StatusCode::BAD_REQUEST, error_payload("SECRET_NOT_EXISTS", "secret is not exists")).into_response()
    }
}

struct InvalidSecretIdentifierErrorResponse {
    entered_identifier: String,
}

impl IntoResponse for InvalidSecretIdentifierErrorResponse {
    fn into_response(self) -> axum::response::Response {
        (
            StatusCode::BAD_REQUEST,
            error_payload_with_data(
                "INVALID_SECRET_IDENTIFIER",
                "entered secret identifier is invalid",
                EnteredIdentifierErrorData { entered_identifier: self.entered_identifier },
            ),
        )
            .into_response()
    }
}

#[derive(Serialize, Debug)]
struct EnteredIdentifierErrorData {
    entered_identifier: String,
}

#[derive(Serialize)]
pub(super) struct SecretResponse {
    pub key: String,
    pub path: String,
    pub reader_policy_ids: Vec<Ulid>,
    pub writer_policy_ids: Vec<Ulid>,
}

struct PolicyNotExistsErrorResponse {
    entered_policy_id: Ulid,
}

impl IntoResponse for PolicyNotExistsErrorResponse {
    fn into_response(self) -> axum::response::Response {
        (
            StatusCode::UNPROCESSABLE_ENTITY,
            error_payload_with_data(
                "ENTERED_POLICY_NOT_EXISTS",
                "entered policy is not exists",
                EnteredPolicyIdErrorData { entered_policy_id: self.entered_policy_id },
            ),
        )
            .into_response()
    }
}

#[derive(Serialize, Debug)]
struct EnteredPolicyIdErrorData {
    entered_policy_id: Ulid,
}

struct PathNotExistsErrorResponse {
    entered_path: String,
}

impl IntoResponse for PathNotExistsErrorResponse {
    fn into_response(self) -> axum::response::Response {
        (
            StatusCode::UNPROCESSABLE_ENTITY,
            error_payload_with_data(
                "ENTERED_PATH_NOT_EXISTS",
                "entered path is not exists",
                EnteredPathErrorData { entered_path: self.entered_path },
            ),
        )
            .into_response()
    }
}

#[derive(Serialize, Debug)]
struct EnteredPathErrorData {
    entered_path: String,
}
