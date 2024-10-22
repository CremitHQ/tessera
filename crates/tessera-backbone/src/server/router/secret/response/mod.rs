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
