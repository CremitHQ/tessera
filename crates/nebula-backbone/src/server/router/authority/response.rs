use axum::{http::StatusCode, response::IntoResponse};
use serde::Serialize;
use ulid::Ulid;

use crate::server::response::error_payload_with_data;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthorityResponse {
    pub id: Ulid,
    pub name: String,
    pub host: String,
    pub public_key: Option<String>,
}

pub struct AuthorityNameAlreadyInUseErrorResponse {
    pub entered_authority_name: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct EnteredAuthorityNameData {
    entered_authority_name: String,
}

impl IntoResponse for AuthorityNameAlreadyInUseErrorResponse {
    fn into_response(self) -> axum::response::Response {
        (
            StatusCode::CONFLICT,
            error_payload_with_data(
                "AUTHORITY_NAME_IS_IN_USE",
                "entered authority name is already in use",
                EnteredAuthorityNameData { entered_authority_name: self.entered_authority_name },
            ),
        )
            .into_response()
    }
}

pub struct AuthorityNotFoundResponse {
    pub entered_authority_id: Ulid,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct EnteredAuthorityIdData {
    entered_authority_id: Ulid,
}

impl IntoResponse for AuthorityNotFoundResponse {
    fn into_response(self) -> axum::response::Response {
        (
            StatusCode::NOT_FOUND,
            error_payload_with_data(
                "AUTHORITY_NOT_EXISTS",
                "authority is not exists",
                EnteredAuthorityIdData { entered_authority_id: self.entered_authority_id },
            ),
        )
            .into_response()
    }
}
