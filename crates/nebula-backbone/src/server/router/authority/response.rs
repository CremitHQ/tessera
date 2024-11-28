use axum::{http::StatusCode, response::IntoResponse};
use serde::Serialize;

use crate::server::response::error_payload_with_data;

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
