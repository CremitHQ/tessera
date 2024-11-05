use crate::{
    application::path,
    server::response::{error_payload, error_payload_with_data, handle_internal_server_error},
};
use axum::{http::StatusCode, response::IntoResponse};
use serde::Serialize;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PathResponse {
    pub path: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct EnteredPathData {
    pub entered_path: String,
}

struct InvalidPathErrorResponse {}

impl IntoResponse for InvalidPathErrorResponse {
    fn into_response(self) -> axum::response::Response {
        (StatusCode::BAD_REQUEST, error_payload("INVALID_PATH", "entered path is invalid.")).into_response()
    }
}

struct ParentPathNotExistsErrorResponse {}

impl IntoResponse for ParentPathNotExistsErrorResponse {
    fn into_response(self) -> axum::response::Response {
        (
            StatusCode::UNPROCESSABLE_ENTITY,
            error_payload("PARENT_PATH_NOT_EXIST", "there is no parent path for entered path"),
        )
            .into_response()
    }
}

struct PathDuplicatedErrorResponse {
    pub entered_path: String,
}

impl IntoResponse for PathDuplicatedErrorResponse {
    fn into_response(self) -> axum::response::Response {
        (
            StatusCode::CONFLICT,
            error_payload_with_data(
                "PATH_DUPLICATED",
                "entered path is already registered.",
                EnteredPathData { entered_path: self.entered_path },
            ),
        )
            .into_response()
    }
}

impl IntoResponse for path::Error {
    fn into_response(self) -> axum::response::Response {
        match self {
            path::Error::Anyhow(e) => handle_internal_server_error(&*e).into_response(),
            path::Error::InvalidPath { .. } => InvalidPathErrorResponse {}.into_response(),
            path::Error::ParentPathNotExists { .. } => ParentPathNotExistsErrorResponse {}.into_response(),
            path::Error::PathDuplicated { entered_path } => {
                PathDuplicatedErrorResponse { entered_path }.into_response()
            }
        }
    }
}
