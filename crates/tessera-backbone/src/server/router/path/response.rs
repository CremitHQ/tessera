use crate::{
    application::path,
    server::response::{error_payload, handle_internal_server_error},
};
use axum::{http::StatusCode, response::IntoResponse};
use serde::Serialize;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PathResponse {
    pub path: String,
}

pub struct InvalidPathErrorResponse {
    pub entered_path: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EnteredPathData {
    pub entered_path: String,
}

impl IntoResponse for InvalidPathErrorResponse {
    fn into_response(self) -> axum::response::Response {
        (StatusCode::BAD_REQUEST, error_payload("INVALID_PATH", "entered path is invalid.")).into_response()
    }
}

impl IntoResponse for path::Error {
    fn into_response(self) -> axum::response::Response {
        match self {
            path::Error::Anyhow(e) => handle_internal_server_error(&*e).into_response(),
            path::Error::InvalidPath { entered_path } => InvalidPathErrorResponse { entered_path }.into_response(),
        }
    }
}
