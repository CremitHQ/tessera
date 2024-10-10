use axum::{http::StatusCode, response::IntoResponse, Json};
use serde::Serialize;
use tracing::error;

pub(crate) fn handle_internal_server_error<E: std::error::Error>(e: E) -> impl IntoResponse {
    error!(error = %e, "unhandled error occurred.");
    StatusCode::INTERNAL_SERVER_ERROR
}

#[derive(Serialize, Debug)]
pub(crate) struct ErrorPayload<'a, D: Serialize> {
    code: &'a str,
    message: &'a str,
    data: D,
}

#[derive(Serialize, Debug)]
pub(crate) struct EmptyData {}

pub fn error_payload<'a>(code: &'a str, message: &'a str) -> Json<ErrorPayload<'a, EmptyData>> {
    Json(ErrorPayload { code, message, data: EmptyData {} })
}

pub fn error_payload_with_data<'a, D: Serialize>(
    code: &'a str,
    message: &'a str,
    data: D,
) -> Json<ErrorPayload<'a, D>> {
    Json(ErrorPayload { code, message, data })
}
