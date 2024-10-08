use axum::{http::StatusCode, response::IntoResponse, Json};
use serde::Serialize;
use tracing::error;

pub(crate) fn handle_internal_server_error<E: std::error::Error>(e: E) -> impl IntoResponse {
    error!(error = %e, "unhandled error occurred.");
    StatusCode::INTERNAL_SERVER_ERROR
}

#[derive(Serialize, Debug)]
pub(crate) struct ErrorPayload<D: Serialize> {
    code: &'static str,
    message: &'static str,
    data: D,
}

#[derive(Serialize, Debug)]
pub(crate) struct EmptyData {}

pub fn error_payload(code: &'static str, message: &'static str) -> Json<ErrorPayload<EmptyData>> {
    Json(ErrorPayload { code, message, data: EmptyData {} })
}

pub fn error_payload_with_data<D: Serialize>(
    code: &'static str,
    message: &'static str,
    data: D,
) -> Json<ErrorPayload<D>> {
    Json(ErrorPayload { code, message, data })
}
