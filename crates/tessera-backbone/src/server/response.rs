use axum::{http::StatusCode, response::IntoResponse};
use tracing::error;

pub(crate) fn handle_internal_server_error<E: std::error::Error>(e: E) -> impl IntoResponse {
    error!(error = %e, "unhandled error occurred.");
    StatusCode::INTERNAL_SERVER_ERROR
}
