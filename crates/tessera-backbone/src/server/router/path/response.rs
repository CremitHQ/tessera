use crate::{application::path, server::response::handle_internal_server_error};
use axum::response::IntoResponse;
use serde::Serialize;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PathResponse {
    pub path: String,
}

impl IntoResponse for path::Error {
    fn into_response(self) -> axum::response::Response {
        match self {
            path::Error::Anyhow(e) => handle_internal_server_error(&*e).into_response(),
        }
    }
}
