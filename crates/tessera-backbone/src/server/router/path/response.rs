use crate::application::path;
use axum::response::IntoResponse;
use serde::Serialize;

#[derive(Serialize)]
pub struct PathResponse {
    pub path: String,
}

impl IntoResponse for path::Error {
    fn into_response(self) -> axum::response::Response {
        match self {}
    }
}
