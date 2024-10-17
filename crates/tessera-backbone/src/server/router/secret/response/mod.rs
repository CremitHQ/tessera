use crate::application;
use axum::response::IntoResponse;
use serde::Serialize;
use ulid::Ulid;

impl IntoResponse for application::secret::Error {
    fn into_response(self) -> axum::response::Response {
        match self {}
    }
}

#[derive(Serialize)]
pub(super) struct SecretResponse {
    pub key: String,
    pub path: String,
    pub reader_policy_ids: Vec<Ulid>,
    pub writer_policy_ids: Vec<Ulid>,
}
