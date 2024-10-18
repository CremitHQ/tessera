use crate::{application, server::response::handle_internal_server_error};
use axum::response::IntoResponse;
use serde::Serialize;
use ulid::Ulid;

impl IntoResponse for application::secret::Error {
    fn into_response(self) -> axum::response::Response {
        match self {
            application::secret::Error::Anyhow(e) => handle_internal_server_error(&*e).into_response(),
        }
    }
}

#[derive(Serialize)]
pub(super) struct SecretResponse {
    pub key: String,
    pub path: String,
    pub reader_policy_ids: Vec<Ulid>,
    pub writer_policy_ids: Vec<Ulid>,
}
