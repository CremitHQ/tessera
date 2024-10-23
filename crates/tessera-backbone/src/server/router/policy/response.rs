use crate::{application::policy, server::response::handle_internal_server_error};
use axum::response::IntoResponse;
use serde::Serialize;
use ulid::Ulid;

#[derive(Serialize)]
pub(super) struct PolicyResponse {
    pub id: Ulid,
    pub name: String,
    pub expression: String,
}

impl IntoResponse for policy::Error {
    fn into_response(self) -> axum::response::Response {
        match self {
            policy::Error::Anyhow(e) => handle_internal_server_error(&*e).into_response(),
        }
    }
}
