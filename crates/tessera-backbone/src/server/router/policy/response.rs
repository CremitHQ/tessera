use crate::application::policy;
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
        match self {}
    }
}
