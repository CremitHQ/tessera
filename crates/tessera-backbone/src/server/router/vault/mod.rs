use std::sync::Arc;

use axum::{debug_handler, extract::State, http::StatusCode, response::IntoResponse, routing::post, Json, Router};

use crate::application::{
    vault::{self, command::CreatingVaultCommand, VaultUseCase},
    Application,
};

use self::request::PostVaultRequest;

mod request;

pub(crate) fn router(application: Arc<Application>) -> axum::Router {
    Router::new().route("/", post(handle_post_vault)).with_state(application)
}

#[debug_handler]
async fn handle_post_vault(
    State(application): State<Arc<Application>>,
    Json(payload): Json<PostVaultRequest>,
) -> Result<impl IntoResponse, vault::Error> {
    application.vault().create(payload.into()).await?;

    Ok(StatusCode::OK)
}

impl From<PostVaultRequest> for CreatingVaultCommand {
    fn from(value: PostVaultRequest) -> Self {
        Self { name: value.name }
    }
}

impl IntoResponse for vault::Error {
    fn into_response(self) -> axum::response::Response {
        unreachable!()
    }
}
