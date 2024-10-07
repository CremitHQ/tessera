use std::sync::Arc;

use axum::{debug_handler, extract::State, response::IntoResponse, routing::post, Router};

use crate::application::Application;

pub(crate) fn router(application: Arc<Application>) -> axum::Router {
    Router::new().route("/", post(handle_post_vault)).with_state(application)
}

#[debug_handler]
async fn handle_post_vault(State(_applicaiton): State<Arc<Application>>) -> impl IntoResponse {
    todo!()
}
