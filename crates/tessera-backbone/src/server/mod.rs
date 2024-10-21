use std::sync::Arc;

use axum::{routing::get, Router};
use tracing::debug;

use crate::{application::Application, config::ApplicationConfig};

mod response;
mod router;

pub(super) struct ServerConfig {
    pub port: u16,
}

impl From<&ApplicationConfig> for ServerConfig {
    fn from(value: &ApplicationConfig) -> Self {
        Self { port: value.port }
    }
}

pub(super) async fn run(application: Application, config: ServerConfig) -> anyhow::Result<()> {
    let application = Arc::new(application);
    let app = Router::new()
        .route("/health", get(|| async { "" }))
        .nest("/workspaces", router::workspace::router(application.clone()))
        .nest("/", router::secret::router(application.clone()));
    let listener = tokio::net::TcpListener::bind(("0.0.0.0", config.port)).await?;
    debug!("starting backbone server on {}", config.port);
    axum::serve(listener, app).await?;
    Ok(())
}
