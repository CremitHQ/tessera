use std::sync::Arc;

use axum::{routing::get, Router};
use nebula_token::auth::layer::NebulaAuthLayer;
use tracing::debug;

mod router;

use crate::{application::Application, config::ApplicationConfig};

pub(super) struct ServerConfig {
    pub port: u16,
}

impl From<ApplicationConfig> for ServerConfig {
    fn from(value: ApplicationConfig) -> Self {
        Self { port: value.port }
    }
}

pub(super) async fn run(application: Application, config: ServerConfig) -> anyhow::Result<()> {
    let application = Arc::new(application);
    let protected_router = Router::new()
        .nest("/v1", router::init::router(application.clone()))
        .layer(NebulaAuthLayer::builder().jwk_discovery(application.jwks_discovery.clone()).build());

    let app = Router::new()
        .route("/health", get(|| async { "OK" }))
        .nest("/v1", router::pubkey::router(application.clone()))
        .merge(protected_router);

    let listener = tokio::net::TcpListener::bind(("0.0.0.0", config.port)).await?;
    debug!("starting authority server on {}", config.port);
    axum::serve(listener, app).await?;
    Ok(())
}
