use axum::Router;
use tracing::debug;

use crate::config::ApplicationConfig;

pub(super) struct ServerConfig {
    pub port: u16,
}

impl From<&ApplicationConfig> for ServerConfig {
    fn from(value: &ApplicationConfig) -> Self {
        Self { port: value.port }
    }
}

pub(super) async fn run(config: ServerConfig) -> anyhow::Result<()> {
    let app = Router::new();
    let listener = tokio::net::TcpListener::bind(("0.0.0.0", config.port)).await?;
    debug!("starting authority server on {}", config.port);
    axum::serve(listener, app).await?;
    Ok(())
}
