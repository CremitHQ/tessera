use axum::Router;
use tracing::debug;

pub(super) struct ServerConfig {
    pub port: u16,
}

pub(super) async fn run(config: ServerConfig) -> anyhow::Result<()> {
    let app = Router::new();
    let listener = tokio::net::TcpListener::bind(("0.0.0.0", config.port)).await?;
    debug!("starting backbone server on {}", config.port);
    axum::serve(listener, app).await?;
    Ok(())
}
