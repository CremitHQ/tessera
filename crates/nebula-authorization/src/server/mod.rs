use std::sync::Arc;

use axum::{routing::get, Router};
use tracing::debug;

use crate::{application::Application, config::ApplicationConfig};

mod router;

pub(super) struct ServerConfig {
    pub port: u16,
    pub path_prefix: Option<String>,
}

impl From<ApplicationConfig> for ServerConfig {
    fn from(value: ApplicationConfig) -> Self {
        Self { port: value.port, path_prefix: value.path_prefix }
    }
}

pub(super) async fn run(application: Application, config: ServerConfig) -> anyhow::Result<()> {
    let application = Arc::new(application);
    let app = Router::new().route("/health", get(|| async { "" }));
    let path_prefix = if let Some(ref path_prefix) = config.path_prefix {
        let path_prefix = format!("/{}/", path_prefix.trim_matches('/'));
        path_prefix
    } else {
        "/".to_string()
    };
    let app = app.nest(&path_prefix, router::router(application.clone()));

    let listener = tokio::net::TcpListener::bind(("0.0.0.0", config.port)).await?;
    debug!("starting authz server on {}", config.port);
    axum::serve(listener, app).await?;
    Ok(())
}
