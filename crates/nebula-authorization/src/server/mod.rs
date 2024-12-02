use std::sync::Arc;

use axum::http::header::{AUTHORIZATION, CONTENT_TYPE, LINK};
use axum::{routing::get, Router};
use tower_http::cors::AllowOrigin;
use tower_http::cors::Any;
use tower_http::cors::CorsLayer;
use tracing::debug;

use crate::config::CorsConfig;
use crate::{application::Application, config::ApplicationConfig};

mod router;

pub(super) struct ServerConfig {
    pub port: u16,
    pub path_prefix: Option<String>,
    pub cors: Option<CorsConfig>,
}

impl From<ApplicationConfig> for ServerConfig {
    fn from(value: ApplicationConfig) -> Self {
        Self { port: value.port, path_prefix: value.path_prefix, cors: value.cors }
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

    let app = if let Some(cors) = config.cors {
        let cors = CorsLayer::new()
            .allow_methods(Any)
            .allow_origin(match cors {
                CorsConfig::AllowAll => AllowOrigin::any(),
                CorsConfig::AllowList(allow_origins) => AllowOrigin::predicate(move |value, _| {
                    let value = value.as_bytes();
                    allow_origins.iter().any(|origin| {
                        let split_byte_wildcard = origin.split('*').map(|s| s.as_bytes()).collect::<Vec<_>>();
                        if split_byte_wildcard.len() == 2 {
                            let (prefix, suffix) = (split_byte_wildcard[0], split_byte_wildcard[1]);
                            value.starts_with(prefix) && value.ends_with(suffix)
                        } else {
                            origin.as_bytes() == value
                        }
                    })
                }),
            })
            .allow_headers([AUTHORIZATION, CONTENT_TYPE, LINK])
            .expose_headers([LINK]);
        app.layer(cors)
    } else {
        app
    };

    let listener = tokio::net::TcpListener::bind(("0.0.0.0", config.port)).await?;
    debug!("starting authz server on {}", config.port);
    axum::serve(listener, app).await?;
    Ok(())
}
