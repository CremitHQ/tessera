use std::sync::Arc;

use axum::{
    extract::{Path, Request},
    http::header::{AUTHORIZATION, CONTENT_TYPE, LINK},
    middleware::{self, Next},
    response::Response,
    routing::get,
    Extension, Router,
};
use nebula_token::{
    auth::layer::NebulaAuthLayer,
    claim::{NebulaClaim, Role},
};
use reqwest::StatusCode;
use serde::Deserialize;
use tower_http::cors::AllowOrigin;
use tower_http::cors::Any;
use tower_http::cors::CorsLayer;
use tracing::debug;

mod router;

use crate::config::CorsConfig;
use crate::{application::Application, config::ApplicationConfig};

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
    let protected_router = Router::new()
        .nest(
            "/workspaces/:workspace_name/",
            router::userkey::router(application.clone()).route_layer(middleware::from_fn(check_workspace_name)),
        )
        .nest(
            "/workspaces/:workspace_name/",
            router::keypair::router(application.clone())
                .route_layer(middleware::from_fn(check_admin_role))
                .route_layer(middleware::from_fn(check_workspace_name)),
        )
        .layer(NebulaAuthLayer::builder().jwk_discovery(application.jwks_discovery.clone()).build());
    let public_router = Router::new()
        .nest("/workspaces/:workspace_name/", router::pubkey::router(application.clone()))
        .nest("/", router::init::router(application.clone()))
        .nest("/", router::disarm::router(application.clone()));

    let app = Router::new().route("/health", get(|| async { "OK" }));
    let app = if let Some(path_prefix) = config.path_prefix {
        let path_prefix = format!("/{}/", path_prefix.trim_matches('/'));
        app.nest(&path_prefix, protected_router).nest(&path_prefix, public_router)
    } else {
        app.merge(protected_router).merge(public_router)
    };

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
    debug!("starting authority server on {}", config.port);
    axum::serve(listener, app).await?;
    Ok(())
}

#[derive(Deserialize)]
pub(crate) struct WorkspaceParams {
    pub workspace_name: String,
}

pub(crate) async fn check_workspace_name(
    Path(WorkspaceParams { workspace_name }): Path<WorkspaceParams>,
    Extension(claim): Extension<NebulaClaim>,
    req: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    if workspace_name == claim.workspace_name {
        Ok(next.run(req).await)
    } else {
        Err(StatusCode::FORBIDDEN)
    }
}

pub(crate) async fn check_admin_role(
    Extension(claim): Extension<NebulaClaim>,
    req: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    if claim.role == Role::Admin {
        Ok(next.run(req).await)
    } else {
        Err(StatusCode::FORBIDDEN)
    }
}
