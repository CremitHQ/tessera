use std::sync::Arc;

use axum::{
    extract::{Path, Request},
    middleware::Next,
    response::Response,
    routing::get,
    Extension, Router,
};
use nebula_token::{
    auth::layer::NebulaAuthLayer,
    claim::{NebulaClaim, Role},
};
use reqwest::StatusCode;
use tracing::debug;

mod router;

use crate::{application::Application, config::ApplicationConfig};

static AUTHORITY_ADMINS: OnceLock<Vec<String>> = OnceLock::new();
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
        // .nest(
        //     "/v1/workspaces/:workspace_name/",
        //     router::init::router(application.clone()).route_layer(middleware::from_fn(check_workspace_name)),
        // )
        .nest("/v1/", router::init::router(application.clone()))
        .layer(NebulaAuthLayer::builder().jwk_discovery(application.jwks_discovery.clone()).build());

    let public_router = Router::new()
        .route("/health", get(|| async { "OK" }))
        .nest("/v1/workspaces/:workspace_name/", router::pubkey::router(application.clone()));

    let app = Router::new().merge(protected_router).merge(public_router);

    let listener = tokio::net::TcpListener::bind(("0.0.0.0", config.port)).await?;
    debug!("starting authority server on {}", config.port);
    axum::serve(listener, app).await?;
    Ok(())
}

async fn check_workspace_name(
    Path(workspace_name): Path<String>,
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

async fn check_admin_role(
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
