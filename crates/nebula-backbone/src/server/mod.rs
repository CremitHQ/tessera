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
        .merge(router::secret::router(application.clone()))
        .merge(router::parameter::router(application.clone()))
        .merge(router::policy::router(application.clone()))
        .merge(router::path::router(application.clone()))
        .merge(router::authority::router(application.clone()))
        .layer(NebulaAuthLayer::builder().jwk_discovery(application.jwks_discovery().clone()).build());
    let listener = tokio::net::TcpListener::bind(("0.0.0.0", config.port)).await?;
    debug!("starting backbone server on {}", config.port);
    axum::serve(listener, app).await?;
    Ok(())
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

pub(crate) async fn check_member_role(
    Extension(claim): Extension<NebulaClaim>,
    req: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    if claim.role == Role::Member || claim.role == Role::Admin {
        Ok(next.run(req).await)
    } else {
        Err(StatusCode::FORBIDDEN)
    }
}

pub(crate) async fn check_workspace_name(
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
