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
use reqwest::{
    header::{AUTHORIZATION, CONTENT_TYPE, LINK},
    StatusCode,
};
use tower_http::cors::AllowOrigin;
use tower_http::cors::Any;
use tower_http::cors::CorsLayer;
use tracing::debug;

use crate::{
    application::Application,
    config::{ApplicationConfig, CorsConfig},
};

mod response;
mod router;

pub(super) struct ServerConfig {
    pub port: u16,
    pub cors: Option<CorsConfig>,
}

impl From<&ApplicationConfig> for ServerConfig {
    fn from(value: &ApplicationConfig) -> Self {
        Self { port: value.port, cors: value.cors.clone() }
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
