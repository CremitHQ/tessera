use std::sync::Arc;

use axum::{
    extract::{Path, State},
    middleware,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use base64::{engine::general_purpose::STANDARD, Engine as _};

use crate::{
    application::{
        self,
        parameter::{ParameterData, ParameterUseCase},
        Application,
    },
    server::{check_admin_role, check_member_role, check_workspace_name},
};

use self::response::ParameterResponse;

mod response;

pub(crate) fn router(application: Arc<Application>) -> axum::Router {
    let member_router = Router::new()
        .route("/workspaces/:workspace_name/parameter", get(handle_get_parameter))
        .route_layer(middleware::from_fn(check_member_role))
        .route_layer(middleware::from_fn(check_workspace_name));
    let admin_router = Router::new()
        .route("/workspaces/:workspace_name/parameter", post(handle_post_parameter))
        .route_layer(middleware::from_fn(check_admin_role))
        .route_layer(middleware::from_fn(check_workspace_name));
    Router::new().merge(member_router).merge(admin_router).with_state(application)
}

async fn handle_post_parameter(
    Path(workspace_name): Path<String>,
    State(application): State<Arc<Application>>,
) -> Result<impl IntoResponse, application::parameter::Error> {
    let parameter = application.with_workspace(&workspace_name).parameter().create().await?;
    let response: ParameterResponse = parameter.try_into()?;

    Ok(Json(response))
}

async fn handle_get_parameter(
    Path(workspace_name): Path<String>,
    State(application): State<Arc<Application>>,
) -> Result<impl IntoResponse, application::parameter::Error> {
    let parameter = application.with_workspace(&workspace_name).parameter().get().await?;
    let response: ParameterResponse = parameter.try_into()?;

    Ok(Json(response))
}

impl TryFrom<ParameterData> for ParameterResponse {
    type Error = application::parameter::Error;

    fn try_from(value: ParameterData) -> Result<Self, Self::Error> {
        let parameter = rmp_serde::to_vec(&value.value)?;
        let parameter = STANDARD.encode(&parameter);
        Ok(Self { version: value.version, parameter })
    }
}
