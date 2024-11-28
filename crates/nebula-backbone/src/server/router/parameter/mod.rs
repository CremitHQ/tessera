use std::sync::Arc;

use axum::{
    extract::{Path, State},
    response::IntoResponse,
    routing::get,
    Json, Router,
};
use base64::{engine::general_purpose::STANDARD, Engine as _};

use crate::application::{
    self,
    parameter::{ParameterData, ParameterUseCase},
    Application,
};

use self::response::ParameterResponse;

mod response;

pub(crate) fn router(application: Arc<Application>) -> axum::Router {
    Router::new()
        .route("/workspaces/:workspace_name/parameter", get(handle_get_parameter).post(handle_post_parameter))
        .with_state(application)
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
