use std::sync::Arc;

use axum::{
    debug_handler,
    extract::{Path, State},
    response::IntoResponse,
    routing::get,
    Json, Router,
};

use crate::application::{
    self,
    parameter::{ParameterData, ParameterUseCase},
    Application,
};

use self::response::ParameterResponse;

mod response;

pub(crate) fn router(application: Arc<Application>) -> axum::Router {
    Router::new().route("/workspaces/:workspace_name/parameter", get(handle_get_parameter)).with_state(application)
}

#[debug_handler]
async fn handle_get_parameter(
    Path(workspace_name): Path<String>,
    State(application): State<Arc<Application>>,
) -> Result<impl IntoResponse, application::parameter::Error> {
    let parameter = application.with_workspace(&workspace_name).parameter().get().await?;
    let response: ParameterResponse = parameter.into();

    Ok(Json(response))
}

#[debug_handler]
async fn handle_create_parameter(
    Path(workspace_name): Path<String>,
    State(application): State<Arc<Application>>,
) -> Result<impl IntoResponse, application::parameter::Error> {
    let parameter = application.with_workspace(&workspace_name).parameter().create().await?;
    let response: ParameterResponse = parameter.into();

    Ok(Json(response))
}

impl From<ParameterData> for ParameterResponse {
    fn from(value: ParameterData) -> Self {
        Self { version: value.version, parameter: value.value }
    }
}
