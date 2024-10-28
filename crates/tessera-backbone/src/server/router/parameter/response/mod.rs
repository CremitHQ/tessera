use crate::{
    application,
    server::response::{error_payload, handle_internal_server_error},
};
use axum::{http::StatusCode, response::IntoResponse};
use serde::Serialize;
use tessera_abe::{curves::bls24479::Bls24479Curve, schemes::rw15::GlobalParams};
use tracing::error;

impl IntoResponse for application::parameter::Error {
    fn into_response(self) -> axum::response::Response {
        match self {
            application::parameter::Error::GetParameterFailed(error) => {
                error!("Failed to get parameter: {}", error);
                (StatusCode::NOT_FOUND, error_payload("GET_PARAMETER_FAILED", "Failed to get parameter"))
                    .into_response()
            }
            application::parameter::Error::Anyhow(e) => handle_internal_server_error(&*e).into_response(),
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct ParameterResponse {
    pub version: i32,
    pub parameter: GlobalParams<Bls24479Curve>,
}
