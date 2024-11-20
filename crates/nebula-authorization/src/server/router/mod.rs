use std::{
    sync::Arc,
    time::{Duration, SystemTime},
};

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Redirect},
    routing::{get, post},
    Form, Json, Router,
};
use axum_thiserror::ErrorStatus;
use josekit::{jws::JwsHeader, jwt::JwtPayload, Map, Value};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{application::Application, domain::token::jwt::Jwt};

pub(crate) fn router(application: Arc<Application>) -> axum::Router {
    Router::new()
        .route("/login/:connector", get(handle_connector_login))
        .route("/callback/saml", post(handle_saml_connector_callback))
        .route("/jwks", get(handle_jwks))
        .with_state(application)
}

async fn handle_connector_login(
    Path(connector): Path<String>,
    State(application): State<Arc<Application>>,
) -> Result<impl IntoResponse, ConnectorLoginError> {
    match connector.as_str() {
        "saml" => {
            let request = application
                .connector
                .authentication_request()
                .map_err(|_| ConnectorLoginError::FailedToCreateSAMLAuthenticationRequest)?;
            let url = request
                .redirect(&application.connector.redirect_uri)
                .map_err(|_| ConnectorLoginError::FailedToCreateSAMLAuthenticationRequest)?
                .ok_or(ConnectorLoginError::FailedToCreateSAMLAuthenticationRequest)?;

            Ok(Redirect::to(url.as_str()))
        }
        _ => Err(ConnectorLoginError::NotFound),
    }
}

#[derive(Error, Debug, ErrorStatus)]
pub enum ConnectorLoginError {
    #[error("Connector not found")]
    #[status(StatusCode::NOT_FOUND)]
    NotFound,

    #[error("Failed to create a SAML authentication request")]
    #[status(StatusCode::INTERNAL_SERVER_ERROR)]
    FailedToCreateSAMLAuthenticationRequest,
}

async fn handle_saml_connector_callback(
    State(application): State<Arc<Application>>,
    Form(payload): Form<SAMLConnectorCallbackRequest>,
) -> Result<impl IntoResponse, SAMLConnectorCallbackError> {
    let identity = application
        .connector
        .identity(&payload.saml_response, &payload.relay_state)
        .map_err(|_| SAMLConnectorCallbackError::FailedToCreateSAMLIdentity)?;

    let mut jws_header = JwsHeader::new();
    jws_header.set_jwk_set_url(format!("{}/jwks", application.base_url));
    jws_header.set_key_id(&application.token_service.jwk_kid);
    jws_header.set_algorithm("ES256");

    let mut jwt_payload = JwtPayload::new();
    jwt_payload
        .set_claim(
            "attributes",
            Some(Value::Object(identity.claims.into_iter().map(|(k, v)| (k, v.into())).collect::<Map<_, _>>())),
        )
        .map_err(|_| SAMLConnectorCallbackError::FailedToCreateJWT)?;
    jwt_payload.set_subject(&identity.user_id);
    jwt_payload.set_issuer("nebula-authorization");

    let now = SystemTime::now();
    let expires_at = now + Duration::from_secs(application.token_service.lifetime);
    jwt_payload.set_expires_at(&expires_at);
    jwt_payload.set_issued_at(&now);

    let jwt = Jwt::new(
        jws_header,
        jwt_payload,
        application
            .token_service
            .jwks
            .get(&application.token_service.jwk_kid)
            .ok_or(SAMLConnectorCallbackError::FailedToCreateJWT)?,
    )
    .map_err(|_| SAMLConnectorCallbackError::FailedToCreateJWT)?;
    Ok(Json(SAMLConnectorCallbackResponse { access_token: jwt }))
}

#[derive(Deserialize)]
pub struct SAMLConnectorCallbackRequest {
    #[serde(rename = "RelayState")]
    relay_state: String,
    #[serde(rename = "SAMLResponse")]
    saml_response: String,
}

#[derive(Error, Debug, ErrorStatus)]
pub enum SAMLConnectorCallbackError {
    #[error("Failed to create a SAML identity")]
    #[status(StatusCode::INTERNAL_SERVER_ERROR)]
    FailedToCreateSAMLIdentity,

    #[error("Failed to create a JWT")]
    #[status(StatusCode::INTERNAL_SERVER_ERROR)]
    FailedToCreateJWT,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SAMLConnectorCallbackResponse {
    access_token: Jwt,
}

async fn handle_jwks(State(application): State<Arc<Application>>) -> impl IntoResponse {
    Json(application.token_service.jwks.clone())
}
