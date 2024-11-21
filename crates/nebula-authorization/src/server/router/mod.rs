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
use nebula_token::{
    claim::{ATTRIBUTES_CLAIM, WORKSPACE_NAME_CLAIM},
    jwk::jwk_set::PublicJwkSet,
    jwt::Jwt,
    JwsHeader, JwtPayload, Map, Value,
};
use sea_orm::DbErr;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use ulid::Ulid;

use crate::{
    application::Application,
    database::{Persistable, WorkspaceScopedTransaction},
    domain::machine_identity::{self, MachineIdentity},
};

pub(crate) fn router(application: Arc<Application>) -> axum::Router {
    Router::new()
        .route("/login/:connector", get(handle_connector_login))
        .route("/callback/saml", post(handle_saml_connector_callback))
        .route("/jwks", get(handle_jwks))
        .route(
            "/workspaces/:workspace_name/machine-identities",
            get(handle_get_machine_identities).post(handle_post_machine_identity),
        )
        .route(
            "/workspaces/:workspace_name/machine-identities/:machine_identity_id",
            get(handle_get_machine_identity)
                .patch(handle_patch_machine_identity)
                .delete(handle_delete_machine_identity),
        )
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
    jws_header.set_jwk_set_url(
        application.base_url.join("/jwks").map_err(|_| SAMLConnectorCallbackError::FailedToCreateJWT)?,
    );
    jws_header.set_key_id(&application.token_service.jwk_kid);
    jws_header.set_algorithm("ES256");

    let mut jwt_payload = JwtPayload::new();
    jwt_payload
        .set_claim(
            ATTRIBUTES_CLAIM,
            Some(Value::Object(identity.claims.into_iter().map(|(k, v)| (k, v.into())).collect::<Map<_, _>>())),
        )
        .map_err(|_| SAMLConnectorCallbackError::FailedToCreateJWT)?;
    jwt_payload.set_subject(&identity.user_id);
    jwt_payload.set_issuer("nebula-authorization");
    jwt_payload.set_claim(WORKSPACE_NAME_CLAIM, Some(identity.workspace_name.into())).unwrap();

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
    Json(PublicJwkSet::new(&application.token_service.jwks))
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Attribute {
    key: String,
    value: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PostMachineIdentityRequest {
    label: String,
    attributes: Vec<Attribute>,
}

#[derive(Error, Debug, ErrorStatus)]
enum MachineIdentityError {
    #[error("machine identity is not exists")]
    #[status(StatusCode::NOT_FOUND)]
    MachineIdentityNotExists { entered_machine_identity_id: Ulid },
    #[error("Error occurrred by database")]
    #[status(StatusCode::INTERNAL_SERVER_ERROR)]
    DatabaseError(#[from] DbErr),
}

impl From<machine_identity::Error> for MachineIdentityError {
    fn from(value: machine_identity::Error) -> Self {
        match value {
            machine_identity::Error::DatabaseError(e) => Self::DatabaseError(e),
        }
    }
}

async fn handle_post_machine_identity(
    Path(workspace_name): Path<String>,
    State(application): State<Arc<Application>>,
    Json(payload): Json<PostMachineIdentityRequest>,
) -> Result<impl IntoResponse, MachineIdentityError> {
    let attributes: Vec<_> =
        payload.attributes.iter().map(|attribute| (attribute.key.as_str(), attribute.value.as_str())).collect();

    let transaction = application.database_connection.begin_with_workspace_scope(&workspace_name).await?;

    application.machine_identity_service.register_machine_identity(&transaction, &payload.label, &attributes).await?;

    transaction.commit().await?;

    Ok(StatusCode::CREATED)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MachineIdentityResponse {
    id: Ulid,
    label: String,
    attributes: Vec<Attribute>,
}

impl From<MachineIdentity> for MachineIdentityResponse {
    fn from(value: MachineIdentity) -> Self {
        Self {
            id: value.id,
            label: value.label,
            attributes: value.attributes.into_iter().map(|(key, value)| Attribute { key, value }).collect(),
        }
    }
}

async fn handle_get_machine_identities(
    Path(workspace_name): Path<String>,
    State(application): State<Arc<Application>>,
) -> Result<impl IntoResponse, MachineIdentityError> {
    let transaction = application.database_connection.begin_with_workspace_scope(&workspace_name).await?;

    let machine_identities = application.machine_identity_service.get_machine_identities(&transaction).await?;

    transaction.commit().await?;

    let payload: Vec<_> = machine_identities.into_iter().map(MachineIdentityResponse::from).collect();

    Ok(Json(payload))
}

async fn handle_get_machine_identity(
    Path((workspace_name, machine_identity_id)): Path<(String, Ulid)>,
    State(application): State<Arc<Application>>,
) -> Result<impl IntoResponse, MachineIdentityError> {
    let transaction = application.database_connection.begin_with_workspace_scope(&workspace_name).await?;

    let machine_identity = application
        .machine_identity_service
        .get_machine_identity(&transaction, &machine_identity_id)
        .await?
        .ok_or_else(|| MachineIdentityError::MachineIdentityNotExists {
            entered_machine_identity_id: machine_identity_id.to_owned(),
        })?;

    transaction.commit().await?;

    let payload = MachineIdentityResponse::from(machine_identity);

    Ok(Json(payload))
}

#[derive(Deserialize)]
struct PatchMachineIdentityRequest {
    attributes: Option<Vec<Attribute>>,
}

async fn handle_patch_machine_identity(
    Path((workspace_name, machine_identity_id)): Path<(String, Ulid)>,
    State(application): State<Arc<Application>>,
    Json(payload): Json<PatchMachineIdentityRequest>,
) -> Result<impl IntoResponse, MachineIdentityError> {
    let transaction = application.database_connection.begin_with_workspace_scope(&workspace_name).await?;

    let mut machine_identity = application
        .machine_identity_service
        .get_machine_identity(&transaction, &machine_identity_id)
        .await?
        .ok_or_else(|| MachineIdentityError::MachineIdentityNotExists {
            entered_machine_identity_id: machine_identity_id.to_owned(),
        })?;

    if let Some(attributes) = payload.attributes {
        let attributes: Vec<_> =
            attributes.iter().map(|attribute| (attribute.key.as_str(), attribute.value.as_str())).collect();
        machine_identity.update_attributes(&attributes);
    }
    machine_identity.persist(&transaction).await?;

    transaction.commit().await?;

    Ok(StatusCode::NO_CONTENT)
}

async fn handle_delete_machine_identity(
    Path((workspace_name, machine_identity_id)): Path<(String, Ulid)>,
    State(application): State<Arc<Application>>,
) -> Result<impl IntoResponse, MachineIdentityError> {
    let transaction = application.database_connection.begin_with_workspace_scope(&workspace_name).await?;

    let mut machine_identity = application
        .machine_identity_service
        .get_machine_identity(&transaction, &machine_identity_id)
        .await?
        .ok_or_else(|| MachineIdentityError::MachineIdentityNotExists {
            entered_machine_identity_id: machine_identity_id.to_owned(),
        })?;

    machine_identity.delete();
    machine_identity.persist(&transaction).await?;

    transaction.commit().await?;

    Ok(StatusCode::NO_CONTENT)
}
