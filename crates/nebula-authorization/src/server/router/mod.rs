use std::{
    sync::Arc,
    time::{Duration, SystemTime},
};

use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Redirect},
    routing::{get, post},
    Form, Json, Router,
};
use axum_thiserror::ErrorStatus;
use nebula_token::{
    claim::{Role, ATTRIBUTES_CLAIM, ROLE_CLAIM, WORKSPACE_NAME_CLAIM},
    jwk::jwk_set::PublicJwkSet,
    jwt::Jwt,
    JwsHeader, JwtPayload, Map, Value,
};
use sea_orm::{DatabaseTransaction, DbErr};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use ulid::Ulid;

use crate::{
    application::Application,
    database::{Persistable, WorkspaceScopedTransaction},
    domain::{
        connector::Identity,
        machine_identity::{self, MachineIdentity, MachineIdentityToken},
    },
};

pub(crate) fn router(application: Arc<Application>) -> axum::Router {
    Router::new()
        .route("/login/:connector", get(handle_connector_login))
        .route("workspaces/:workspace_name/machine-identities/login", get(handle_machine_identity_login))
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
        .route(
            "/workspaces/:workspace_name/machine-identities/:machine_identity_id/tokens",
            get(handle_get_machine_identity_tokens).post(handle_post_machine_identity_token),
        )
        .route(
            "/workspaces/:workspace_name/machine-identities/:machine_identity_id/tokens/:machine_identity_token_id",
            get(handle_get_machine_identity_token).delete(handle_delete_machine_identity_token),
        )
        .with_state(application)
}

async fn handle_machine_identity_login(
    Path(workspace_name): Path<String>,
    headers: HeaderMap,
    State(application): State<Arc<Application>>,
) -> Result<impl IntoResponse, MachineIdentityLoginError> {
    let transaction = application.database_connection.begin_with_workspace_scope(&workspace_name).await?;

    let machine_token = headers
        .get("token")
        .ok_or(MachineIdentityLoginError::NoToken)?
        .to_str()
        .map_err(|_| MachineIdentityLoginError::InvalidTokenFormat)?;
    let token = application
        .machine_identity_service
        .get_machine_identity_by_token(&transaction, machine_token)
        .await
        .map_err(|_| MachineIdentityLoginError::FailedToGetMachineIdentityToken)?
        .ok_or(MachineIdentityLoginError::InvalidToken)?;

    transaction.commit().await?;

    let identity = Identity::new(token.id.into(), workspace_name, Role::Member, token.attributes.into_iter().collect());
    let jwt =
        application.token_service.create_jwt(&identity).map_err(|_| MachineIdentityLoginError::FailedToCreateJWT)?;

    Ok(Json(MachineIdentityLoginResponse { access_token: jwt }))
}

#[derive(Error, Debug, ErrorStatus)]
pub enum MachineIdentityLoginError {
    #[error("there is no token in the header")]
    #[status(StatusCode::BAD_REQUEST)]
    NoToken,

    #[error("invalid token format")]
    #[status(StatusCode::INTERNAL_SERVER_ERROR)]
    InvalidTokenFormat,

    #[error("failed to get machine identity token")]
    #[status(StatusCode::INTERNAL_SERVER_ERROR)]
    FailedToGetMachineIdentityToken,

    #[error("invalid token")]
    #[status(StatusCode::UNAUTHORIZED)]
    InvalidToken,

    #[error("Error occurrred by database")]
    #[status(StatusCode::INTERNAL_SERVER_ERROR)]
    DatabaseError(#[from] DbErr),

    #[error("failed to create a JWT")]
    #[status(StatusCode::INTERNAL_SERVER_ERROR)]
    FailedToCreateJWT,
}

#[derive(Debug, Serialize)]
pub struct MachineIdentityLoginResponse {
    pub access_token: Jwt,
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

    let jwt =
        application.token_service.create_jwt(&identity).map_err(|_| SAMLConnectorCallbackError::FailedToCreateJWT)?;
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
    #[error("machine identity token is not exists")]
    #[status(StatusCode::NOT_FOUND)]
    MachineIdentityTokenNotExists { entered_machine_identity_token_id: Ulid },
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

async fn get_machine_identity(
    application: &Application,
    transaction: &DatabaseTransaction,
    machine_identity_id: &Ulid,
) -> Result<MachineIdentity, MachineIdentityError> {
    application.machine_identity_service.get_machine_identity(transaction, machine_identity_id).await?.ok_or_else(
        || MachineIdentityError::MachineIdentityNotExists {
            entered_machine_identity_id: machine_identity_id.to_owned(),
        },
    )
}

async fn handle_get_machine_identity(
    Path((workspace_name, machine_identity_id)): Path<(String, Ulid)>,
    State(application): State<Arc<Application>>,
) -> Result<impl IntoResponse, MachineIdentityError> {
    let transaction = application.database_connection.begin_with_workspace_scope(&workspace_name).await?;

    let machine_identity = get_machine_identity(&application, &transaction, &machine_identity_id).await?;

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

    let mut machine_identity = get_machine_identity(&application, &transaction, &machine_identity_id).await?;

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

    let mut machine_identity = get_machine_identity(&application, &transaction, &machine_identity_id).await?;

    machine_identity.delete();
    machine_identity.persist(&transaction).await?;

    transaction.commit().await?;

    Ok(StatusCode::NO_CONTENT)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MachineIdentityTokenResponse {
    pub id: Ulid,
    pub token: String,
}

impl From<MachineIdentityToken> for MachineIdentityTokenResponse {
    fn from(value: MachineIdentityToken) -> Self {
        Self { id: value.id, token: value.token }
    }
}

async fn handle_get_machine_identity_tokens(
    Path((workspace_name, machine_identity_id)): Path<(String, Ulid)>,
    State(application): State<Arc<Application>>,
) -> Result<impl IntoResponse, MachineIdentityError> {
    let transaction = application.database_connection.begin_with_workspace_scope(&workspace_name).await?;

    let machine_identity = get_machine_identity(&application, &transaction, &machine_identity_id).await?;
    let tokens =
        application.machine_identity_service.get_machine_identity_tokens(&transaction, &machine_identity).await?;

    transaction.commit().await?;

    let payload: Vec<_> = tokens.into_iter().map(MachineIdentityTokenResponse::from).collect();

    Ok(Json(payload))
}

async fn handle_post_machine_identity_token(
    Path((workspace_name, machine_identity_id)): Path<(String, Ulid)>,
    State(application): State<Arc<Application>>,
) -> Result<impl IntoResponse, MachineIdentityError> {
    let transaction = application.database_connection.begin_with_workspace_scope(&workspace_name).await?;

    let machine_identity = get_machine_identity(&application, &transaction, &machine_identity_id).await?;
    application.machine_identity_service.create_new_machine_identity_token(&transaction, &machine_identity).await?;

    transaction.commit().await?;

    Ok(StatusCode::CREATED)
}

async fn handle_get_machine_identity_token(
    Path((workspace_name, machine_identity_id, machine_identity_token_id)): Path<(String, Ulid, Ulid)>,
    State(application): State<Arc<Application>>,
) -> Result<impl IntoResponse, MachineIdentityError> {
    let transaction = application.database_connection.begin_with_workspace_scope(&workspace_name).await?;

    let machine_identity = get_machine_identity(&application, &transaction, &machine_identity_id).await?;

    let token = application
        .machine_identity_service
        .get_machine_identity_token(&transaction, &machine_identity, &machine_identity_token_id)
        .await?
        .ok_or_else(|| MachineIdentityError::MachineIdentityTokenNotExists {
            entered_machine_identity_token_id: machine_identity_token_id.to_owned(),
        })?;

    transaction.commit().await?;

    let payload = MachineIdentityTokenResponse::from(token);

    Ok(Json(payload))
}

async fn handle_delete_machine_identity_token(
    Path((workspace_name, machine_identity_id, machine_identity_token_id)): Path<(String, Ulid, Ulid)>,
    State(application): State<Arc<Application>>,
) -> Result<impl IntoResponse, MachineIdentityError> {
    let transaction = application.database_connection.begin_with_workspace_scope(&workspace_name).await?;

    let machine_identity = get_machine_identity(&application, &transaction, &machine_identity_id).await?;
    let mut token = application
        .machine_identity_service
        .get_machine_identity_token(&transaction, &machine_identity, &machine_identity_token_id)
        .await?
        .ok_or_else(|| MachineIdentityError::MachineIdentityTokenNotExists {
            entered_machine_identity_token_id: machine_identity_token_id.to_owned(),
        })?;
    token.delete();
    token.persist(&transaction).await?;

    transaction.commit().await?;

    Ok(StatusCode::CREATED)
}
