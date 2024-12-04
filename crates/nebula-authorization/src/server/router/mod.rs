use std::sync::Arc;

use axum::{
    extract::{Path, Query, Request, State},
    http::{HeaderMap, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Redirect, Response},
    routing::{delete, get, patch, post},
    Extension, Form, Json, Router,
};
use axum_thiserror::ErrorStatus;
use nebula_token::{
    auth::{jwks_discovery::StaticJwksDiscovery, layer::NebulaAuthLayer},
    claim::{NebulaClaim, Role},
    jwk::jwk_set::PublicJwkSet,
    jwt::Jwt,
};
use sea_orm::{DatabaseTransaction, DbErr, TransactionTrait};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use ulid::Ulid;

use crate::{
    application::Application,
    database::{Persistable, WorkspaceScopedTransaction},
    domain::{
        self,
        connector::Identity,
        machine_identity::{self, MachineIdentity, MachineIdentityToken},
    },
};

pub(crate) fn router(application: Arc<Application>) -> axum::Router {
    let public_router = Router::new()
        .route("/workspaces", post(handle_post_workspace))
        .route("/login/:connector", get(handle_connector_login))
        .route("/workspaces/:workspace_name/machine-identities/login", get(handle_machine_identity_login))
        .route("/callback/saml", post(handle_saml_connector_callback))
        .route("/jwks", get(handle_jwks))
        .with_state(application.clone());

    let private_router = Router::new()
        .route(
            "/workspaces/:workspace_name/machine-identities",
            get(handle_get_machine_identities).post(handle_post_machine_identity),
        )
        .route("/workspaces/:workspace_name/machine-identities/:machine_identity_id", get(handle_get_machine_identity))
        .route(
            "/workspaces/:workspace_name/machine-identities/:machine_identity_id",
            patch(handle_patch_machine_identity).route_layer(middleware::from_fn(check_admin_role)),
        )
        .route(
            "/workspaces/:workspace_name/machine-identities/:machine_identity_id",
            delete(handle_delete_machine_identity).route_layer(middleware::from_fn_with_state(
                application.clone(),
                check_machine_identity_owner_or_admin_role,
            )),
        )
        .route(
            "/workspaces/:workspace_name/machine-identities/:machine_identity_id/tokens",
            get(handle_get_machine_identity_tokens).post(handle_post_machine_identity_token).route_layer(
                middleware::from_fn_with_state(application.clone(), check_machine_identity_owner_or_admin_role),
            ),
        )
        .route(
            "/workspaces/:workspace_name/machine-identities/:machine_identity_id/tokens/:machine_identity_token_id",
            get(handle_get_machine_identity_token).delete(handle_delete_machine_identity_token).route_layer(
                middleware::from_fn_with_state(application.clone(), check_machine_identity_owner_or_admin_role),
            ),
        )
        .route_layer(middleware::from_fn(check_workspace_name))
        .layer(
            NebulaAuthLayer::builder()
                .jwk_discovery(Arc::new(StaticJwksDiscovery::new(application.token_service.jwks.clone())))
                .build(),
        )
        .with_state(application);

    Router::new().merge(public_router).merge(private_router)
}

#[derive(Deserialize)]
pub(crate) struct WorkspaceParams {
    pub workspace_name: String,
}

pub(crate) async fn check_workspace_name(
    Path(WorkspaceParams { workspace_name }): Path<WorkspaceParams>,
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

pub(crate) async fn check_machine_identity_owner_or_admin_role(
    Path((_, machine_identity_id)): Path<(String, Ulid)>,
    Extension(claim): Extension<NebulaClaim>,
    State(application): State<Arc<Application>>,
    req: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    if claim.role == Role::Admin {
        return Ok(next.run(req).await);
    }

    let transaction = application
        .database_connection
        .begin_with_workspace_scope(&claim.workspace_name)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let machine_identity = application
        .machine_identity_service
        .get_machine_identity(&transaction, &machine_identity_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;

    if machine_identity.owner_gid == claim.gid {
        Ok(next.run(req).await)
    } else {
        Err(StatusCode::FORBIDDEN)
    }
}

const TOKEN_HEADER_NAME: &str = "token";

async fn handle_machine_identity_login(
    Path(workspace_name): Path<String>,
    headers: HeaderMap,
    State(application): State<Arc<Application>>,
) -> Result<impl IntoResponse, MachineIdentityLoginError> {
    let transaction = application.database_connection.begin_with_workspace_scope(&workspace_name).await?;

    let machine_token = headers
        .get(TOKEN_HEADER_NAME)
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
#[serde(rename_all = "camelCase")]
pub struct MachineIdentityLoginResponse {
    pub access_token: Jwt,
}

#[derive(Error, Debug, ErrorStatus)]
enum WorkspaceError {
    #[error("Workspace name is already in used")]
    #[status(StatusCode::CONFLICT)]
    WorkspaceNameConflicted,
    #[error("Unhandled error is occurred")]
    #[status(StatusCode::INTERNAL_SERVER_ERROR)]
    UnhandledError(#[from] anyhow::Error),
    #[error("Error occurrred by database")]
    #[status(StatusCode::INTERNAL_SERVER_ERROR)]
    DatabaseError(#[from] DbErr),
}

impl From<domain::workspace::Error> for WorkspaceError {
    fn from(value: domain::workspace::Error) -> Self {
        match value {
            domain::workspace::Error::WorkspaceNameConflicted => Self::WorkspaceNameConflicted,
            domain::workspace::Error::Anyhow(e) => e.into(),
        }
    }
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PostWorkspaceRequest {
    pub name: String,
}

async fn handle_post_workspace(
    State(application): State<Arc<Application>>,
    Json(payload): Json<PostWorkspaceRequest>,
) -> Result<impl IntoResponse, WorkspaceError> {
    let transaction = application.database_connection.begin().await?;

    application.workspace_service.create(&transaction, &payload.name).await?;

    transaction.commit().await?;

    Ok(StatusCode::CREATED)
}

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ConnectorLoginQuery {
    pub callback_port: Option<u16>,
}

async fn handle_connector_login(
    Path(connector): Path<String>,
    Query(query): Query<ConnectorLoginQuery>,
    State(application): State<Arc<Application>>,
) -> Result<impl IntoResponse, ConnectorLoginError> {
    match connector.as_str() {
        "saml" => {
            let request = application
                .connector
                .authentication_request()
                .map_err(|_| ConnectorLoginError::FailedToCreateSAMLAuthenticationRequest)?;
            let url = request
                .redirect(&if let Some(port) = query.callback_port {
                    format!("nebula-callback-port={}", port)
                } else {
                    "".to_string()
                })
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
) -> Result<Response, SAMLConnectorCallbackError> {
    let identity = application
        .connector
        .identity(&payload.saml_response, &payload.relay_state)
        .map_err(|_| SAMLConnectorCallbackError::FailedToCreateSAMLIdentity)?;

    let jwt =
        application.token_service.create_jwt(&identity).map_err(|_| SAMLConnectorCallbackError::FailedToCreateJWT)?;
    if payload.relay_state.starts_with("nebula-callback-port=") {
        let relay_state = payload.relay_state.trim_start_matches("nebula-callback-port=");
        let url = format!(
            "http://localhost:{}/callback/saml?access-token={}",
            relay_state.parse::<u16>().map_err(|_| SAMLConnectorCallbackError::InvalidRelayState)?,
            jwt.serialized_repr
        );
        Ok(Redirect::to(&url).into_response())
    } else {
        Ok(Json(SAMLConnectorCallbackResponse { access_token: jwt }).into_response())
    }
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

    #[error("Failed to parse the relay state as a port number. The relay state should be a port number")]
    #[status(StatusCode::BAD_REQUEST)]
    InvalidRelayState,
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
    Extension(claim): Extension<NebulaClaim>,
    Json(payload): Json<PostMachineIdentityRequest>,
) -> Result<impl IntoResponse, MachineIdentityError> {
    let transaction = application.database_connection.begin_with_workspace_scope(&workspace_name).await?;

    application.machine_identity_service.register_machine_identity(&transaction, &claim, &payload.label).await?;

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
