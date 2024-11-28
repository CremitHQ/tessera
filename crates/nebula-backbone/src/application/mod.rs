use std::sync::Arc;

use parameter::{ParameterUseCase, ParameterUseCaseImpl};
use sea_orm::{DatabaseConnection, TransactionTrait};

use crate::{
    config::ApplicationConfig,
    database::{self, connect_to_database, AuthMethod},
    domain::{
        authority::{AuthorityService, PostgresAuthorityService},
        parameter::{ParameterService, PostgresParameterService},
        policy::{PolicyService, PostgresPolicyService},
        secret::{PostgresSecretService, SecretService},
        workspace::WorkspaceServiceImpl,
    },
};

use workspace::{WorkspaceUseCase, WorkspaceUseCaseImpl};

use self::{
    authority::{AuthorityUseCase, AuthorityUseCaseImpl},
    path::{PathUseCase, PathUseCaseImpl},
    policy::{PolicyUseCase, PolicyUseCaseImpl},
    secret::{SecretUseCase, SecretUseCaseImpl},
};

pub(crate) mod authority;
pub(crate) mod parameter;
pub(crate) mod path;
pub(crate) mod policy;
pub(crate) mod secret;
pub(crate) mod workspace;

pub(crate) struct Application {
    database_connection: Arc<DatabaseConnection>,
    workspace_service: Arc<WorkspaceServiceImpl>,
    secret_service: Arc<dyn SecretService + Sync + Send>,
    parameter_service: Arc<dyn ParameterService + Sync + Send>,
    policy_service: Arc<dyn PolicyService + Sync + Send>,
    authority_service: Arc<dyn AuthorityService + Sync + Send>,
}

impl Application {
    pub fn workspace(&self) -> impl WorkspaceUseCase {
        WorkspaceUseCaseImpl::new(self.database_connection.clone(), self.workspace_service.clone())
    }

    pub fn with_workspace(&self, workspace_name: &str) -> ApplicationWithWorkspace {
        ApplicationWithWorkspace {
            workspace_name: workspace_name.to_owned(),
            database_connection: self.database_connection.clone(),
            secret_service: self.secret_service.clone(),
            parameter_service: self.parameter_service.clone(),
            policy_service: self.policy_service.clone(),
            authority_service: self.authority_service.clone(),
        }
    }
}

pub(crate) struct ApplicationWithWorkspace {
    workspace_name: String,
    database_connection: Arc<DatabaseConnection>,
    secret_service: Arc<dyn SecretService + Sync + Send>,
    parameter_service: Arc<dyn ParameterService + Sync + Send>,
    policy_service: Arc<dyn PolicyService + Sync + Send>,
    authority_service: Arc<dyn AuthorityService + Sync + Send>,
}

impl ApplicationWithWorkspace {
    pub fn secret(&self) -> impl SecretUseCase {
        SecretUseCaseImpl::new(
            self.workspace_name.to_owned(),
            self.database_connection.clone(),
            self.secret_service.clone(),
            self.policy_service.clone(),
        )
    }

    pub fn parameter(&self) -> impl ParameterUseCase {
        ParameterUseCaseImpl::new(
            self.workspace_name.to_owned(),
            self.database_connection.clone(),
            self.parameter_service.clone(),
        )
    }

    pub fn policy(&self) -> impl PolicyUseCase {
        PolicyUseCaseImpl::new(
            self.workspace_name.to_owned(),
            self.database_connection.clone(),
            self.policy_service.clone(),
        )
    }

    pub fn path(&self) -> impl PathUseCase {
        PathUseCaseImpl::new(
            self.workspace_name.to_owned(),
            self.database_connection.clone(),
            self.secret_service.clone(),
        )
    }

    pub fn authority(&self) -> impl AuthorityUseCase {
        AuthorityUseCaseImpl::new(
            self.workspace_name.to_owned(),
            self.database_connection.clone(),
            self.authority_service.clone(),
        )
    }
}

pub(super) async fn init(config: &ApplicationConfig) -> anyhow::Result<Application> {
    let database_connection = init_database_connection(config).await?;
    database::migrate(database_connection.as_ref()).await?;
    database::migrate_all_workspaces(
        &database_connection.begin().await?,
        &config.database.host,
        config.database.port,
        &config.database.database_name,
        &create_database_auth_method(config),
    )
    .await?;

    let workspace_service = Arc::new(WorkspaceServiceImpl::new(
        database_connection.clone(),
        config.database.host.to_owned(),
        config.database.port,
        config.database.database_name.to_owned(),
        create_database_auth_method(config),
    ));
    let secret_service = Arc::new(PostgresSecretService {});
    let parameter_service = Arc::new(PostgresParameterService);
    let policy_service = Arc::new(PostgresPolicyService {});
    let authority_service = Arc::new(PostgresAuthorityService {});

    Ok(Application {
        database_connection,
        workspace_service,
        secret_service,
        parameter_service,
        policy_service,
        authority_service,
    })
}

async fn init_database_connection(config: &ApplicationConfig) -> anyhow::Result<Arc<DatabaseConnection>> {
    let database_host = &config.database.host;
    let database_port = config.database.port;
    let database_name = &config.database.database_name;
    let auth_method = create_database_auth_method(config);

    connect_to_database(database_host, database_port, database_name, &auth_method).await
}

fn create_database_auth_method(config: &ApplicationConfig) -> AuthMethod {
    match &config.database.auth {
        crate::config::DatabaseAuthConfig::Credential { username, password } => {
            AuthMethod::Credential { username: username.to_owned(), password: password.to_owned() }
        }
        crate::config::DatabaseAuthConfig::RdsIamAuth { username } => AuthMethod::RdsIamAuth {
            host: config.database.host.to_owned(),
            port: config.database.port,
            username: username.to_owned(),
        },
    }
}
