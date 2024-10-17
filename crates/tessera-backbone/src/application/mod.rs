use std::sync::Arc;

use sea_orm::DatabaseConnection;

use crate::{
    config::ApplicationConfig,
    database::{connect_to_database, AuthMethod},
    domain::workspace::WorkspaceServiceImpl,
};

use workspace::{WorkspaceUseCase, WorkspaceUseCaseImpl};

use self::secret::{SecretUseCase, SecretUseCaseImpl};

pub mod secret;
pub mod workspace;

pub(crate) struct Application {
    database_connection: Arc<DatabaseConnection>,
    workspace_service: Arc<WorkspaceServiceImpl>,
}

impl Application {
    pub fn workspace(&self) -> impl WorkspaceUseCase {
        WorkspaceUseCaseImpl::new(self.database_connection.clone(), self.workspace_service.clone())
    }

    pub fn with_workspace(&self, workspace_name: &str) -> ApplicationWithWorkspace {
        ApplicationWithWorkspace::new(workspace_name.to_owned())
    }
}

pub(crate) struct ApplicationWithWorkspace {
    workspace_name: String,
}

impl ApplicationWithWorkspace {
    pub fn new(workspace_name: String) -> Self {
        Self { workspace_name }
    }

    pub fn secret(&self) -> impl SecretUseCase {
        SecretUseCaseImpl::new(self.workspace_name.to_owned())
    }
}

pub(super) async fn init(config: &ApplicationConfig) -> anyhow::Result<Application> {
    let database_connection = init_database_connection(config).await?;
    let workspace_service = Arc::new(WorkspaceServiceImpl::new());

    Ok(Application { database_connection, workspace_service })
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
