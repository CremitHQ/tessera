use std::sync::Arc;

use sea_orm::DatabaseConnection;

use crate::{
    config::ApplicationConfig,
    database::{connect_to_database, AuthMethod},
    domain::vault::VaultServiceImpl,
};

use self::vault::{VaultUseCase, VaultUseCaseImpl};

pub mod vault;

pub(crate) struct Application {
    database_connection: Arc<DatabaseConnection>,
    vault_service: Arc<VaultServiceImpl>,
}

impl Application {
    pub fn vault(&self) -> impl VaultUseCase {
        VaultUseCaseImpl::new(self.database_connection.clone(), self.vault_service.clone())
    }
}

pub(super) async fn init(config: &ApplicationConfig) -> anyhow::Result<Application> {
    let database_connection = init_database_connection(config).await?;
    let vault_service = Arc::new(VaultServiceImpl::new());

    Ok(Application { database_connection, vault_service })
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
