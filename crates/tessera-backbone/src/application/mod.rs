use sea_orm::DatabaseConnection;

use crate::{
    config::ApplicationConfig,
    database::{connect_to_database, AuthMethod},
};

use self::vault::{VaultUseCase, VaultUseCaseImpl};

pub mod vault;

pub(crate) struct Application {
    database_connection: DatabaseConnection,
}

impl Application {
    pub fn vault(&self) -> impl VaultUseCase {
        VaultUseCaseImpl::new(self.database_connection.clone())
    }
}

pub(super) async fn init(config: &ApplicationConfig) -> anyhow::Result<Application> {
    let database_connection = init_database_connection(config).await?;

    Ok(Application { database_connection })
}

async fn init_database_connection(config: &ApplicationConfig) -> anyhow::Result<DatabaseConnection> {
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
