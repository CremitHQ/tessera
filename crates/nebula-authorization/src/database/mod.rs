use std::{
    borrow::Borrow,
    fmt::Display,
    ops::Deref,
    sync::Arc,
    time::{Duration, SystemTime},
};

use async_trait::async_trait;
use aws_config::BehaviorVersion;
use aws_credential_types::provider::ProvideCredentials;
use aws_sigv4::{
    http_request::{sign, SignableBody, SignableRequest, SigningSettings},
    sign::v4::SigningParams,
};
use sea_orm::{sqlx::postgres::PgConnectOptions, ConnectionTrait, DatabaseBackend, Statement, TransactionTrait};
use sea_orm::{ConnectOptions, Database, DatabaseConnection, DatabaseTransaction, DbErr, TryFromU64, TryGetError};
use ulid::Ulid;
use url::Url;

pub use workspace_migration::{migrate_all_workspaces, migrate_workspace};

pub(crate) mod machine_identity;
pub(crate) mod machine_identity_attribute;
pub(crate) mod machine_identity_token;
pub(crate) mod types;
pub(crate) mod workspace;
mod workspace_migration;

pub(crate) enum AuthMethod {
    Credential { username: String, password: Option<String> },
    RdsIamAuth { host: String, port: u16, username: String },
}

async fn generate_rds_iam_token(db_hostname: &str, port: u16, db_username: &str) -> anyhow::Result<String> {
    let config = aws_config::load_defaults(BehaviorVersion::latest()).await;

    let credentials = config
        .credentials_provider()
        .expect("no credentials provider found")
        .provide_credentials()
        .await
        .expect("unable to load credentials");
    let identity = credentials.into();
    let region = config.region().unwrap().to_string();

    let mut signing_settings = SigningSettings::default();
    signing_settings.expires_in = Some(Duration::from_secs(900));
    signing_settings.signature_location = aws_sigv4::http_request::SignatureLocation::QueryParams;

    let signing_params = SigningParams::builder()
        .identity(&identity)
        .region(&region)
        .name("rds-db")
        .time(SystemTime::now())
        .settings(signing_settings)
        .build()?;

    let url = format!(
        "https://{db_hostname}:{port}/?Action=connect&DBUser={db_user}",
        db_hostname = db_hostname,
        port = port,
        db_user = db_username
    );

    let signable_request =
        SignableRequest::new("GET", &url, std::iter::empty(), SignableBody::Bytes(&[])).expect("signable request");

    let (signing_instructions, _signature) = sign(signable_request, &signing_params.into())?.into_parts();

    let mut url = url::Url::parse(&url).unwrap();
    for (name, value) in signing_instructions.params() {
        url.query_pairs_mut().append_pair(name, value);
    }

    let response = url.to_string().split_off("https://".len());

    Ok(response)
}

pub async fn connect_to_database(
    host: &str,
    port: u16,
    database_name: &str,
    auth: &AuthMethod,
) -> anyhow::Result<Arc<DatabaseConnection>> {
    connect_to_database_with_search_path(host, port, database_name, auth, None).await
}

async fn connect_to_database_with_search_path(
    host: &str,
    port: u16,
    database_name: &str,
    auth: &AuthMethod,
    search_path: Option<&str>,
) -> anyhow::Result<Arc<DatabaseConnection>> {
    let mut options = match auth {
        AuthMethod::Credential { username, password } => {
            let mut conn_str = Url::parse(&format!("postgres://{host}:{port}/{database_name}?sslmode=Prefer"))?;
            conn_str.set_username(username).unwrap();
            conn_str.set_password(password.as_deref()).unwrap();
            ConnectOptions::new(conn_str)
        }
        AuthMethod::RdsIamAuth { host: auth_host, port: auth_port, username } => {
            let password = generate_rds_iam_token(auth_host, *auth_port, username).await?;
            let mut conn_str = Url::parse(&format!("postgres://{host}:{port}/postgres?sslmode=Prefer"))?;
            conn_str.set_username(username).unwrap();
            conn_str.set_password(Some(urlencoding::encode(&password).as_ref())).unwrap();
            ConnectOptions::new(conn_str)
        }
    };

    if let Some(search_path) = search_path {
        options.set_schema_search_path(search_path);
    }

    options.sqlx_logging_level(tracing::log::LevelFilter::Debug);

    let connection = Arc::new(Database::connect(options).await?);

    if let AuthMethod::RdsIamAuth { host: auth_host, port: auth_port, username } = auth {
        reassign_token_periodically_to_database(connection.clone(), auth_host.clone(), *auth_port, username.clone());
    };

    Ok(connection)
}

fn reassign_token_periodically_to_database(
    database: Arc<DatabaseConnection>,
    database_host: String,
    database_port: u16,
    database_user: String,
) {
    tokio::spawn({
        async move {
            loop {
                tokio::time::sleep(tokio::time::Duration::from_secs(600)).await;
                if let Ok(token) = generate_rds_iam_token(&database_host, database_port, &database_user).await {
                    let pool = database.get_postgres_connection_pool();
                    let new_option = PgConnectOptions::new()
                        .host(&database_host)
                        .database("postgres")
                        .username(&database_user)
                        .password(&token);
                    pool.set_connect_options(new_option);
                }
            }
        }
    });
}

#[derive(Clone, Debug, PartialEq, Eq, Copy)]
pub struct UlidId(Ulid);

impl UlidId {
    pub fn new(ulid: Ulid) -> Self {
        Self(ulid)
    }

    pub fn inner(self) -> Ulid {
        self.0
    }
}

impl From<Ulid> for UlidId {
    fn from(value: Ulid) -> Self {
        Self::new(value)
    }
}

impl From<&Ulid> for UlidId {
    fn from(value: &Ulid) -> Self {
        Self::new(value.to_owned())
    }
}

impl AsRef<Ulid> for UlidId {
    fn as_ref(&self) -> &Ulid {
        &self.0
    }
}

impl Borrow<Ulid> for UlidId {
    fn borrow(&self) -> &Ulid {
        self.as_ref()
    }
}

impl Display for UlidId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl Deref for UlidId {
    type Target = Ulid;

    fn deref(&self) -> &Self::Target {
        self.as_ref()
    }
}

impl From<UlidId> for sea_orm::Value {
    fn from(value: UlidId) -> Self {
        Self::String(Some(Box::new(value.to_string())))
    }
}

impl sea_orm::TryGetable for UlidId {
    fn try_get_by<I: sea_orm::ColIdx>(
        res: &sea_orm::prelude::QueryResult,
        index: I,
    ) -> Result<Self, sea_orm::TryGetError> {
        let val = String::try_get_by(res, index)?;

        Ulid::from_string(&val)
            .map(Self::from)
            .map_err(|e| TryGetError::DbErr(DbErr::TryIntoErr { from: "String", into: "Ulid", source: Box::new(e) }))
    }
}

impl TryFromU64 for UlidId {
    fn try_from_u64(n: u64) -> Result<Self, DbErr> {
        let val = String::try_from_u64(n)?;
        Ulid::from_string(&val).map(Self::from).map_err(|e| DbErr::TryIntoErr {
            from: "u64",
            into: "Ulid",
            source: Box::new(e),
        })
    }
}

impl sea_orm::sea_query::ValueType for UlidId {
    fn try_from(v: sea_orm::prelude::Value) -> Result<Self, sea_orm::sea_query::ValueTypeErr> {
        match v {
            sea_orm::Value::String(v) => {
                let v = v.ok_or(sea_orm::sea_query::ValueTypeErr)?;
                Ulid::from_string(&v).map(Self::from).map_err(|_| sea_orm::sea_query::ValueTypeErr)
            }
            _ => Err(sea_orm::sea_query::ValueTypeErr),
        }
    }

    fn type_name() -> String {
        "Ulid".to_owned()
    }

    fn array_type() -> sea_orm::sea_query::ArrayType {
        sea_orm::sea_query::ArrayType::String
    }

    fn column_type() -> sea_orm::prelude::ColumnType {
        sea_orm::prelude::ColumnType::String(sea_orm::sea_query::StringLen::N(26))
    }
}

#[async_trait]
pub trait WorkspaceScopedTransaction {
    async fn begin_with_workspace_scope(&self, workspace_slug: &str) -> Result<DatabaseTransaction, DbErr>;
}

#[async_trait]
impl WorkspaceScopedTransaction for DatabaseConnection {
    async fn begin_with_workspace_scope(&self, workspace_slug: &str) -> Result<DatabaseTransaction, DbErr> {
        let transaction = self.begin().await?;
        transaction
            .execute(Statement::from_string(
                DatabaseBackend::Postgres,
                format!("SET LOCAL search_path TO \"{workspace_slug}\", \"public\";"),
            ))
            .await?;

        Ok(transaction)
    }
}

#[async_trait]
pub(crate) trait Persistable {
    type Error;

    async fn persist(self, transaction: &DatabaseTransaction) -> std::result::Result<(), Self::Error>;
}
