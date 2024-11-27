use std::{
    sync::Arc,
    time::{Duration, SystemTime},
};

use aws_config::BehaviorVersion;
use aws_credential_types::provider::ProvideCredentials;
use aws_sigv4::{
    http_request::{sign, SignableBody, SignableRequest, SigningSettings},
    sign::v4::SigningParams,
};
use sea_orm::sqlx::postgres::PgConnectOptions;
use sea_orm::{ConnectOptions, Database, DatabaseConnection};
use url::Url;

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
