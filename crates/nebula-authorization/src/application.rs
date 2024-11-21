use std::sync::Arc;

use crate::{
    config::{ApplicationConfig, UpstreamIdpConfig},
    database::{connect_to_database, AuthMethod},
    domain::connector::saml::{SAMLConnector, SAMLConnertorConfig},
};

use nebula_token::jwk::jwk_set::{JwkSet, JWK_SET_DEFAULT_KEY_ID};
use sea_orm::DatabaseConnection;
use url::Url;

pub struct Application {
    pub base_url: Url,
    pub database_connection: Arc<DatabaseConnection>,
    pub connector: Arc<SAMLConnector>,
    pub token_service: Arc<TokenService>,
}

pub struct TokenService {
    pub lifetime: u64,
    pub jwks: JwkSet,
    pub jwk_kid: String,
}

impl Application {
    pub async fn new(config: &ApplicationConfig) -> anyhow::Result<Self> {
        let database_connection = init_database_connection(config).await?;

        let saml_config = match config.upstream_idp {
            UpstreamIdpConfig::Saml(ref saml) => SAMLConnertorConfig::builder()
                .redirect_uri(config.base_url.join("/callback/saml")?)
                .sso_url(&saml.sso_url)
                .idp_issuer(&saml.idp_issuer)
                .maybe_entity_id(saml.entity_id.as_ref())
                .ca(openssl::x509::X509::from_pem(saml.ca.as_bytes())?)
                .attributes_config(saml.attributes.clone())
                .workspace_config(config.workspace.clone())
                .build(),
        };

        let saml_connector = Arc::new(SAMLConnector::new(saml_config)?);

        let (jwks, kid) = match (&config.token.jwks, &config.token.jwk_kid) {
            (Some(jwks), Some(kid)) => (jwks.clone(), kid.clone()),
            (Some(jwks), None) => (jwks.clone(), JWK_SET_DEFAULT_KEY_ID.to_string()),
            _ => (JwkSet::default(), JWK_SET_DEFAULT_KEY_ID.to_string()),
        };

        Ok(Self {
            base_url: config.base_url.clone(),
            database_connection,
            connector: saml_connector,
            token_service: Arc::new(TokenService { lifetime: config.token.lifetime, jwks, jwk_kid: kid }),
        })
    }
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
