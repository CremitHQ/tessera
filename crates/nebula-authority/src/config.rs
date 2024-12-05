use std::path::PathBuf;

use config::{Config, File, FileFormat};
use nebula_config_path::config_dir;
use serde::Deserialize;
use url::Url;

#[derive(Deserialize, Debug)]
pub(crate) struct ApplicationConfig {
    pub port: u16,
    pub storage: StorageConfig,
    pub backbone: BackboneConfig,
    pub authority: AuthorityConfig,
    pub jwks_url: Url,
    pub jwks_refresh_interval: Option<u64>,
    pub disarm_key_shares: Option<Vec<String>>,
    pub path_prefix: Option<String>,
    pub cors: Option<CorsConfig>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", tag = "type")]
pub(crate) enum StorageConfig {
    File { path: String },
    Postgres(PostgresConfig),
}

#[derive(Deserialize, Debug)]
pub struct PostgresConfig {
    pub host: String,
    pub port: u16,
    pub database_name: String,
    pub auth: PostgresAuthMethod,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", tag = "method")]
pub(crate) enum PostgresAuthMethod {
    Credential { username: String, password: Option<String> },
    RdsIamAuth { username: String },
}

#[derive(Deserialize, Debug)]
pub(crate) struct BackboneConfig {
    pub host: Url,
}

#[derive(Deserialize, Debug)]
pub(crate) struct AuthorityConfig {
    pub name: String,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", tag = "type", content = "domains")]
pub(crate) enum CorsConfig {
    AllowAll,
    AllowList(Vec<String>),
}

pub(super) fn load_config(
    path_override: Option<PathBuf>,
    port_override: Option<u16>,
) -> anyhow::Result<ApplicationConfig> {
    let config_file_path = if let Some(path_override) = path_override {
        path_override
    } else {
        let user_config_dir = config_dir().expect("Failed to get user config directory");
        let nebula_config_dir = user_config_dir.join("nebula");
        if !nebula_config_dir.exists() {
            std::fs::create_dir_all(&nebula_config_dir)?;
        }
        nebula_config_dir.join("authority_config.toml")
    };

    let config: ApplicationConfig = Config::builder()
        .add_source(File::from(config_file_path).format(FileFormat::Toml))
        .set_default("port", 8090)?
        .set_override_option("port", port_override)?
        .build()?
        .try_deserialize()?;

    Ok(config)
}
