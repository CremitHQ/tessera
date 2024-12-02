use std::path::Path;

use crate::Args;
use config::{Config, File, FileFormat};
use serde::Deserialize;
use url::Url;

#[derive(Deserialize, Debug)]
pub(crate) struct ApplicationConfig {
    pub port: u16,
    pub jwks_url: Url,
    pub jwks_refresh_interval: Option<u64>,
    pub database: DatabaseConfig,
}

#[derive(Deserialize, Debug)]
pub struct DatabaseConfig {
    pub host: String,
    pub port: u16,
    pub database_name: String,
    pub auth: DatabaseAuthConfig,
}

#[derive(Deserialize, Debug)]
#[serde(tag = "method", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DatabaseAuthConfig {
    Credential { username: String, password: Option<String> },
    RdsIamAuth { username: String },
}

pub(super) fn load_config(args: Args) -> anyhow::Result<ApplicationConfig> {
    let config_file_path = if let Some(path_override) = args.config {
        path_override
    } else {
        let xdg_dirs = xdg::BaseDirectories::with_prefix("nebula").unwrap();

        let user_config_dir = xdg_dirs.get_config_home();
        if !user_config_dir.exists() {
            std::fs::create_dir_all(&user_config_dir)?;
        }

        let mut config_file_path = user_config_dir.clone();
        config_file_path.push("backbone_config.toml");

        if !config_file_path.exists() {
            write_default_config_file(&config_file_path)?;
        }

        config_file_path
    };

    let config: ApplicationConfig = Config::builder()
        .add_source(File::new(config_file_path.to_str().unwrap(), FileFormat::Toml))
        .set_override_option("port", args.port.map(|port| port.to_string()))?
        .set_override_option("database.host", args.database_host)?
        .set_override_option("database.port", args.database_port)?
        .set_override_option("database.database_name", args.database_name)?
        .set_override_option("database.auth.username", args.database_username)?
        .set_override_option("database.auth.password", args.database_password)?
        .build()?
        .try_deserialize()?;

    Ok(config)
}

fn write_default_config_file(path: &Path) -> anyhow::Result<()> {
    let default_config_content = include_str!("../static/default_config.toml");
    std::fs::write(path, default_config_content)?;
    Ok(())
}
