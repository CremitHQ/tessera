use std::path::PathBuf;

use config::{Config, File, FileFormat};
use nebula_config_path::config_dir;
use serde::{Deserialize, Serialize};
use url::Url;

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct NebulaConfigs {
    pub profiles: Vec<NebulaConfig>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct NebulaConfig {
    pub name: String,
    pub workspace: String,
    pub backbone: BackboneConfig,
    pub authorization: AuthorizationConfig,
}

impl NebulaConfig {
    pub fn new(
        profile: String,
        workspace: String,
        backbone: BackboneConfig,
        authorization: AuthorizationConfig,
    ) -> Self {
        Self { name: profile, workspace, backbone, authorization }
    }

    pub fn load(profile: &str, config_path: Option<PathBuf>) -> anyhow::Result<NebulaConfig> {
        let config_file_path = config_file_path(config_path)?;

        let config: NebulaConfigs = Config::builder()
            .add_source(File::from(config_file_path.clone()).format(FileFormat::Toml))
            .build()?
            .try_deserialize()?;

        config.profiles.into_iter().find(|c| c.name == profile).ok_or_else(|| {
            anyhow::anyhow!(format!(
                "Profile `{}` not found. Please check your configuration file at {}",
                profile,
                config_file_path.to_str().expect("Failed to convert path to string")
            ))
        })
    }

    pub fn append(&self) -> anyhow::Result<()> {
        let config_file_path = config_file_path(None)?;
        let mut config: NebulaConfigs = Config::builder()
            .add_source(File::from(config_file_path.clone()).format(FileFormat::Toml))
            .build()?
            .try_deserialize()
            .unwrap_or_default();
        config.profiles.push(self.clone());
        Ok(std::fs::write(config_file_path, toml::to_string(&config)?)?)
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct BackboneConfig {
    pub host: Url,
}

impl BackboneConfig {
    pub fn new(host: Url) -> Self {
        Self { host }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AuthorizationConfig {
    pub host: Url,
    #[serde(flatten)]
    pub method: AuthorizationMethod,
}

impl AuthorizationConfig {
    pub fn new(host: Url, method: AuthorizationMethod) -> Self {
        Self { host, method }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", tag = "method")]
pub enum AuthorizationMethod {
    Saml,
    MachineIdentity { token: String },
}

const NEBULA_PATH: &str = "nebula";
const TOKEN_PATH: &str = ".token";

fn config_file_path(config_path: Option<PathBuf>) -> anyhow::Result<PathBuf> {
    if let Some(path_override) = config_path {
        Ok(path_override)
    } else {
        let user_config_dir = config_dir().ok_or_else(|| anyhow::anyhow!("Failed to get user config directory"))?;
        let nebula_config_dir = user_config_dir.join(NEBULA_PATH);
        if !nebula_config_dir.exists() {
            std::fs::create_dir_all(&nebula_config_dir)?;
        }
        Ok(nebula_config_dir.join("cli_config.toml"))
    }
}

fn token_file_path() -> anyhow::Result<PathBuf> {
    let user_config_dir = config_dir().ok_or_else(|| anyhow::anyhow!("Failed to get user config directory"))?;
    let nebula_config_dir = user_config_dir.join(NEBULA_PATH);
    if !nebula_config_dir.exists() {
        std::fs::create_dir_all(&nebula_config_dir)?;
    }
    Ok(nebula_config_dir.join(TOKEN_PATH))
}

pub fn has_profile(profile: &str, config_path: Option<PathBuf>) -> anyhow::Result<bool> {
    let config_file_path = config_file_path(config_path)?;

    let config: NebulaConfigs = Config::builder()
        .add_source(File::from(config_file_path.clone()).format(FileFormat::Toml))
        .build()?
        .try_deserialize()?;

    Ok(config.profiles.into_iter().any(|c| c.name == profile))
}

pub fn load_token() -> anyhow::Result<String> {
    let token_path = token_file_path()?;

    Ok(std::fs::read_to_string(token_path)?)
}

pub fn save_token(token: &str) -> anyhow::Result<()> {
    let token_path = token_file_path()?;

    Ok(std::fs::write(token_path, token)?)
}
