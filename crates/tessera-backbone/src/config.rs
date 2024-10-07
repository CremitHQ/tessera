use std::path::{Path, PathBuf};

use config::{Config, File, FileFormat};
use serde::Deserialize;

#[derive(Deserialize, Debug)]
pub(crate) struct ApplicationConfig {
    pub port: u16,
}

pub(super) fn load_config(
    path_override: Option<PathBuf>,
    port_override: Option<u16>,
) -> anyhow::Result<ApplicationConfig> {
    let config_file_path = if let Some(path_override) = path_override {
        path_override
    } else {
        let xdg_dirs = xdg::BaseDirectories::with_prefix("tessera").unwrap();

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
        .set_default("port", 8080)?
        .add_source(File::new(config_file_path.to_str().unwrap(), FileFormat::Toml))
        .set_override_option("port", port_override)?
        .build()?
        .try_deserialize()?;

    Ok(config)
}

fn write_default_config_file(path: &Path) -> anyhow::Result<()> {
    let default_config_content = include_str!("../static/default_config.toml");
    std::fs::write(path, default_config_content)?;
    Ok(())
}
