use std::{path::PathBuf, sync::Arc, time::Duration};

use application::Application;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use clap::Parser;
use domain::authority::Authority;
use nebula_secret_sharing::shamir::Share;
use nebula_token::auth::jwks_discovery::{CachedRemoteJwksDiscovery, JwksDiscovery};

use crate::logger::LoggerConfig;

mod application;
mod config;
mod database;
mod domain;
mod logger;
mod server;

#[derive(Parser, Debug)]
#[command(version, about)]
struct Args {
    /// Sets a custom config file
    #[arg(short, long, value_name = "FILE")]
    pub config: Option<PathBuf>,
    /// Sets a port to start a authority server
    #[arg(short, long, value_name = "PORT")]
    pub port: Option<u16>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    logger::init_logger(LoggerConfig::default());
    let args = Args::parse();
    let app_config = config::load_config(args.config, args.port)?;
    let authority = Authority::new(&app_config).await?;
    let jwks_discovery: Arc<dyn JwksDiscovery + Send + Sync> =
        if let Some(refresh_interval) = app_config.jwks_refresh_interval {
            Arc::new(CachedRemoteJwksDiscovery::new(app_config.jwks_url.clone(), Duration::from_secs(refresh_interval)))
        } else {
            Arc::new(CachedRemoteJwksDiscovery::new(app_config.jwks_url.clone(), Duration::from_secs(10)))
        };
    let application = Application::new(authority, jwks_discovery);
    if let Some(key_shares) = &app_config.disarm_key_shares {
        let key_shares = key_shares
            .iter()
            .map(|s| {
                STANDARD
                    .decode(s.as_bytes())
                    .map_err(|e| anyhow::anyhow!(e))
                    .and_then(|decoded| rmp_serde::from_slice(&decoded).map_err(|e| anyhow::anyhow!(e)))
            })
            .collect::<Result<Vec<Share>, _>>()?;
        application.authority.disarm_key_pair_storage(&key_shares).await?;
    }

    server::run(application, app_config.into()).await?;
    Ok(())
}
