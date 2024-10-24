use std::path::PathBuf;

use clap::Parser;
use domain::application::Application;

use crate::logger::LoggerConfig;

mod config;
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
    let application = Application::new(&app_config)?;
    let _key_pair = application.key_pair(&app_config.authority.name).await?;

    server::run((&app_config).into()).await?;
    Ok(())
}
