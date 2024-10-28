use std::path::PathBuf;

use application::Application;
use clap::Parser;
use domain::authority::Authority;

use crate::logger::LoggerConfig;

mod application;
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
    let authority = Authority::new(&app_config)?;
    let application = Application::new(authority);

    server::run(application, app_config.into()).await?;
    Ok(())
}
