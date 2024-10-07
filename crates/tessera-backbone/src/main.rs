use std::path::PathBuf;

use clap::Parser;

use crate::logger::LoggerConfig;

mod application;
mod config;
mod database;
mod logger;
mod server;

#[derive(Parser, Debug)]
#[command(version, about)]
struct Args {
    /// Sets a custom config file
    #[arg(short, long, value_name = "FILE")]
    pub config: Option<PathBuf>,
    /// Sets a port to start a backbone server
    #[arg(short, long, value_name = "FILE")]
    pub port: Option<u16>,
    /// Sets a database host
    #[arg(long)]
    pub database_host: Option<String>,
    /// Sets a database port
    #[arg(long)]
    pub database_port: Option<String>,
    /// Sets a database name
    #[arg(long)]
    pub database_name: Option<String>,
    /// Sets a database username
    #[arg(long)]
    pub database_username: Option<String>,
    /// Sets a database password
    #[arg(long)]
    pub database_password: Option<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    let app_config = config::load_config(args)?;

    logger::init_logger(LoggerConfig::default());

    let application = application::init(&app_config).await?;

    server::run(application, (&app_config).into()).await?;
    Ok(())
}
