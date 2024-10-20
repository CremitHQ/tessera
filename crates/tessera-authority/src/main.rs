use std::path::PathBuf;

use clap::Parser;

use crate::logger::LoggerConfig;

mod config;
mod logger;
mod server;

#[derive(Parser, Debug)]
#[command(version, about)]
struct Args {
    /// Sets a custom config file
    #[arg(short, long, value_name = "FILE")]
    pub config: Option<PathBuf>,
    /// Sets a port to start a authority server
    #[arg(short, long, value_name = "FILE")]
    pub port: Option<u16>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    let app_config = config::load_config(args.config, args.port)?;

    logger::init_logger(LoggerConfig::default());

    server::run((&app_config).into()).await?;
    Ok(())
}
