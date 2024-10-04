use std::path::PathBuf;

use clap::Parser;
use server::ServerConfig;

use crate::logger::LoggerConfig;

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
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    logger::init_logger(LoggerConfig::default());

    server::run(ServerConfig { port: args.port.unwrap_or(8080u16) }).await?;
    Ok(())
}
