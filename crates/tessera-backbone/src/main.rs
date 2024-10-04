use std::path::{Path, PathBuf};

use clap::{Arg, Parser};
use tracing::{debug, info};

use crate::logger::LoggerConfig;

mod logger;
mod server;

#[derive(Parser, Debug)]
#[command(version, about)]
struct Args {
    /// Sets a custom config file
    #[arg(short, long, value_name = "FILE")]
    pub config: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    logger::init_logger(LoggerConfig::default());
    server::run().await?;
    Ok(())
}
