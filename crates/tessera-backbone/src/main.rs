use tracing::info;

use crate::logger::LoggerConfig;

mod logger;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    logger::init_logger(LoggerConfig::default());
    info!("Hello, world!");
    Ok(())
}
