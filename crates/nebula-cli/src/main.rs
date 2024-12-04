use anyhow::Result;
use clap::Parser as _;
use command::Cli;

mod api;
mod command;
mod config;
mod utils;

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    cli.run().await?;

    Ok(())
}
