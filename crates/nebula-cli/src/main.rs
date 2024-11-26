use anyhow::Result;
use clap::Parser as _;
use command::{Cli, RunCommand};

mod command;

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    cli.run().await?;

    Ok(())
}
