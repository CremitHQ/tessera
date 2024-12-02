use anyhow::Result;
use clap::Parser as _;
use command::Cli;

mod api;
mod command;
mod config;
mod utils;

fn main() -> Result<()> {
    let cli = Cli::parse();
    smol::block_on(async move { cli.run().await })?;

    Ok(())
}
