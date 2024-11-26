use async_trait::async_trait;
use auth::AuthCommand;
use clap::{command, Parser};

pub mod auth;

#[async_trait]
pub trait RunCommand {
    async fn run(&self) -> anyhow::Result<()>;
}

#[derive(Parser, Debug)]
#[command(term_width = 0, version, name = "nebula")]
pub enum Cli {
    #[clap(subcommand)]
    Auth(AuthCommand),
}

#[async_trait]
impl RunCommand for Cli {
    async fn run(&self) -> anyhow::Result<()> {
        match self {
            Cli::Auth(ref auth) => {
                auth.run().await?;
            }
        }
        Ok(())
    }
}
