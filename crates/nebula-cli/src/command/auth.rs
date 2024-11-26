use async_trait::async_trait;
use clap::{Args, Subcommand};
use serde::{Deserialize, Serialize};

use super::RunCommand;

#[derive(Subcommand, Debug)]
pub enum AuthCommand {
    Login(LoginCommand),
}

#[async_trait]
impl RunCommand for AuthCommand {
    async fn run(&self) -> anyhow::Result<()> {
        match self {
            AuthCommand::Login(ref login) => {
                login.run().await?;
            }
        }
        Ok(())
    }
}

#[derive(Args, Debug)]
#[clap(disable_help_flag = true)]
pub struct LoginCommand {
    #[arg(short = 't', long, env = "NEBULA_MACHINE_IDENTITY_TOKEN", required_if_eq("method", "machine-token"))]
    pub token: Option<String>,

    #[arg(short = 'h', long, env = "NEBULA_HOST")]
    pub host: String,

    #[arg(short = 'm', long, env = "NEBULA_AUTH_METHOD", default_value_t, value_enum)]
    pub method: AuthMethod,
}

#[async_trait]
impl RunCommand for LoginCommand {
    async fn run(&self) -> anyhow::Result<()> {
        Ok(())
    }
}

#[derive(clap::ValueEnum, Clone, Default, Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AuthMethod {
    #[default]
    Saml,
    MachineToken,
}
