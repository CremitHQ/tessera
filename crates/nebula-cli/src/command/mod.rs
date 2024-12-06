use access_condition::AccessConditionCommand;
use async_trait::async_trait;
use authority::AuthorityCommand;
use clap::{command, Args, Parser};
use config::ConfigCommand;
use login::LoginCommand;
use path::PathCommand;
use secret::SecretCommand;

pub mod access_condition;
pub mod authority;
pub mod config;
pub mod login;
pub mod path;
pub mod secret;

#[derive(Args, Debug)]
pub struct GlobalArgs {
    #[arg(short = 'c', long, env = "NEBULA_CONFIG", global = true)]
    pub config: Option<String>,

    #[arg(short = 'p', long, env = "NEBULA_PROFILE", default_value = "default", global = true)]
    pub profile: String,
}

#[async_trait]
pub trait RunCommand {
    async fn run(&self, args: &GlobalArgs) -> anyhow::Result<()>;
}

#[derive(Parser, Debug)]
#[command(term_width = 0, version, name = "nebula")]
pub struct Cli {
    #[clap(subcommand)]
    pub command: CliCommand,
    #[clap(flatten)]
    pub args: GlobalArgs,
}

impl Cli {
    pub async fn run(&self) -> anyhow::Result<()> {
        self.command.run(&self.args).await
    }
}

#[derive(Parser, Debug)]
pub enum CliCommand {
    Login(LoginCommand),
    #[clap(subcommand)]
    Config(ConfigCommand),
    #[clap(subcommand)]
    Secret(SecretCommand),
    #[clap(subcommand)]
    AccessCondition(AccessConditionCommand),
    #[clap(subcommand)]
    Authority(AuthorityCommand),
    #[clap(subcommand)]
    Path(PathCommand),
}

#[async_trait]
impl RunCommand for CliCommand {
    async fn run(&self, args: &GlobalArgs) -> anyhow::Result<()> {
        match self {
            CliCommand::Config(ref config) => {
                config.run(args).await?;
            }
            CliCommand::Login(ref login) => {
                login.run(args).await?;
            }
            CliCommand::Secret(ref secret) => {
                secret.run(args).await?;
            }
            CliCommand::AccessCondition(ref access_condition) => {
                access_condition.run(args).await?;
            }
            CliCommand::Authority(ref authority) => {
                authority.run(args).await?;
            }
            CliCommand::Path(ref path) => {
                path.run(args).await?;
            }
        }
        Ok(())
    }
}
