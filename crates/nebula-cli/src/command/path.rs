use std::io::stdout;

use async_trait::async_trait;
use clap::{Args, Subcommand};

use crossterm::execute;
use crossterm::style::{Color, Print, ResetColor, SetForegroundColor};

use crate::api::backbone::{create_path, CreatePathRequest};
use crate::config::{load_token, NebulaConfig};

use super::{GlobalArgs, RunCommand};

#[derive(Subcommand, Debug)]
pub enum PathCommand {
    Create(PathCreateCommand),
}

#[async_trait]
impl RunCommand for PathCommand {
    async fn run(&self, args: &GlobalArgs) -> anyhow::Result<()> {
        match self {
            PathCommand::Create(cmd) => cmd.run(args).await,
        }
    }
}

#[derive(Args, Debug)]
pub struct PathCreateCommand {
    #[clap(long)]
    pub path: String,
}

#[async_trait]
impl RunCommand for PathCreateCommand {
    async fn run(&self, args: &GlobalArgs) -> anyhow::Result<()> {
        let config = NebulaConfig::load(args.profile.as_str(), args.config.clone().map(Into::into))?;
        let token = load_token(&args.profile)?;
        let backbone_url = config.backbone.host;
        let workspace_name = config.workspace;

        let request = CreatePathRequest {
            path: self.path.clone(),
            applied_policies: vec![], // TODO: Implement applied policies for path creation
        };

        create_path(backbone_url.clone(), &workspace_name, request, &token).await?;

        execute!(stdout(), SetForegroundColor(Color::Green), Print("✅ Successfully created path\n"), ResetColor)?;

        Ok(())
    }
}
