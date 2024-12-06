use std::io::stdout;

use async_trait::async_trait;
use clap::{Args, Subcommand};
use comfy_table::modifiers::UTF8_ROUND_CORNERS;
use comfy_table::presets::UTF8_FULL;
use comfy_table::{Cell, Table};
use crossterm::execute;
use crossterm::style::{Color, Print, ResetColor, SetForegroundColor};

use crate::api::backbone::{create_access_condition, get_access_conditions, PostPolicyRequest};
use crate::config::{load_token, NebulaConfig};

use super::{GlobalArgs, RunCommand};

#[derive(Subcommand, Debug)]
pub enum AccessConditionCommand {
    List(AccessConditionListCommand),
    Create(AccessConditionCreateCommand),
}

#[async_trait]
impl RunCommand for AccessConditionCommand {
    async fn run(&self, args: &GlobalArgs) -> anyhow::Result<()> {
        match self {
            AccessConditionCommand::List(cmd) => cmd.run(args).await,
            AccessConditionCommand::Create(cmd) => cmd.run(args).await,
        }
    }
}

#[derive(Args, Debug)]
pub struct AccessConditionListCommand {}

#[async_trait]
impl RunCommand for AccessConditionListCommand {
    async fn run(&self, args: &GlobalArgs) -> anyhow::Result<()> {
        let config = NebulaConfig::load(args.profile.as_str(), args.config.clone().map(Into::into))?;
        let token = load_token(&args.profile)?;
        let backbone_url = config.backbone.host;
        let workspace_name = config.workspace;

        let access_conditions = get_access_conditions(backbone_url.clone(), &workspace_name, &token).await?;

        let mut table = Table::new();
        table.load_preset(UTF8_FULL).apply_modifier(UTF8_ROUND_CORNERS);
        table.set_header(vec!["ID", "Name", "Expression"]);

        for access_condition in access_conditions {
            table.add_row(vec![
                Cell::new(access_condition.id),
                Cell::new(access_condition.name),
                Cell::new(access_condition.expression),
            ]);
        }
        println!("{table}");
        Ok(())
    }
}

#[derive(Args, Debug)]
pub struct AccessConditionCreateCommand {
    #[clap(short = 'n', long)]
    pub name: String,
    #[clap(short = 'e', long)]
    pub expression: String,
}

#[async_trait]
impl RunCommand for AccessConditionCreateCommand {
    async fn run(&self, args: &GlobalArgs) -> anyhow::Result<()> {
        let config = NebulaConfig::load(args.profile.as_str(), args.config.clone().map(Into::into))?;
        let token = load_token(&args.profile)?;
        let backbone_url = config.backbone.host;
        let workspace_name = config.workspace;

        let request = PostPolicyRequest { name: self.name.clone(), expression: self.expression.clone() };

        create_access_condition(backbone_url.clone(), &workspace_name, request, &token).await?;

        execute!(
            stdout(),
            SetForegroundColor(Color::Green),
            Print("✅ Successfully created access condition\n"),
            ResetColor
        )?;

        Ok(())
    }
}
