use async_trait::async_trait;
use clap::{Args, Subcommand};
use comfy_table::modifiers::UTF8_ROUND_CORNERS;
use comfy_table::presets::UTF8_FULL;
use comfy_table::{Cell, Table};

use crate::api::backbone::get_access_conditions;
use crate::config::{load_token, NebulaConfig};

use super::{GlobalArgs, RunCommand};

#[derive(Subcommand, Debug)]
pub enum AccessConditionCommand {
    List(AccessConditionListCommand),
}

#[async_trait]
impl RunCommand for AccessConditionCommand {
    async fn run(&self, args: &GlobalArgs) -> anyhow::Result<()> {
        match self {
            AccessConditionCommand::List(cmd) => cmd.run(args).await,
        }
    }
}

#[derive(Args, Debug)]
pub struct AccessConditionListCommand {}

#[async_trait]
impl RunCommand for AccessConditionListCommand {
    async fn run(&self, args: &GlobalArgs) -> anyhow::Result<()> {
        let config = NebulaConfig::load(args.profile.as_str(), args.config.clone().map(Into::into))?;
        let token = load_token()?;
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
