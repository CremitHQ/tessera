use std::io::stdout;

use async_trait::async_trait;
use clap::{Args, Subcommand};
use comfy_table::modifiers::UTF8_ROUND_CORNERS;
use comfy_table::presets::UTF8_FULL;
use comfy_table::{Cell, Table};
use crossterm::execute;
use crossterm::style::{Color, Print, ResetColor, SetForegroundColor};
use inquire::validator::Validation;
use inquire::{CustomType, Password, Text};

use crate::api::authority::{disarm, init};
use crate::api::backbone::{add_authority, get_authorities, PostAuthorityRequest};
use crate::config::{load_token, NebulaConfig};
use crate::utils::validation::validate_url;

use super::{GlobalArgs, RunCommand};

#[derive(Subcommand, Debug)]
pub enum AuthorityCommand {
    List(AuthorityListCommand),
    Init(AuthorityInitCommand),
    Add(AuthorityAddCommand),
    Disarm(AuthorityDisarmCommand),
}

#[async_trait]
impl RunCommand for AuthorityCommand {
    async fn run(&self, args: &GlobalArgs) -> anyhow::Result<()> {
        match self {
            AuthorityCommand::List(cmd) => cmd.run(args).await,
            AuthorityCommand::Init(cmd) => cmd.run(args).await,
            AuthorityCommand::Add(cmd) => cmd.run(args).await,
            AuthorityCommand::Disarm(cmd) => cmd.run(args).await,
        }
    }
}

#[derive(Args, Debug)]
pub struct AuthorityListCommand {}

#[async_trait]
impl RunCommand for AuthorityListCommand {
    async fn run(&self, args: &GlobalArgs) -> anyhow::Result<()> {
        let config = NebulaConfig::load(args.profile.as_str(), args.config.clone().map(Into::into))?;
        let token = load_token(&args.profile)?;
        let backbone_url = config.backbone.host;
        let workspace_name = config.workspace;

        let authorities = get_authorities(backbone_url.clone(), &workspace_name, &token).await?;

        let mut table = Table::new();
        table.load_preset(UTF8_FULL).apply_modifier(UTF8_ROUND_CORNERS);
        table.set_header(vec!["Name", "Host"]);

        for authority in authorities {
            table.add_row(vec![Cell::new(authority.name), Cell::new(authority.host)]);
        }
        println!("{table}");
        Ok(())
    }
}

#[derive(Args, Debug)]
pub struct AuthorityInitCommand {
    #[clap(short = 'n', long = "name")]
    name: String,

    #[clap(long = "shares")]
    secret_shares: Option<u8>,

    #[clap(long = "threshold")]
    secret_threshold: Option<u8>,

    #[clap(long = "file")]
    file: Option<String>,
}

#[async_trait]
impl RunCommand for AuthorityInitCommand {
    async fn run(&self, args: &GlobalArgs) -> anyhow::Result<()> {
        let config = NebulaConfig::load(args.profile.as_str(), args.config.clone().map(Into::into))?;
        let token = load_token(&args.profile)?;
        let backbone_url = config.backbone.host;
        let workspace_name = config.workspace;

        let authorities = get_authorities(backbone_url.clone(), &workspace_name, &token).await?;

        let authority = authorities
            .into_iter()
            .find(|a| a.name == self.name)
            .ok_or_else(|| anyhow::anyhow!(format!("Authority `{}` not found", self.name)))?;

        let (shares, threshold) = match (self.secret_shares, self.secret_threshold) {
            (Some(shares), Some(threshold)) => (shares, threshold),
            (Some(shares), None) => {
                let threshold = AuthorityInitCommand::get_threshold(shares)?;
                (shares, threshold)
            }
            (None, Some(threshold)) => {
                let shares = AuthorityInitCommand::get_shares(threshold)?;
                (shares, threshold)
            }
            (None, None) => {
                let shares = AuthorityInitCommand::get_shares(0)?;
                let threshold = AuthorityInitCommand::get_threshold(shares)?;
                (shares, threshold)
            }
        };

        let result = init(authority.host, shares, threshold).await?;

        if let Some(file) = &self.file {
            std::fs::write(file, result.join("\n"))?;
            execute!(
                stdout(),
                SetForegroundColor(Color::Green),
                Print("✅ Successfully saved shares to file\n"),
                ResetColor
            )?;
        } else {
            let mut table = Table::new();
            table.load_preset(UTF8_FULL).apply_modifier(UTF8_ROUND_CORNERS);
            table.set_header(vec!["Share"]);
            for share in result {
                table.add_row(vec![Cell::new(share)]);
            }
            println!("{table}");
        }

        Ok(())
    }
}

impl AuthorityInitCommand {
    fn get_threshold(shares: u8) -> anyhow::Result<u8> {
        Ok(CustomType::<u8>::new("Enter the secret threshold (number of shares required to reconstruct the secret)")
            .with_validator(move |s: &u8| {
                if *s == 0 {
                    return Ok(Validation::Invalid("threshold must be greater than 0".into()));
                }

                if *s > shares {
                    return Ok(Validation::Invalid("threshold must be less than or equal to shares".into()));
                }
                Ok(Validation::Valid)
            })
            .with_error_message("Please enter a valid number")
            .prompt()?)
    }

    fn get_shares(threshold: u8) -> anyhow::Result<u8> {
        Ok(CustomType::<u8>::new("Enter the number of secret shares (number of shares to split the secret into)")
            .with_validator(move |s: &u8| {
                if *s == 0 {
                    return Ok(Validation::Invalid("shares must be greater than 0".into()));
                }
                if *s < threshold {
                    return Ok(Validation::Invalid(
                        format!("secret shares must be greater than or equal to {threshold}").into(),
                    ));
                }
                Ok(Validation::Valid)
            })
            .with_error_message("Please enter a valid number")
            .prompt()?)
    }
}

#[derive(Args, Debug)]
pub struct AuthorityAddCommand {
    #[clap(short = 'n', long = "name")]
    name: Option<String>,

    #[clap(long = "host")]
    host: Option<String>,
}

#[async_trait]
impl RunCommand for AuthorityAddCommand {
    async fn run(&self, args: &GlobalArgs) -> anyhow::Result<()> {
        let config = NebulaConfig::load(args.profile.as_str(), args.config.clone().map(Into::into))?;
        let token = load_token(&args.profile)?;
        let backbone_url = config.backbone.host;
        let workspace_name = config.workspace;

        let name = if let Some(name) = &self.name { name.clone() } else { Text::new("Authority name:").prompt()? };

        let host = if let Some(host) = &self.host {
            if matches!(validate_url(host), Ok(Validation::Valid)) {
                host.clone()
            } else {
                return Err(anyhow::anyhow!("Invalid host url"));
            }
        } else {
            Text::new("Authority host:").with_validator(validate_url).prompt()?
        };

        add_authority(backbone_url, &workspace_name, PostAuthorityRequest { name, host }, &token).await?;

        execute!(stdout(), SetForegroundColor(Color::Green), Print("✅ Successfully added authority\n"), ResetColor)?;

        Ok(())
    }
}

#[derive(Args, Debug)]
pub struct AuthorityDisarmCommand {
    #[clap(short = 'n', long = "name")]
    name: String,
}

#[async_trait]
impl RunCommand for AuthorityDisarmCommand {
    async fn run(&self, args: &GlobalArgs) -> anyhow::Result<()> {
        let config = NebulaConfig::load(args.profile.as_str(), args.config.clone().map(Into::into))?;
        let token = load_token(&args.profile)?;
        let backbone_url = config.backbone.host;
        let workspace_name = config.workspace;

        let authorities = get_authorities(backbone_url.clone(), &workspace_name, &token).await?;

        let authority = authorities
            .into_iter()
            .find(|a| a.name == self.name)
            .ok_or_else(|| anyhow::anyhow!(format!("Authority `{}` not found", self.name)))?;

        let shared_count = CustomType::<u8>::new("Enter the number of shared secrets to disarm: ")
            .with_validator(|s: &u8| {
                if *s == 0 {
                    return Ok(Validation::Invalid("shared count must be greater than 0".into()));
                }
                Ok(Validation::Valid)
            })
            .with_error_message("Please enter a valid number")
            .prompt()?;

        let shares = (0..shared_count)
            .map(|i| {
                Password::new(&format!("Enter shared secret ({}/{shared_count})", i + 1))
                    .with_display_mode(inquire::PasswordDisplayMode::Masked)
                    .with_display_toggle_enabled()
                    .without_confirmation()
                    .prompt()
            })
            .collect::<Result<Vec<String>, _>>()?;

        disarm(authority.host, shares).await?;
        execute!(
            stdout(),
            SetForegroundColor(Color::Green),
            Print("✅ Successfully disarmed authority\n"),
            ResetColor
        )?;

        Ok(())
    }
}
