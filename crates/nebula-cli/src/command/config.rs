use std::fmt::Display;

use async_trait::async_trait;
use clap::{Args, Subcommand, ValueEnum};
use inquire::{validator::Validation, Select};
use inquire::{Password, Text};
use serde::{Deserialize, Serialize};
use url::Url;

use crate::config::{AuthorizationConfig, AuthorizationMethod, BackboneConfig, NebulaConfig};
use crate::utils::validation::{validate_new_profile, validate_url, validate_workspace_name};

use super::{GlobalArgs, RunCommand};

#[derive(Subcommand, Debug)]
pub enum ConfigCommand {
    Init(InitConfigCommand),
}

#[async_trait]
impl RunCommand for ConfigCommand {
    async fn run(&self, args: &GlobalArgs) -> anyhow::Result<()> {
        match self {
            ConfigCommand::Init(cmd) => cmd.run(args).await,
        }
    }
}

#[derive(Args, Debug)]
pub struct InitConfigCommand {
    #[clap(short = 'b', long = "backbone")]
    backbone_url: Option<String>,
    #[clap(short = 'a', long = "auth")]
    authz_url: Option<String>,
    #[clap(long = "auth-method", value_enum)]
    auth_method: Option<AuthMethod>,
    #[clap(long = "machine-identity-token", required_if_eq("auth_method", "machine-identity"))]
    machine_identity_token: Option<String>,
    #[clap(short = 'w', long = "workspace")]
    workspace_name: Option<String>,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Serialize, Deserialize, Default, Debug)]
#[serde(rename_all = "kebab-case")]
pub enum AuthMethod {
    #[default]
    Saml,
    MachineIdentity,
}

impl Display for AuthMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthMethod::Saml => write!(f, "SAML"),
            AuthMethod::MachineIdentity => write!(f, "Machine Identity"),
        }
    }
}

#[async_trait]
impl RunCommand for InitConfigCommand {
    async fn run(&self, args: &GlobalArgs) -> anyhow::Result<()> {
        let backbone_url = if let Some(backbone_url) = &self.backbone_url {
            if matches!(validate_url(backbone_url), Ok(Validation::Valid)) {
                backbone_url.clone()
            } else {
                return Err(anyhow::anyhow!("Invalid backbone url"));
            }
        } else {
            Text::new("Backbone server url:").with_validator(validate_url).prompt()?
        };

        let authz_url = if let Some(authz_url) = &self.authz_url {
            if matches!(validate_url(authz_url), Ok(Validation::Valid)) {
                authz_url.clone()
            } else {
                return Err(anyhow::anyhow!("Invalid authorization url"));
            }
        } else {
            Text::new("Authorization server url:").with_validator(validate_url).prompt()?
        };

        let auth_method = if let Some(auth_method) = &self.auth_method {
            *auth_method
        } else {
            Select::new("Select an authentication method:", vec![AuthMethod::Saml, AuthMethod::MachineIdentity])
                .prompt()?
        };

        let machine_identity_token = if auth_method == AuthMethod::MachineIdentity {
            if let Some(machine_identity_token) = &self.machine_identity_token {
                Some(machine_identity_token.clone())
            } else {
                Some(
                    Password::new("Machine identity token (press Ctrl+R if you want to see the token):")
                        .with_display_mode(inquire::PasswordDisplayMode::Masked)
                        .with_display_toggle_enabled()
                        .without_confirmation()
                        .prompt()?,
                )
            }
        } else {
            None
        };

        let workspace_name = if let Some(workspace_name) = &self.workspace_name {
            if matches!(validate_workspace_name(workspace_name), Ok(Validation::Valid)) {
                workspace_name.clone()
            } else {
                return Err(anyhow::anyhow!("Invalid workspace name"));
            }
        } else {
            Text::new("Workspace name:").with_validator(validate_workspace_name).prompt()?
        };

        let profile = Text::new("Save a profile as:")
            .with_validator(validate_new_profile(args.config.clone()))
            .with_default(&args.profile)
            .prompt()?;

        let backbone_config = BackboneConfig::new(Url::parse(&backbone_url)?);
        let authz_config = AuthorizationConfig::new(
            Url::parse(&authz_url)?,
            match auth_method {
                AuthMethod::Saml => AuthorizationMethod::Saml,
                AuthMethod::MachineIdentity => {
                    AuthorizationMethod::MachineIdentity { token: machine_identity_token.unwrap() }
                }
            },
        );
        let nebula_config = NebulaConfig::new(profile, workspace_name, backbone_config, authz_config);

        nebula_config.append()?;

        Ok(())
    }
}
