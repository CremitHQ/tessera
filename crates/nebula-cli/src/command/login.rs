use async_trait::async_trait;
use clap::Args;

use crate::api::get_token_from_machine_identity_token;
use crate::config::{save_token, AuthorizationMethod, NebulaConfig};

use super::{GlobalArgs, RunCommand};

#[derive(Args, Debug)]
pub struct LoginCommand {}

#[async_trait]
impl RunCommand for LoginCommand {
    async fn run(&self, args: &GlobalArgs) -> anyhow::Result<()> {
        let config = NebulaConfig::load(args.profile.as_str(), args.config.clone().map(Into::into))?;
        match config.authorization.method {
            AuthorizationMethod::Saml => unimplemented!(),
            AuthorizationMethod::MachineIdentity { token } => {
                let token = get_token_from_machine_identity_token(
                    config.authorization.host.clone(),
                    config.workspace.as_str(),
                    token.as_str(),
                )
                .await?;

                save_token(&token)?;
            }
        };

        Ok(())
    }
}
