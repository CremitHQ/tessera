use std::io::stdout;

use async_trait::async_trait;
use clap::Args;
use crossterm::execute;
use crossterm::style::{Color, Print, ResetColor, SetForegroundColor};
use rand::Rng;
use tiny_http::{Response, Server};

use crate::api::authorization::get_token_from_machine_identity_token;
use crate::config::{save_token, AuthorizationMethod, NebulaConfig};

use super::{GlobalArgs, RunCommand};

#[derive(Args, Debug)]
pub struct LoginCommand {}

#[async_trait]
impl RunCommand for LoginCommand {
    async fn run(&self, args: &GlobalArgs) -> anyhow::Result<()> {
        let config = NebulaConfig::load(args.profile.as_str(), args.config.clone().map(Into::into))?;
        match config.authorization.method {
            AuthorizationMethod::Saml => {
                let port: u16 = rand::thread_rng().gen_range(1024..65535);
                let server = Server::http(("0.0.0.0", port)).map_err(|e| anyhow::anyhow!(e))?;
                execute!(
                    stdout(),
                    SetForegroundColor(Color::Blue),
                    Print("🔗 Opening browser for SAML login...\n"),
                    ResetColor
                )?;
                webbrowser::open(
                    config.authorization.host.join(&format!("login/saml?callback-port={port}"))?.as_str(),
                )?;

                for request in server.incoming_requests() {
                    let url = request.url();
                    if url.starts_with("/callback/saml?access-token=") {
                        let token = url.trim_start_matches("/callback/saml?access-token=");
                        let response =
                            Response::from_string("Successfully logged in! Close this tab and return to the terminal.");
                        save_token(&args.profile, token)?;
                        request.respond(response)?;
                        break;
                    }
                }
            }
            AuthorizationMethod::MachineIdentity { token } => {
                let token = get_token_from_machine_identity_token(
                    config.authorization.host.clone(),
                    config.workspace.as_str(),
                    token.as_str(),
                )
                .await?;

                save_token(&args.profile, &token)?;
            }
        };

        execute!(stdout(), SetForegroundColor(Color::Green), Print("✅ Successfully logged in!\n"), ResetColor)?;
        Ok(())
    }
}
