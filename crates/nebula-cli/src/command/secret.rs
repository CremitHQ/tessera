use std::collections::HashMap;
use std::io::stdout;
use std::str::FromStr;

use async_trait::async_trait;
use base64::engine::{general_purpose::STANDARD, Engine as _};
use clap::{Args, Subcommand};
use comfy_table::modifiers::UTF8_ROUND_CORNERS;
use comfy_table::presets::UTF8_FULL;
use comfy_table::{Cell, Table};
use crossterm::execute;
use crossterm::style::{Color, Print, ResetColor, SetForegroundColor};
use futures_util::future::join_all;
use nebula_abe::curves::bn462::Bn462Curve;
use nebula_abe::random::miracl::MiraclRng;
use nebula_abe::schemes::isabella24::{decrypt, encrypt, AuthorityPublicKey, Ciphertext, GlobalParams, UserSecretKey};
use nebula_abe::PolicyLanguage;
use rand::rngs::OsRng;
use rand::Rng as _;
use ulid::Ulid;

use crate::api::authority::{get_public_key, get_user_key};
use crate::api::backbone::{
    create_secret, get_access_condition, get_authorities, get_global_params, get_paths, get_secret_with_identifier,
    get_secrets, PostSecretRequest,
};
use crate::config::{load_token, NebulaConfig};

use super::{GlobalArgs, RunCommand};

#[derive(Subcommand, Debug)]
pub enum SecretCommand {
    List(SecretListCommand),
    Get(SecretGetCommand),
    Create(SecretCreateCommand),
}

#[async_trait]
impl RunCommand for SecretCommand {
    async fn run(&self, args: &GlobalArgs) -> anyhow::Result<()> {
        match self {
            SecretCommand::List(cmd) => cmd.run(args).await,
            SecretCommand::Get(cmd) => cmd.run(args).await,
            SecretCommand::Create(cmd) => cmd.run(args).await,
        }
    }
}

#[derive(Args, Debug)]
pub struct SecretListCommand {
    #[clap(long, default_value = "/")]
    path: String,
}

#[async_trait]
impl RunCommand for SecretListCommand {
    async fn run(&self, args: &GlobalArgs) -> anyhow::Result<()> {
        let config = NebulaConfig::load(args.profile.as_str(), args.config.clone().map(Into::into))?;
        let token = load_token(&args.profile)?;
        let backbone_url = config.backbone.host;
        let workspace_name = config.workspace;

        let paths = get_paths(backbone_url.clone(), &workspace_name, &token).await?;
        let secrets = get_secrets(backbone_url.clone(), &workspace_name, &self.path, &token).await?;

        let mut table = Table::new();
        table.load_preset(UTF8_FULL).apply_modifier(UTF8_ROUND_CORNERS);
        table.set_header(vec!["", "Path", "Access Condition"]);

        for path_response in paths {
            let search_path = self.path.trim_end_matches('/');
            let search_path = if search_path.is_empty() { "/" } else { &format!("{}/", search_path) };

            if !path_response.path.starts_with(search_path) {
                continue;
            }
            let path = path_response.path.trim_start_matches(search_path);
            if path.is_empty() || path.contains('/') {
                continue;
            }

            table.add_row(vec![
                Cell::new("📁").set_alignment(comfy_table::CellAlignment::Center),
                Cell::new(format!("{}{}/", search_path, path)),
            ]);
        }

        for secret in secrets {
            let access_condition = join_all(
                secret
                    .access_condition_ids
                    .iter()
                    .map(|ac| get_access_condition(backbone_url.clone(), &workspace_name, ac, &token)),
            )
            .await
            .into_iter()
            .collect::<Result<Vec<_>, _>>()?;

            table.add_row(vec![
                Cell::new("🔑").set_alignment(comfy_table::CellAlignment::Center),
                Cell::new(format!("{}/{}", secret.path.trim_end_matches('/'), secret.key)),
                Cell::new(access_condition.iter().map(|ac| ac.expression.clone()).collect::<Vec<_>>().join(" OR ")),
            ]);
        }

        println!("{table}");

        Ok(())
    }
}

#[derive(Args, Debug)]
pub struct SecretGetCommand {
    #[clap(long)]
    path: String,
}

#[async_trait]
impl RunCommand for SecretGetCommand {
    async fn run(&self, args: &GlobalArgs) -> anyhow::Result<()> {
        let config = NebulaConfig::load(args.profile.as_str(), args.config.clone().map(Into::into))?;
        let token = load_token(&args.profile)?;
        let backbone_url = config.backbone.host;
        let workspace_name = config.workspace;
        let identifier = &self.path;

        let gp = get_global_params(backbone_url.clone(), &workspace_name, &token).await?;
        let gp = STANDARD.decode(gp.parameter)?;
        let gp: GlobalParams<Bn462Curve> = rmp_serde::from_slice(&gp)?;

        let authorities = get_authorities(backbone_url.clone(), &workspace_name, &token).await?;
        let secret = get_secret_with_identifier(backbone_url, &workspace_name, identifier, &token).await?;
        let ct = STANDARD.decode(secret.cipher)?;
        let ct: Ciphertext<Bn462Curve> = rmp_serde::from_slice(&ct)?;

        let mut usks = vec![];
        for authority in authorities {
            let usk = get_user_key(&authority.host, &workspace_name, &token).await?;

            let usk = STANDARD.decode(&usk.user_key)?;
            let usk: UserSecretKey<Bn462Curve> = rmp_serde::from_slice(&usk)?;
            usks.push(usk);
        }

        let sk = UserSecretKey::<Bn462Curve>::sum(usks.into_iter())?;

        let plaintext = decrypt(&gp, &sk, &ct)?;

        let mut table = Table::new();
        table.load_preset(UTF8_FULL).apply_modifier(UTF8_ROUND_CORNERS);
        table.set_header(vec!["Path", "Plaintext"]);

        table.add_row(vec![Cell::new(&self.path), Cell::new(String::from_utf8_lossy(&plaintext))]);

        println!("{table}");

        Ok(())
    }
}

#[derive(Args, Debug)]
pub struct SecretCreateCommand {
    #[clap(long)]
    path: String,

    #[clap(short = 'v', long)]
    value: String,

    #[clap(long, value_delimiter = ',')]
    access_condition_ids: Vec<String>,
}

#[async_trait]
impl RunCommand for SecretCreateCommand {
    async fn run(&self, args: &GlobalArgs) -> anyhow::Result<()> {
        let config = NebulaConfig::load(args.profile.as_str(), args.config.clone().map(Into::into))?;
        let token = load_token(&args.profile)?;
        let backbone_url = config.backbone.host;
        let workspace_name = config.workspace;

        let gp = get_global_params(backbone_url.clone(), &workspace_name, &token).await?;
        let gp = STANDARD.decode(gp.parameter)?;
        let gp: GlobalParams<Bn462Curve> = rmp_serde::from_slice(&gp)?;

        let authorities = get_authorities(backbone_url.clone(), &workspace_name, &token).await?;
        let mut pks = HashMap::new();
        for authority in authorities {
            let pk_response = get_public_key(&authority.host, &workspace_name).await?;

            let pk = STANDARD.decode(&pk_response.public_key)?;
            let pk: AuthorityPublicKey<Bn462Curve> = rmp_serde::from_slice(&pk)?;
            pks.insert(format!("{}-{}#{}", authority.name, workspace_name, pk_response.version), pk);
        }

        let mut rng = MiraclRng::new();
        let mut seed = [0u8; 64];
        OsRng.fill(&mut seed);
        rng.seed(&seed);

        let mut policy = vec![];
        for id in &self.access_condition_ids {
            let access_condition =
                get_access_condition(backbone_url.clone(), &workspace_name, &Ulid::from_str(id)?, &token).await?;
            policy.push(access_condition.expression);
        }
        let policy = (policy.join(" OR "), PolicyLanguage::HumanPolicy);

        let trimmed_path = self.path.trim_matches('/');
        if trimmed_path.is_empty() {
            return Err(anyhow::anyhow!("Invalid path"));
        }
        let path = format!("/{}", trimmed_path);
        let key = path.split('/').last().unwrap().to_string();
        let path = path.trim_end_matches(&key).to_string();

        let ct = encrypt(&mut rng, &gp, &pks, policy, self.value.as_bytes())?;
        let ct = rmp_serde::to_vec(&ct)?;
        let ct = STANDARD.encode(&ct);

        let access_condition_ids =
            self.access_condition_ids.iter().map(|id| Ulid::from_str(id)).collect::<Result<Vec<_>, _>>()?;

        let request = PostSecretRequest { path, key, cipher: ct, access_condition_ids };
        create_secret(backbone_url.clone(), &workspace_name, request, &token).await?;

        execute!(stdout(), SetForegroundColor(Color::Green), Print("✅ Successfully created secret\n"), ResetColor)?;

        Ok(())
    }
}
