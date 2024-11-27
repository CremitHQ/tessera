use async_trait::async_trait;
use futures_util::future::join_all;
use sea_orm::{DatabaseTransaction, DbErr, EntityTrait};
use sea_orm_migration::{IntoSchemaManagerConnection, MigrationTrait, MigratorTrait};

use super::{workspace, AuthMethod};

mod m20241126_001_init_backbone;

pub struct Migrator;

#[async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![Box::new(m20241126_001_init_backbone::Migration)]
    }
}

pub async fn migrate_all_workspaces(
    transaction: &DatabaseTransaction,
    host: &str,
    port: u16,
    database_name: &str,
    auth: &AuthMethod,
) -> anyhow::Result<()> {
    let workspaces = workspace::Entity::find().all(transaction).await?;

    let results = join_all(
        workspaces.iter().map(|workspace| migrate_workspace(&workspace.name, host, port, database_name, auth)),
    )
    .await;

    for result in results {
        result?;
    }

    Ok(())
}

pub async fn migrate_workspace(
    workspace_slug: &str,
    host: &str,
    port: u16,
    database_name: &str,
    auth: &AuthMethod,
) -> anyhow::Result<()> {
    let connection =
        super::connect_to_database_with_search_path(host, port, database_name, auth, Some(workspace_slug)).await?;

    migrate(connection.as_ref()).await?;

    Ok(())
}

async fn migrate<'d, D>(db: D) -> Result<(), DbErr>
where
    D: IntoSchemaManagerConnection<'d>,
{
    Migrator::up(db, None).await
}
