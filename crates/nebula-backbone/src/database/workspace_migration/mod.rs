use async_trait::async_trait;
use futures_util::future::join_all;
use sea_orm::{DatabaseTransaction, DbErr, EntityTrait};
use sea_orm_migration::{IntoSchemaManagerConnection, MigrationTrait, MigratorTrait};

use super::{workspace, AuthMethod};

mod m20241126_001_init_backbone;
mod m20241128_001_create_authority_table;
mod m20241206_001_remove_unused_column_applied_policy_table;

pub struct Migrator;

#[async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![
            Box::new(m20241126_001_init_backbone::Migration),
            Box::new(m20241128_001_create_authority_table::Migration),
            Box::new(m20241206_001_remove_unused_column_applied_policy_table::Migration),
        ]
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

#[cfg(test)]
pub async fn migrate_workspace(
    _workspace_slug: &str,
    _host: &str,
    _port: u16,
    _database_name: &str,
    _auth: &AuthMethod,
) -> anyhow::Result<()> {
    use tracing::debug;

    debug!("workspace migration not supported in test environment");

    Ok(())
}

#[cfg(not(test))]
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
