use async_trait::async_trait;
use sea_orm::DbErr;
use sea_orm_migration::{IntoSchemaManagerConnection, MigrationTrait, MigratorTrait};

mod m20241126_001_init;

pub struct Migrator;

#[async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![Box::new(m20241126_001_init::Migration)]
    }
}

pub async fn migrate<'d, D>(db: D) -> Result<(), DbErr>
where
    D: IntoSchemaManagerConnection<'d>,
{
    Migrator::up(db, None).await
}
