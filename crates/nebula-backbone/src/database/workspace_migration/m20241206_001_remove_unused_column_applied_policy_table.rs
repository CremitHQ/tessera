use async_trait::async_trait;
use sea_orm_migration::{prelude::*, schema::*};

#[derive(DeriveIden)]
pub enum AppliedPolicy {
    Table,
    Type,
}

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(Table::alter().table(AppliedPolicy::Table).drop_column(AppliedPolicy::Type).to_owned())
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(AppliedPolicy::Table)
                    .add_column_if_not_exists(string_len(AppliedPolicy::Type, 50))
                    .to_owned(),
            )
            .await?;
        Ok(())
    }
}
