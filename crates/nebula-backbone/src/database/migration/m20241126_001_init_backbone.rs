use async_trait::async_trait;
use sea_orm_migration::{prelude::*, schema::*};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[derive(DeriveIden)]
pub enum Workspace {
    Table,
    Id,
    Name,
    CreatedAt,
    UpdatedAt,
}

#[async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(Workspace::Table)
                    .if_not_exists()
                    .col(char_len(Workspace::Id, 26).primary_key())
                    .col(string_len_uniq(Workspace::Name, 50))
                    .col(timestamp_with_time_zone(Workspace::CreatedAt))
                    .col(timestamp_with_time_zone(Workspace::UpdatedAt))
                    .take(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager.drop_table(Table::drop().table(Workspace::Table).if_exists().take()).await
    }
}
