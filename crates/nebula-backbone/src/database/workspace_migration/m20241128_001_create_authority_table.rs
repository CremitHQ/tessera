use async_trait::async_trait;
use sea_orm_migration::{prelude::*, schema::*};

#[derive(DeriveIden)]
pub enum Authority {
    Table,
    Id,
    Name,
    Host,
    PublicKey,
    CreatedAt,
    UpdatedAt,
}

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(Authority::Table)
                    .if_not_exists()
                    .col(char_len(Authority::Id, 26).primary_key())
                    .col(string_len(Authority::Name, 255))
                    .col(text(Authority::Host))
                    .col(text_null(Authority::PublicKey))
                    .col(timestamp_with_time_zone(Authority::CreatedAt))
                    .col(timestamp_with_time_zone(Authority::UpdatedAt))
                    .take(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager.drop_table(Table::drop().table(Authority::Table).if_exists().take()).await?;

        Ok(())
    }
}
