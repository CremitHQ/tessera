use async_trait::async_trait;
use sea_orm_migration::{prelude::*, schema::*};

#[derive(DeriveIden)]
pub enum MachineIdentity {
    Table,
    Id,
    Label,
    OwnerGid,
    CreatedAt,
    UpdatedAt,
}

#[derive(DeriveIden)]
pub enum MachineIdentityAttribute {
    Table,
    Id,
    MachineIdentityId,
    Key,
    Value,
    CreatedAt,
    UpdatedAt,
}

#[derive(DeriveIden)]
pub enum MachineIdentityToken {
    Table,
    Id,
    MachineIdentityId,
    Token,
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
                    .table(MachineIdentity::Table)
                    .col(char_len(MachineIdentity::Id, 26).primary_key())
                    .col(string_len(MachineIdentity::Label, 255))
                    .col(string_len(MachineIdentity::OwnerGid, 255))
                    .col(timestamp_with_time_zone(MachineIdentity::CreatedAt))
                    .col(timestamp_with_time_zone(MachineIdentity::UpdatedAt))
                    .take(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .table(MachineIdentity::Table)
                    .name("idx_machine_identity_owner_gid")
                    .col(MachineIdentity::OwnerGid)
                    .take(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(MachineIdentityAttribute::Table)
                    .col(char_len(MachineIdentityAttribute::Id, 26).primary_key())
                    .col(char_len(MachineIdentityAttribute::MachineIdentityId, 26))
                    .col(string_len(MachineIdentityAttribute::Key, 255))
                    .col(string_len(MachineIdentityAttribute::Value, 255))
                    .col(timestamp_with_time_zone(MachineIdentityAttribute::CreatedAt))
                    .col(timestamp_with_time_zone(MachineIdentityAttribute::UpdatedAt))
                    .take(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .table(MachineIdentityAttribute::Table)
                    .name("idx_machine_identity_attribute_machine_identity_id")
                    .col(MachineIdentityAttribute::MachineIdentityId)
                    .take(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(MachineIdentityToken::Table)
                    .col(char_len(MachineIdentityToken::Id, 26).primary_key())
                    .col(char_len(MachineIdentityToken::MachineIdentityId, 26))
                    .col(string_len(MachineIdentityToken::Token, 255))
                    .col(timestamp_with_time_zone(MachineIdentityToken::CreatedAt))
                    .col(timestamp_with_time_zone(MachineIdentityToken::UpdatedAt))
                    .take(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .table(MachineIdentityToken::Table)
                    .name("idx_machine_identity_token_machine_identity_id")
                    .col(MachineIdentityToken::MachineIdentityId)
                    .take(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager.drop_table(Table::drop().table(MachineIdentity::Table).take()).await?;

        Ok(())
    }
}
