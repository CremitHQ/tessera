use async_trait::async_trait;
use sea_orm_migration::{prelude::*, schema::*};

#[derive(DeriveIden)]
pub enum AppliedPathPolicy {
    Table,
    Id,
    PathId,
    Expression,
    CreatedAt,
    UpdatedAt,
}

#[derive(DeriveIden)]
pub enum AppliedPathPolicyAllowedAction {
    Table,
    Id,
    AppliedPathPolicyId,
    Action,
    CreatedAt,
    UpdatedAt,
}

#[derive(DeriveIden)]
pub enum AppliedPolicy {
    Table,
    Id,
    SecretMetadataId,
    PolicyId,
    CreatedAt,
    UpdatedAt,
}

#[derive(DeriveIden)]
pub enum Parameter {
    Table,
    Id,
    Version,
    Value,
    CreatedAt,
    UpdatedAt,
}

#[derive(DeriveIden)]
#[allow(clippy::enum_variant_names)]
pub enum Path {
    Table,
    Id,
    Path,
    CreatedAt,
    UpdatedAt,
}

#[derive(DeriveIden)]
pub enum Policy {
    Table,
    Id,
    Name,
    Expression,
    CreatedAt,
    UpdatedAt,
}

#[derive(DeriveIden)]
pub enum SecretMetadata {
    Table,
    Id,
    Key,
    Path,
    CreatedAt,
    UpdatedAt,
}

#[derive(DeriveIden)]
pub enum SecretValue {
    Table,
    Id,
    Identifier,
    Cipher,
    CreatedAt,
    UpdatedAt,
}

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
                    .table(AppliedPathPolicy::Table)
                    .if_not_exists()
                    .col(char_len(AppliedPathPolicy::Id, 26).primary_key())
                    .col(char_len(AppliedPathPolicy::PathId, 26))
                    .col(text(AppliedPathPolicy::Expression))
                    .col(timestamp_with_time_zone(AppliedPathPolicy::CreatedAt))
                    .col(timestamp_with_time_zone(AppliedPathPolicy::UpdatedAt))
                    .take(),
            )
            .await?;
        manager
            .create_table(
                Table::create()
                    .table(AppliedPathPolicyAllowedAction::Table)
                    .if_not_exists()
                    .col(char_len(AppliedPathPolicyAllowedAction::Id, 26).primary_key())
                    .col(char_len(AppliedPathPolicyAllowedAction::AppliedPathPolicyId, 26))
                    .col(string_len(AppliedPathPolicyAllowedAction::Action, 50))
                    .col(timestamp_with_time_zone(AppliedPathPolicyAllowedAction::CreatedAt))
                    .col(timestamp_with_time_zone(AppliedPathPolicyAllowedAction::UpdatedAt))
                    .take(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .table(AppliedPathPolicyAllowedAction::Table)
                    .if_not_exists()
                    .name("idx_applied_path_policy_allowed_action_applied_path_policy_id")
                    .col(AppliedPathPolicyAllowedAction::AppliedPathPolicyId)
                    .take(),
            )
            .await?;
        manager
            .create_table(
                Table::create()
                    .table(AppliedPolicy::Table)
                    .if_not_exists()
                    .col(char_len(AppliedPolicy::Id, 26).primary_key())
                    .col(char_len(AppliedPolicy::SecretMetadataId, 26))
                    .col(char_len(AppliedPolicy::PolicyId, 26))
                    .col(timestamp_with_time_zone(AppliedPolicy::CreatedAt))
                    .col(timestamp_with_time_zone(AppliedPolicy::UpdatedAt))
                    .take(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .table(AppliedPolicy::Table)
                    .if_not_exists()
                    .name("idx_applied_policy_secret_metadata_id")
                    .col(AppliedPolicy::SecretMetadataId)
                    .take(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .table(AppliedPolicy::Table)
                    .if_not_exists()
                    .name("idx_applied_policy_policy_id")
                    .col(AppliedPolicy::PolicyId)
                    .take(),
            )
            .await?;
        manager
            .create_table(
                Table::create()
                    .table(Parameter::Table)
                    .if_not_exists()
                    .col(char_len(Parameter::Id, 26).primary_key())
                    .col(integer(Parameter::Version))
                    .col(blob(Parameter::Value))
                    .col(timestamp_with_time_zone(Parameter::CreatedAt))
                    .col(timestamp_with_time_zone(Parameter::UpdatedAt))
                    .take(),
            )
            .await?;
        manager
            .create_table(
                Table::create()
                    .table(Path::Table)
                    .if_not_exists()
                    .col(char_len(Path::Id, 26).primary_key())
                    .col(text(Path::Path))
                    .col(timestamp_with_time_zone(Path::CreatedAt))
                    .col(timestamp_with_time_zone(Path::UpdatedAt))
                    .take(),
            )
            .await?;
        manager
            .create_table(
                Table::create()
                    .table(Policy::Table)
                    .if_not_exists()
                    .col(char_len(Policy::Id, 26).primary_key())
                    .col(string_len(Policy::Name, 100))
                    .col(text(Policy::Expression))
                    .col(timestamp_with_time_zone(Policy::CreatedAt))
                    .col(timestamp_with_time_zone(Policy::UpdatedAt))
                    .take(),
            )
            .await?;
        manager
            .create_table(
                Table::create()
                    .table(SecretMetadata::Table)
                    .if_not_exists()
                    .col(char_len(SecretMetadata::Id, 26).primary_key())
                    .col(string_len(SecretMetadata::Key, 100))
                    .col(string_len(SecretMetadata::Path, 100))
                    .col(timestamp_with_time_zone(SecretMetadata::CreatedAt))
                    .col(timestamp_with_time_zone(SecretMetadata::UpdatedAt))
                    .take(),
            )
            .await?;
        manager
            .create_table(
                Table::create()
                    .table(SecretValue::Table)
                    .if_not_exists()
                    .col(char_len(SecretValue::Id, 26).primary_key())
                    .col(string_len(SecretValue::Identifier, 10485760))
                    .col(blob(SecretValue::Cipher))
                    .col(timestamp_with_time_zone(SecretValue::CreatedAt))
                    .col(timestamp_with_time_zone(SecretValue::UpdatedAt))
                    .take(),
            )
            .await?;

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
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager.drop_table(Table::drop().table(AppliedPathPolicy::Table).if_exists().take()).await?;
        manager.drop_table(Table::drop().table(Authority::Table).if_exists().take()).await?;
        manager.drop_table(Table::drop().table(AppliedPathPolicyAllowedAction::Table).if_exists().take()).await?;
        manager.drop_table(Table::drop().table(AppliedPolicy::Table).if_exists().take()).await?;
        manager.drop_table(Table::drop().table(Parameter::Table).if_exists().take()).await?;
        manager.drop_table(Table::drop().table(Path::Table).if_exists().take()).await?;
        manager.drop_table(Table::drop().table(Policy::Table).if_exists().take()).await?;
        manager.drop_table(Table::drop().table(SecretMetadata::Table).if_exists().take()).await?;
        manager.drop_table(Table::drop().table(SecretValue::Table).if_exists().take()).await?;

        Ok(())
    }
}
