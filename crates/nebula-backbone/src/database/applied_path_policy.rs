use chrono::{DateTime, Utc};
use sea_orm::prelude::*;

use super::UlidId;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "applied_path_policy")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: UlidId,
    pub path_id: UlidId,
    pub expression: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(belongs_to = "super::path::Entity", from = "Column::PathId", to = "super::path::Column::Id")]
    Path,
    #[sea_orm(has_many = "super::applied_path_policy_allowed_action::Entity")]
    AppliedPathPolicyAllowedAction,
}

impl ActiveModelBehavior for ActiveModel {}

impl Related<super::path::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Path.def()
    }
}

impl Related<super::applied_path_policy_allowed_action::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::AppliedPathPolicyAllowedAction.def()
    }
}
