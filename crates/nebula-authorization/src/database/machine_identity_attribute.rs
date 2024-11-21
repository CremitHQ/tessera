use chrono::{DateTime, Utc};
use sea_orm::prelude::*;

use super::UlidId;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "machine_identity_attribute")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: UlidId,
    pub machine_identity_id: UlidId,
    pub key: String,
    pub value: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::machine_identity::Entity",
        from = "Column::MachineIdentityId",
        to = "super::machine_identity::Column::Id"
    )]
    MachineIdentity,
}

impl ActiveModelBehavior for ActiveModel {}

impl Related<super::machine_identity::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::MachineIdentity.def()
    }
}
