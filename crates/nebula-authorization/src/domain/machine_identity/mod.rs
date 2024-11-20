use chrono::Utc;
use sea_orm::{ActiveModelTrait, DatabaseTransaction, DbErr, EntityTrait, Set};
use thiserror::Error;
use ulid::Ulid;

use crate::database::{machine_identity, machine_identity_attribute, UlidId};

pub struct MachineIdentityService {}

impl MachineIdentityService {
    pub async fn register_machine_identity(
        &self,
        transaction: &DatabaseTransaction,
        label: &str,
        attributes: &[(&str, &str)],
    ) -> Result<()> {
        let machine_identity_id = UlidId::new(Ulid::new());
        let now = Utc::now();
        machine_identity::ActiveModel {
            id: Set(machine_identity_id),
            label: Set(label.to_owned()),
            created_at: Set(now),
            updated_at: Set(now),
        }
        .insert(transaction)
        .await?;

        if !attributes.is_empty() {
            let attributes_active_models =
                attributes.iter().map(|(key, value)| machine_identity_attribute::ActiveModel {
                    id: Set(UlidId::new(Ulid::new())),
                    machine_identity_id: Set(machine_identity_id),
                    key: Set(key.to_string()),
                    value: Set(value.to_string()),
                    created_at: Set(now),
                    updated_at: Set(now),
                });

            machine_identity_attribute::Entity::insert_many(attributes_active_models).exec(transaction).await?;
        }

        Ok(())
    }
}

#[derive(Error, Debug)]
pub enum Error {
    #[error("Error occurrred by database")]
    DatabaseError(#[from] DbErr),
}

pub type Result<T> = std::result::Result<T, Error>;
