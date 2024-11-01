use std::collections::HashSet;
use std::{path::PathBuf, time::Duration};

use crate::Storage;
use bon::Builder;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::Row;
use thiserror::Error;

pub struct PostgresStorage {
    pool: sqlx::PgPool,
    table_name: String,
}

#[derive(Builder)]
pub struct PostgresStorageOptions {
    #[builder(into)]
    host: String,
    port: u16,
    #[builder(into)]
    username: String,
    #[builder(into)]
    password: String,
    #[builder(into)]
    database: String,
    #[builder(into, default = "kv_store")]
    table_name: String,
    #[builder(into)]
    tls_ca_cert: Option<PathBuf>,
    #[builder(default = 5)]
    max_connections: u32,
    #[builder(default = 1)]
    min_connections: u32,
    #[builder(default = Duration::from_secs(10 * 60))]
    idle_timeout: Duration,
}

impl PostgresStorage {
    pub async fn new(options: PostgresStorageOptions) -> Result<Self, PostgresStorageError> {
        let mut connection_options = PgConnectOptions::new()
            .host(&options.host)
            .port(options.port)
            .username(&options.username)
            .password(&options.password)
            .database(&options.database);

        if let Some(tls_ca_cert) = options.tls_ca_cert {
            connection_options = connection_options.ssl_root_cert(tls_ca_cert);
        }

        let pool = PgPoolOptions::new()
            .max_connections(options.max_connections)
            .min_connections(options.min_connections)
            .idle_timeout(options.idle_timeout)
            .connect_with(connection_options)
            .await?;

        let table_name = quote_ident(&options.table_name);

        sqlx::query(&format!(
            r#"CREATE TABLE IF NOT EXISTS {table_name} (
                  key         TEXT COLLATE "C" PRIMARY KEY,
                  value       BYTEA,
                );"#
        ))
        .execute(&pool)
        .await?;

        Ok(PostgresStorage { pool, table_name })
    }
}

#[derive(Error, Debug)]
pub enum PostgresStorageError {
    #[error("sqlx error: {0}")]
    Sqlx(#[from] sqlx::Error),
}

impl Storage for PostgresStorage {
    type Key = str;
    type Value = [u8];

    type StorageError = PostgresStorageError;

    async fn get(&self, key: &Self::Key) -> Result<Option<<Self::Value as ToOwned>::Owned>, Self::StorageError> {
        let table_name = &self.table_name;

        match sqlx::query(&format!("SELECT value FROM {table_name} WHERE key = $1"))
            .bind(key)
            .fetch_one(&self.pool)
            .await
        {
            Ok(row) => Ok(Some(row.get("value"))),
            Err(sqlx::Error::RowNotFound) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    async fn set(&self, key: &Self::Key, value: &Self::Value) -> Result<(), Self::StorageError> {
        let table_name = &self.table_name;

        sqlx::query(&format!(
            r#"INSERT INTO {table_name} (key, value) VALUES ($1, $2)
               ON CONFLICT (key) DO UPDATE SET value = $2;"#
        ))
        .bind(key)
        .bind(value)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn delete(&self, key: &Self::Key) -> Result<(), Self::StorageError> {
        let table_name = &self.table_name;

        sqlx::query(&format!(r#"DELETE FROM {table_name} WHERE key = $1;"#)).bind(key).execute(&self.pool).await?;
        Ok(())
    }

    async fn list(
        &self,
        prefix: &Self::Key,
    ) -> Result<impl IntoIterator<Item = <Self::Key as ToOwned>::Owned>, Self::StorageError> {
        let table_name = &self.table_name;
        let full_paths = sqlx::query(&format!(r#"SELECT key as full_path FROM {table_name} WHERE key LIKE $1"#))
            .bind(format!("{}%", prefix))
            .fetch_all(&self.pool)
            .await?
            .into_iter()
            .map(|row| row.get("key"))
            .fold(HashSet::new(), |mut set, path: String| {
                let trimmed_path = path.trim_start_matches(prefix);
                let index = trimmed_path.find('/');
                if let Some(index) = index {
                    set.insert(trimmed_path[..index + 1].to_string());
                } else {
                    set.insert(trimmed_path.to_string());
                }

                set
            });

        Ok(full_paths)
    }
}

fn quote_ident(ident: &str) -> String {
    format!(r#""{}""#, ident.replace('"', r#""""#).replace(';', ""))
}
