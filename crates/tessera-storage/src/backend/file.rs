use std::{borrow::Cow, path::Path};

use crate::Storage;
use thiserror::Error;
use tokio::fs;

pub struct FileStorage<'a> {
    path: Cow<'a, Path>,
}

impl<'a> FileStorage<'a> {
    pub fn new<P>(path: P) -> Self
    where
        P: Into<Cow<'a, Path>>,
    {
        FileStorage { path: path.into() }
    }
}

#[derive(Error, Debug)]
pub enum FileStorageError<'a> {
    #[error("File Storage IO Error: {0}")]
    Io(#[from] std::io::Error),
    #[error("File Storage Path Error: {0}")]
    Path(Cow<'a, str>),
}

impl<'a> Storage for FileStorage<'a> {
    type Key = str;
    type Value = [u8];

    type StorageError = FileStorageError<'a>;

    async fn get(&self, key: &Self::Key) -> Result<<Self::Value as ToOwned>::Owned, Self::StorageError> {
        let path = self.path.clone().into_owned().join(key);
        let data = fs::read(path).await?;
        Ok(data)
    }

    async fn set(&self, key: &Self::Key, value: &Self::Value) -> Result<(), Self::StorageError> {
        let path = self.path.clone().into_owned().join(key);
        let parent = path.parent().ok_or(FileStorageError::Path("No parent directory".into()))?;
        fs::create_dir_all(parent).await?;
        fs::write(path, value).await?;
        Ok(())
    }

    async fn delete(&self, key: &Self::Key) -> Result<(), Self::StorageError> {
        let path = self.path.clone().into_owned().join(key);
        fs::remove_file(path).await?;
        Ok(())
    }

    async fn list(
        &self,
        prefix: &Self::Key,
    ) -> Result<impl IntoIterator<Item = <Self::Key as ToOwned>::Owned>, Self::StorageError> {
        let mut path = self.path.clone().into_owned();
        path.push(prefix);

        let mut entries = fs::read_dir(path).await?;
        let mut list = vec![];
        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            let file_name = path.file_name();
            if let Some(file_name) = file_name {
                let mut file_name = file_name.to_string_lossy().into_owned();
                if path.is_dir() {
                    file_name.push('/');
                }
                list.push(file_name);
            }
        }

        Ok(list)
    }
}
