use anyhow::{bail, Result};
use async_trait::async_trait;
use nebula_abe::{
    curves::bn462::Bn462Curve,
    random::miracl::MiraclRng,
    schemes::isabella24::{AuthorityKeyPair, GlobalParams},
};
use nebula_secret_sharing::shamir::{combine, split, Share};
use nebula_storage::{
    backend::file::FileStorage,
    shield::{aes::AESShieldStorage, Shield},
    Storage as _,
};
use rand::{rngs::OsRng, RngCore as _};
use zeroize::Zeroizing;

pub type KeyPair = AuthorityKeyPair<Bn462Curve>;

const KEY_PAIR_PATH: &str = "/authority/keypair/";
const KEY_PAIR_VERSION_NAME: &str = "version";

#[async_trait]
pub trait KeyPairService {
    #[inline(always)]
    fn version_path(&self, name: &str) -> String {
        format!("{}{}/{}", KEY_PAIR_PATH, name, KEY_PAIR_VERSION_NAME)
    }
    #[inline(always)]
    fn key_pair_path(&self, name: &str, version: u64) -> String {
        format!("{}{}/{}", KEY_PAIR_PATH, name, version)
    }

    async fn generate_key_pair(&self, gp: &GlobalParams<Bn462Curve>, name: &str) -> Result<KeyPair>;
    async fn latest_key_pair_version(&self, name: &str) -> Result<Option<u64>>;
    async fn latest_key_pair(&self, name: &str) -> Result<Option<KeyPair>>;
    async fn key_pair_by_version(&self, name: &str, version: u64) -> Result<Option<KeyPair>>;
    async fn store_latest_key_pair(&self, key_pair: &KeyPair) -> Result<()>;
}

#[async_trait]
pub trait ShieldedKeyPairService: KeyPairService {
    async fn shield_initialize(&self, share: usize, threshold: usize) -> Result<Zeroizing<Vec<Share>>>;
    async fn storage_armor(&self) -> Result<()>;
    async fn storage_disarm(&self, shares: &[Share]) -> Result<()>;
}

pub struct FileKeyPairService<'a> {
    storage: AESShieldStorage<FileStorage<'a>>,
}

impl<'a> FileKeyPairService<'a> {
    pub fn new(storage: FileStorage<'a>) -> Self {
        Self { storage: AESShieldStorage::new(storage) }
    }
}

#[async_trait]
impl KeyPairService for FileKeyPairService<'_> {
    async fn generate_key_pair(&self, gp: &GlobalParams<Bn462Curve>, name: &str) -> Result<KeyPair> {
        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        let mut rng = MiraclRng::new();
        rng.seed(&seed);

        let key_pair = KeyPair::new(&mut rng, gp, name);
        Ok(key_pair)
    }

    async fn latest_key_pair_version(&self, name: &str) -> Result<Option<u64>> {
        let version_path = self.version_path(name);
        let version = self.storage.get(&version_path).await?;
        match version {
            Some(version) => {
                let version: u64 = String::from_utf8(version)?.parse()?;
                Ok(Some(version))
            }
            None => Ok(None),
        }
    }

    async fn latest_key_pair(&self, name: &str) -> Result<Option<KeyPair>> {
        let version_path = self.version_path(name);
        let version = self.storage.get(&version_path).await?;

        match version {
            Some(version) => {
                let version: u64 = String::from_utf8(version)?.parse()?;
                self.key_pair_by_version(name, version).await
            }
            None => Ok(None),
        }
    }

    async fn key_pair_by_version(&self, name: &str, version: u64) -> Result<Option<KeyPair>> {
        let key_pair_path = self.key_pair_path(name, version);
        let key_pair = self.storage.get(&key_pair_path).await?;
        match key_pair {
            Some(key_pair) => {
                let key_pair: KeyPair = rmp_serde::from_slice(&key_pair)?;
                Ok(Some(key_pair))
            }
            None => Ok(None),
        }
    }

    async fn store_latest_key_pair(&self, key_pair: &KeyPair) -> Result<()> {
        let authority_name = &key_pair.name;
        let version_path = self.version_path(authority_name);
        let latest_version = self.latest_key_pair_version(authority_name).await?.unwrap_or(0);

        let new_version = latest_version + 1;
        let new_version_path = self.key_pair_path(authority_name, new_version);
        let key_pair_bytes = rmp_serde::to_vec(key_pair)?;
        self.storage.set(&new_version_path, &key_pair_bytes).await?;
        self.storage.set(&version_path, new_version.to_string().as_bytes()).await?;

        Ok(())
    }
}

#[async_trait]
impl ShieldedKeyPairService for FileKeyPairService<'_> {
    async fn shield_initialize(&self, share: usize, threshold: usize) -> Result<Zeroizing<Vec<Share>>> {
        if self.storage.is_initialized().await? {
            bail!("shield storage is already initialized");
        }

        let master_key = self.storage.generate_key().await?;
        let shares = Zeroizing::new(split(&master_key, share, threshold));
        self.storage.initialize(&master_key).await?;

        self.storage.disarm(&master_key).await?; // Disarm the storage immediately after initialization
        Ok(shares)
    }

    async fn storage_armor(&self) -> Result<()> {
        Ok(self.storage.armor().await?)
    }

    async fn storage_disarm(&self, shares: &[Share]) -> Result<()> {
        let master_key = Zeroizing::new(combine(shares));
        Ok(self.storage.disarm(&master_key).await?)
    }
}
