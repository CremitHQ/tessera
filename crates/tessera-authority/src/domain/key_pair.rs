use anyhow::Result;
use async_trait::async_trait;
use rand::{rngs::OsRng, RngCore as _};
use tessera_abe::{
    curves::bls24479::Bls24479Curve,
    random::miracl::MiraclRng,
    schemes::rw15::{AuthorityKeyPair, GlobalParams},
};
use tessera_storage::{backend::file::FileStorage, Storage as _};

type KeyPair = AuthorityKeyPair<Bls24479Curve>;

const KEY_PAIR_PATH: &str = "/authority/keypair/";
const KEY_PAIR_VERSION_NAME: &str = "version";

#[async_trait]
pub trait KeyPairService {
    #[inline(always)]
    fn version_path(&self, authority_name: &str) -> String {
        format!("{}{}/{}", KEY_PAIR_PATH, authority_name, KEY_PAIR_VERSION_NAME)
    }
    #[inline(always)]
    fn key_pair_path(&self, authority_name: &str, version: u64) -> String {
        format!("{}{}/{}", KEY_PAIR_PATH, authority_name, version)
    }

    async fn generate_key_pair(&self, gp: &GlobalParams<Bls24479Curve>, authority_name: &str) -> Result<KeyPair>;
    async fn latest_key_pair_version(&self, authority_name: &str) -> Result<Option<u64>>;
    async fn load_latest_key_pair(&self, authority_name: &str) -> Result<Option<KeyPair>>;
    async fn load_key_pair(&self, authority_name: &str, version: u64) -> Result<Option<KeyPair>>;
    async fn store_latest_key_pair(&self, key_pair: KeyPair) -> Result<()>;
}

pub struct FileKeyPairService<'a> {
    storage: FileStorage<'a>,
}

impl<'a> FileKeyPairService<'a> {
    pub fn new(storage: FileStorage<'a>) -> Self {
        Self { storage }
    }
}

#[async_trait]
impl KeyPairService for FileKeyPairService<'_> {
    async fn generate_key_pair(&self, gp: &GlobalParams<Bls24479Curve>, authority_name: &str) -> Result<KeyPair> {
        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        let mut rng = MiraclRng::new();
        rng.seed(&seed);

        let key_pair = KeyPair::new(&mut rng, &gp, authority_name);
        Ok(key_pair)
    }

    async fn latest_key_pair_version(&self, authority_name: &str) -> Result<Option<u64>> {
        let version_path = self.version_path(authority_name);
        let version = self.storage.get(&version_path).await?;
        match version {
            Some(version) => {
                let version: u64 = String::from_utf8(version)?.parse()?;
                Ok(Some(version))
            }
            None => Ok(None),
        }
    }

    async fn load_latest_key_pair(&self, authority_name: &str) -> Result<Option<KeyPair>> {
        let version_path = self.version_path(authority_name);
        let version = self.storage.get(&version_path).await?;

        match version {
            Some(version) => {
                let version: u64 = String::from_utf8(version)?.parse()?;
                self.load_key_pair(authority_name, version).await
            }
            None => Ok(None),
        }
    }

    async fn load_key_pair(&self, authority_name: &str, version: u64) -> Result<Option<KeyPair>> {
        let key_pair_path = self.key_pair_path(authority_name, version);
        let key_pair = self.storage.get(&key_pair_path).await?;
        match key_pair {
            Some(key_pair) => {
                let key_pair: KeyPair = bincode::deserialize(&key_pair)?;
                Ok(Some(key_pair))
            }
            None => Ok(None),
        }
    }

    async fn store_latest_key_pair(&self, key_pair: KeyPair) -> Result<()> {
        let authority_name = &key_pair.name;
        let version_path = self.version_path(authority_name);
        let latest_version = self.latest_key_pair_version(authority_name).await?.unwrap_or(0);

        let new_version = latest_version + 1;
        let new_version_path = self.key_pair_path(authority_name, new_version);
        let key_pair_bytes = bincode::serialize(&key_pair)?;
        self.storage.set(&new_version_path, &key_pair_bytes).await?;
        self.storage.set(&version_path, new_version.to_string().as_bytes()).await?;

        Ok(())
    }
}
