extern crate alloc;

use base64::{engine::general_purpose::STANDARD, Engine as _};
#[cfg(target_arch = "wasm32")]
use lol_alloc::{FreeListAllocator, LockedAllocator};
mod utils;
use std::collections::HashMap;

use getrandom::getrandom;

use tessera_abe::{
    curves::bn462::Bn462Curve,
    error::ABEError,
    random::miracl::MiraclRng,
    schemes::isabella24::{
        decrypt, encrypt, AuthorityKeyPair, AuthorityMasterKey, AuthorityPublicKey, Ciphertext, GlobalParams,
        UserSecretKey,
    },
};
use tessera_policy::pest::PolicyLanguage;
use wasm_bindgen::prelude::*;

#[cfg(target_arch = "wasm32")]
#[global_allocator]
static ALLOCATOR: LockedAllocator<FreeListAllocator> = LockedAllocator::new(FreeListAllocator::new());

#[wasm_bindgen(getter_with_clone)]
pub struct TesseraError {
    pub r#type: String,
    pub message: String,
    pub metadata: JsValue,
}

enum TesseraCryptError {
    DecodeBase64(base64::DecodeError),
    EncodeMessagePack(rmp_serde::encode::Error),
    DecodeMessagePack(rmp_serde::decode::Error),
    GetRandom(getrandom::Error),
    AttributeBasedEncrypt(tessera_abe::error::ABEError),
    SumUserSecretKey(tessera_abe::schemes::isabella24::SumUserSecretKeyError),
}

impl From<TesseraCryptError> for TesseraError {
    fn from(e: TesseraCryptError) -> TesseraError {
        match e {
            TesseraCryptError::DecodeBase64(e) => {
                TesseraError { r#type: "DecodeBase64".to_string(), message: e.to_string(), metadata: JsValue::null() }
            }
            TesseraCryptError::EncodeMessagePack(e) => TesseraError {
                r#type: "EncodeMessagePack".to_string(),
                message: e.to_string(),
                metadata: JsValue::null(),
            },
            TesseraCryptError::DecodeMessagePack(e) => TesseraError {
                r#type: "DecodeMessagePack".to_string(),
                message: e.to_string(),
                metadata: JsValue::null(),
            },
            TesseraCryptError::GetRandom(e) => {
                TesseraError { r#type: "GetRandom".to_string(), message: e.to_string(), metadata: JsValue::null() }
            }
            TesseraCryptError::AttributeBasedEncrypt(e) => e.into(),
            TesseraCryptError::SumUserSecretKey(e) => TesseraError {
                r#type: "SumUserSecretKey".to_string(),
                message: e.to_string(),
                metadata: JsValue::null(),
            },
        }
    }
}

impl From<ABEError> for TesseraError {
    fn from(e: ABEError) -> Self {
        let message = e.to_string();
        match e {
            tessera_abe::error::ABEError::InvalidPolicy(policy) => match policy {
                tessera_abe::error::InvalidPolicyErrorKind::PolicyNotSatisfied => {
                    TesseraError { r#type: "PolicyNotSatisfied".to_string(), message, metadata: JsValue::null() }
                }
                _ => TesseraError { r#type: "InvalidPolicy".to_string(), message, metadata: JsValue::null() },
            },
            tessera_abe::error::ABEError::InvalidAuthority(invalid_authority_error_kind) => {
                match invalid_authority_error_kind {
                    tessera_abe::error::InvalidAuthorityErrorKind::AuthorityNotFound(authority_name) => TesseraError {
                        r#type: "AuthorityNotFound".to_string(),
                        message,
                        metadata: JsValue::from_str(&authority_name),
                    },
                }
            }
            tessera_abe::error::ABEError::InvalidAttribute(invalid_attribute_kind) => match invalid_attribute_kind {
                tessera_abe::error::InvalidAttributeKind::AttributeNotFound(attribute) => TesseraError {
                    r#type: "AttributeNotFound".to_string(),
                    message,
                    metadata: JsValue::from_str(&attribute),
                },
                tessera_abe::error::InvalidAttributeKind::ParseAttributeError(_) => {
                    TesseraError { r#type: "FailedParseAttribute".to_string(), message, metadata: JsValue::null() }
                }
            },
            _ => TesseraError { r#type: "UnexpectedError".to_string(), message, metadata: JsValue::null() },
        }
    }
}

#[wasm_bindgen]
pub fn tessera_encrypt(gp: &str, pks: Vec<String>, policy: &str, data: &str) -> Result<String, TesseraError> {
    let gp = STANDARD.decode(gp).map_err(TesseraCryptError::DecodeBase64)?;
    let gp: GlobalParams<Bn462Curve> = rmp_serde::from_slice(&gp).map_err(TesseraCryptError::DecodeMessagePack)?;

    let pks = pks
        .iter()
        .map(|public_key| {
            let decoded = STANDARD.decode(public_key).map_err(TesseraCryptError::DecodeBase64)?;
            let value: AuthorityPublicKey<Bn462Curve> =
                rmp_serde::from_slice(&decoded).map_err(TesseraCryptError::DecodeMessagePack)?;
            Ok((value.name.clone(), value))
        })
        .collect::<Result<HashMap<String, AuthorityPublicKey<Bn462Curve>>, TesseraCryptError>>()?;

    let policy = (policy.to_string(), PolicyLanguage::HumanPolicy);

    let mut rng = MiraclRng::new();
    let mut seed = [0u8; 32];
    getrandom(&mut seed).map_err(TesseraCryptError::GetRandom)?;
    rng.seed(&seed);

    let ciphertext = encrypt::<Bn462Curve>(&mut rng, &gp, &pks, policy, data.as_bytes())
        .map_err(TesseraCryptError::AttributeBasedEncrypt)?;
    let ciphertext = rmp_serde::to_vec(&ciphertext).map_err(TesseraCryptError::EncodeMessagePack)?;
    Ok(STANDARD.encode(&ciphertext))
}

#[wasm_bindgen]
pub fn tessera_decrypt(gp: &str, sk: Vec<String>, ct: &str) -> Result<String, TesseraError> {
    let sk = UserSecretKey::<Bn462Curve>::sum(
        sk.iter()
            .map(|sk| {
                let decoded = STANDARD.decode(sk).map_err(TesseraCryptError::DecodeBase64)?;
                rmp_serde::from_slice(&decoded).map_err(TesseraCryptError::DecodeMessagePack)
            })
            .collect::<Result<Vec<UserSecretKey<Bn462Curve>>, TesseraCryptError>>()?
            .into_iter(),
    )
    .map_err(TesseraCryptError::SumUserSecretKey)?;

    let gp = STANDARD.decode(gp).map_err(TesseraCryptError::DecodeBase64)?;
    let gp: GlobalParams<Bn462Curve> = rmp_serde::from_slice(&gp).map_err(TesseraCryptError::DecodeMessagePack)?;

    let ct = STANDARD.decode(ct).map_err(TesseraCryptError::DecodeBase64)?;
    let ct: Ciphertext<Bn462Curve> = rmp_serde::from_slice(&ct).map_err(TesseraCryptError::DecodeMessagePack)?;

    let plaintext = decrypt::<Bn462Curve>(&gp, &sk, &ct).map_err(TesseraCryptError::AttributeBasedEncrypt)?;
    String::from_utf8(plaintext).map_err(|e| TesseraError {
        r#type: "DecodeUtf8".to_string(),
        message: e.to_string(),
        metadata: JsValue::null(),
    })
}

// -------------------
// The below functions are for testing purposes only. will be removed in the future
// -------------------

#[wasm_bindgen]
pub fn mock_global_params() -> Result<String, TesseraError> {
    let mut rng = MiraclRng::new();
    let mut seed = [0u8; 32];
    getrandom(&mut seed).map_err(TesseraCryptError::GetRandom)?;
    rng.seed(&seed);

    let gp = GlobalParams::<Bn462Curve>::new(&mut rng);
    let gp = rmp_serde::to_vec(&gp).map_err(TesseraCryptError::EncodeMessagePack)?;
    Ok(STANDARD.encode(&gp))
}

#[wasm_bindgen(getter_with_clone)]
pub struct AuthorityKey {
    pub name: String,
    pub pk: String,
    pub mk: String,
}

#[wasm_bindgen]
pub fn mock_authority(gp: &str, name: &str) -> Result<AuthorityKey, TesseraError> {
    let mut rng = MiraclRng::new();
    let mut seed = [0u8; 32];
    getrandom(&mut seed).map_err(TesseraCryptError::GetRandom)?;
    rng.seed(&seed);

    let gp = STANDARD.decode(gp).map_err(TesseraCryptError::DecodeBase64)?;
    let gp: GlobalParams<Bn462Curve> = rmp_serde::from_slice(&gp).map_err(TesseraCryptError::DecodeMessagePack)?;
    let authority = AuthorityKeyPair::<Bn462Curve>::new(&mut rng, &gp, name);

    let pk = rmp_serde::to_vec(&authority.pk).map_err(TesseraCryptError::EncodeMessagePack)?;
    let pk = STANDARD.encode(&pk);
    let mk = rmp_serde::to_vec(&authority.mk).map_err(TesseraCryptError::EncodeMessagePack)?;
    let mk = STANDARD.encode(&mk);

    Ok(AuthorityKey { name: name.to_string(), pk, mk })
}

#[wasm_bindgen]
pub fn mock_user_secret_key(gp: &str, mk: &str, gid: &str, attributes: Vec<String>) -> Result<String, TesseraError> {
    let mut rng = MiraclRng::new();
    let mut seed = [0u8; 32];
    getrandom(&mut seed).map_err(TesseraCryptError::GetRandom)?;
    rng.seed(&seed);

    let gp = STANDARD.decode(gp).map_err(TesseraCryptError::DecodeBase64)?;
    let gp: GlobalParams<Bn462Curve> = rmp_serde::from_slice(&gp).map_err(TesseraCryptError::DecodeMessagePack)?;

    let mk = STANDARD.decode(mk).map_err(TesseraCryptError::DecodeBase64)?;
    let mk: AuthorityMasterKey<Bn462Curve> =
        rmp_serde::from_slice(&mk).map_err(TesseraCryptError::DecodeMessagePack)?;

    let user_secret_key = UserSecretKey::<Bn462Curve>::new(&mut rng, &gp, &mk, gid, &attributes);
    let user_secret_key = rmp_serde::to_vec(&user_secret_key).map_err(TesseraCryptError::EncodeMessagePack)?;
    Ok(STANDARD.encode(&user_secret_key))
}
