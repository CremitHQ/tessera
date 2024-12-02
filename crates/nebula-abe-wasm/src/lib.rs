extern crate alloc;

use base64::{engine::general_purpose::STANDARD, Engine as _};
#[cfg(target_arch = "wasm32")]
use lol_alloc::{FreeListAllocator, LockedAllocator};
mod utils;
use std::collections::HashMap;

use getrandom::getrandom;

use nebula_abe::{
    curves::bn462::Bn462Curve,
    error::ABEError,
    random::miracl::MiraclRng,
    schemes::isabella24::{decrypt, encrypt, AuthorityPublicKey, Ciphertext, GlobalParams, UserSecretKey},
};
use nebula_policy::pest::PolicyLanguage;
use wasm_bindgen::prelude::*;

#[cfg(target_arch = "wasm32")]
#[global_allocator]
static ALLOCATOR: LockedAllocator<FreeListAllocator> = LockedAllocator::new(FreeListAllocator::new());

#[wasm_bindgen(getter_with_clone)]
pub struct NebulaError {
    pub r#type: String,
    pub message: String,
    pub metadata: JsValue,
}

enum NebulaCryptError {
    DecodeBase64(base64::DecodeError),
    EncodeMessagePack(rmp_serde::encode::Error),
    DecodeMessagePack(rmp_serde::decode::Error),
    GetRandom(getrandom::Error),
    AttributeBasedEncrypt(nebula_abe::error::ABEError),
    SumUserSecretKey(nebula_abe::schemes::isabella24::SumUserSecretKeyError),
}

impl From<NebulaCryptError> for NebulaError {
    fn from(e: NebulaCryptError) -> NebulaError {
        match e {
            NebulaCryptError::DecodeBase64(e) => {
                NebulaError { r#type: "DecodeBase64".to_string(), message: e.to_string(), metadata: JsValue::null() }
            }
            NebulaCryptError::EncodeMessagePack(e) => NebulaError {
                r#type: "EncodeMessagePack".to_string(),
                message: e.to_string(),
                metadata: JsValue::null(),
            },
            NebulaCryptError::DecodeMessagePack(e) => NebulaError {
                r#type: "DecodeMessagePack".to_string(),
                message: e.to_string(),
                metadata: JsValue::null(),
            },
            NebulaCryptError::GetRandom(e) => {
                NebulaError { r#type: "GetRandom".to_string(), message: e.to_string(), metadata: JsValue::null() }
            }
            NebulaCryptError::AttributeBasedEncrypt(e) => e.into(),
            NebulaCryptError::SumUserSecretKey(e) => NebulaError {
                r#type: "SumUserSecretKey".to_string(),
                message: e.to_string(),
                metadata: JsValue::null(),
            },
        }
    }
}

impl From<ABEError> for NebulaError {
    fn from(e: ABEError) -> Self {
        let message = e.to_string();
        match e {
            nebula_abe::error::ABEError::InvalidPolicy(policy) => match policy {
                nebula_abe::error::InvalidPolicyErrorKind::PolicyNotSatisfied => {
                    NebulaError { r#type: "PolicyNotSatisfied".to_string(), message, metadata: JsValue::null() }
                }
                _ => NebulaError { r#type: "InvalidPolicy".to_string(), message, metadata: JsValue::null() },
            },
            nebula_abe::error::ABEError::InvalidAuthority(invalid_authority_error_kind) => {
                match invalid_authority_error_kind {
                    nebula_abe::error::InvalidAuthorityErrorKind::AuthorityNotFound(authority_name) => NebulaError {
                        r#type: "AuthorityNotFound".to_string(),
                        message,
                        metadata: JsValue::from_str(&authority_name),
                    },
                }
            }
            nebula_abe::error::ABEError::InvalidAttribute(invalid_attribute_kind) => match invalid_attribute_kind {
                nebula_abe::error::InvalidAttributeKind::AttributeNotFound(attribute) => NebulaError {
                    r#type: "AttributeNotFound".to_string(),
                    message,
                    metadata: JsValue::from_str(&attribute),
                },
                nebula_abe::error::InvalidAttributeKind::ParseAttributeError(_) => {
                    NebulaError { r#type: "FailedParseAttribute".to_string(), message, metadata: JsValue::null() }
                }
            },
            _ => NebulaError { r#type: "UnexpectedError".to_string(), message, metadata: JsValue::null() },
        }
    }
}

#[wasm_bindgen]
pub fn nebula_encrypt(gp: &str, pks: Vec<String>, policy: &str, data: &str) -> Result<String, NebulaError> {
    let gp = STANDARD.decode(gp).map_err(NebulaCryptError::DecodeBase64)?;
    let gp: GlobalParams<Bn462Curve> = rmp_serde::from_slice(&gp).map_err(NebulaCryptError::DecodeMessagePack)?;

    let pks = pks
        .iter()
        .map(|public_key| {
            let decoded = STANDARD.decode(public_key).map_err(NebulaCryptError::DecodeBase64)?;
            let value: AuthorityPublicKey<Bn462Curve> =
                rmp_serde::from_slice(&decoded).map_err(NebulaCryptError::DecodeMessagePack)?;
            Ok((value.name.clone(), value))
        })
        .collect::<Result<HashMap<String, AuthorityPublicKey<Bn462Curve>>, NebulaCryptError>>()?;

    let policy = (policy.to_string(), PolicyLanguage::HumanPolicy);

    let mut rng = MiraclRng::new();
    let mut seed = [0u8; 32];
    getrandom(&mut seed).map_err(NebulaCryptError::GetRandom)?;
    rng.seed(&seed);

    let ciphertext = encrypt::<Bn462Curve>(&mut rng, &gp, &pks, policy, data.as_bytes())
        .map_err(NebulaCryptError::AttributeBasedEncrypt)?;
    let ciphertext = rmp_serde::to_vec(&ciphertext).map_err(NebulaCryptError::EncodeMessagePack)?;
    Ok(STANDARD.encode(&ciphertext))
}

#[wasm_bindgen]
pub fn nebula_decrypt(gp: &str, sk: Vec<String>, ct: &str) -> Result<String, NebulaError> {
    let sk = UserSecretKey::<Bn462Curve>::sum(
        sk.iter()
            .map(|sk| {
                let decoded = STANDARD.decode(sk).map_err(NebulaCryptError::DecodeBase64)?;
                rmp_serde::from_slice(&decoded).map_err(NebulaCryptError::DecodeMessagePack)
            })
            .collect::<Result<Vec<UserSecretKey<Bn462Curve>>, NebulaCryptError>>()?
            .into_iter(),
    )
    .map_err(NebulaCryptError::SumUserSecretKey)?;

    let gp = STANDARD.decode(gp).map_err(NebulaCryptError::DecodeBase64)?;
    let gp: GlobalParams<Bn462Curve> = rmp_serde::from_slice(&gp).map_err(NebulaCryptError::DecodeMessagePack)?;

    let ct = STANDARD.decode(ct).map_err(NebulaCryptError::DecodeBase64)?;
    let ct: Ciphertext<Bn462Curve> = rmp_serde::from_slice(&ct).map_err(NebulaCryptError::DecodeMessagePack)?;

    let plaintext = decrypt::<Bn462Curve>(&gp, &sk, &ct).map_err(NebulaCryptError::AttributeBasedEncrypt)?;
    String::from_utf8(plaintext).map_err(|e| NebulaError {
        r#type: "DecodeUtf8".to_string(),
        message: e.to_string(),
        metadata: JsValue::null(),
    })
}
