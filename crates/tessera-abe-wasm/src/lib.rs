extern crate wee_alloc;
mod utils;
use std::collections::HashMap;

use getrandom::getrandom;

use serde::Serialize as _;
use serde_wasm_bindgen::Serializer;
use tessera_abe::{
    curves::{
        bls24479::{Curve, Rand},
        Rand as _,
    },
    schemes::rw15::{decrypt, encrypt, AuthorityPublicKey, Ciphertext, GlobalParams, UserSecretKey},
};
use tessera_policy::pest::PolicyLanguage;
use wasm_bindgen::prelude::*;

#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

#[wasm_bindgen]
pub fn bls_24479_encryption(data: &str, gp: JsValue, pks: JsValue, policy: JsValue) -> Result<JsValue, JsValue> {
    let global_params: GlobalParams<Curve> = serde_wasm_bindgen::from_value(gp)?;
    let pks: HashMap<String, AuthorityPublicKey<Curve>> = serde_wasm_bindgen::from_value(pks)?;
    let policy: (String, PolicyLanguage) = serde_wasm_bindgen::from_value(policy)?;
    let mut rng = Rand::new();
    let mut seed = [0u8; 32];
    getrandom(&mut seed).map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;
    rng.seed(&seed);

    let ciphertext = encrypt::<Curve>(&mut rng, &global_params, &pks, policy, data.as_bytes())
        .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;
    let serializer = Serializer::new().serialize_large_number_types_as_bigints(true);
    ciphertext.serialize(&serializer).map_err(|e| JsValue::from_str(&format!("{:?}", e)))
}

#[wasm_bindgen]
pub fn bls_24479_decryption(sk: JsValue, ct: JsValue) -> Result<JsValue, JsValue> {
    let sk: UserSecretKey<Curve> = serde_wasm_bindgen::from_value(sk)?;
    let ct: Ciphertext<Curve> = serde_wasm_bindgen::from_value(ct)?;

    let plaintext = decrypt::<Curve>(&sk, &ct).map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;
    Ok(serde_wasm_bindgen::to_value(&plaintext)?)
}
