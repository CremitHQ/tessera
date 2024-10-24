extern crate alloc;

#[cfg(target_arch = "wasm32")]
use lol_alloc::{FreeListAllocator, LockedAllocator};
mod utils;
use std::collections::HashMap;

use getrandom::getrandom;

use serde::Serialize as _;
use serde_wasm_bindgen::Serializer;
use tessera_abe::{
    curves::bls24479::Bls24479Curve,
    random::miracl::MiraclRng,
    schemes::rw15::{decrypt, encrypt, AuthorityPublicKey, Ciphertext, GlobalParams, UserSecretKey},
};
use tessera_policy::pest::PolicyLanguage;
use wasm_bindgen::prelude::*;

#[cfg(target_arch = "wasm32")]
#[global_allocator]
static ALLOCATOR: LockedAllocator<FreeListAllocator> = LockedAllocator::new(FreeListAllocator::new());

#[wasm_bindgen]
pub fn bls_24479_encryption(data: &str, gp: JsValue, pks: JsValue, policy: JsValue) -> Result<JsValue, JsValue> {
    let global_params: GlobalParams<Bls24479Curve> = serde_wasm_bindgen::from_value(gp)?;
    let pks: HashMap<String, AuthorityPublicKey<Bls24479Curve>> = serde_wasm_bindgen::from_value(pks)?;
    let pks = pks.iter().map(|(k, v)| (k.clone(), v)).collect::<HashMap<_, &_>>();
    let policy: (String, PolicyLanguage) = serde_wasm_bindgen::from_value(policy)?;
    let mut rng = MiraclRng::new();
    let mut seed = [0u8; 32];
    getrandom(&mut seed).map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;
    rng.seed(&seed);

    let ciphertext = encrypt::<Bls24479Curve>(&mut rng, &global_params, &pks, policy, data.as_bytes())
        .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;
    let serializer = Serializer::new().serialize_large_number_types_as_bigints(true);
    ciphertext.serialize(&serializer).map_err(|e| JsValue::from_str(&format!("{:?}", e)))
}

#[wasm_bindgen]
pub fn bls_24479_decryption(sk: JsValue, ct: JsValue) -> Result<JsValue, JsValue> {
    let sk: UserSecretKey<Bls24479Curve> = serde_wasm_bindgen::from_value(sk)?;
    let ct: Ciphertext<Bls24479Curve> = serde_wasm_bindgen::from_value(ct)?;

    let plaintext = decrypt::<Bls24479Curve>(&sk, &ct).map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;
    Ok(serde_wasm_bindgen::to_value(&plaintext)?)
}
