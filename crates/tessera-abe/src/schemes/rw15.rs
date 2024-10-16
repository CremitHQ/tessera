use crate::{
    curves::FieldWithOrder,
    error::ABEError,
    random::Random,
    utils::{
        aes::{decrypt_symmetric, encrypt_symmetric},
        secret_shares::{calc_coefficients, calc_pruned, gen_shares_policy, remove_index},
        tools::traverse_policy,
    },
};

use crate::curves::{Field, GroupG1, GroupG2, GroupGt, Inv as _, PairingCurve, Pow as _};
use serde::{Deserialize, Serialize};
use std::{borrow::Cow, collections::HashMap};
use tessera_policy::pest::{parse, PolicyLanguage};

#[derive(Serialize, Deserialize)]
pub struct GlobalParams<T>
where
    T: PairingCurve,
{
    pub g1: T::G1,
    pub g2: T::G2,
    pub e: T::Gt,
}

impl<T> GlobalParams<T>
where
    T: PairingCurve,
{
    pub fn new(rng: &mut <T::Field as Random>::Rng) -> Self {
        let x = T::Field::random(rng);
        let g1 = T::G1::new(&x);
        let g2 = T::G2::new(&x);
        let e = T::pair(&g1, &g2);

        Self { g1, g2, e }
    }
}

#[derive(Serialize, Deserialize)]
pub struct AuthorityKeyPair<'a, T: PairingCurve> {
    pub name: Cow<'a, str>,
    pub pk: AuthorityPublicKey<T>,
    pub mk: AuthorityMasterKey<T>,
}

#[derive(Serialize, Deserialize)]
pub struct AuthorityPublicKey<T: PairingCurve> {
    pub e_alpha: T::Gt,
    pub gy: T::G1,
}

#[derive(Serialize, Deserialize)]
pub struct AuthorityMasterKey<T: PairingCurve> {
    pub alpha: T::Field,
    pub y: T::Field,
}

impl<'a, T> AuthorityKeyPair<'a, T>
where
    T: PairingCurve,
{
    pub fn new<S>(rng: &mut <T::Field as Random>::Rng, gp: &GlobalParams<T>, name: S) -> AuthorityKeyPair<'a, T>
    where
        S: Into<Cow<'a, str>>,
    {
        let alpha = T::Field::random(rng);
        let y = T::Field::random(rng);
        let e_alpha = gp.e.clone().pow(&alpha);
        let gy = gp.g1.clone() * &y;

        let pk = AuthorityPublicKey { e_alpha, gy };
        let mk = AuthorityMasterKey { alpha, y };
        Self { name: name.into(), pk, mk }
    }
}

#[derive(Serialize, Deserialize)]
pub struct UserAttributeKey<T: PairingCurve> {
    pub k: T::G2,
    pub kp: T::G1,
}

#[derive(Serialize, Deserialize)]
pub struct UserSecretKey<T: PairingCurve> {
    pub gid: String,
    pub inner: HashMap<String, UserAttributeKey<T>>,
}

impl<T> UserAttributeKey<T>
where
    T: PairingCurve,
{
    pub fn new<S: AsRef<str>>(
        rng: &mut <T::Field as Random>::Rng,
        gp: &GlobalParams<T>,
        mk: &AuthorityMasterKey<T>,
        gid: &str,
        attribute: S,
    ) -> Self {
        let t = T::Field::random(rng);
        let k = gp.g2.clone() * &mk.alpha;
        let k = k + (T::hash_to_g2(gid.as_bytes()) * &mk.y);
        let k = k + (T::hash_to_g2(attribute.as_ref().as_bytes()) * &t);
        let kp = gp.g1.clone() * &t;
        Self { k, kp }
    }
}

impl<T> UserSecretKey<T>
where
    T: PairingCurve,
{
    pub fn new<S: AsRef<str>>(
        rng: &mut <T::Field as Random>::Rng,
        gp: &GlobalParams<T>,
        mk: &AuthorityMasterKey<T>,
        gid: &str,
        attributes: &[S],
    ) -> Self {
        let inner = attributes
            .iter()
            .map(|attr| {
                let key = UserAttributeKey::new(rng, gp, mk, gid, attr);
                (attr.as_ref().to_string(), key)
            })
            .collect();
        Self { gid: gid.to_string(), inner }
    }

    pub fn add_attribute<S>(
        &mut self,
        rng: &mut <T::Field as Random>::Rng,
        gp: &GlobalParams<T>,
        mk: &AuthorityMasterKey<T>,
        attribute: S,
    ) where
        S: AsRef<str> + Clone,
    {
        let key = UserAttributeKey::new(rng, gp, mk, &self.gid, attribute.clone());
        self.inner.insert(attribute.as_ref().to_string(), key);
    }

    pub fn add_attributes<S>(
        &mut self,
        rng: &mut <T::Field as Random>::Rng,
        gp: &GlobalParams<T>,
        mk: &AuthorityMasterKey<T>,
        attributes: &[S],
    ) where
        S: AsRef<str> + Clone,
    {
        for attr in attributes {
            let key = UserAttributeKey::new(rng, gp, mk, &self.gid, attr);
            self.inner.insert(attr.as_ref().to_string(), key);
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct Ciphertext<T: PairingCurve> {
    pub policy: (String, PolicyLanguage),
    pub c0: T::Gt,
    pub c1: HashMap<String, T::Gt>,
    pub c2: HashMap<String, T::G1>,
    pub c3: HashMap<String, T::G1>,
    pub c4: HashMap<String, T::G2>,
    pub ct: Vec<u8>,
}

pub fn encrypt<T: PairingCurve>(
    rng: &mut <T::Field as Random>::Rng,
    gp: &GlobalParams<T>,
    pks: &HashMap<String, AuthorityPublicKey<T>>,
    policy: (String, PolicyLanguage),
    data: &[u8],
) -> Result<Ciphertext<T>, ABEError> {
    let (policy_name, language) = policy;
    let policy = parse(&policy_name, language)?;
    let s = T::Field::random_within_order(rng);
    let w = T::Field::new();

    let s_shares = gen_shares_policy::<T>(rng, &s, &policy, None);
    let w_shares = gen_shares_policy::<T>(rng, &w, &policy, None);

    let c0 = T::Gt::random(rng);
    let msg: Vec<u8> = c0.clone().into();

    let c0 = c0 * &(gp.e.clone().pow(&s));
    let mut c1 = HashMap::new();
    let mut c2 = HashMap::new();
    let mut c3 = HashMap::new();
    let mut c4 = HashMap::new();

    for (attr_name, s_share) in s_shares.into_iter() {
        let tx = T::Field::random(rng);
        let authority_name =
            attr_name.split_once("@").ok_or(ABEError::EncryptionError("Invalid attribute name".to_string()))?.0;
        let attr = remove_index(&attr_name);

        let pk_attr = pks.get(authority_name);
        if let Some(authority_pk) = pk_attr {
            let c1x = gp.e.clone().pow(&s_share);
            let c1x = c1x * &(authority_pk.e_alpha.clone().pow(&tx));
            c1.insert(attr_name.clone(), c1x);

            let c2x = -(gp.g1.clone() * &tx);
            c2.insert(attr_name.clone(), c2x);

            let wx = w_shares.get(&attr_name).ok_or(ABEError::EncryptionError("Invalid attribute name".to_string()))?;
            let c3x = (authority_pk.gy.clone() * &tx) + (gp.g1.clone() * wx);
            c3.insert(attr_name.clone(), c3x);

            let c4x = T::hash_to_g2(attr.as_bytes()) * &tx;
            c4.insert(attr_name.clone(), c4x);
        }
    }

    let ct = encrypt_symmetric::<T, _>(rng, msg, data)?;
    Ok(Ciphertext { policy: (policy_name, language), c0, c1, c2, c3, c4, ct })
}

pub fn decrypt<T: PairingCurve>(sk: &UserSecretKey<T>, ct: &Ciphertext<T>) -> Result<Vec<u8>, ABEError> {
    let (policy_name, lang) = ct.policy.clone();
    let policy = parse(&policy_name, lang)?;

    let attributes = sk.inner.keys().map(|k| k.to_string()).collect::<Vec<_>>();
    let is_satisfied_policy = traverse_policy(&attributes, &policy, tessera_policy::pest::PolicyType::Leaf);
    if !is_satisfied_policy {
        return Err(ABEError::PolicyNotSatisfied);
    }

    let (is_matched, matched_nodes) = calc_pruned(&attributes, &policy, None)?;
    if !is_matched {
        return Err(ABEError::PolicyNotSatisfied);
    }

    let mut coefficients = HashMap::new();
    calc_coefficients::<T>(&policy, T::Field::one(), &mut coefficients, None);

    let h_user = T::hash_to_g2(sk.gid.as_bytes());
    let mut b = T::Gt::one();

    for (attr, attr_and_index) in matched_nodes {
        let c1 = ct.c1.get(&attr_and_index).ok_or(ABEError::DecryptionError("Failed to get c1".to_string()))?;
        let c2 = ct.c2.get(&attr_and_index).ok_or(ABEError::DecryptionError("Failed to get c2".to_string()))?;
        let c3 = ct.c3.get(&attr_and_index).ok_or(ABEError::DecryptionError("Failed to get c3".to_string()))?;
        let c4 = ct.c4.get(&attr_and_index).ok_or(ABEError::DecryptionError("Failed to get c4".to_string()))?;
        let k = &sk
            .inner
            .get(&attr)
            .ok_or(ABEError::DecryptionError("Failed to get k from user secret key".to_string()))?
            .k;
        let kp = &sk
            .inner
            .get(&attr)
            .ok_or(ABEError::DecryptionError("Failed to get kp from user secret key".to_string()))?
            .kp;
        let coeff = coefficients
            .get(&attr_and_index)
            .ok_or(ABEError::DecryptionError("Failed to get coefficent".to_string()))?;

        let base = T::pair(c2, k) * c1;
        let base = base * &T::pair(c3, &h_user);
        let base = base * &T::pair(kp, c4);
        let base = base.pow(coeff);

        b = b * &base;
    }

    b = b.inverse();

    let c0 = ct.c0.clone();
    let msg = c0 * &b;
    let msg: Vec<u8> = msg.into();
    decrypt_symmetric(msg, &ct.ct)
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use rand::Rng as _;

    use super::*;
    use crate::{curves::bls24479::Bls24479Curve, random::miracl::MiraclRng};

    #[test]
    fn encrypt_and_decrypt() {
        let mut rng = MiraclRng::new();
        let mut thread_rng = rand::thread_rng();
        let mut seed = [0u8; 128];
        thread_rng.fill(&mut seed);
        rng.seed(&seed);

        let gp = GlobalParams::<Bls24479Curve>::new(&mut rng);

        println!("Global parameters generated.");
        let authority_a = AuthorityKeyPair::new(&mut rng, &gp, "Aauthority");
        println!("Authority A generated.");
        let authority_b = AuthorityKeyPair::new(&mut rng, &gp, "Bauthority");
        println!("Authority B generated.");

        let mut alice =
            UserSecretKey::new(&mut rng, &gp, &authority_a.mk, "alice", &["Aauthority@ADMIN", "Aauthority@GOD"]);
        println!("Alice generated.");

        alice.add_attributes(&mut rng, &gp, &authority_b.mk, &["Bauthority@CTO"]);
        println!("Alice added attributes.");

        // let alice_by_authority_b = UserSecretKey::new(&mut rng, &gp, &authority_b.mk, "alice", &["B_authority@CEO"]);

        let mut bob = UserSecretKey::new(&mut rng, &gp, &authority_a.mk, "bob", &["Aauthority@USER"]);
        println!("Bob generated.");
        bob.add_attributes(&mut rng, &gp, &authority_b.mk, &["Bauthority@CTO"]);
        println!("Bob added attributes.");
        // let bob_by_authority_b = UserSecretKey::new(&mut rng, &gp, &authority_b.mk, "bob", &["B_authority@CTO"]);

        let plaintext = "THIS IS SECRET MESSAGE";
        let policy = r#""Aauthority@GOD" and "Bauthority@CTO""#;

        let mut pks = HashMap::new();
        pks.insert("Aauthority".to_string(), authority_a.pk);
        pks.insert("Bauthority".to_string(), authority_b.pk);
        let t = Instant::now();
        let ciphertext =
            encrypt(&mut rng, &gp, &pks, (policy.to_string(), PolicyLanguage::HumanPolicy), plaintext.as_bytes())
                .unwrap();
        println!("Time taken to encrypt: {:?}", t.elapsed());
        println!("Ciphertext generated.");

        let decrypt_text = decrypt(&alice, &ciphertext).unwrap();
        assert_eq!(plaintext.as_bytes(), decrypt_text.as_slice());
        println!("Decrypted text: {:?}", String::from_utf8(decrypt_text.clone()).unwrap());
    }
}
