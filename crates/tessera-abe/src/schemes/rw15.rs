use crate::{
    curves::{FieldWithOrder, RefMul as _, RefPow as _},
    error::ABEError,
    random::Random,
    utils::{
        aes::{decrypt_symmetric, encrypt_symmetric},
        secret_shares::{calc_coefficients, calc_pruned, gen_shares_policy, remove_index},
        tools::traverse_policy,
    },
};

use crate::curves::{Field, GroupG1, GroupG2, GroupGt, Inv as _, PairingCurve};
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
pub struct AuthorityKeyPair<T: PairingCurve> {
    pub name: String,
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

impl<T> AuthorityKeyPair<T>
where
    T: PairingCurve,
{
    pub fn new<'a, S>(rng: &mut <T::Field as Random>::Rng, gp: &GlobalParams<T>, name: S) -> AuthorityKeyPair<T>
    where
        S: Into<Cow<'a, str>>,
    {
        let alpha = T::Field::random(rng);
        let y = T::Field::random(rng);
        let e_alpha = gp.e.pow(&alpha);
        let gy = gp.g1.mul(&y);

        let pk = AuthorityPublicKey { e_alpha, gy };
        let mk = AuthorityMasterKey { alpha, y };
        let name: Cow<'a, str> = name.into();

        Self { name: name.into_owned(), pk, mk }
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
        let k = gp.g2.mul(&mk.alpha);
        let k = k + (T::hash_to_g2(gid.as_bytes()).mul(&mk.y));
        let k = k + (T::hash_to_g2(attribute.as_ref().as_bytes()).mul(&t));
        let kp = gp.g1.mul(&t);
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
    pks: &HashMap<String, &AuthorityPublicKey<T>>,
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
    let c0 = c0.mul(&(gp.e.pow(&s)));
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
            let c1x = gp.e.pow(&s_share);
            let c1x = c1x.mul(&(authority_pk.e_alpha.pow(&tx)));
            c1.insert(attr_name.clone(), c1x);

            let c2x = -(gp.g1.mul(&tx));
            c2.insert(attr_name.clone(), c2x);

            let wx = w_shares.get(&attr_name).ok_or(ABEError::EncryptionError("Invalid attribute name".to_string()))?;
            let c3x = authority_pk.gy.mul(&tx) + gp.g1.mul(wx);
            c3.insert(attr_name.clone(), c3x);

            let c4x = T::hash_to_g2(attr.as_bytes()).mul(&tx);
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
        let base = T::pair(c3, &h_user) * base;
        let base = T::pair(kp, c4) * base;
        let base = base.pow(coeff);

        b = b.mul(&base);
    }

    b = b.inverse();

    let msg = ct.c0.mul(&b);
    let msg: Vec<u8> = msg.into();
    decrypt_symmetric(msg, &ct.ct)
}

#[cfg(test)]
mod tests {
    use std::{borrow::BorrowMut, time::Instant};

    use rand::Rng as _;
    use rand_core::OsRng;

    use super::*;
    use crate::{curves::bls24479::Bls24479Curve, random::miracl::MiraclRng};
    use rstest::*;

    fn rng() -> MiraclRng {
        let mut rng = MiraclRng::new();
        let mut seed = [0u8; 128];
        OsRng.fill(&mut seed);
        rng.seed(&seed);
        rng
    }

    #[fixture]
    #[once]
    fn gp() -> GlobalParams<Bls24479Curve> {
        let mut rng = rng();
        GlobalParams::<Bls24479Curve>::new(&mut rng)
    }

    #[fixture]
    #[once]
    fn authority_a(gp: &GlobalParams<Bls24479Curve>) -> AuthorityKeyPair<Bls24479Curve> {
        let mut rng = rng();
        AuthorityKeyPair::new(&mut rng, &gp, "A")
    }

    #[fixture]
    #[once]
    fn authority_b(gp: &GlobalParams<Bls24479Curve>) -> AuthorityKeyPair<Bls24479Curve> {
        let mut rng = rng();
        AuthorityKeyPair::new(&mut rng, &gp, "B")
    }

    #[fixture]
    #[once]
    fn authority_c(gp: &GlobalParams<Bls24479Curve>) -> AuthorityKeyPair<Bls24479Curve> {
        let mut rng = rng();
        AuthorityKeyPair::new(&mut rng, &gp, "C")
    }

    #[fixture]
    #[once]
    fn alice(
        gp: &GlobalParams<Bls24479Curve>,
        authority_a: &AuthorityKeyPair<Bls24479Curve>,
        authority_b: &AuthorityKeyPair<Bls24479Curve>,
    ) -> UserSecretKey<Bls24479Curve> {
        let mut rng = rng();
        let mut alice =
            UserSecretKey::new(&mut rng, &gp, &authority_a.mk, "alice", &["A@ADMIN", "A@INFRA", "A@LEVEL_3"]);
        alice.add_attributes(&mut rng, &gp, &authority_b.mk, &["B@CTO"]);
        alice
    }

    #[fixture]
    #[once]
    fn bob(
        gp: &GlobalParams<Bls24479Curve>,
        authority_a: &AuthorityKeyPair<Bls24479Curve>,
        authority_c: &AuthorityKeyPair<Bls24479Curve>,
    ) -> UserSecretKey<Bls24479Curve> {
        let mut rng = rng();
        let mut bob = UserSecretKey::new(&mut rng, &gp, &authority_a.mk, "bob", &["A@USER", "A@LEVEL_2"]);
        bob.add_attributes(&mut rng, &gp, &authority_c.mk, &["C@CEO"]);
        bob
    }

    #[rstest]
    #[case("THIS IS SECRET MESSAGE!", r#""A@ADMIN" and "B@CTO""#, true, false)]
    #[case("A~l=GG>APhr0/ML3*nFo#v<#y,=xa+", r#""A@ADMIN" or "C@CEO""#, true, true)]
    #[case("test_message", r#""A@ADMIN" or ("A@USER" and "C@CEO")"#, true, true)]
    #[case("test_message", r#""A@ADMIN" or ("A@USER" and "C@CEO")"#, true, true)]
    #[case("test_message", r#""C@CEO""#, false, true)]
    fn encrypt_and_decrypt(
        gp: &GlobalParams<Bls24479Curve>,
        authority_a: &AuthorityKeyPair<Bls24479Curve>,
        authority_b: &AuthorityKeyPair<Bls24479Curve>,
        authority_c: &AuthorityKeyPair<Bls24479Curve>,
        alice: &UserSecretKey<Bls24479Curve>,
        bob: &UserSecretKey<Bls24479Curve>,
        #[case] plaintext: &str,
        #[case] policy: &str,
        #[case] expected_alice: bool,
        #[case] expected_bob: bool,
    ) {
        let mut rng = rng();

        let mut pks = HashMap::new();
        pks.insert("A".to_string(), &authority_a.pk);
        pks.insert("B".to_string(), &authority_b.pk);
        pks.insert("C".to_string(), &authority_c.pk);

        let ciphertext =
            encrypt(&mut rng, &gp, &pks, (policy.to_string(), PolicyLanguage::HumanPolicy), plaintext.as_bytes())
                .unwrap();

        let decrypt_by_alice = decrypt(&alice, &ciphertext);
        let decrypt_by_bob = decrypt(&bob, &ciphertext);
        assert_eq!(decrypt_by_alice.is_ok(), expected_alice);
        assert_eq!(decrypt_by_bob.is_ok(), expected_bob);
        if expected_alice {
            assert_eq!(decrypt_by_alice.unwrap(), plaintext.as_bytes());
        }
        if expected_bob {
            assert_eq!(decrypt_by_bob.unwrap(), plaintext.as_bytes());
        }
    }
}
