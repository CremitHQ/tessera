use crate::{
    curves::{FieldWithOrder as _, RefAdd, RefMul, RefNeg, RefPow as _},
    error::{ABEError, InvalidAttributeKind, InvalidAuthorityErrorKind, InvalidPolicyErrorKind},
    random::Random,
    utils::{
        aes::{decrypt_symmetric, encrypt_symmetric},
        attribute::{unpack_attribute, Attribute},
        secret_shares::calc_pruned,
    },
};

use crate::curves::{Field, GroupG1, GroupG2, GroupGt, Inv as _, PairingCurve};
use nebula_policy::{
    msp::MonotoneSpanProgram,
    pest::{parse, PolicyLanguage},
    utils::remove_index,
};
use serde::{Deserialize, Serialize};
use std::{
    borrow::Cow,
    collections::{HashMap, HashSet},
};
use thiserror::Error;

#[derive(Serialize, Deserialize, Clone)]
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
        let x = T::Field::random_within_order(rng);
        let g1 = T::G1::new(&x);
        let g2 = T::G2::new(&x);
        let e = T::pair(&g1, &g2);

        Self { g1, g2, e }
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct AuthorityKeyPair<T: PairingCurve> {
    pub name: String,
    pub pk: AuthorityPublicKey<T>,
    pub mk: AuthorityMasterKey<T>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct AuthorityPublicKey<T: PairingCurve> {
    pub name: String,
    pub large_a: T::G1,
    pub large_b: T::G1,
    pub large_b_prime: T::G1,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct AuthorityMasterKey<T: PairingCurve> {
    pub name: String,
    pub beta: T::Field,
    pub b: T::Field,
    pub b_prime: T::Field,
}

impl<T> AuthorityKeyPair<T>
where
    T: PairingCurve,
{
    pub fn new<'a, S>(rng: &mut <T::Field as Random>::Rng, gp: &GlobalParams<T>, name: S) -> AuthorityKeyPair<T>
    where
        S: Into<Cow<'a, str>>,
    {
        let beta = T::Field::random_within_order(rng);
        let b = T::Field::random_within_order(rng);
        let b_prime = T::Field::random_within_order(rng);

        let large_a = gp.g1.ref_mul(&beta);
        let large_b = gp.g1.ref_mul(&b);
        let large_b_prime = gp.g1.ref_mul(&b_prime);
        let name = name.into().into_owned();

        let pk = AuthorityPublicKey { name: name.clone(), large_a, large_b, large_b_prime };
        let mk = AuthorityMasterKey { name: name.clone(), beta, b, b_prime };

        Self { name, pk, mk }
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct UserAttributeKey<T: PairingCurve> {
    pub k0: T::G2,
    pub k1: T::G2,
    pub k2: HashMap<String, T::G1>,
}

#[derive(Serialize, Deserialize, Clone)]
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
        authority_name: &str,
        gp: &GlobalParams<T>,
        mk: &AuthorityMasterKey<T>,
        gid: &str,
        attributes: &[S],
    ) -> Self {
        let r = T::Field::random_within_order(rng);
        let k0 = gp.g2.ref_mul(&r);
        let k1 = gp.g2.ref_mul(&mk.beta)
            + T::hash_to_g2(gid.as_bytes()).ref_mul(&mk.b)
            + gp.g2.ref_mul(&r.ref_mul(&mk.b_prime));
        let mut k2 = HashMap::new();
        for attribute in attributes {
            let attribute = format!("{}@{}", attribute.as_ref(), authority_name);
            let k = T::hash_to_g1(attribute.as_bytes()).ref_mul(&r);
            k2.insert(attribute, k);
        }
        Self { k0, k1, k2 }
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
        let mut inner = HashMap::new();
        let authority_name = mk.name.as_str();
        let attribute_key = UserAttributeKey::new(rng, authority_name, gp, mk, gid, attributes);
        inner.insert(authority_name.to_string(), attribute_key);
        Self { gid: gid.to_string(), inner }
    }

    pub fn add_attribute_key<S: AsRef<str>>(
        &mut self,
        rng: &mut <T::Field as Random>::Rng,
        gp: &GlobalParams<T>,
        mk: &AuthorityMasterKey<T>,
        attributes: &[S],
    ) {
        let authority_name = mk.name.as_str();
        let attribute_key = UserAttributeKey::new(rng, authority_name, gp, mk, &self.gid, attributes);
        self.inner.insert(authority_name.to_string(), attribute_key);
    }
}

#[derive(Debug, Error)]
pub enum SumUserSecretKeyError {
    #[error("gid mismatch: expected `{0}`, found `{1}`")]
    GidMismatch(String, String),
    #[error("empty user secret key")]
    Empty,
}

impl<T> UserSecretKey<T>
where
    T: PairingCurve,
{
    pub fn sum<I: Iterator<Item = Self>>(mut iter: I) -> Result<Self, SumUserSecretKeyError> {
        let first = iter.next().ok_or(SumUserSecretKeyError::Empty)?;
        let gid = first.gid;
        let mut inner = first.inner;
        for key in iter {
            if key.gid != gid {
                return Err(SumUserSecretKeyError::GidMismatch(gid, key.gid));
            }
            for (authority_name, attribute_key) in key.inner {
                inner.entry(authority_name).or_insert(attribute_key);
            }
        }
        Ok(Self { gid, inner })
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Ciphertext<T: PairingCurve> {
    pub policy: (String, PolicyLanguage),
    pub c1: Vec<T::G2>,
    pub cp: T::Gt,
    pub cj: HashMap<String, Cj<T>>,
    pub ct: Vec<u8>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Cj<T: PairingCurve> {
    pub c2: T::G1,
    pub c3: T::G1,
    pub c4: T::G1,
    pub c5: T::G1,
}

pub fn encrypt<T: PairingCurve>(
    rng: &mut <T::Field as Random>::Rng,
    gp: &GlobalParams<T>,
    pks: &HashMap<String, AuthorityPublicKey<T>>,
    policy: (String, PolicyLanguage),
    data: &[u8],
) -> Result<Ciphertext<T>, ABEError> {
    let (policy_name, language) = policy;
    let (policy, attributes_index_size) = parse(&policy_name, language).map_err(InvalidPolicyErrorKind::ParsePolicy)?;
    let msp = MonotoneSpanProgram::from(&policy);
    let n2 = msp.column_size;

    let m = *attributes_index_size.values().max().ok_or(InvalidPolicyErrorKind::EmptyPolicy)?;
    let s_tilde = T::Field::random_within_order(rng);
    let s_prime = (0..=m).map(|_| T::Field::random_within_order(rng)).collect::<Vec<_>>();

    let c0 = T::Gt::random(rng);
    let msg: Vec<u8> = c0.clone().into();
    let cp = gp.e.ref_pow(&s_tilde).ref_mul(&c0);

    let mut v = vec![s_tilde.clone()];
    let mut v_prime = vec![T::Field::new()];
    for _ in 1..n2 {
        v.push(T::Field::random_within_order(rng));
        v_prime.push(T::Field::random_within_order(rng));
    }

    let mut c1 = vec![];
    for s in s_prime.iter().take(m + 1) {
        c1.push(gp.g2.ref_mul(s));
    }

    let mut c_j = HashMap::new();
    for (attribute_with_idx, row) in msp.matrix {
        let s_j = T::Field::random_within_order(rng);
        let Attribute { index, authority, .. } =
            unpack_attribute(&attribute_with_idx).map_err(InvalidAttributeKind::ParseAttributeError)?;

        let attribute_stripped = remove_index(&attribute_with_idx);

        let auth_pk = pks.get(&authority).ok_or(InvalidAuthorityErrorKind::AuthorityNotFound(authority.clone()))?;
        let attribute_hash = T::hash_to_g1(attribute_stripped.as_bytes());

        let lambda_j = row
            .iter()
            .zip(v.iter())
            .map(|(&x, y)| {
                let v = T::Field::from(x.unsigned_abs() as u64);
                if x.is_negative() {
                    v.ref_neg().ref_mul(y)
                } else {
                    v.ref_mul(y)
                }
            })
            .sum::<T::Field>();
        let mu_j = row
            .iter()
            .zip(v_prime.iter())
            .map(|(&x, y)| {
                let v = T::Field::from(x.unsigned_abs() as u64);
                if x.is_negative() {
                    v.ref_neg().ref_mul(y)
                } else {
                    v.ref_mul(y)
                }
            })
            .sum::<T::Field>();

        let c2 = gp.g1.ref_mul(&s_j);
        let c3 = gp.g1.ref_mul(&mu_j) + auth_pk.large_b.ref_mul(&s_j);
        let c4 = auth_pk.large_b_prime.ref_mul(&s_j) + attribute_hash.ref_mul(&s_prime[index]);
        let c5 = gp.g1.ref_mul(&lambda_j) + auth_pk.large_a.ref_mul(&s_j);
        c_j.insert(attribute_with_idx, Cj::<T> { c2, c3, c4, c5 });
    }

    let ct = encrypt_symmetric::<T, _>(rng, msg, data)?;
    Ok(Ciphertext { policy: (policy_name, language), c1, cp, cj: c_j, ct })
}

pub fn decrypt<T: PairingCurve>(
    gp: &GlobalParams<T>,
    sk: &UserSecretKey<T>,
    ct: &Ciphertext<T>,
) -> Result<Vec<u8>, ABEError> {
    let (policy_name, lang) = ct.policy.clone();
    let (policy, attributes_index_size) = parse(&policy_name, lang).map_err(InvalidPolicyErrorKind::ParsePolicy)?;
    let m = *attributes_index_size.values().max().ok_or(InvalidPolicyErrorKind::EmptyPolicy)?;
    let attributes = sk.inner.values().flat_map(|uk| uk.k2.keys()).map(|k| k.to_string()).collect::<Vec<_>>();

    let (is_matched, matched_nodes) = calc_pruned(&attributes, &policy);
    if !is_matched {
        return Err(InvalidPolicyErrorKind::PolicyNotSatisfied.into());
    }

    let gid_hash = T::hash_to_g2(sk.gid.as_bytes());

    let mut authorities = HashSet::new();

    let mut c2_sum = HashMap::new();
    let mut c3_sum = T::G1::zero();
    let mut c4_sum = HashMap::new();
    let mut c5_sum = T::G1::zero();
    let mut k2_sum = (0..=m).map(|_| T::G1::zero()).collect::<Vec<_>>();

    for (attr, attribute_with_idx) in matched_nodes {
        let Attribute { index, authority, .. } =
            unpack_attribute(&attribute_with_idx).map_err(InvalidAttributeKind::ParseAttributeError)?;
        authorities.insert(authority.clone());
        let cj = ct
            .cj
            .get(&attribute_with_idx)
            .ok_or(InvalidAttributeKind::AttributeNotFound(attribute_with_idx.clone()))?;
        let c2 = c2_sum.entry(authority.clone()).or_insert_with(T::G1::zero);
        let c4 = c4_sum.entry(authority.clone()).or_insert_with(T::G1::zero);

        *c2 = cj.c2.ref_add(c2);
        *c4 = cj.c4.ref_add(c4);

        c3_sum = cj.c3.ref_add(&c3_sum);
        c5_sum = cj.c5.ref_add(&c5_sum);

        k2_sum[index] = sk
            .inner
            .get(&authority)
            .ok_or(InvalidAuthorityErrorKind::AuthorityNotFound(authority.clone()))?
            .k2
            .get(&attr)
            .ok_or(InvalidAttributeKind::AttributeNotFound(attribute_with_idx.clone()))?
            .ref_add(&k2_sum[index]);
    }

    let mut e1 = T::Gt::one();
    let mut e2 = T::Gt::one();
    for authority in &authorities {
        e1 = T::pair(&c4_sum[authority], &sk.inner[authority].k0).ref_mul(&e1);
        e2 = T::pair(&c2_sum[authority], &sk.inner[authority].k1).ref_mul(&e2);
    }
    let e3 = T::pair(&c3_sum, &gid_hash);
    let mut e4 = T::Gt::one();
    for (i, k2) in k2_sum.iter().enumerate() {
        e4 = T::pair(k2, &ct.c1[i]).ref_mul(&e4);
    }
    let e5 = T::pair(&c5_sum, &gp.g2);

    e2 = e2.inverse();
    e4 = e4.inverse();
    let e = e1.ref_mul(&e2).ref_mul(&e3).ref_mul(&e4).ref_mul(&e5);
    let e = e.inverse();
    let msg = ct.cp.ref_mul(&e);
    let msg: Vec<u8> = msg.into();
    decrypt_symmetric(msg, &ct.ct)
}

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
mod tests {
    use rand::Rng as _;
    use rand_core::OsRng;

    use super::*;
    use crate::{curves::bn462::Bn462Curve, random::miracl::MiraclRng};
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
    fn gp() -> GlobalParams<Bn462Curve> {
        let mut rng = rng();
        GlobalParams::<Bn462Curve>::new(&mut rng)
    }

    #[fixture]
    #[once]
    fn authority_a(gp: &GlobalParams<Bn462Curve>) -> AuthorityKeyPair<Bn462Curve> {
        let mut rng = rng();
        AuthorityKeyPair::new(&mut rng, gp, "A")
    }

    #[fixture]
    #[once]
    fn authority_b(gp: &GlobalParams<Bn462Curve>) -> AuthorityKeyPair<Bn462Curve> {
        let mut rng = rng();
        AuthorityKeyPair::new(&mut rng, gp, "B")
    }

    #[fixture]
    #[once]
    fn authority_c(gp: &GlobalParams<Bn462Curve>) -> AuthorityKeyPair<Bn462Curve> {
        let mut rng = rng();
        AuthorityKeyPair::new(&mut rng, gp, "C")
    }

    #[fixture]
    #[once]
    fn alice(
        gp: &GlobalParams<Bn462Curve>,
        authority_a: &AuthorityKeyPair<Bn462Curve>,
        authority_b: &AuthorityKeyPair<Bn462Curve>,
    ) -> UserSecretKey<Bn462Curve> {
        let mut rng = rng();
        let mut alice = UserSecretKey::new(&mut rng, gp, &authority_a.mk, "alice", &["ADMIN", "INFRA", "LEVEL_3"]);
        alice.add_attribute_key(&mut rng, gp, &authority_b.mk, &["CTO", "PROFESSOR"]);
        alice
    }

    #[fixture]
    #[once]
    fn bob(
        gp: &GlobalParams<Bn462Curve>,
        authority_a: &AuthorityKeyPair<Bn462Curve>,
        authority_c: &AuthorityKeyPair<Bn462Curve>,
    ) -> UserSecretKey<Bn462Curve> {
        let mut rng = rng();
        let mut bob = UserSecretKey::new(&mut rng, gp, &authority_a.mk, "bob", &["USER", "LEVEL_2"]);
        bob.add_attribute_key(&mut rng, gp, &authority_c.mk, &["CEO"]);
        bob
    }

    #[rstest]
    #[case("case: and policy", r#""ADMIN@A" and "CTO@B""#, true, false)]
    #[case("case: or policy", r#""ADMIN@A" or "CEO@C""#, true, true)]
    #[case("case: or (_ and _)", r#""ADMIN@A" or ("USER@A" and "CEO@C")"#, true, true)]
    #[case("case: only one attribute", r#""CEO@C""#, false, true)]
    #[case("case: and (_ or _)", r#""INFRA@A" and ("LEVEL_3@A" or "CEO@C")"#, true, false)]
    #[case("case: _ and _ and (_ or _)", r#""INFRA@A" and "ADMIN@A" and ("LEVEL_3@A" or "CEO@C")"#, true, false)]
    #[case("case: () or ()", r#"("INFRA@A" and "ADMIN@A") or ("USER@A" and "LEVEL_2@A" and "CEO@C")"#, true, true)]
    #[case(
        "case: complicated policy case",
        r#"("ADMIN@A" OR "CTO@B") AND (("ADMIN@A" AND "INFRA@A") AND ("CTO@B" OR "PROFESSOR@B"))"#,
        true,
        false
    )]
    fn isabella24_encrypt_and_decrypt(
        gp: &GlobalParams<Bn462Curve>,
        authority_a: &AuthorityKeyPair<Bn462Curve>,
        authority_b: &AuthorityKeyPair<Bn462Curve>,
        authority_c: &AuthorityKeyPair<Bn462Curve>,
        alice: &UserSecretKey<Bn462Curve>,
        bob: &UserSecretKey<Bn462Curve>,
        #[case] plaintext: &str,
        #[case] policy: &str,
        #[case] expected_alice: bool,
        #[case] expected_bob: bool,
    ) {
        let mut rng = rng();

        let mut pks = HashMap::new();
        pks.insert("A".to_string(), authority_a.pk.clone());
        pks.insert("B".to_string(), authority_b.pk.clone());
        pks.insert("C".to_string(), authority_c.pk.clone());

        let ciphertext =
            encrypt(&mut rng, gp, &pks, (policy.to_string(), PolicyLanguage::HumanPolicy), plaintext.as_bytes())
                .unwrap();

        let decrypt_by_alice = decrypt(gp, alice, &ciphertext);
        let decrypt_by_bob = decrypt(gp, bob, &ciphertext);
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
