use std::ops::{Add, Div, Mul, Neg, Rem, Sub};

use crate::random::{miracl::MiraclRng, Random};

use super::{Field, FieldWithOrder, GroupG1, GroupG2, GroupGt, Inv, PairingCurve, Pow};
use lazy_static::lazy_static;

use rand_core::RngCore as _;
use serde::{Deserialize, Serialize};
use tessera_miracl::{
    bls24479::{
        big::{BIG, MODBYTES, NLEN},
        ecp::ECP,
        ecp4::ECP4,
        fp24::FP24,
        pair4,
        rom::CURVE_ORDER,
    },
    hash256::HASH256,
};

#[derive(Clone, Copy, Serialize, Deserialize)]
pub struct Bls24479Field {
    inner: BIG,
}

const MODULUS: [i64; NLEN] = CURVE_ORDER;
const MSG_SIZE: usize = 48 * (MODBYTES as usize);

lazy_static! {
    pub static ref MODULUS_BIG: BIG = BIG::new_ints(&MODULUS);
}

impl Field for Bls24479Field {
    type Chunk = i64;

    fn new() -> Self {
        Self { inner: BIG::new() }
    }

    fn one() -> Self {
        Self { inner: BIG::new_int(1) }
    }

    fn new_int(x: Self::Chunk) -> Self {
        Self { inner: BIG::new_int(x as isize) }
    }

    fn new_ints(x: &[Self::Chunk]) -> Self {
        Self { inner: BIG::new_ints(x) }
    }
}

impl Random for Bls24479Field {
    type Rng = MiraclRng;
    fn random(rng: &mut Self::Rng) -> Self {
        Self { inner: BIG::random(&mut rng.inner) }
    }
}

impl FieldWithOrder for Bls24479Field {
    fn order() -> Self {
        Self { inner: MODULUS_BIG.clone() }
    }

    fn random_within_order(rng: &mut <Self as Random>::Rng) -> Self {
        let mut r = BIG::random(&mut rng.inner);
        r.rmod(&MODULUS_BIG);
        Self { inner: r }
    }
}

impl Add for Bls24479Field {
    type Output = Self;

    fn add(self, other: Self) -> Self {
        Self { inner: BIG::modadd(&self.inner, &other.inner, &MODULUS_BIG) }
    }
}

impl Add<&Self> for Bls24479Field {
    type Output = Self;

    fn add(self, other: &Self) -> Self {
        Self { inner: BIG::modadd(&self.inner, &other.inner, &MODULUS_BIG) }
    }
}

impl Div for Bls24479Field {
    type Output = Self;

    fn div(self, mut other: Self) -> Self {
        other.inner.invmodp(&MODULUS_BIG);
        Self { inner: BIG::modmul(&self.inner, &other.inner, &MODULUS_BIG) }
    }
}

impl Rem for Bls24479Field {
    type Output = Self;

    fn rem(mut self, other: Self) -> Self {
        self.inner.rmod(&other.inner);
        self
    }
}

impl Mul for Bls24479Field {
    type Output = Self;

    fn mul(self, other: Self) -> Self {
        Self { inner: BIG::modmul(&self.inner, &other.inner, &MODULUS_BIG) }
    }
}

impl Mul<&Self> for Bls24479Field {
    type Output = Self;

    fn mul(self, other: &Self) -> Self {
        Self { inner: BIG::modmul(&self.inner, &other.inner, &MODULUS_BIG) }
    }
}

impl Sub for Bls24479Field {
    type Output = Self;

    fn sub(self, other: Self) -> Self {
        let neg_other = BIG::modneg(&other.inner, &MODULUS_BIG);
        Self { inner: BIG::modadd(&self.inner, &neg_other, &MODULUS_BIG) }
    }
}

impl Sub<&Self> for Bls24479Field {
    type Output = Self;

    fn sub(self, other: &Self) -> Self {
        let neg_other = BIG::modneg(&other.inner, &MODULUS_BIG);
        Self { inner: BIG::modadd(&self.inner, &neg_other, &MODULUS_BIG) }
    }
}

impl Neg for Bls24479Field {
    type Output = Self;

    fn neg(self) -> Self {
        Self { inner: BIG::modneg(&self.inner, &MODULUS_BIG) }
    }
}

impl Pow<&Self> for Bls24479Field {
    type Output = Self;
    fn pow(mut self, e: &Self) -> Self {
        self.inner.powmod(&e.inner, &MODULUS_BIG);
        self
    }
}

impl PartialEq for Bls24479Field {
    fn eq(&self, other: &Self) -> bool {
        BIG::comp(&self.inner, &other.inner) == 0
    }
}

#[derive(Clone, Copy, Deserialize, Serialize)]
pub struct G1 {
    inner: ECP,
}

impl GroupG1 for G1 {
    type Field = Bls24479Field;

    fn new(x: &Self::Field) -> Self {
        Self::generator() * x
    }

    fn generator() -> Self {
        Self { inner: ECP::generator() }
    }
}

impl Mul<&Bls24479Field> for G1 {
    type Output = Self;

    fn mul(self, rhs: &Bls24479Field) -> Self {
        Self { inner: pair4::g1mul(&self.inner, &rhs.inner) }
    }
}

impl Add for G1 {
    type Output = Self;

    fn add(mut self, other: Self) -> Self {
        self.inner.add(&other.inner);
        self
    }
}

impl Neg for G1 {
    type Output = Self;

    fn neg(mut self) -> Self {
        self.inner.neg();
        self
    }
}

#[derive(Clone, Copy, Serialize, Deserialize)]
pub struct G2 {
    inner: ECP4,
}

impl GroupG2 for G2 {
    type Field = Bls24479Field;

    fn new(x: &Self::Field) -> Self {
        Self::generator() * x
    }

    fn generator() -> Self {
        Self { inner: ECP4::generator() }
    }
}

impl Mul<&Bls24479Field> for G2 {
    type Output = Self;

    fn mul(self, rhs: &Bls24479Field) -> Self {
        Self { inner: pair4::g2mul(&self.inner, &rhs.inner) }
    }
}

impl Add for G2 {
    type Output = Self;

    fn add(mut self, other: Self) -> Self {
        self.inner.add(&other.inner);
        self
    }
}

#[derive(Clone, Copy, Serialize, Deserialize)]
pub struct Gt {
    inner: FP24,
}

impl GroupGt for Gt {
    type Field = Bls24479Field;

    fn one() -> Self {
        let mut r = FP24::new();
        r.one();
        Self { inner: r }
    }
}

impl From<Gt> for Vec<u8> {
    fn from(gt: Gt) -> Self {
        let mut bytes = vec![0u8; MSG_SIZE];
        gt.inner.tobytes(&mut bytes);
        bytes
    }
}

impl<'a> From<&'a [u8]> for Gt {
    fn from(bytes: &'a [u8]) -> Self {
        Self { inner: FP24::frombytes(bytes) }
    }
}

impl Random for Gt {
    type Rng = MiraclRng;
    fn random(rng: &mut Self::Rng) -> Self {
        let mut rand_bytes = [0u8; MSG_SIZE];
        rng.fill_bytes(&mut rand_bytes);
        let r = FP24::frombytes(&rand_bytes);
        Self { inner: r }
    }
}

impl Mul<&Self> for Gt {
    type Output = Self;

    fn mul(mut self, rhs: &Self) -> Self {
        self.inner.mul(&rhs.inner);
        self
    }
}

impl Pow<&Bls24479Field> for Gt {
    type Output = Self;

    fn pow(self, rhs: &Bls24479Field) -> Self {
        Self { inner: pair4::gtpow(&self.inner, &rhs.inner) }
    }
}

impl Inv for Gt {
    type Output = Self;

    fn inverse(mut self) -> Self {
        self.inner.inverse();
        self
    }
}

#[derive(Serialize, Deserialize)]
pub struct Bls24479Curve;

impl PairingCurve for Bls24479Curve {
    type Rng = MiraclRng;
    type Field = Bls24479Field;
    type G1 = G1;
    type G2 = G2;
    type Gt = Gt;

    fn pair(e1: &Self::G1, e2: &Self::G2) -> Self::Gt {
        Self::Gt { inner: pair4::fexp(&pair4::ate(&e2.inner, &e1.inner)) }
    }

    fn hash_to_g2(msg: &[u8]) -> Self::G2 {
        let mut hash = HASH256::new();
        hash.process_array(msg);
        let h = hash.hash();
        Self::G2 { inner: ECP4::mapit(&h) }
    }
}
