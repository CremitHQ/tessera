use std::ops::{Add, Div, Mul, Neg, Sub};

use crate::random::{miracl::MiraclRng, Random};

use super::{
    Field, FieldWithOrder, GroupG1, GroupG2, GroupGt, Inv, PairingCurve, Pow, RefAdd, RefDiv, RefMul, RefNeg, RefPow,
    RefSub,
};
use lazy_static::lazy_static;

use rand_core::RngCore as _;
use serde::{Deserialize, Serialize};
use tessera_miracl::{
    bls48556::{
        big::{BIG, MODBYTES, NLEN},
        ecp::ECP,
        ecp8::ECP8,
        fp48::FP48,
        pair8,
        rom::CURVE_ORDER,
    },
    hash256::HASH256,
};

#[derive(Clone, Serialize, Deserialize)]
pub struct Bls48556Field {
    inner: BIG,
}

const MODULUS: [i64; NLEN] = CURVE_ORDER;
const MSG_SIZE: usize = 48 * MODBYTES;

lazy_static! {
    pub static ref MODULUS_BIG: BIG = BIG::new_ints(&MODULUS);
}

impl Field for Bls48556Field {
    type Chunk = i64;

    #[inline]
    fn new() -> Self {
        Self { inner: BIG::new() }
    }

    #[inline]
    fn one() -> Self {
        Self { inner: BIG::new_int(1) }
    }

    #[inline]
    fn new_int(x: Self::Chunk) -> Self {
        Self { inner: BIG::new_int(x as isize) }
    }

    #[inline]
    fn new_ints(x: &[Self::Chunk]) -> Self {
        Self { inner: BIG::new_ints(x) }
    }
}

impl From<u64> for Bls48556Field {
    #[inline]
    fn from(x: u64) -> Self {
        Self { inner: BIG::new_int(x as isize) }
    }
}

impl Random for Bls48556Field {
    type Rng = MiraclRng;

    #[inline]
    fn random(rng: &mut Self::Rng) -> Self {
        Self { inner: BIG::random(&mut rng.inner) }
    }
}

impl FieldWithOrder for Bls48556Field {
    #[inline]
    fn order() -> Self {
        Self { inner: *MODULUS_BIG }
    }
    #[inline]
    fn random_within_order(rng: &mut <Self as Random>::Rng) -> Self {
        let mut r = BIG::random(&mut rng.inner);
        r.rmod(&MODULUS_BIG);
        Self { inner: r }
    }
}

impl Add for Bls48556Field {
    type Output = Self;

    #[inline]
    fn add(self, other: Self) -> Self {
        self.ref_add(&other)
    }
}

impl RefAdd for Bls48556Field {
    type Output = Self;

    #[inline]
    fn ref_add(&self, other: &Self) -> Self {
        Self { inner: BIG::modadd(&self.inner, &other.inner, &MODULUS_BIG) }
    }
}

impl Div for Bls48556Field {
    type Output = Self;

    #[inline]
    fn div(self, mut other: Self) -> Self {
        other.inner.invmodp(&MODULUS_BIG);
        Self { inner: BIG::modmul(&self.inner, &other.inner, &MODULUS_BIG) }
    }
}

impl RefDiv for Bls48556Field {
    type Output = Self;

    #[inline]
    fn ref_div(&self, other: &Self) -> Self {
        let mut other = other.inner;
        other.invmodp(&MODULUS_BIG);
        Self { inner: BIG::modmul(&self.inner, &other, &MODULUS_BIG) }
    }
}

impl Mul for Bls48556Field {
    type Output = Self;

    #[inline]
    fn mul(self, other: Self) -> Self {
        self.ref_mul(&other)
    }
}

impl RefMul for Bls48556Field {
    type Output = Self;

    #[inline]
    fn ref_mul(&self, other: &Self) -> Self {
        Self { inner: BIG::modmul(&self.inner, &other.inner, &MODULUS_BIG) }
    }
}

impl Sub for Bls48556Field {
    type Output = Self;

    #[inline]
    fn sub(self, other: Self) -> Self {
        self.ref_sub(&other)
    }
}

impl RefSub for Bls48556Field {
    type Output = Self;

    #[inline]
    fn ref_sub(&self, other: &Self) -> Self {
        let neg_other = BIG::modneg(&other.inner, &MODULUS_BIG);
        Self { inner: BIG::modadd(&self.inner, &neg_other, &MODULUS_BIG) }
    }
}

impl Neg for Bls48556Field {
    type Output = Self;

    #[inline]
    fn neg(self) -> Self {
        self.ref_neg()
    }
}

impl RefNeg for Bls48556Field {
    type Output = Self;

    #[inline]
    fn ref_neg(&self) -> Self {
        Self { inner: BIG::modneg(&self.inner, &MODULUS_BIG) }
    }
}

impl Pow for Bls48556Field {
    type Output = Self;

    #[inline]
    fn pow(mut self, e: &Self) -> Self {
        Self { inner: self.inner.powmod(&e.inner, &MODULUS_BIG) }
    }
}

impl RefPow for Bls48556Field {
    type Output = Self;

    #[inline]
    fn ref_pow(&self, e: &Self) -> Self {
        self.clone().pow(e)
    }
}

impl PartialEq for Bls48556Field {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        BIG::comp(&self.inner, &other.inner) == 0
    }
}

#[derive(Clone, Deserialize, Serialize)]
pub struct G1 {
    inner: ECP,
}

impl GroupG1 for G1 {
    type Field = Bls48556Field;

    #[inline]
    fn new(x: &Self::Field) -> Self {
        Self::generator() * x
    }

    #[inline]
    fn generator() -> Self {
        Self { inner: ECP::generator() }
    }
}

impl Mul<Bls48556Field> for G1 {
    type Output = Self;

    #[inline]
    fn mul(self, rhs: Bls48556Field) -> Self {
        self.ref_mul(&rhs)
    }
}

impl Mul<&Bls48556Field> for G1 {
    type Output = Self;

    #[inline]
    fn mul(self, rhs: &Bls48556Field) -> Self {
        self.ref_mul(rhs)
    }
}

impl RefMul<Bls48556Field> for G1 {
    type Output = Self;

    #[inline]
    fn ref_mul(&self, rhs: &Bls48556Field) -> Self {
        Self { inner: pair8::g1mul(&self.inner, &rhs.inner) }
    }
}

impl Add for G1 {
    type Output = Self;

    #[inline]
    fn add(self, other: Self) -> Self {
        self + &other
    }
}

impl Add<&G1> for G1 {
    type Output = Self;

    #[inline]
    fn add(mut self, other: &Self) -> Self {
        self.inner.add(&other.inner);
        self
    }
}

impl RefAdd for G1 {
    type Output = Self;

    #[inline]
    fn ref_add(&self, other: &Self) -> Self {
        self.clone() + other
    }
}

impl Neg for G1 {
    type Output = Self;

    #[inline]
    fn neg(mut self) -> Self {
        self.inner.neg();
        self
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct G2 {
    inner: ECP8,
}

impl GroupG2 for G2 {
    type Field = Bls48556Field;

    fn new(x: &Self::Field) -> Self {
        Self::generator() * x
    }

    fn generator() -> Self {
        Self { inner: ECP8::generator() }
    }
}

impl Mul<Bls48556Field> for G2 {
    type Output = Self;

    #[inline]
    fn mul(self, rhs: Bls48556Field) -> Self {
        self.ref_mul(&rhs)
    }
}

impl Mul<&Bls48556Field> for G2 {
    type Output = Self;

    #[inline]
    fn mul(self, rhs: &Bls48556Field) -> Self {
        self.ref_mul(rhs)
    }
}

impl RefMul<Bls48556Field> for G2 {
    type Output = Self;

    #[inline]
    fn ref_mul(&self, rhs: &Bls48556Field) -> Self {
        Self { inner: pair8::g2mul(&self.inner, &rhs.inner) }
    }
}

impl Add for G2 {
    type Output = Self;

    #[inline]
    fn add(self, other: Self) -> Self {
        self + &other
    }
}

impl Add<&G2> for G2 {
    type Output = Self;

    #[inline]
    fn add(mut self, other: &Self) -> Self {
        self.inner.add(&other.inner);
        self
    }
}

impl RefAdd for G2 {
    type Output = Self;

    #[inline]
    fn ref_add(&self, other: &Self) -> Self {
        self.clone() + other
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Gt {
    inner: FP48,
}

impl GroupGt for Gt {
    type Field = Bls48556Field;

    #[inline]
    fn one() -> Self {
        let mut r = FP48::new();
        r.one();
        Self { inner: r }
    }
}

impl From<Gt> for Vec<u8> {
    #[inline]
    fn from(gt: Gt) -> Self {
        let mut bytes = vec![0u8; MSG_SIZE];
        gt.inner.tobytes(&mut bytes);
        bytes
    }
}

impl<'a> From<&'a [u8]> for Gt {
    #[inline]
    fn from(bytes: &'a [u8]) -> Self {
        Self { inner: FP48::frombytes(bytes) }
    }
}

impl Random for Gt {
    type Rng = MiraclRng;
    fn random(rng: &mut Self::Rng) -> Self {
        let mut rand_bytes = [0u8; MSG_SIZE];
        rng.fill_bytes(&mut rand_bytes);
        let r = FP48::frombytes(&rand_bytes);
        Self { inner: r }
    }
}

impl Mul for Gt {
    type Output = Self;

    #[inline]
    fn mul(self, other: Self) -> Self {
        self * &other
    }
}

impl Mul<&Self> for Gt {
    type Output = Self;

    #[inline]
    fn mul(mut self, rhs: &Self) -> Self {
        self.inner.mul(&rhs.inner);
        self
    }
}

impl RefMul for Gt {
    type Output = Self;

    #[inline]
    fn ref_mul(&self, rhs: &Self) -> Self {
        self.clone() * rhs
    }
}

impl Pow<Bls48556Field> for Gt {
    type Output = Self;

    #[inline]
    fn pow(self, rhs: &Bls48556Field) -> Self {
        self.ref_pow(rhs)
    }
}

impl RefPow<Bls48556Field> for Gt {
    type Output = Self;

    #[inline]
    fn ref_pow(&self, rhs: &Bls48556Field) -> Self {
        Self { inner: pair8::gtpow(&self.inner, &rhs.inner) }
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
pub struct Bls48556Curve;

impl PairingCurve for Bls48556Curve {
    type Rng = MiraclRng;
    type Field = Bls48556Field;
    type G1 = G1;
    type G2 = G2;
    type Gt = Gt;

    fn pair(e1: &Self::G1, e2: &Self::G2) -> Self::Gt {
        Self::Gt { inner: pair8::fexp(&pair8::ate(&e2.inner, &e1.inner)) }
    }

    fn hash_to_g2(msg: &[u8]) -> Self::G2 {
        let mut hash = HASH256::new();
        hash.process_array(msg);
        let h = hash.hash();
        Self::G2 { inner: ECP8::mapit(&h) }
    }
}
