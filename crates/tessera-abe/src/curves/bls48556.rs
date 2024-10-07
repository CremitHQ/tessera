use std::ops::{Add, Div, Mul, Neg, Rem, Sub};

use super::{
    BigNumber as BigNumberTrait, Curve as CurveTrait, Gt as GtTrait, Inv, Pow, Rand as RandTrait, G1 as G1Trait,
    G2 as G2Trait,
};
use lazy_static::lazy_static;

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
    rand::RAND,
};

pub struct Rand {
    inner: RAND,
}

impl RandTrait for Rand {
    fn new() -> Self {
        Self { inner: RAND::new() }
    }

    fn seed(&mut self, seed: &[u8]) {
        self.inner.seed(seed.len(), seed);
    }

    fn get_byte(&mut self) -> u8 {
        self.inner.getbyte()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for i in 0..dest.len() {
            dest[i] = self.inner.getbyte();
        }
    }
}

#[derive(Clone, Copy)]
pub struct BigNumber {
    inner: BIG,
}

const MODULUS: [i64; NLEN] = CURVE_ORDER;
const MSG_SIZE: usize = 48 * (MODBYTES as usize);

lazy_static! {
    static ref MODULUS_BIG: BIG = BIG::new_ints(&MODULUS);
}

impl BigNumberTrait for BigNumber {
    type Chunk = i64;
    type Rng = Rand;

    fn new() -> Self {
        Self { inner: BIG::new() }
    }

    fn one() -> Self {
        Self { inner: BIG::new_int(1) }
    }

    fn random(rng: &mut Self::Rng) -> Self {
        Self { inner: BIG::random(&mut rng.inner) }
    }

    fn random_mod_order(rng: &mut Self::Rng) -> Self {
        let mut r = BIG::random(&mut rng.inner);
        r.rmod(&MODULUS_BIG);
        Self { inner: r }
    }

    fn new_int(x: Self::Chunk) -> Self {
        Self { inner: BIG::new_int(x as isize) }
    }

    fn new_ints(x: &[Self::Chunk]) -> Self {
        Self { inner: BIG::new_ints(x) }
    }
}

impl Add for BigNumber {
    type Output = Self;

    fn add(self, other: Self) -> Self {
        Self { inner: BIG::modadd(&self.inner, &other.inner, &MODULUS_BIG) }
    }
}

impl Add<&Self> for BigNumber {
    type Output = Self;

    fn add(self, other: &Self) -> Self {
        Self { inner: BIG::modadd(&self.inner, &other.inner, &MODULUS_BIG) }
    }
}

impl Div for BigNumber {
    type Output = Self;

    fn div(self, mut other: Self) -> Self {
        other.inner.invmodp(&MODULUS_BIG);
        Self { inner: BIG::modmul(&self.inner, &other.inner, &MODULUS_BIG) }
    }
}

impl Rem for BigNumber {
    type Output = Self;

    fn rem(mut self, other: Self) -> Self {
        self.inner.rmod(&other.inner);
        self
    }
}

impl Mul for BigNumber {
    type Output = Self;

    fn mul(self, other: Self) -> Self {
        Self { inner: BIG::modmul(&self.inner, &other.inner, &MODULUS_BIG) }
    }
}

impl Mul<&Self> for BigNumber {
    type Output = Self;

    fn mul(self, other: &Self) -> Self {
        Self { inner: BIG::modmul(&self.inner, &other.inner, &MODULUS_BIG) }
    }
}

impl Sub for BigNumber {
    type Output = Self;

    fn sub(self, other: Self) -> Self {
        let neg_other = BIG::modneg(&other.inner, &MODULUS_BIG);
        Self { inner: BIG::modadd(&self.inner, &neg_other, &MODULUS_BIG) }
    }
}

impl Sub<&Self> for BigNumber {
    type Output = Self;

    fn sub(self, other: &Self) -> Self {
        let neg_other = BIG::modneg(&other.inner, &MODULUS_BIG);
        Self { inner: BIG::modadd(&self.inner, &neg_other, &MODULUS_BIG) }
    }
}

impl Neg for BigNumber {
    type Output = Self;

    fn neg(self) -> Self {
        Self { inner: BIG::modneg(&self.inner, &MODULUS_BIG) }
    }
}

impl Pow for BigNumber {
    type Output = Self;
    type Rhs = Self;
    fn pow(mut self, e: &Self) -> Self {
        self.inner.powmod(&e.inner, &MODULUS_BIG);
        self
    }
}

impl PartialEq for BigNumber {
    fn eq(&self, other: &Self) -> bool {
        BIG::comp(&self.inner, &other.inner) == 0
    }
}

#[derive(Clone, Copy)]
pub struct G1 {
    inner: ECP,
}

impl G1Trait for G1 {
    type Big = BigNumber;
    type Rng = Rand;

    fn new(x: &Self::Big) -> Self {
        Self::generator() * x
    }

    fn generator() -> Self {
        Self { inner: ECP::generator() }
    }
}

impl Mul<&BigNumber> for G1 {
    type Output = Self;

    fn mul(self, rhs: &BigNumber) -> Self {
        Self { inner: pair8::g1mul(&self.inner, &rhs.inner) }
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

#[derive(Clone, Copy)]
pub struct G2 {
    inner: ECP8,
}

impl G2Trait for G2 {
    type Big = BigNumber;
    type Rng = Rand;

    fn new(x: &Self::Big) -> Self {
        Self::generator() * x
    }

    fn generator() -> Self {
        Self { inner: ECP8::generator() }
    }
}

impl Mul<&BigNumber> for G2 {
    type Output = Self;

    fn mul(self, rhs: &BigNumber) -> Self {
        Self { inner: pair8::g2mul(&self.inner, &rhs.inner) }
    }
}

impl Add for G2 {
    type Output = Self;

    fn add(mut self, other: Self) -> Self {
        self.inner.add(&other.inner);
        self
    }
}

#[derive(Clone, Copy)]
pub struct Gt {
    inner: FP48,
}

impl GtTrait for Gt {
    type Big = BigNumber;
    type Rng = Rand;

    fn one() -> Self {
        let mut r = FP48::new();
        r.one();
        Self { inner: r }
    }

    fn random(rng: &mut Self::Rng) -> Self {
        let mut rand_bytes = [0u8; MSG_SIZE];
        rng.fill_bytes(&mut rand_bytes);
        let r = FP48::frombytes(&rand_bytes);
        Self { inner: r }
    }

    fn from_bytes(bytes: &[u8]) -> Self {
        Self { inner: FP48::frombytes(bytes) }
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![0u8; MSG_SIZE];
        self.inner.tobytes(&mut bytes);
        bytes
    }
}

impl Mul<&Self> for Gt {
    type Output = Self;

    fn mul(mut self, rhs: &Self) -> Self {
        self.inner.mul(&rhs.inner);
        self
    }
}

impl Pow for Gt {
    type Output = Self;
    type Rhs = BigNumber;

    fn pow(self, rhs: &BigNumber) -> Self {
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

pub struct Curve;

impl CurveTrait for Curve {
    type Chunk = i64;
    type Big = BigNumber;
    type G1 = G1;
    type G2 = G2;
    type Gt = Gt;
    type Rng = Rand;

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
