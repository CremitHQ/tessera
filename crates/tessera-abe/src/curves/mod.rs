pub mod bls24479;
pub mod bls48556;

use std::ops::{Add, Div, Mul, Neg, Rem, Sub};

use serde::{Deserialize, Serialize};

pub trait Pow {
    type Output;
    type Rhs;

    fn pow(self, x: &Self::Rhs) -> Self::Output;
}

pub trait Inv {
    type Output;

    fn inverse(self) -> Self::Output;
}

pub trait Rand {
    fn new() -> Self;
    fn seed(&mut self, seed: &[u8]);
    fn get_byte(&mut self) -> u8;
    fn fill_bytes(&mut self, dest: &mut [u8]);
}

pub trait BigNumber:
    Copy
    + PartialEq
    + Rem<Output = Self>
    + Pow<Rhs = Self, Output = Self>
    + Neg<Output = Self>
    + Add<Output = Self>
    + Sub<Output = Self>
    + Mul<Output = Self>
    + Div<Output = Self>
    + Serialize
where
    Self: for<'a> Add<&'a Self, Output = Self>,
    Self: for<'a> Sub<&'a Self, Output = Self>,
    Self: for<'a> Mul<&'a Self, Output = Self>,
    Self: for<'de> Deserialize<'de>,
{
    type Chunk;
    type Rng: Rand;

    fn new() -> Self;
    fn one() -> Self;
    fn random(rng: &mut Self::Rng) -> Self;
    fn random_mod_order(rng: &mut Self::Rng) -> Self;
    fn new_int(x: Self::Chunk) -> Self;
    fn new_ints(x: &[Self::Chunk]) -> Self;
}

pub trait G1: Copy + Clone + Sized + Neg<Output = Self> + Add<Output = Self> + Serialize
where
    Self: for<'a> Mul<&'a Self::Big, Output = Self>,
    Self: for<'de> Deserialize<'de>,
{
    type Big: BigNumber;
    type Rng: Rand;

    fn new(x: &Self::Big) -> Self;
    fn generator() -> Self;
}

pub trait G2: Copy + Clone + Sized + Add<Output = Self> + Serialize
where
    Self: for<'a> Mul<&'a Self::Big, Output = Self>,
    Self: for<'de> Deserialize<'de>,
{
    type Big: BigNumber;
    type Rng: Rand;

    fn new(x: &Self::Big) -> Self;
    fn generator() -> Self;
}

pub trait Gt: Sized + Pow<Rhs = Self::Big, Output = Self> + Inv<Output = Self> + Clone + Copy + Serialize
where
    for<'a> Self: Mul<&'a Self, Output = Self>,
    Self: for<'de> Deserialize<'de>,
{
    type Big: BigNumber;
    type Rng: Rand;

    fn one() -> Self;
    fn random(rng: &mut Self::Rng) -> Self;
    fn from_bytes(bytes: &[u8]) -> Self;
    fn to_bytes(&self) -> Vec<u8>;
}

pub trait Curve {
    type Chunk: TryFrom<usize> + Copy + Default;
    type Big: BigNumber<Chunk = Self::Chunk, Rng = Self::Rng>;
    type G1: G1<Big = Self::Big, Rng = Self::Rng>;
    type G2: G2<Big = Self::Big, Rng = Self::Rng>;
    type Gt: Gt<Big = Self::Big, Rng = Self::Rng>;

    type Rng: Rand;

    fn pair(e1: &Self::G1, e2: &Self::G2) -> Self::Gt;
    fn hash_to_g2(msg: &[u8]) -> Self::G2;
}
