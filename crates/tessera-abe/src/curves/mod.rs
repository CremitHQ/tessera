pub mod bls24479;
pub mod bls48556;

use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use std::ops::{Add, Div, Mul, Neg, Rem, Sub};

use crate::random::Random;

pub trait Pow<Rhs = Self> {
    type Output;

    fn pow(self, x: Rhs) -> Self::Output;
}

pub trait Inv {
    type Output;

    fn inverse(self) -> Self::Output;
}

pub trait FieldWithOrder: Field {
    fn order() -> Self;
    fn random_within_order(rng: &mut <Self as Random>::Rng) -> Self;
}

pub trait Field:
    Sized
    + Clone
    + PartialEq
    + Rem<Output = Self>
    + Neg<Output = Self>
    + Add<Output = Self>
    + Sub<Output = Self>
    + Mul<Output = Self>
    + Div<Output = Self>
    + Serialize
    + Random
where
    Self: for<'a> Add<&'a Self, Output = Self>,
    Self: for<'a> Sub<&'a Self, Output = Self>,
    Self: for<'a> Mul<&'a Self, Output = Self>,
    Self: for<'a> Pow<&'a Self, Output = Self>,
    Self: for<'de> Deserialize<'de>,
{
    type Chunk: TryFrom<usize> + Copy + Default;

    fn new() -> Self;
    fn one() -> Self;
    fn new_int(x: Self::Chunk) -> Self;
    fn new_ints(x: &[Self::Chunk]) -> Self;
}

pub trait GroupG1: Clone + Sized + Neg<Output = Self> + Add<Output = Self> + Serialize
where
    Self: for<'a> Mul<&'a Self::Field, Output = Self>,
    Self: for<'de> Deserialize<'de>,
{
    type Field: Field;

    fn new(x: &Self::Field) -> Self;
    fn generator() -> Self;
}

pub trait GroupG2: Clone + Sized + Add<Output = Self> + Serialize
where
    Self: for<'a> Mul<&'a Self::Field, Output = Self>,
    Self: for<'de> Deserialize<'de>,
{
    type Field: Field;

    fn new(x: &Self::Field) -> Self;
    fn generator() -> Self;
}

pub trait GroupGt: Sized + Inv<Output = Self> + Clone + Serialize + Random + Into<Vec<u8>>
where
    for<'a> Self: Mul<&'a Self, Output = Self>,
    for<'a> Self: Pow<&'a Self::Field, Output = Self>,
    Self: for<'de> Deserialize<'de>,
    Self: for<'a> From<&'a [u8]>,
{
    type Field: Field;

    fn one() -> Self;
}

pub trait PairingCurve {
    type Rng: CryptoRng + RngCore;
    type Field: FieldWithOrder<Rng = Self::Rng>;
    type G1: GroupG1<Field = Self::Field>;
    type G2: GroupG2<Field = Self::Field>;
    type Gt: GroupGt<Field = Self::Field, Rng = Self::Rng>;

    fn pair(e1: &Self::G1, e2: &Self::G2) -> Self::Gt;
    fn hash_to_g2(msg: &[u8]) -> Self::G2;
}
