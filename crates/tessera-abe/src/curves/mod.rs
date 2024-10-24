pub mod bls24479;
pub mod bls48556;

use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use std::ops::{Add, Div, Mul, Neg, Sub};

use crate::random::Random;

pub trait Pow<Rhs = Self> {
    type Output;

    fn pow(self, x: &Rhs) -> Self::Output;
}

pub trait Inv {
    type Output;

    fn inverse(self) -> Self::Output;
}

pub trait RefAdd<Rhs = Self> {
    type Output;

    fn ref_add(&self, x: &Rhs) -> Self::Output;
}

pub trait RefMul<Rhs = Self> {
    type Output;

    fn ref_mul(&self, x: &Rhs) -> Self::Output;
}

pub trait RefSub<Rhs = Self> {
    type Output;

    fn ref_sub(&self, x: &Rhs) -> Self::Output;
}

pub trait RefDiv<Rhs = Self> {
    type Output;

    fn ref_div(&self, x: &Rhs) -> Self::Output;
}

pub trait RefNeg {
    type Output;

    fn ref_neg(&self) -> Self::Output;
}

pub trait RefPow<Rhs = Self> {
    type Output;

    fn ref_pow(&self, x: &Rhs) -> Self::Output;
}

pub trait FieldWithOrder: Field {
    fn order() -> Self;
    fn random_within_order(rng: &mut <Self as Random>::Rng) -> Self;
}

pub trait Field:
    Sized
    + Clone
    + PartialEq
    + RefNeg<Output = Self>
    + Neg<Output = Self>
    + RefAdd<Output = Self>
    + Add<Output = Self>
    + RefSub<Output = Self>
    + Sub<Output = Self>
    + RefMul<Output = Self>
    + Mul<Output = Self>
    + RefDiv<Output = Self>
    + Div<Output = Self>
    + Pow<Self, Output = Self>
    + RefPow<Self, Output = Self>
    + Serialize
    + Random
where
    Self: for<'de> Deserialize<'de>,
{
    type Chunk: From<u32> + Copy + Default;

    fn new() -> Self;
    fn one() -> Self;
    fn new_int(x: Self::Chunk) -> Self;
    fn new_ints(x: &[Self::Chunk]) -> Self;
}

pub trait GroupG1:
    Clone
    + Sized
    + Neg<Output = Self>
    + RefAdd<Output = Self>
    + Add<Output = Self>
    + RefMul<Self::Field, Output = Self>
    + Mul<Self::Field, Output = Self>
    + Serialize
where
    Self: for<'de> Deserialize<'de>,
{
    type Field: Field;

    fn new(x: &Self::Field) -> Self;
    fn generator() -> Self;
}

pub trait GroupG2:
    Clone
    + Sized
    + RefAdd<Output = Self>
    + Add<Output = Self>
    + RefMul<Self::Field, Output = Self>
    + Mul<Self::Field, Output = Self>
    + Serialize
where
    Self: for<'de> Deserialize<'de>,
{
    type Field: Field;

    fn new(x: &Self::Field) -> Self;
    fn generator() -> Self;
}

pub trait GroupGt:
    Sized
    + Inv<Output = Self>
    + RefMul<Output = Self>
    + Mul<Output = Self>
    + RefPow<Self::Field, Output = Self>
    + Pow<Self::Field, Output = Self>
    + Clone
    + Serialize
    + Random
    + Into<Vec<u8>>
where
    Self: for<'de> Deserialize<'de>,
    Self: for<'a> From<&'a [u8]>,
    Self: for<'a> Mul<&'a Self, Output = Self>,
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
