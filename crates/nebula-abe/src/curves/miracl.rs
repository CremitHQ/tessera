#[macro_export]
macro_rules! define_miracl_pairing_curve {
    (
        $curve_name:ident,
        $field_name:ident,
        $field_type:ty,
        $g1_type:ty,
        $g2_type:ty,
        $gt_type:ty,
        $pair_function:ident,
        $hash_function:ident,
        $msg_size_const:expr,
        $modulus_const:expr,
        $nlen:expr,
        $modbytes:expr
    ) => {
        use std::{
            iter::Sum,
            ops::{Add, Div, Mul, Neg, Sub},
        };

        use $crate::random::{miracl::MiraclRng, Random};

        use super::{
            Field, FieldWithOrder, GroupG1, GroupG2, GroupGt, Inv, PairingCurve, Pow, RefAdd, RefDiv, RefMul, RefNeg,
            RefPow, RefSub,
        };
        use lazy_static::lazy_static;

        use rand_core::RngCore as _;
        use serde::{Deserialize, Serialize};

        #[cfg(feature = "zeroize")]
        use zeroize::{Zeroize, ZeroizeOnDrop};

        #[derive(Clone, Serialize, Deserialize)]
        #[cfg_attr(feature = "zeroize", derive(Zeroize, ZeroizeOnDrop))]
        pub struct $field_name {
            inner: $field_type,
        }

        const MODULUS: [i64; $nlen] = $modulus_const;
        const MSG_SIZE: usize = $msg_size_const * $modbytes;

        lazy_static! {
            pub static ref MODULUS_BIG: BIG = <$field_type>::new_ints(&MODULUS);
        }

        impl Field for $field_name {
            type Chunk = i64;

            #[inline]
            fn new() -> Self {
                Self { inner: <$field_type>::new() }
            }

            #[inline]
            fn one() -> Self {
                Self { inner: <$field_type>::new_int(1) }
            }

            #[inline]
            fn new_int(x: Self::Chunk) -> Self {
                Self { inner: <$field_type>::new_int(x as isize) }
            }

            #[inline]
            fn new_ints(x: &[Self::Chunk]) -> Self {
                Self { inner: <$field_type>::new_ints(x) }
            }
        }

        impl From<u64> for $field_name {
            #[inline]
            fn from(x: u64) -> Self {
                Self { inner: <$field_type>::new_int(x as isize) }
            }
        }

        impl Random for $field_name {
            type Rng = MiraclRng;

            #[inline]
            fn random(rng: &mut Self::Rng) -> Self {
                Self { inner: <$field_type>::random(&mut rng.inner) }
            }
        }

        impl FieldWithOrder for $field_name {
            #[inline]
            fn order() -> Self {
                Self { inner: MODULUS_BIG.clone() }
            }
            #[inline]
            fn random_within_order(rng: &mut <Self as Random>::Rng) -> Self {
                let mut r = <$field_type>::random(&mut rng.inner);
                r.rmod(&MODULUS_BIG);
                Self { inner: r }
            }
        }

        impl Sum<$field_name> for $field_name {
            fn sum<I: Iterator<Item = $field_name>>(iter: I) -> Self {
                iter.fold(Self::new(), |acc, x| acc + x)
            }
        }

        impl Add for $field_name {
            type Output = Self;

            #[inline]
            fn add(self, other: Self) -> Self {
                self.ref_add(&other)
            }
        }

        impl RefAdd for $field_name {
            type Output = Self;

            #[inline]
            fn ref_add(&self, other: &Self) -> Self {
                Self { inner: <$field_type>::modadd(&self.inner, &other.inner, &MODULUS_BIG) }
            }
        }

        impl Div for $field_name {
            type Output = Self;

            #[inline]
            fn div(self, mut other: Self) -> Self {
                other.inner.invmodp(&MODULUS_BIG);
                Self { inner: <$field_type>::modmul(&self.inner, &other.inner, &MODULUS_BIG) }
            }
        }

        impl RefDiv for $field_name {
            type Output = Self;

            #[inline]
            fn ref_div(&self, other: &Self) -> Self {
                let mut other = other.inner.clone();
                other.invmodp(&MODULUS_BIG);
                Self { inner: <$field_type>::modmul(&self.inner, &other, &MODULUS_BIG) }
            }
        }

        impl Mul for $field_name {
            type Output = Self;

            #[inline]
            fn mul(self, other: Self) -> Self {
                self.ref_mul(&other)
            }
        }

        impl RefMul for $field_name {
            type Output = Self;

            #[inline]
            fn ref_mul(&self, other: &Self) -> Self {
                Self { inner: <$field_type>::modmul(&self.inner, &other.inner, &MODULUS_BIG) }
            }
        }

        impl Sub for $field_name {
            type Output = Self;

            #[inline]
            fn sub(self, other: Self) -> Self {
                self.ref_sub(&other)
            }
        }

        impl RefSub for $field_name {
            type Output = Self;

            #[inline]
            fn ref_sub(&self, other: &Self) -> Self {
                let neg_other = <$field_type>::modneg(&other.inner, &MODULUS_BIG);
                Self { inner: <$field_type>::modadd(&self.inner, &neg_other, &MODULUS_BIG) }
            }
        }

        impl Neg for $field_name {
            type Output = Self;

            #[inline]
            fn neg(self) -> Self {
                self.ref_neg()
            }
        }

        impl RefNeg for $field_name {
            type Output = Self;

            #[inline]
            fn ref_neg(&self) -> Self {
                Self { inner: <$field_type>::modneg(&self.inner, &MODULUS_BIG) }
            }
        }

        impl Pow for $field_name {
            type Output = Self;

            #[inline]
            fn pow(mut self, e: &Self) -> Self {
                Self { inner: self.inner.powmod(&e.inner, &MODULUS_BIG) }
            }
        }

        impl RefPow for $field_name {
            type Output = Self;

            #[inline]
            fn ref_pow(&self, e: &Self) -> Self {
                self.clone().pow(e)
            }
        }

        impl PartialEq for $field_name {
            #[inline]
            fn eq(&self, other: &Self) -> bool {
                <$field_type>::comp(&self.inner, &other.inner) == 0
            }
        }

        #[derive(Clone, Deserialize, Serialize)]
        #[cfg_attr(feature = "zeroize", derive(ZeroizeOnDrop, Zeroize))]
        pub struct G1 {
            inner: $g1_type,
        }

        impl GroupG1 for G1 {
            type Field = $field_name;

            #[inline]
            fn new(x: &Self::Field) -> Self {
                Self::generator() * x
            }

            #[inline]
            fn zero() -> Self {
                Self { inner: <$g1_type>::new() }
            }

            #[inline]
            fn generator() -> Self {
                Self { inner: <$g1_type>::generator() }
            }
        }

        impl Mul<$field_name> for G1 {
            type Output = Self;

            #[inline]
            fn mul(self, rhs: $field_name) -> Self {
                self.ref_mul(&rhs)
            }
        }

        impl Mul<&$field_name> for G1 {
            type Output = Self;

            #[inline]
            fn mul(self, rhs: &$field_name) -> Self {
                self.ref_mul(rhs)
            }
        }

        impl RefMul<$field_name> for G1 {
            type Output = Self;

            #[inline]
            fn ref_mul(&self, rhs: &$field_name) -> Self {
                Self { inner: $pair_function::g1mul(&self.inner, &rhs.inner) }
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
        #[cfg_attr(feature = "zeroize", derive(ZeroizeOnDrop, Zeroize))]
        pub struct G2 {
            inner: $g2_type,
        }

        impl GroupG2 for G2 {
            type Field = $field_name;

            fn new(x: &Self::Field) -> Self {
                Self::generator() * x
            }

            fn generator() -> Self {
                Self { inner: <$g2_type>::generator() }
            }
        }

        impl Mul<$field_name> for G2 {
            type Output = Self;

            #[inline]
            fn mul(self, rhs: $field_name) -> Self {
                self.ref_mul(&rhs)
            }
        }

        impl Mul<&$field_name> for G2 {
            type Output = Self;

            #[inline]
            fn mul(self, rhs: &$field_name) -> Self {
                self.ref_mul(rhs)
            }
        }

        impl RefMul<$field_name> for G2 {
            type Output = Self;

            #[inline]
            fn ref_mul(&self, rhs: &$field_name) -> Self {
                Self { inner: $pair_function::g2mul(&self.inner, &rhs.inner) }
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
        #[cfg_attr(feature = "zeroize", derive(ZeroizeOnDrop, Zeroize))]
        pub struct Gt {
            inner: $gt_type,
        }

        impl GroupGt for Gt {
            type Field = $field_name;

            #[inline]
            fn one() -> Self {
                let mut r = <$gt_type>::new();
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
                Self { inner: <$gt_type>::frombytes(bytes) }
            }
        }

        impl Random for Gt {
            type Rng = MiraclRng;
            fn random(rng: &mut Self::Rng) -> Self {
                let mut rand_bytes = [0u8; MSG_SIZE];
                rng.fill_bytes(&mut rand_bytes);
                let r = <$gt_type>::frombytes(&rand_bytes);
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

        impl Pow<$field_name> for Gt {
            type Output = Self;

            #[inline]
            fn pow(self, rhs: &$field_name) -> Self {
                self.ref_pow(rhs)
            }
        }

        impl RefPow<$field_name> for Gt {
            type Output = Self;

            #[inline]
            fn ref_pow(&self, rhs: &$field_name) -> Self {
                Self { inner: $pair_function::gtpow(&self.inner, &rhs.inner) }
            }
        }

        impl Inv for Gt {
            type Output = Self;

            fn inverse(mut self) -> Self {
                self.inner.inverse();
                self
            }
        }

        #[derive(Serialize, Deserialize, Clone)]
        #[cfg_attr(feature = "zeroize", derive(ZeroizeOnDrop, Zeroize))]
        pub struct $curve_name;

        impl PairingCurve for $curve_name {
            type Rng = MiraclRng;
            type Field = $field_name;
            type G1 = G1;
            type G2 = G2;
            type Gt = Gt;

            fn pair(e1: &Self::G1, e2: &Self::G2) -> Self::Gt {
                Self::Gt { inner: $pair_function::fexp(&$pair_function::ate(&e2.inner, &e1.inner)) }
            }

            fn hash_to_g1(msg: &[u8]) -> Self::G1 {
                let mut hash = $hash_function::new();
                hash.process_array(msg);
                let h = hash.hash();
                Self::G1 { inner: <$g1_type>::mapit(&h) }
            }

            fn hash_to_g2(msg: &[u8]) -> Self::G2 {
                let mut hash = $hash_function::new();
                hash.process_array(msg);
                let h = hash.hash();
                Self::G2 { inner: <$g2_type>::mapit(&h) }
            }
        }
    };
}
