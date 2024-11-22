use nebula_miracl::{
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

use crate::define_miracl_pairing_curve;
define_miracl_pairing_curve!(
    Bls48556Curve,
    Bls48556Field,
    BIG,
    ECP,
    ECP8,
    FP48,
    pair8,
    HASH256,
    48,
    CURVE_ORDER,
    NLEN,
    MODBYTES
);
