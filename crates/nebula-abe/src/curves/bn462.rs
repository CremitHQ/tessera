use nebula_miracl::{
    bn462::{
        big::{BIG, MODBYTES, NLEN},
        ecp::ECP,
        ecp2::ECP2,
        fp12::FP12,
        pair,
        rom::CURVE_ORDER,
    },
    hash256::HASH256,
};

use crate::define_miracl_pairing_curve;

define_miracl_pairing_curve!(
    Bn462Curve,
    Bn462Field,
    BIG,
    ECP,
    ECP2,
    FP12,
    pair,
    HASH256,
    12,
    CURVE_ORDER,
    NLEN,
    MODBYTES
);
