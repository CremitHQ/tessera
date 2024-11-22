use nebula_miracl::{
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

use crate::define_miracl_pairing_curve;

define_miracl_pairing_curve!(
    Bls24479Curve,
    Bls24479Field,
    BIG,
    ECP,
    ECP4,
    FP24,
    pair4,
    HASH256,
    24,
    CURVE_ORDER,
    NLEN,
    MODBYTES
);
