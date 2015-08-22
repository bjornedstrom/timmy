//! Naive RSA implementation. Do not use.

use num::{Zero, One};
use num::bigint::{BigUint};
use std::mem::replace;

// Adapted from https://github.com/jsanders/rust-rsa
fn mod_exp(base: &BigUint, exponent: &BigUint, modulus: &BigUint) -> BigUint {
    let (zero, one): (BigUint, BigUint) = (Zero::zero(), One::one());

    let mut result = one.clone();
    let mut baseAcc = base.clone();
    let mut exponentAcc = exponent.clone();

    while exponentAcc > zero {
        if (&exponentAcc & &one) == one {
            result = result * &baseAcc;
            result = result % modulus;
        }
        baseAcc = &baseAcc * &baseAcc;
        baseAcc = &baseAcc % modulus;
        exponentAcc = exponentAcc >> 1;
    }

    result
}

pub fn rsa_encrypt(m: &BigUint, e: &BigUint, n: &BigUint) -> BigUint {
    mod_exp(m, e, n)
}
