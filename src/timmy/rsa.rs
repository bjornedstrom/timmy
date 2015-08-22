//! Naive RSA implementation. Do not use.

use num::{Zero, One};
use num::bigint::BigUint;

// Adapted from https://github.com/jsanders/rust-rsa
fn mod_exp(base: &BigUint, exponent: &BigUint, modulus: &BigUint) -> BigUint {
    let (zero, one): (BigUint, BigUint) = (Zero::zero(), One::one());

    let mut result = one.clone();
    let mut base_acc = base.clone();
    let mut exponent_acc = exponent.clone();

    while exponent_acc > zero {
        if (&exponent_acc & &one) == one {
            result = result * &base_acc;
            result = result % modulus;
        }
        base_acc = &base_acc * &base_acc;
        base_acc = &base_acc % modulus;
        exponent_acc = exponent_acc >> 1;
    }

    result
}

pub fn rsa_encrypt(m: &BigUint, e: &BigUint, n: &BigUint) -> BigUint {
    mod_exp(m, e, n)
}

pub fn estimate_bit_size(n: &BigUint) -> usize {
    let zero: BigUint = Zero::zero();
    let mut n_ = n.clone();
    let mut bits = 0;

    while n_ > zero {
        bits += 1;
        n_ = n_ >> 1;
    }

    bits
}

pub fn crypto_compare(buf_a: &Vec<u8>, buf_b: &Vec<u8>) -> bool {
    let mut equals = 0;
    for i in 0 .. buf_a.len() {
        equals |= buf_a[i] ^ buf_b[i];
    }
    equals == 0
}

pub fn make_pkcs1_sig_padding(n: &BigUint, hash_material: &Vec<u8>) -> Vec<u8> {
    let byte_size: usize = (estimate_bit_size(&n) + 1) / 8; // XXX: Wrong for e.g. 2046 bits

    assert!(byte_size == 256); // XXX

    let mut pkcs1 = Vec::new();

    pkcs1.push(0x01);

    // ignore leading zero
    for _ in 0 .. (byte_size - 2 - hash_material.len() - 1) {
        pkcs1.push(0xff);
    }
    pkcs1.push(0x00);
    for byte in hash_material {
        pkcs1.push(*byte);
    }

    pkcs1
}
