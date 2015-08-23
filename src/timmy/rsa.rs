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

pub fn count_bits(n: &BigUint) -> usize {
    let zero: BigUint = Zero::zero();
    let mut n_ = n.clone();
    let mut bits = 0;

    while n_ > zero {
        bits += 1;
        n_ = n_ >> 1;
    }

    bits
}

pub fn estimate_bit_size(bits: usize) -> usize {
    if bits % 8 == 0 {
        bits
    } else {
        (bits / 8 + 1) * 8
    }
}

pub fn crypto_compare(buf_a: &Vec<u8>, buf_b: &Vec<u8>) -> bool {
    let mut equals = 0;
    for i in 0 .. buf_a.len() {
        equals |= buf_a[i] ^ buf_b[i];
    }
    equals == 0
}

pub fn make_pkcs1_sig_padding(n: &BigUint, hash_material: &Vec<u8>) -> Vec<u8> {
    let byte_size: usize = estimate_bit_size(count_bits(&n)) / 8;

    // TODO: For now or until we discover a weird size key
    assert!(byte_size == 256 || byte_size == 384 || byte_size == 512);

    let mut pkcs1 = Vec::new();

    pkcs1.push(0x00);
    pkcs1.push(0x01);

    for _ in 0 .. (byte_size - 3 - hash_material.len()) {
        pkcs1.push(0xff);
    }
    pkcs1.push(0x00);
    for byte in hash_material {
        pkcs1.push(*byte);
    }

    pkcs1
}

#[cfg(test)]
mod tests {
    use super::*;
    use num::bigint::BigUint;

    #[test]
    fn test_rsa_encrypt() {
        let big_a = BigUint::parse_bytes(b"188394207298085200331335318886080117835", 10).unwrap();
        let big_b = BigUint::parse_bytes(b"65537", 10).unwrap();
        let big_c = BigUint::parse_bytes(b"313451135729381938245427493117266465994", 10).unwrap();

        let res = rsa_encrypt(&big_a, &big_b, &big_c);

        assert_eq!(BigUint::parse_bytes(b"140863285186154755267136119549725662143", 10).unwrap(),
                   res);
    }

    #[test]
    fn test_count_bits() {
        let big_a = BigUint::parse_bytes(b"1001001001", 2).unwrap();

        assert_eq!(10, count_bits(&big_a));
    }

    #[test]
    fn test_estimate() {
        assert_eq!(2048, estimate_bit_size(2048));
        assert_eq!(2048, estimate_bit_size(2047));
    }

    #[test]
    fn test_pkcs1_sig_padding() {
        let hash_material: [u8; 20] = [0xcc; 20];
        let big_n = BigUint::parse_bytes(b"16158503035655503650357438344334975980222051334857742016065172713762327569433945446598600705761456731844358980460949009747059779575245460547544076193224141560315438683650498045875098875194826053398028819192033784138396109321309878080919047169238085235290822926018152521443787945770532904303776199561965192760957166694834171210342487393282284747428088017663161029038902829665513096354230157075129296432088558362971801859230928678799175576150822952201848806616643615613562842355410104862578550863465661734839271290328348967522998634176499319107762583194718667771801067716614802322659239302476074096777926805529798062900", 10).unwrap();

        let pkcs1 = make_pkcs1_sig_padding(&big_n, &hash_material.iter().cloned().collect());

        assert_eq!(256, pkcs1.len());

        assert_eq!(0x00, pkcs1[0]);
        assert_eq!(0x01, pkcs1[1]);
        assert_eq!(0xff, pkcs1[2]);
        assert_eq!(0xff, pkcs1[234]);
        assert_eq!(0x00, pkcs1[235]);
        assert_eq!(0xcc, pkcs1[236]);
        assert_eq!(0xcc, pkcs1[255]);
    }
}
