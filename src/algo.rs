use num_bigint::{BigInt, BigUint, ToBigInt};
use num_integer::Integer;
use num_traits::{One, Zero};
use sha2::Digest;

/// Mask generation function.
///
/// Panics if out is larger than 2**32. This is in accordance with RFC 8017 - PKCS #1 B.2.1
pub fn mgf1_xor<D: Digest>(out: &mut [u8], seed: &[u8]) {
    const MAX_LEN: u64 = core::u32::MAX as u64;
    assert!(out.len() as u64 <= MAX_LEN);

    let out_size = D::output_size();

    let sections = out.len().div_ceil(&out_size) as u32;

    for (i, out) in (0..sections).zip(out.chunks_mut(out_size)) {
        let mut hasher = D::new();

        hasher.update(seed);
        let ctr = i.to_le_bytes();
        hasher.update(ctr);
        let digest = &*hasher.finalize();
        for (dst, src) in out.iter_mut().zip(digest) {
            *dst ^= *src;
        }
    }
}

/// Extended Euclidian algorithm. Taken directly from wikipedia
#[allow(clippy::many_single_char_names)]
pub fn egcd(a: &BigUint, b: &BigUint) -> (BigInt, BigInt, BigInt) {
    let (mut old_r, mut r) = (a.to_bigint().unwrap(), b.to_bigint().unwrap());
    let (mut old_s, mut s) = (BigInt::one(), BigInt::zero());
    let (mut old_t, mut t) = (BigInt::zero(), BigInt::one());

    while !r.is_zero() {
        let q = &old_r / &r;

        let temp = r.clone();
        r = old_r - &q * r;
        old_r = temp;

        let temp = s.clone();
        s = old_s - &q * s;
        old_s = temp;

        let temp = t.clone();
        t = old_t - q * t;
        old_t = temp;
    }
    (old_r, old_s, old_t)
}

/// Modulo inverse. Taken directly from wikipedia. Returns None is inverse doesn't exist
#[allow(clippy::many_single_char_names)]
pub fn invmod(a: &BigUint, n: &BigUint) -> Option<BigUint> {
    // assert!(a < n);
    let (gcd, inverse, _) = egcd(a, n);
    if gcd == One::one() {
        let res = inverse.mod_floor(&n.to_bigint().unwrap());
        Some(res.to_biguint().unwrap())
    } else {
        None
    }
}
