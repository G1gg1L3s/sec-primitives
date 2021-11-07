use num_integer::Integer;
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
