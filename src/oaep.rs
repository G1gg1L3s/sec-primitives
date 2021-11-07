use num_bigint::BigUint;
use num_integer::Integer;
use rand::Rng;
use sha2::Digest;

use crate::{
    algo,
    rsa::{RsaError, RsaPublic},
};

pub fn encrypt<D: Digest, R: Rng>(
    mut rng: R,
    pub_key: &RsaPublic,
    data: &[u8],
) -> Result<Vec<u8>, RsaError> {
    let n: usize = pub_key
        .n()
        .bits()
        .div_ceil(&8)
        .try_into()
        .map_err(|_| RsaError::MsgTooLong)?;

    if data.len() + 2 * D::output_size() + 2 > n {
        return Err(RsaError::MsgTooLong);
    }

    let padded = padd::<D, _>(&mut rng, data, n);

    let as_num = BigUint::from_bytes_be(&padded);

    let encrypted = pub_key.encrypt_raw(&as_num).expect("len is checked");
    Ok(encrypted.to_bytes_be())
}

fn padd<D: Digest, R: Rng>(mut rng: R, data: &[u8], len: usize) -> Vec<u8> {
    let hash_size = D::output_size();

    let mut res = vec![0u8; len];
    // res = 00 || payload
    let (_, payload) = res.split_at_mut(1);
    // payload = rand(hash_len) || datablock
    let (seed, datablock) = payload.split_at_mut(hash_size);

    rng.fill(seed);

    // label = hash("")
    let label_hasher = D::new();
    let label = &*label_hasher.finalize();

    // datablock = hash(label) || 00 .. 00 || 01 || data
    let db_len = len - hash_size - 1;
    let data_start = db_len - data.len();

    datablock[0..hash_size].copy_from_slice(label);
    datablock[data_start - 1] = 1;
    datablock[data_start..].copy_from_slice(data);

    algo::mgf1_xor::<D>(datablock, seed);
    algo::mgf1_xor::<D>(seed, datablock);

    res
}
