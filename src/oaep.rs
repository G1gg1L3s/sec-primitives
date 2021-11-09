use num_bigint::BigUint;
use num_integer::Integer;
use rand::Rng;
use sha2::Digest;

use crate::{
    algo::{self, mgf1_xor},
    rsa::{RsaError, RsaPrivate, RsaPublic},
};

fn left_padd(vec: &mut Vec<u8>, len: usize, element: u8) {
    if vec.len() >= len {
        return;
    }
    let diff = len - vec.len();
    vec.resize(len, element);
    vec.rotate_right(diff);
}

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

pub fn decrypt<D: Digest>(key: &RsaPrivate, ciphertext: &[u8]) -> Result<Vec<u8>, RsaError> {
    let key_size: usize = key
        .n()
        .bits()
        .div_ceil(&8)
        .try_into()
        .map_err(|_| RsaError::Decrypt)?;
    if key_size < 11 {
        return Err(RsaError::Decrypt);
    }

    let num = BigUint::from_bytes_be(ciphertext);
    let decrypted = {
        let num = key.decrypt_raw(&num).map_err(|_| RsaError::Decrypt)?;
        let mut bytes = num.to_bytes_be();
        left_padd(&mut bytes, key_size, 0);
        bytes
    };

    unpadd::<D>(decrypted).ok_or(RsaError::Decrypt)
}

fn unpadd<D: Digest>(mut decrypted: Vec<u8>) -> Option<Vec<u8>> {
    let hash_size = D::output_size();
    // label = hash("")
    let label_hasher = D::new();
    let label = &*label_hasher.finalize();

    let (first, payload) = decrypted.split_at_mut(1);
    let (seed, datablock) = payload.split_at_mut(hash_size);

    let is_first_valid = first[0] == 0;

    mgf1_xor::<D>(seed, datablock);
    mgf1_xor::<D>(datablock, seed);

    // TODO: make constant time
    let are_hashes_equal = &datablock[..hash_size] == label;

    enum State {
        Zero,
        One,
        Data { index: usize },
        Error,
    }

    // TODO: make constant time
    let mut state = State::Zero;
    for (i, e) in datablock.iter().enumerate().skip(hash_size) {
        state = match (state, *e) {
            (State::Zero, 0) => State::Zero,
            (State::Zero, 1) => State::One,
            (State::One, _) => State::Data { index: i },
            (c @ State::Data { .. }, _) => c,
            _ => State::Error,
        }
    }

    let valid = matches!(state, State::Data { .. }) & are_hashes_equal & is_first_valid;

    if valid {
        let index = if let State::Data { index } = state {
            index
        } else {
            unreachable!();
        };
        Some(datablock[index..].to_vec())
    } else {
        None
    }
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

#[cfg(test)]
mod tests {
    use sha2::Sha256;

    use super::*;

    #[test]
    fn left_padd_test() {
        let mut vec = vec![1, 2, 3];
        left_padd(&mut vec, 5, 0);
        assert_eq!(vec, [0, 0, 1, 2, 3]);
    }

    #[test]
    fn padd_unpadd() {
        let data = b"hello world";
        let padded = padd::<Sha256, _>(rand::thread_rng(), data, 256);
        let unpadded = unpadd::<Sha256>(padded).unwrap();
        assert_eq!(unpadded, data);
    }
}
