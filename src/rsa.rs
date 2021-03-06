///! Rsa
///!
///! This module implements all rsa-dedicated logic. Only encryption with
///! OAEP-SHA256 padding is supported.
///!
///! # Example
///! ```
///! use sec_primitives::rsa::generate_rsa_pair;
///!
///! let data = b"my fancy data";
///! let (public, private) = generate_rsa_pair(1024).unwrap();
///! let mut rng = rand::thread_rng();
///! let ciphertext = public.encrypt_oaep_sha256(&mut rng, data).unwrap();
///! let plaintext = private.decrypt_oaep_sha256(&ciphertext).unwrap();
///! assert_eq!(plaintext, data);
///! ```
use num_bigint::BigUint;
use num_traits::One;
use rand::Rng;
use sha2::Sha256;
use thiserror::Error;

use crate::{algo, oaep, prime::gen};

const MIN_KEY_SIZE: u64 = 512;
const MAX_KEY_SIZE: u64 = 16384;

/// Default exponent for RSA keys
const EXP: u64 = 65537;

#[derive(Debug, Error)]
pub enum RsaError {
    #[error("message is too long")]
    MsgTooLong,
    #[error("decryption error")]
    Decrypt,
}

#[derive(Debug, Error)]
pub enum RsaGenError {
    #[error("key size is too small")]
    KeyTooSMall,

    #[error("key size is too big")]
    KeyTooBig,
}

/// Rsa private key
pub struct RsaPrivate {
    d: BigUint,
    n: BigUint,
}

/// Rsa public key
pub struct RsaPublic {
    e: BigUint,
    n: BigUint,
}

impl RsaPrivate {
    pub fn decrypt_oaep_sha256(&self, ciphertext: &[u8]) -> Result<Vec<u8>, RsaError> {
        oaep::decrypt::<Sha256>(self, ciphertext)
    }

    pub(crate) fn decrypt_raw(&self, num: &BigUint) -> Result<BigUint, &'static str> {
        if num >= &self.n {
            return Err("data length is larger than modulus");
        }
        let c = num.modpow(&self.d, &self.n);
        Ok(c)
    }

    /// Get a reference to the rsa private's n.
    pub fn n(&self) -> &BigUint {
        &self.n
    }

    /// Get a reference to the rsa private's d.
    pub fn d(&self) -> &BigUint {
        &self.d
    }
}

impl RsaPublic {
    pub fn encrypt_oaep_sha256<R: Rng>(&self, rng: R, data: &[u8]) -> Result<Vec<u8>, RsaError> {
        oaep::encrypt::<Sha256, R>(rng, self, data)
    }

    /// Encrypting plaintext that will be decrypted using private key
    pub(crate) fn encrypt_raw(&self, num: &BigUint) -> Result<BigUint, &'static str> {
        if num >= &self.n {
            return Err("data length is larger than modulus");
        }
        let c = num.modpow(&self.e, &self.n);
        Ok(c)
    }

    /// Get a reference to the rsa public's e.
    pub fn e(&self) -> &BigUint {
        &self.e
    }

    /// Get a reference to the rsa public's n.
    pub fn n(&self) -> &BigUint {
        &self.n
    }
}

/// Generates RSA key pair
#[allow(clippy::many_single_char_names)]
pub fn generate_rsa_pair(size: u64) -> Result<(RsaPublic, RsaPrivate), RsaGenError> {
    if size < MIN_KEY_SIZE {
        return Err(RsaGenError::KeyTooSMall);
    }
    if size > MAX_KEY_SIZE {
        return Err(RsaGenError::KeyTooBig);
    }
    let size = size / 2;
    let e = BigUint::from(EXP);

    let try_generate = || {
        let (p, q) = gen_prime_pair(size, &e);
        let n = &p * &q;
        let totient = (p - 1u32) * (q - 1u32);
        let d = algo::invmod(&e, &totient)?;
        Some((d, n))
    };

    let (d, n) = loop {
        if let Some(pair) = try_generate() {
            break pair;
        }
    };
    let public = RsaPublic { e, n: n.clone() };
    let private = RsaPrivate { d, n };
    Ok((public, private))
}

/// Generates prime P of given size until P % e != 1
fn gen_prime(size: u64, e: &BigUint) -> BigUint {
    loop {
        let p = gen::new_prime(size);
        if &p % e != One::one() {
            return p;
        }
    }
}

fn gen_prime_pair(size: u64, e: &BigUint) -> (BigUint, BigUint) {
    let p = gen_prime(size, e);
    loop {
        let q = gen_prime(size, e);
        if p != q {
            break (p, q);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rsa_enc_dec_raw() {
        let data = BigUint::parse_bytes(b"6675636b696e67206c616273", 16).unwrap();
        let (public, private) = generate_rsa_pair(1024).unwrap();
        let ciphertext = public.encrypt_raw(&data).unwrap();
        let plaintext = private.decrypt_raw(&ciphertext).unwrap();
        assert_eq!(plaintext, data);
    }

    #[test]
    fn rsa_enc_dec() {
        let data = b"my fancy data";
        let (public, private) = generate_rsa_pair(1024).unwrap();
        let mut rng = rand::thread_rng();
        let ciphertext = public.encrypt_oaep_sha256(&mut rng, data).unwrap();
        let plaintext = private.decrypt_oaep_sha256(&ciphertext).unwrap();
        assert_eq!(plaintext, data);
    }

    #[test]
    fn rsa_enc_distorb_dec() {
        let data = b"my fancy data";
        let (public, private) = generate_rsa_pair(1024).unwrap();
        let mut rng = rand::thread_rng();
        let mut ciphertext = public.encrypt_oaep_sha256(&mut rng, data).unwrap();
        // oops
        ciphertext[17] = !ciphertext[17];
        let plaintext = private.decrypt_oaep_sha256(&ciphertext);
        assert!(plaintext.is_err());
    }
}
