//! Letter
//! The Letter respresents the object, that allows communication with a use of
//! hybrid cryptography. It encrypts message with a sender's private key
//! and receiver's public key, so that only the receiver, that knows the
//! sender's key, could decrypt the message.
//!
//! # Themis
//! This is an analogue of SecureMessage in [themis](https://docs.cossacklabs.com/themis/crypto-theory/cryptosystems/secure-message/)
//!
//! # Under the hood
//! 1) It derives shared secret from asymmetric keys using the ECDH key exchange.
//! 2) It derives symmetric key from the shared secret
//! 3) The letter encrypts the message using the Cell.
//!
//! # Usage
//! ```
//! use sec_primitives::{
//!     ecdsa::{curves, PrivateKey, PublicKey},
//!     letter::Letter
//! };
//!
//! let curve = &curves::P256;
//!
//! let alice = PrivateKey::random(curve);
//! let bob = PrivateKey::random(curve);
//!
//! // The key that alice will send to bob
//! let alice_pub = alice.public_key();
//! // The key that bob will send to alice
//! let bob_pub = bob.public_key();
//!
//! // This what the alice would do
//! let alice_to_bob = Letter::new(&alice, &bob_pub).unwrap();
//! // This what the bob would do
//! let bob_to_alice = Letter::new(&bob, &alice_pub).unwrap();
//!
//! let msg = "It was me who ate the cake";
//!
//! // bob encrypts and sends message to the alice
//! let encrypted_letter = bob_to_alice.encrypt(msg.as_bytes()).unwrap();
//!
//! // alice decrypts the message from the bob
//! let decrypted_letter = alice_to_bob.decrypt(&encrypted_letter).unwrap();
//!
//! assert_eq!(decrypted_letter, msg.as_bytes());
//! ```
use crate::{
    cell::{Cell, CellKey, AES_KEY_LEN},
    ec,
    ecdsa::{PrivateKey, PublicKey},
};

use thiserror::Error;
use zeroize::Zeroize;

pub struct Letter {
    cell: Cell,
}

#[derive(Debug, Error)]
pub enum LetterError {
    #[error("keys are not valid")]
    InvalidKeys,

    #[error("creating the letter")]
    Create,

    #[error("encrypting error")]
    Encrypt,

    #[error("decrypting error")]
    Decrypt,
}

fn hash_point_to_key(point: &ec::Point) -> Result<CellKey, LetterError> {
    // TODO: probably insecure
    let serialized = point.serialize();
    // TODO: should be static
    let mut config = argon2::Config::default();
    const SALT: &[u8] = b"Letter salt";
    config.hash_length = AES_KEY_LEN as u32;

    let mut raw = argon2::hash_raw(&serialized, SALT, &config).map_err(|_| LetterError::Create)?;
    let key = CellKey::from_slice(&raw).expect("length is checked");
    raw.zeroize();
    Ok(key)
}

impl Letter {
    pub fn new(private: &PrivateKey, public: &PublicKey) -> Result<Self, LetterError> {
        let shared_secret = private
            .shared_secret(public)
            .map_err(|_| LetterError::Create)?;
        let key = hash_point_to_key(&shared_secret)?;
        Ok(Self {
            cell: Cell::new(&key),
        })
    }

    pub fn encrypt(&self, msg: &[u8]) -> Result<Vec<u8>, LetterError> {
        self.cell.encrypt(msg).map_err(|_| LetterError::Encrypt)
    }
    pub fn decrypt(&self, msg: &[u8]) -> Result<Vec<u8>, LetterError> {
        self.cell.decrypt(msg).map_err(|_| LetterError::Decrypt)
    }
}

#[cfg(test)]
mod tests {
    use crate::ecdsa::curves;

    use super::*;

    #[test]
    fn gen_enc_dec() {
        let curve = &curves::P256;

        let alice = PrivateKey::random(curve);
        let bob = PrivateKey::random(curve);

        let alice_pub = alice.public_key();
        let bob_pub = bob.public_key();

        let alice_to_bob = Letter::new(&alice, &bob_pub).unwrap();
        let bob_to_alice = Letter::new(&bob, &alice_pub).unwrap();

        let msg = "It was me who ate the cake";

        let encrypted_letter = bob_to_alice.encrypt(msg.as_bytes()).unwrap();

        let decrypted_letter = alice_to_bob.decrypt(&encrypted_letter).unwrap();

        assert_eq!(decrypted_letter, msg.as_bytes());
    }

    #[test]
    fn gen_change_enc_dec() {
        let curve = &curves::P256;

        let alice = PrivateKey::random(curve);
        let bob = PrivateKey::random(curve);
        let eve = PrivateKey::random(curve);

        let alice_pub = alice.public_key();
        let bob_pub = bob.public_key();

        let alice_to_bob = Letter::new(&alice, &bob_pub).unwrap();
        // eve changed
        let bob_to_alice = Letter::new(&eve, &alice_pub).unwrap();

        let msg = "It was me who ate the cake";

        let encrypted_letter = bob_to_alice.encrypt(msg.as_bytes()).unwrap();

        alice_to_bob.decrypt(&encrypted_letter).unwrap_err();
    }
}
