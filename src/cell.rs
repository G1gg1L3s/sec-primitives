//! Cell
//! Cell represents an object, which can encrypt and decrypt data with a simple
//! API using symmetric cryptography.
//!
//! # Themis
//! This is the obvious plagiarism from [themis' SecureCell](https://docs.cossacklabs.com/themis/crypto-theory/cryptosystems/secure-cell/)
//!
//! # Underlying primitives
//! Under the hood the AES-GCM-256 is used. Nonce is generated by secure RNG and
//! stored together with ciphertext.
//!
//! # Usage
//! ```
//! use sec_primitives::cell::{CellKey, Cell};
//! let key = CellKey::random();
//! let cell = Cell::new(&key);
//! let msg = b"secure cell";
//!
//! let encrypted = cell.encrypt(msg).unwrap();
//! let decrypted = cell.decrypt(&encrypted).unwrap();
//! assert_eq!(decrypted, msg);
//! ```
use aes_gcm::{
    aead::{AeadInPlace, NewAead},
    Aes256Gcm, Key, Nonce, Tag,
};
use rand::Rng;
use thiserror::Error;
use zeroize::Zeroize;

pub const AES_KEY_LEN: usize = 32;
const AES_NONCE_LEN: usize = 12;
const AES_TAG_LEN: usize = 16;

pub struct Cell {
    cipher: Aes256Gcm,
}

#[derive(Debug, Error)]
pub enum CellError {
    #[error("key length is incorrect (expected 32 bytes)")]
    IncorrectKeyLength,
    #[error("encrypting error")]
    Encrypt,
    #[error("decrypting error")]
    Decrypt,
}

#[derive(Zeroize, Clone)]
#[zeroize(drop)]
pub struct CellKey([u8; AES_KEY_LEN]);

impl std::fmt::Debug for CellKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "CellKey(<key>)")
    }
}

impl AsRef<[u8]> for CellKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl CellKey {
    pub fn random() -> Self {
        let mut this = Self([0; AES_KEY_LEN]);
        rand::thread_rng().fill(&mut this.0);
        this
    }

    pub fn from_slice(key: &[u8]) -> Result<Self, CellError> {
        Ok(Self(
            key.try_into().map_err(|_| CellError::IncorrectKeyLength)?,
        ))
    }
}

impl Cell {
    pub fn new(key: &CellKey) -> Self {
        let key = Key::from_slice(key.as_ref());
        let cipher = Aes256Gcm::new(key);
        Self { cipher }
    }

    pub fn encrypt_with_ad(&self, msg: &[u8], ad: &[u8]) -> Result<Vec<u8>, CellError> {
        let mut nonce = [0u8; AES_NONCE_LEN];
        rand::thread_rng().fill(&mut nonce);
        let nonce = Nonce::from_slice(&nonce);

        // result = nonce || tag || ciphertext
        let mut result = vec![0u8; AES_NONCE_LEN + AES_TAG_LEN + msg.len()];
        let (nonce_buff, tag_data) = result.split_at_mut(AES_NONCE_LEN);
        let (tag_buff, data) = tag_data.split_at_mut(AES_TAG_LEN);
        nonce_buff.copy_from_slice(nonce);
        data.copy_from_slice(msg);

        let tag = self
            .cipher
            .encrypt_in_place_detached(nonce, ad, data)
            .map_err(|_| CellError::Encrypt)?;

        tag_buff.copy_from_slice(&tag);

        Ok(result)
    }

    pub fn encrypt(&self, msg: &[u8]) -> Result<Vec<u8>, CellError> {
        self.encrypt_with_ad(msg, &[])
    }

    pub fn decrypt_with_ad(&self, msg: &[u8], ad: &[u8]) -> Result<Vec<u8>, CellError> {
        if msg.len() < AES_NONCE_LEN + AES_TAG_LEN {
            return Err(CellError::Decrypt);
        }

        let (nonce, tag_data) = msg.split_at(AES_NONCE_LEN);
        let (tag, data) = tag_data.split_at(AES_TAG_LEN);

        let nonce = Nonce::from_slice(nonce);
        let tag = Tag::from_slice(tag);

        let mut buff = data.to_vec();
        self.cipher
            .decrypt_in_place_detached(nonce, ad, &mut buff, tag)
            .map_err(|_| CellError::Decrypt)?;

        Ok(buff)
    }

    pub fn decrypt(&self, msg: &[u8]) -> Result<Vec<u8>, CellError> {
        self.decrypt_with_ad(msg, &[])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cell_enc_dec() {
        let key = CellKey::random();
        let cell = Cell::new(&key);
        let msg = b"-@-@-";
        let ad = b"cell enc dec test";

        let encrypted = cell.encrypt_with_ad(msg, ad).unwrap();
        let decrypted = cell.decrypt_with_ad(&encrypted, ad).unwrap();
        assert_eq!(decrypted, msg);
    }

    #[test]
    fn cell_enc_change_dec() {
        let key = CellKey::random();
        let cell = Cell::new(&key);
        let msg = b"-@-@-";
        let ad = b"cell enc dec test";

        let mut encrypted = cell.encrypt_with_ad(msg, ad).unwrap();
        encrypted[5] = !encrypted[5];
        cell.decrypt_with_ad(&encrypted, ad).unwrap_err();
    }

    #[test]
    fn cell_enc_change_ad_dec() {
        let key = CellKey::random();
        let cell = Cell::new(&key);
        let msg = b"-@-@-";
        let ad = b"cell enc dec test";

        let encrypted = cell.encrypt_with_ad(msg, ad).unwrap();
        cell.decrypt_with_ad(&encrypted, b"associated data? what does it even mean???")
            .unwrap_err();
    }

    #[test]
    fn cell_enc_dec_empty() {
        let key = CellKey::random();
        let cell = Cell::new(&key);
        let msg = b"";

        let encrypted = cell.encrypt(msg).unwrap();
        let decrypted = cell.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, msg);
    }
}
