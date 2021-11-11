//! ECDSA
//!
//! This module contains ECDSA signature and keys generation and verification.
//!
//! # Example
//! ```rust
//! use sec_primitives::ecdsa::{curves, PrivateKey};
//!
//! let params = &curves::P256;
//! let data = "👾";
//! let signer = PrivateKey::random(params);
//!
//! let sig = signer.sign(rand::thread_rng(), data.as_bytes());
//! let verifier = signer.public_key();
//!
//! let result = verifier.verify(data.as_bytes(), &sig);
//! assert!(result.is_ok());
//! ```

use num_bigint::{BigInt, RandBigInt, Sign};
use num_integer::Integer;
use num_traits::{One, Zero};
use rand::Rng;
use sha2::{digest::Output, Digest, Sha256};

use crate::ec::{self, EcError, Invmod, Point};

/// All parameters that are required for ECDSA signing
pub struct CurveParams {
    curve: ec::Curve,
    order: BigInt,
    gen: ec::Point,
}

/// Private key for the signature generation
pub struct PrivateKey<'a> {
    /// secret number d
    secret: BigInt,
    params: &'a CurveParams,
}

/// Key for verification
pub struct PublicKey<'a> {
    public: Point,
    params: &'a CurveParams,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Signature {
    r: BigInt,
    s: BigInt,
}

impl<'a> PrivateKey<'a> {
    pub fn random(curve: &'a CurveParams) -> Self {
        let one = BigInt::one();
        let secret = rand::thread_rng().gen_bigint_range(&one, &curve.order);
        Self {
            secret,
            params: curve,
        }
    }

    #[allow(clippy::many_single_char_names)]
    pub fn sign(&self, mut rng: impl Rng, msg: &[u8]) -> Signature {
        let n = &self.params.order;
        let n_len: usize = self
            .params
            .order
            .bits()
            .div_ceil(&8)
            .try_into()
            .expect("sorry, curve order is too big");

        let hash = just_hash::<Sha256>(msg);

        let z = BigInt::from_bytes_be(Sign::Plus, &hash[..n_len]);
        let one = BigInt::one();
        let mut try_gen = || -> Option<Signature> {
            let k = rng.gen_bigint_range(&one, &self.params.order);
            // kg = k*G
            let kg = self.params.gen.mul(k.clone(), &self.params.curve);
            let (x, _) = kg
                .as_coords()
                .expect("cannot be infinity, because k != order");

            let r = x % n;
            if r.is_zero() {
                return None;
            }
            // k_inv = k^(-1) (mod n)
            let k_inv = k.inv_mod(n).expect("n should be prime");

            let s = (k_inv * (&z + &r * &self.secret)) % n;
            if s.is_zero() {
                None
            } else {
                Some(Signature::new(r, s))
            }
        };

        loop {
            if let Some(sig) = try_gen() {
                return sig;
            }
        }
    }

    /// Returns appropriate public key
    pub fn public_key(&self) -> PublicKey<'a> {
        let public = self.params.gen.mul(self.secret.clone(), &self.params.curve);
        PublicKey {
            public,
            params: self.params,
        }
    }

    /// Returns shared secret as in ECDH
    pub fn shared_secret(&self, public: &PublicKey<'a>) -> Result<ec::Point, EcError> {
        let valid = public.check_consistency();
        if valid {
            let point = public.public.mul(self.secret.clone(), &self.params.curve);
            Ok(point)
        } else {
            Err(EcError::InvalidPublicKey)
        }
    }
}

impl Signature {
    pub fn new(r: BigInt, s: BigInt) -> Self {
        Self { r, s }
    }

    /// Get a reference to the signature's r.
    pub fn r(&self) -> &BigInt {
        &self.r
    }

    /// Get a reference to the signature's s.
    pub fn s(&self) -> &BigInt {
        &self.s
    }
}

impl<'a> PublicKey<'a> {
    /// Returns true if the parameters are consistent
    fn check_consistency(&self) -> bool {
        let CurveParams { curve, order, .. } = &self.params;
        let is_public_infinite = self.public.is_infinity();
        let is_public_on_curve = self.public.is_part_of(curve);
        let n_public_is_infinite = self.public.mul(order.clone(), curve).is_infinity();
        !is_public_infinite & is_public_on_curve & n_public_is_infinite
    }

    /// Returns true if signature is in valid range
    fn check_sig(&self, sig: &Signature) -> bool {
        let zero = BigInt::zero();
        let r_in_range = zero < sig.r && sig.r < self.params.order;
        let s_in_range = zero < sig.s && sig.s < self.params.order;
        r_in_range & s_in_range
    }

    /// Verifies the data and signature
    pub fn verify(&self, msg: &[u8], sig: &Signature) -> Result<(), EcError> {
        let valid = {
            let is_consistent = self.check_consistency();
            let is_sig_valid = self.check_sig(sig);
            is_consistent & is_sig_valid
        };
        if !valid {
            return Err(EcError::InvalidSignature);
        }

        let CurveParams {
            curve, order: n, ..
        } = &self.params;

        let n_len: usize = self
            .params
            .order
            .bits()
            .div_ceil(&8)
            .try_into()
            .expect("sorry, curve order is too big");

        let hash = just_hash::<Sha256>(msg);

        let z = BigInt::from_bytes_be(Sign::Plus, &hash[..n_len]);

        // it would be cool to have `try` expressions, but it can be simulated
        // like here
        let try_compute = || -> Option<()> {
            let s_inv = sig.s.inv_mod(n).expect("n is prime");
            let u1 = z * &s_inv % n;
            let u2 = &sig.r * s_inv % n;
            let u1g = self.params.gen.mul(u1, curve);
            let u2p = self.public.mul(u2, curve);
            let sum = u1g.add(&u2p, curve);
            let (x, _) = sum.as_coords()?;
            let valid = x % n == sig.r;
            if valid {
                Some(())
            } else {
                None
            }
        };

        try_compute().ok_or(EcError::InvalidSignature)
    }
}

fn just_hash<D: Digest>(msg: &[u8]) -> Output<D> {
    let mut hasher = D::new();
    hasher.update(msg);
    hasher.finalize()
}

pub mod curves {
    use lazy_static::lazy_static;

    use super::*;

    lazy_static! {
        /// P-256 NIST Curve described here:
        /// https://csrc.nist.gov/csrc/media/publications/fips/186/2/archive/2000-01-27/documents/fips186-2.pdf
        /// Is considered unsafe (http://safecurves.cr.yp.to/index.html)
        pub static ref P256: CurveParams = {
            let p: BigInt =
                "115792089210356248762697446949407573530086143415290314195533631308867097853951"
                    .parse()
                    .unwrap();

            let a = BigInt::from(-3).mod_floor(&p);
            let b = BigInt::parse_bytes(
                b"5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
                16,
            )
            .unwrap();

            let order: BigInt =
                "115792089210356248762697446949407573529996955224135760342422259061068512044369"
                    .parse()
                    .unwrap();
            let x = BigInt::parse_bytes(
                b"6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
                16,
            )
            .unwrap();

            let y = BigInt::parse_bytes(
                b"4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
                16,
            )
            .unwrap();
            let curve = ec::Curve::new(a, b, p.to_biguint().unwrap()).unwrap();
            let gen = Point::new(x, y);
            CurveParams { curve, gen, order }
        };
    }
}

#[cfg(test)]
mod tests {
    use num_bigint::BigUint;

    use crate::ec::Curve;

    use super::*;

    fn get_params() -> CurveParams {
        let curve = Curve::new(
            BigInt::parse_bytes(
                b"6277101735386680763835789423207666416083908700390324961276",
                10,
            )
            .unwrap(),
            BigInt::parse_bytes(
                b"2455155546008943817740293915197451784769108058161191238065",
                10,
            )
            .unwrap(),
            BigUint::parse_bytes(
                b"6277101735386680763835789423207666416083908700390324961279",
                10,
            )
            .unwrap(),
        )
        .unwrap();

        let x: BigInt = "602046282375688656758213480587526111916698976636884684818"
            .parse()
            .unwrap();
        let y: BigInt = "174050332293622031404857552280219410364023488927386650641"
            .parse()
            .unwrap();

        let order: BigInt = "6277101735386680763835789423176059013767194773182842284081"
            .parse()
            .unwrap();
        let gen = Point::new(x, y);

        CurveParams { curve, order, gen }
    }

    #[test]
    fn ecdsa_sign_verify() {
        let params = get_params();
        let data = "👾";
        let signer = PrivateKey::random(&params);

        let sig = signer.sign(rand::thread_rng(), data.as_bytes());
        let verifier = signer.public_key();

        verifier.verify(data.as_bytes(), &sig).unwrap();
    }

    #[test]
    fn ecdsa_sign_change_verify() {
        let params = get_params();
        let data = "👾";
        let signer = PrivateKey::random(&params);

        let mut sig = signer.sign(rand::thread_rng(), data.as_bytes());
        sig.r += 1u32;
        let verifier = signer.public_key();

        verifier.verify(data.as_bytes(), &sig).unwrap_err();
    }

    #[test]
    fn ecdsa_p256_sign_verify() {
        let params = &curves::P256;
        let data = "👾";
        let signer = PrivateKey::random(params);

        let sig = signer.sign(rand::thread_rng(), data.as_bytes());
        let verifier = signer.public_key();

        verifier.verify(data.as_bytes(), &sig).unwrap();
    }
}
