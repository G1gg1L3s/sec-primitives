//! This module contains ECDSA signature generation and verification.
//! Originally, the challenge only required the signature generation, but I
//! implemented verification as well, because I had to debug all these.
//! Although, signature versification is done terribly wrong, because not all checks
//! are included.

use num_bigint::{BigInt, RandBigInt, Sign};
use num_integer::Integer;
use num_traits::{One, Zero};
use rand::Rng;
use sha2::{digest::Output, Digest, Sha256};

use crate::ec::{self, EcError, Invmod, Point};

/// All parameters that are required for ECDSA signing
pub struct SigningParams {
    curve: ec::Curve,
    order: BigInt,
    gen: ec::Point,
}

/// Private key for the signature generation
pub struct SigningKey<'a> {
    /// secret number d
    secret: BigInt,
    params: &'a SigningParams,
}

/// Key for verification
pub struct VerifyingKey<'a> {
    public: Point,
    params: &'a SigningParams,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Signature {
    r: BigInt,
    s: BigInt,
}

impl<'a> SigningKey<'a> {
    pub fn random(mut rng: impl Rng, curve: &'a SigningParams) -> Self {
        let one = BigInt::one();
        let secret = rng.gen_bigint_range(&one, &curve.order);
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
    pub fn verifying_key(&self) -> VerifyingKey<'a> {
        let public = self.params.gen.mul(self.secret.clone(), &self.params.curve);
        VerifyingKey {
            public,
            params: self.params,
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

impl<'a> VerifyingKey<'a> {
    /// Returns true if the parameters are consistent
    fn check_consistency(&self) -> bool {
        let SigningParams { curve, order, .. } = &self.params;
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

        let SigningParams {
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

#[cfg(test)]
mod tests {
    use num_bigint::BigUint;

    use crate::ec::Curve;

    use super::*;

    fn get_params() -> SigningParams {
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

        SigningParams { curve, order, gen }
    }

    #[test]
    fn ecdsa_sign_verify() {
        let params = get_params();
        let data = "👾";
        let signer = SigningKey::random(rand::thread_rng(), &params);

        let sig = signer.sign(rand::thread_rng(), data.as_bytes());
        let verifier = signer.verifying_key();

        verifier.verify(data.as_bytes(), &sig).unwrap();
    }

    #[test]
    fn ecdsa_sign_change_verify() {
        let params = get_params();
        let data = "👾";
        let signer = SigningKey::random(rand::thread_rng(), &params);

        let mut sig = signer.sign(rand::thread_rng(), data.as_bytes());
        sig.r += 1u32;
        let verifier = signer.verifying_key();

        verifier.verify(data.as_bytes(), &sig).unwrap_err();
    }
}
