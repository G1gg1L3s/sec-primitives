use num_bigint::{BigInt, BigUint};
use num_integer::Integer;
use num_traits::{One, Zero};
use thiserror::Error;

use crate::{algo, prime::ver};

#[derive(Debug, Error)]
pub enum EcError {
    #[error("N is not a prime")]
    ModulusisNotAPrime { a: BigInt, b: BigInt, n: BigUint },
}

/// Curve in Weierstrass form
#[derive(Debug, Clone)]
pub struct Curve {
    a: BigInt,
    b: BigInt,
    n: BigInt,
}

/// Point on the curve. Either the pair of coordinates or the infinity.
#[derive(Clone, PartialEq, Eq)]
pub enum Point {
    Affine { x: BigInt, y: BigInt },
    // I wanted to do all these math with rust philosophy in mind.
    // Using enum to represent infinity gives some advantages, like you will never
    // forget to check every case, but at the same time it makes code uglier at some places
    // But anyway, I think it's better than just boolean flag (or maybe not).
    Infinity,
}

impl std::fmt::Debug for Point {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Point::Affine { x, y } => f.debug_tuple("Point").field(x).field(y).finish(),
            Point::Infinity => f.debug_struct("O").finish(),
        }
    }
}

impl Curve {
    pub fn new(a: BigInt, b: BigInt, n: BigUint) -> Result<Self, EcError> {
        if ver::is_prime(&n) {
            Ok(Self { a, b, n: n.into() })
        } else {
            Err(EcError::ModulusisNotAPrime { a, b, n })
        }
    }

    /// Computes the value of f(x) = x^3 + ax + b (mod n)
    pub fn value_at(&self, x: &BigInt) -> BigInt {
        (x.pow(3) + &self.a * x + &self.b).mod_floor(&self.n)
    }
}

impl Point {
    pub fn new(x: impl Into<BigInt>, y: impl Into<BigInt>) -> Self {
        Self::Affine {
            x: x.into(),
            y: y.into(),
        }
    }

    /// Negate the point
    pub fn neg(&self, curve: &Curve) -> Self {
        match self {
            Point::Affine { x, y } => {
                let x = x.clone();
                let y = &curve.n - y;
                Point::Affine { x, y }
            }
            Point::Infinity => self.clone(), // is it correct?
        }
    }

    /// Cast Point as a tuple of (x, y)
    /// Returns `None` if point is at infinite
    pub fn as_coords(&self) -> Option<(&BigInt, &BigInt)> {
        match self {
            Point::Affine { x, y } => Some((x, y)),
            Point::Infinity => None,
        }
    }

    /// Adds self to rhs in curve
    ///
    /// # Panic
    ///
    /// Panics if coordinates don't form a field (curve.n is not a prime), which
    /// can results in inability of finding the inverse.
    pub fn add(&self, rhs: &Self, curve: &Curve) -> Self {
        use Point::*;

        match (self, rhs) {
            (Infinity, rhs) => rhs.clone(),
            (lhs, Infinity) => lhs.clone(),
            (Affine { x: x1, y: y1 }, Affine { x: x2, y: y2 })
                if x1 == x2 && *y1 == (-y2).mod_floor(&curve.n) =>
            {
                Infinity
            }
            (Affine { x: x1, y: y1 }, Affine { x: x2, y: y2 }) => {
                let lambda = if x1 == x2 && y1 == y2 {
                    (x1.pow(2) * 3u8 + &curve.a).div_mod(&(2 * y1), &curve.n)
                } else {
                    (y2 - y1).div_mod(&(x2 - x1), &curve.n)
                };
                let x = (lambda.pow(2) - x1 - x2).mod_floor(&curve.n);
                let y = (lambda * (x1 - &x) - y1).mod_floor(&curve.n);
                Affine { x, y }
            }
        }
    }

    /// Adds self to itself k times.
    ///
    /// # Panic
    ///
    /// Panics if coordinates don't form a field (curve.n is not a prime), which
    /// can results in inability of finding the inverse.
    pub fn mul(&self, mut k: BigInt, curve: &Curve) -> Self {
        let mut q = self.clone();
        let mut r = Point::Infinity;
        while k > Zero::zero() {
            if k.is_odd() {
                r = r.add(&q, curve);
            }
            q = q.add(&q, curve);
            k /= 2;
        }
        r
    }

    /// Check if self is a part of the curve
    pub fn is_part_of(&self, curve: &Curve) -> bool {
        match self {
            Self::Infinity => true,
            Self::Affine { x, y } => (y.pow(2) - curve.value_at(x)).mod_floor(&curve.n).is_zero(),
        }
    }
}

pub trait Invmod: Sized {
    fn inv_mod(&self, n: &Self) -> Option<Self>;
}

// Having some experience I can say that using BigUints was a terrible decision
impl Invmod for BigInt {
    fn inv_mod(&self, n: &Self) -> Option<Self> {
        let mod_floor = self.mod_floor(n);
        let (gcd, inverse, _) = algo::egcd(
            &mod_floor
                .to_biguint()
                .expect("after mod floor is always positive"),
            &n.to_biguint().expect("should be positive"),
        );
        if gcd == One::one() {
            Some(inverse.mod_floor(n))
        } else {
            None
        }
    }
}

/// Trait for division in a field
pub trait Divmod {
    /// This is the same as `self / denom (mod n)`
    fn div_mod(self, denom: &BigInt, n: &BigInt) -> BigInt;
}

impl Divmod for BigInt {
    /// Calculates `self / denom (mod n)`.
    ///
    /// # Panic
    ///
    /// Panics if can't find the inverse of `denom`.
    fn div_mod(self, denom: &BigInt, n: &BigInt) -> BigInt {
        let inv = denom
            .inv_mod(n)
            .expect("can't find the inverse. Is n a prime?");
        (self * inv).mod_floor(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_test() {
        let curve = Curve {
            a: 497.into(),
            b: 1768.into(),
            n: 9739.into(),
        };
        let x = Point::new(5274, 2841);
        let y = Point::new(8669, 740);
        let z = x.add(&y, &curve);
        assert_eq!(z, Point::new(1024, 4440));
    }

    #[test]
    fn mul_test() {
        let curve = Curve {
            a: 497.into(),
            b: 1768.into(),
            n: 9739.into(),
        };
        let x = Point::new(5323, 5438);
        let y = x.mul(1337.into(), &curve);
        assert_eq!(y, Point::new(1089, 6931));
    }
}
