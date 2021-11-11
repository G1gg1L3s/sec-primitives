mod algo;

/// Module dedicated to the cell primitive - a wrapper around symmetric
/// encryption with an easy api
pub mod cell;

/// Module dedicated to the Elliptic Curve primitives. Should not be used
/// outside this crate
pub mod ec;

/// Module dedicated to the generation of ECDSA keys and signatures
pub mod ecdsa;

/// Module dedicated to the letter - cryptographic primitive, which allows
/// encrypting messages with asymmetric cryptography.
pub mod letter;

/// Module dedicated to the RSA-OAEP padding
mod oaep;

/// Module dedicated to the prime number generation and verification
pub mod prime;

/// Module dedicated to the rsa utils
pub mod rsa;
