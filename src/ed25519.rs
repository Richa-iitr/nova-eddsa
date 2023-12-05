use bellpepper_ed25519::curve::AffinePoint;
use bellpepper_ed25519::curve::Ed25519Curve;    
use sha3::{Digest, Sha3_256};
use num_bigint::{BigUint};

pub fn hash(msg: &[u8], key: &BigUint) -> BigUint {
    let mut hasher = Sha3_256::new();
    hasher.update(msg);
    let result = hasher.finalize();
    let mut result = BigUint::from_bytes_be(&result);
    result %= key;
    result
}

// Define the finite field type (e.g., Fp25519 from the `ff` crate)
pub fn sign(message: &[u8], private_key: &BigUint) -> (AffinePoint, BigUint)
{
    //basepoint of eddsa
    let G = Ed25519Curve::basepoint();

    let pubKey = Ed25519Curve::scalar_multiplication(&G, private_key);
    // r = hash(hash(privKey) + msg) mod q (this is a bit simplified)
    let r = hash(&[private_key.to_bytes_be(), message.to_vec()].concat(), &Ed25519Curve::order());
    let R = Ed25519Curve::scalar_multiplication(&G, &r);

    //generate a random hash
    let h = hash(&[message.to_vec()].concat(), &Ed25519Curve::order());
    // let h = hash(&[, message.to_vec()].concat(), &Ed25519Curve::order());
    let s = private_key *  &(&r + &h);

    (R, s)
}

fn main() {
    let message = b"Hello, world!";
    let private_key = BigUint::from(6u8);
    sign(message, &private_key);
}

