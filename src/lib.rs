// following
// <https://crypto.stackexchange.com/questions/99617/how-proxy-re-encryption-works-layman-perspective>

#![allow(non_snake_case)]
pub use p256::{
    elliptic_curve::{
        ops::Reduce as _, point::AffineCoordinates as _, Field as _, FieldBytesEncoding as _,
    },
    AffinePoint as Point, Scalar, U256,
};
pub use rand::thread_rng as rng;
use sha2::Digest as _;

pub const G: Point = Point::GENERATOR;

pub struct Encryption {
    pub N: Point,
    pub E: Point,
}

pub fn random_scalar() -> Scalar {
    Scalar::random(rng())
}

pub fn random_point() -> Point {
    public_key(random_scalar())
}

pub fn public_key(secret_key: Scalar) -> Point {
    (G * secret_key).to_affine()
}

// This is El Gamal encryption: pick a nonce,
// blind secret with agreement
pub fn encrypt(B: Point, S: Point) -> Encryption {
    let n = random_scalar();
    // (N, E) = (nG, S + nB)
    Encryption {
        N: (G * n).to_affine(),
        E: ((B * n) + S).to_affine(),
    }
}

// This is El Gamal decryption
pub fn decrypt(b: Scalar, e: Encryption) -> Point {
    (-e.N * b + e.E).to_affine()
}

// This is a quick n' dirty commitment
pub fn hash(P: Point) -> Scalar {
    let x = P.x();
    let h = &sha2::Sha256::new_with_prefix(x).finalize();
    Scalar::reduce(U256::decode_field_bytes(h))
}

// Calculate the re-encryption key, given the decryption
// key and a recipient's public key
pub fn rekey(b: Scalar, T: Point) -> Scalar {
    let denominator = hash((T * b).to_affine());
    b * denominator.invert().unwrap()
}

// Re-encrypt an encrypted secret, given a re-encryption key
pub fn re_encrypt(mut e: Encryption, r: Scalar) -> Encryption {
    e.N = (e.N * r).to_affine();
    e
}

// Decrypt a re-encryption, given our decryption key
// and the original encryption key.
pub fn reveal(t: Scalar, B: Point, re: Encryption) -> Point {
    // this is bN
    let x = re.N * hash((B * t).to_affine());
    (-x + re.E).to_affine()
}

#[test]
// sanity check: El Gamal works
fn decrypt_encryption() {
    let a = random_scalar();
    let A = public_key(a);
    for _ in 0..10 {
        let S = random_point();
        let encryption = encrypt(A, S);
        let decryption = decrypt(a, encryption);
        assert_eq!(decryption, S);
    }
}

#[test]
// check the recipient can decrypt their re-encryption
fn reveal_reencryption() {
    // backup key
    let b = random_scalar();
    let B = public_key(b);
    // transport key
    let t = random_scalar();
    let T = public_key(t);

    for _ in 0..10 {
        let S = random_point();
        let encryption = encrypt(B, S);
        let r = rekey(b, T);
        let re = re_encrypt(encryption, r);
        let decryption = reveal(t, B, re);

        assert_eq!(decryption, S);
    }
}
