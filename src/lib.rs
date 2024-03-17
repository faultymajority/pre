// following
// <https://crypto.stackexchange.com/questions/99617/how-proxy-re-encryption-works-layman-perspective>

#![allow(non_snake_case)]

pub use chacha20poly1305::{
    aead::{Aead as _, AeadCore as _, KeyInit as _},
    ChaCha20Poly1305, Nonce,
};
pub use p256::{
    elliptic_curve::{
        ops::Reduce as _, point::AffineCoordinates as _, Field as _, FieldBytesEncoding as _,
    },
    AffinePoint as Point, Scalar, U256,
};
pub use rand::{thread_rng as rng, RngCore as _};
use sha2::Digest as _;

pub const G: Point = Point::GENERATOR;

#[derive(Copy, Clone)]
pub struct Encryption {
    pub N: Point,
    pub E: Point,
}

pub fn random<const N: usize>() -> [u8; N] {
    let mut bytes = [0u8; N];
    rng().fill_bytes(&mut bytes);
    bytes
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
pub fn recipher(mut e: Encryption, r: Scalar) -> Encryption {
    e.N = (e.N * r).to_affine();
    e
}

// Decrypt a re-encryption, given our decryption key
// and the original encryption key.
pub fn decipher(t: Scalar, B: Point, re: Encryption) -> Point {
    // this is bN
    let x = re.N * hash((B * t).to_affine());
    (-x + re.E).to_affine()
}

pub struct Boxed {
    pub otp: Scalar,
    pub capsule: Encryption,
    pub ciphertext: Vec<u8>,
    pub nonce: Nonce,
}

impl Boxed {
    pub fn new(B: Point, s: [u8; 32], msg: &[u8]) -> Boxed {
        let s = s.into();
        let cipher = ChaCha20Poly1305::new(&s);
        let nonce = ChaCha20Poly1305::generate_nonce(&mut rng()); // 192-bits; unique per message
        let ciphertext = cipher.encrypt(&nonce, msg).expect("can this fail??");
        let S = random_point();
        let capsule = encrypt(B, S);
        let s = Scalar::reduce(U256::decode_field_bytes(&s));
        let s_prime = hash(S);
        let otp = s - s_prime;
        Boxed {
            otp,
            capsule,
            ciphertext,
            nonce,
        }
    }

    pub fn open(&self, b: Scalar) -> Vec<u8> {
        let S = decrypt(b, self.capsule);
        let s_prime = hash(S);
        let s = self.otp + s_prime;
        let cipher = ChaCha20Poly1305::new(&s.into());
        let plaintext = cipher
            .decrypt(&self.nonce, self.ciphertext.as_ref())
            .expect("decryption works");
        plaintext
    }

    pub fn recipher(mut self, r: Scalar) -> Self {
        self.capsule = recipher(self.capsule, r);
        self
    }

    pub fn decipher(&self, t: Scalar, B: Point) -> Vec<u8> {
        let S = decipher(t, B, self.capsule);
        let s_prime = hash(S);
        let s = self.otp + s_prime;
        let cipher = ChaCha20Poly1305::new(&s.into());
        let plaintext = cipher
            .decrypt(&self.nonce, self.ciphertext.as_ref())
            .expect("decryption works");
        plaintext
    }
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
fn decipher_reciphered() {
    // backup key
    let b = random_scalar();
    let B = public_key(b);
    for _ in 0..10 {
        // transport key
        let t = random_scalar();
        let T = public_key(t);

        let S = random_point();
        let encryption = encrypt(B, S);
        let r = rekey(b, T);
        let re = recipher(encryption, r);
        let decryption = decipher(t, B, re);

        assert_eq!(decryption, S);
    }
}

#[test]
fn baby_age() {
    let b = random_scalar();
    for _ in 0..10 {
        let msg = random::<256>();
        let s = random::<32>();
        let boxed = Boxed::new(public_key(b), s, &msg);
        assert_eq!(msg, boxed.open(b).as_ref());
    }
}

#[test]
fn pre_age() {
    // backup key
    let b = random_scalar();
    let B = public_key(b);

    for _ in 0..10 {
        // transport key
        let t = random_scalar();
        let T = public_key(t);
        let r = rekey(b, T);

        let msg = random::<256>();
        let s = random::<32>();
        let boxed = Boxed::new(B, s, &msg);

        let re = boxed.recipher(r);
        let decryption = re.decipher(t, B);

        assert_eq!(msg, decryption.as_ref());
    }
}
