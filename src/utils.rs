use base64;
use std::num::NonZeroU32;
use crate::error::{Error, Field, Kind};

#[cfg(feature = "sha256")]
use ring::digest::{self, SHA256_OUTPUT_LEN, digest as ring_digest};
#[cfg(feature = "sha256")]
use ring::hmac::{self, Context, HMAC_SHA256, Key, Tag};
#[cfg(feature = "sha256")]
use ring::pbkdf2::{self, PBKDF2_HMAC_SHA256 as SHA256};

#[cfg(feature = "sm3")]
use ::hmac::{Hmac, Mac};
#[cfg(feature = "sm3")]
use sm3::{Digest, Sm3};
#[cfg(feature = "sm3")]
type HmacSm3 = Hmac<Sm3>;

/// Hash algorithm trait for SCRAM implementations
pub trait HashAlgorithm {
    const OUTPUT_LEN: usize;
    type Signature;

    fn pbkdf2_derive(password: &[u8], salt: &[u8], iterations: NonZeroU32, output: &mut [u8]);
    fn hmac_sign(key: &[u8], data: &[u8]) -> Self::Signature;
    fn hash(data: &[u8]) -> Vec<u8>;
    fn signature_as_bytes(sig: &Self::Signature) -> &[u8];
}

/// SHA-256 hash algorithm implementation
#[cfg(feature = "sha256")]
pub struct Sha256;

#[cfg(feature = "sha256")]
impl HashAlgorithm for Sha256 {
    const OUTPUT_LEN: usize = SHA256_OUTPUT_LEN;
    type Signature = Tag;

    fn pbkdf2_derive(password: &[u8], salt: &[u8], iterations: NonZeroU32, output: &mut [u8]) {
        pbkdf2::derive(SHA256, iterations, salt, password, output);
    }

    fn hmac_sign(key: &[u8], data: &[u8]) -> Self::Signature {
        let signing_key = Key::new(HMAC_SHA256, key);
        hmac::sign(&signing_key, data)
    }

    fn hash(data: &[u8]) -> Vec<u8> {
        ring_digest(&digest::SHA256, data).as_ref().to_vec()
    }

    fn signature_as_bytes(sig: &Self::Signature) -> &[u8] {
        sig.as_ref()
    }
}

/// SM3 hash algorithm implementation
#[cfg(feature = "sm3")]
pub struct Sm3Hash;

#[cfg(feature = "sm3")]
impl HashAlgorithm for Sm3Hash {
    const OUTPUT_LEN: usize = 32; // SM3 output length
    type Signature = Vec<u8>;

    fn pbkdf2_derive(password: &[u8], salt: &[u8], iterations: NonZeroU32, output: &mut [u8]) {
        let mut result = vec![0u8; Self::OUTPUT_LEN];

        // PBKDF2 implementation with SM3
        let mut mac = HmacSm3::new_from_slice(password).expect("HMAC can take key of any size");
        mac.update(salt);
        mac.update(&[0, 0, 0, 1]); // INT(1) in big-endian
        let u_result = mac.finalize();
        let mut u = u_result.into_bytes().to_vec();
        result.copy_from_slice(&u);

        for _ in 1..iterations.get() {
            let mut mac = HmacSm3::new_from_slice(password).expect("HMAC can take key of any size");
            mac.update(&u);
            let u_result = mac.finalize();
            u = u_result.into_bytes().to_vec();

            // result = result XOR u
            for (r, u_byte) in result.iter_mut().zip(u.iter()) {
                *r ^= *u_byte;
            }
        }

        output.copy_from_slice(&result);
    }

    fn hmac_sign(key: &[u8], data: &[u8]) -> Self::Signature {
        let mut mac = HmacSm3::new_from_slice(key).expect("HMAC can take key of any size");
        mac.update(data);
        let result = mac.finalize();
        result.into_bytes().to_vec()
    }

    fn hash(data: &[u8]) -> Vec<u8> {
        Sm3::digest(data).to_vec()
    }

    fn signature_as_bytes(sig: &Self::Signature) -> &[u8] {
        sig.as_slice()
    }
}

/// Parses a part of a SCRAM message, after it has been split on commas.
/// Checks to make sure there's a key, and then verifies its the right key.
/// Returns everything after the first '='.
/// Returns a `ExpectedField` error when one of the above conditions fails.
macro_rules! parse_part {
    ($iter:expr, $field:ident, $key:expr) => {
        if let Some(part) = $iter.next() {
            if part.len() < 2 {
                return Err(Error::Protocol(Kind::ExpectedField(Field::$field)));
            } else if &part.as_bytes()[..2] == $key {
                &part[2..]
            } else {
                return Err(Error::Protocol(Kind::ExpectedField(Field::$field)));
            }
        } else {
            return Err(Error::Protocol(Kind::ExpectedField(Field::$field)));
        }
    };
}

/// Hashes a password with the specified hash algorithm.
pub fn hash_password<H: HashAlgorithm>(
    password: &str,
    iterations: NonZeroU32,
    salt: &[u8],
) -> Vec<u8> {
    let mut salted_password = vec![0u8; H::OUTPUT_LEN];
    H::pbkdf2_derive(password.as_bytes(), salt, iterations, &mut salted_password);
    salted_password
}

/// Finds the client proof and server signature based on the shared hashed key.
pub fn find_proofs<H: HashAlgorithm>(
    gs2header: &str,
    client_first_bare: &str,
    server_first: &str,
    salted_password: &[u8],
    nonce: &str,
) -> (Vec<u8>, H::Signature) {
    let client_final_without_proof =
        format!("c={},r={}", base64::encode(gs2header.as_bytes()), nonce);
    let auth_message = format!(
        "{},{},{}",
        client_first_bare, server_first, client_final_without_proof
    );

    let client_key_bytes = H::hmac_sign(salted_password, b"Client Key");
    let server_key_bytes = H::hmac_sign(salted_password, b"Server Key");
    let client_key = H::signature_as_bytes(&client_key_bytes);
    let stored_key = H::hash(client_key);
    let client_signature = H::hmac_sign(&stored_key, auth_message.as_bytes());
    let server_signature = H::hmac_sign(
        H::signature_as_bytes(&server_key_bytes),
        auth_message.as_bytes(),
    );

    let mut client_proof = vec![0u8; H::OUTPUT_LEN];
    let xor_iter = client_key
        .iter()
        .zip(H::signature_as_bytes(&client_signature).iter())
        .map(|(k, s)| k ^ s);
    for (p, x) in client_proof.iter_mut().zip(xor_iter) {
        *p = x
    }
    (client_proof, server_signature)
}

// Convenience functions for specific algorithms
#[cfg(feature = "sha256")]
pub fn hash_password_sha256(
    password: &str,
    iterations: NonZeroU32,
    salt: &[u8],
) -> [u8; SHA256_OUTPUT_LEN] {
    let result = hash_password::<Sha256>(password, iterations, salt);
    let mut array = [0u8; SHA256_OUTPUT_LEN];
    array.copy_from_slice(&result);
    array
}

#[cfg(feature = "sm3")]
pub fn hash_password_sm3(password: &str, iterations: NonZeroU32, salt: &[u8]) -> [u8; 32] {
    let result = hash_password::<Sm3Hash>(password, iterations, salt);
    let mut array = [0u8; 32];
    array.copy_from_slice(&result);
    array
}

#[cfg(feature = "sha256")]
pub fn find_proofs_sha256(
    gs2header: &str,
    client_first_bare: &str,
    server_first: &str,
    salted_password: &[u8],
    nonce: &str,
) -> ([u8; SHA256_OUTPUT_LEN], Tag) {
    let (client_proof_vec, server_signature) = find_proofs::<Sha256>(
        gs2header,
        client_first_bare,
        server_first,
        salted_password,
        nonce,
    );
    let mut client_proof = [0u8; SHA256_OUTPUT_LEN];
    client_proof.copy_from_slice(&client_proof_vec);
    (client_proof, server_signature)
}

#[cfg(feature = "sm3")]
pub fn find_proofs_sm3(
    gs2header: &str,
    client_first_bare: &str,
    server_first: &str,
    salted_password: &[u8],
    nonce: &str,
) -> ([u8; 32], Vec<u8>) {
    let (client_proof_vec, server_signature) = find_proofs::<Sm3Hash>(
        gs2header,
        client_first_bare,
        server_first,
        salted_password,
        nonce,
    );
    let mut client_proof = [0u8; 32];
    client_proof.copy_from_slice(&client_proof_vec);
    (client_proof, server_signature)
}
