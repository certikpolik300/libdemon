extern crate openssl;
extern crate libc;
extern crate flate2;
extern crate base64;

use openssl::rsa::{Rsa, Padding};
use openssl::pkey::{PKey, Private, Public};
use openssl::symm::{Cipher, Crypter, Mode};
use openssl::ec::{EcKey, EcGroup};
use openssl::bn::BigNum;
use openssl::sha::{Sha256, Sha512};
use openssl::hash::MessageDigest;
use openssl::sign::{Signer, Verifier};
use openssl::rand::rand_bytes;
use hmac::{Hmac, Mac};
use flate2::{Compression, write::ZlibEncoder, read::ZlibDecoder};
use std::time::{SystemTime, UNIX_EPOCH};
use std::io::{Write, Read};
use std::collections::HashMap;

type HmacSha256 = Hmac<Sha256>;

const AES_KEY_SIZE: usize = 32;
const HMAC_KEY_SIZE: usize = 32;
const NONCE_SIZE: usize = 12;
const RSA_KEY_SIZE: usize = 4096;
const TIMESTAMP_TOLERANCE: u64 = 30; // Replay protection

/// Struct holding encryption context
pub struct EncryptionContext {
    ecdh_private_key: EcKey<Private>,
    ecdh_public_key: EcKey<Public>,
    rsa_private_key: Rsa<Private>,
    rsa_public_key: Rsa<Public>,
    aes_key: Option<Vec<u8>>,
    hmac_key: Option<Vec<u8>>,
}

impl EncryptionContext {
    /// Initializes encryption context (ECDH + RSA)
    pub fn new() -> Self {
        let group = EcGroup::from_curve_name(openssl::nid::Nid::SECP384R1()).unwrap();
        let ecdh_private_key = EcKey::generate(&group).unwrap();
        let ecdh_public_key = EcKey::from_public_key(&group, ecdh_private_key.public_key()).unwrap();

        let rsa_private_key = Rsa::generate(RSA_KEY_SIZE as u32).unwrap();
        let rsa_public_key = Rsa::from_public_components(
            rsa_private_key.n().to_owned().unwrap(),
            rsa_private_key.e().to_owned().unwrap(),
        )
        .unwrap();

        EncryptionContext {
            ecdh_private_key,
            ecdh_public_key,
            rsa_private_key,
            rsa_public_key,
            aes_key: None,
            hmac_key: None,
        }
    }

    /// Returns ECDH public key
    pub fn get_ecdh_public_key(&self) -> Vec<u8> {
        self.ecdh_public_key.to_pem().unwrap()
    }

    /// Returns RSA public key
    pub fn get_rsa_public_key(&self) -> Vec<u8> {
        self.rsa_public_key.public_key_to_pem().unwrap()
    }

    /// Derives a shared secret using ECDH and HKDF
    pub fn derive_shared_secret(&mut self, peer_public_key_pem: &[u8]) -> Vec<u8> {
        let peer_public_key = EcKey::public_key_from_pem(peer_public_key_pem).unwrap();
        let shared_secret = self
            .ecdh_private_key
            .derive(&peer_public_key.public_key())
            .unwrap();

        let mut derived_key = vec![0; AES_KEY_SIZE + HMAC_KEY_SIZE];
        let mut hasher = Sha256::new();
        hasher.update(&shared_secret);
        derived_key.copy_from_slice(&hasher.finish());

        self.aes_key = Some(derived_key[..AES_KEY_SIZE].to_vec());
        self.hmac_key = Some(derived_key[AES_KEY_SIZE..].to_vec());
        self.aes_key.clone().unwrap()
    }

    /// Message Signing (RSA)
    pub fn sign_message(&self, message: &str) -> Vec<u8> {
        let mut signer = Signer::new(MessageDigest::sha256(), &PKey::from_rsa(self.rsa_private_key.clone()).unwrap()).unwrap();
        signer.update(message.as_bytes()).unwrap();
        signer.sign_to_vec().unwrap()
    }

    /// Verify Signed Message
    pub fn verify_signature(&self, message: &str, signature: &[u8]) -> bool {
        let mut verifier = Verifier::new(MessageDigest::sha256(), &PKey::from_rsa(self.rsa_public_key.clone()).unwrap()).unwrap();
        verifier.update(message.as_bytes()).unwrap();
        verifier.verify(signature).unwrap_or(false)
    }

    /// Authenticate Peer
    pub fn authenticate_peer(&self, peer_public_key_pem: &[u8], signed_message: &[u8]) -> bool {
        let peer_public_key = Rsa::public_key_from_pem(peer_public_key_pem).unwrap();
        let pkey = PKey::from_rsa(peer_public_key).unwrap();
        let mut verifier = Verifier::new(MessageDigest::sha256(), &pkey).unwrap();
        verifier.update(b"authentication_message").unwrap();
        verifier.verify(signed_message).unwrap_or(false)
    }

    /// Encrypt Metadata (AES-GCM)
    pub fn encrypt_metadata(&self, metadata: &HashMap<String, String>) -> Vec<u8> {
        let aes_key = self.aes_key.as_ref().unwrap();
        let nonce = {
            let mut buf = [0u8; NONCE_SIZE];
            rand_bytes(&mut buf).unwrap();
            buf
        };

        let metadata_json = serde_json::to_string(metadata).unwrap();
        let cipher = Cipher::aes_256_gcm();
        let mut encrypter = Crypter::new(cipher, Mode::Encrypt, aes_key, Some(&nonce)).unwrap();
        let mut encrypted_metadata = vec![0; metadata_json.len() + cipher.block_size()];
        let mut count = encrypter.update(metadata_json.as_bytes(), &mut encrypted_metadata).unwrap();
        count += encrypter.finalize(&mut encrypted_metadata[count..]).unwrap();
        encrypted_metadata.truncate(count);

        [nonce.to_vec(), encrypted_metadata].concat()
    }

    /// Decrypt Metadata (AES-GCM)
    pub fn decrypt_metadata(&self, encrypted_metadata: &[u8]) -> HashMap<String, String> {
        let aes_key = self.aes_key.as_ref().unwrap();
        let nonce = &encrypted_metadata[..NONCE_SIZE];
        let encrypted_data = &encrypted_metadata[NONCE_SIZE..];

        let cipher = Cipher::aes_256_gcm();
        let mut decrypter = Crypter::new(cipher, Mode::Decrypt, aes_key, Some(nonce)).unwrap();
        let mut decrypted_data = vec![0; encrypted_data.len() + cipher.block_size()];
        let mut count = decrypter.update(encrypted_data, &mut decrypted_data).unwrap();
        count += decrypter.finalize(&mut decrypted_data[count..]).unwrap();
        decrypted_data.truncate(count);

        serde_json::from_slice(&decrypted_data).unwrap()
    }
}
