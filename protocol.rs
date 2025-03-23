extern crate openssl;
extern crate rsa;
extern crate ecdsa;
extern crate aes;
extern crate hmac;
extern crate sha2;
extern crate zlib;
extern crate base64;

use openssl::rsa::{Rsa, Padding};
use openssl::ec::{EcKey, EcGroup, Nid};
use openssl::pkey::{PKey, Private};
use openssl::symm::{Cipher, Crypter, Mode};
use openssl::hash::MessageDigest;
use openssl::rand::rand_bytes;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use base64::{encode, decode};
use zlib::compression::{Compression, ZlibWriter};
use std::time::{SystemTime, UNIX_EPOCH};
use std::io::Write;

const AES_KEY_SIZE: usize = 32;
const HMAC_KEY_SIZE: usize = 32;
const NONCE_SIZE: usize = 12;
const RSA_KEY_SIZE: usize = 4096;
const TIMESTAMP_TOLERANCE: u64 = 30;

pub struct E2EE {
    ecdh_private_key: EcKey<openssl::ec::Private>,
    rsa_private_key: Rsa<openssl::rsa::Private>,
    aes_key: Vec<u8>,
    hmac_key: Vec<u8>,
}

impl E2EE {
    pub fn new() -> Self {
        let ecdh_private_key = EcKey::generate(&EcGroup::from_curve_name(Nid::SECP384R1).unwrap()).unwrap();
        let rsa_private_key = Rsa::generate(RSA_KEY_SIZE).unwrap();

        Self {
            ecdh_private_key,
            rsa_private_key,
            aes_key: vec![],
            hmac_key: vec![],
        }
    }

    pub fn get_ecdh_public_key(&self) -> Vec<u8> {
        let public_key = self.ecdh_private_key.public_key_to_pem().unwrap();
        public_key
    }

    pub fn get_rsa_public_key(&self) -> Vec<u8> {
        let public_key = self.rsa_private_key.public_key_to_pem().unwrap();
        public_key
    }

    pub fn derive_shared_secret(&mut self, peer_public_key_pem: &[u8]) -> String {
        let peer_public_key = EcKey::public_key_from_pem(peer_public_key_pem).unwrap();
        let shared_secret = self.ecdh_private_key.ecdh(&peer_public_key).unwrap();

        let mut hasher = Sha256::new();
        hasher.update(&shared_secret);
        let key_material = hasher.finalize();

        self.aes_key = key_material[0..AES_KEY_SIZE].to_vec();
        self.hmac_key = key_material[AES_KEY_SIZE..AES_KEY_SIZE + HMAC_KEY_SIZE].to_vec();

        encode(&self.aes_key)
    }

    pub fn sign_message(&self, message: &str) -> String {
        let signature = self.rsa_private_key.sign_oaep::<Sha256>(message.as_bytes()).unwrap();
        encode(&signature)
    }

    pub fn verify_signature(&self, message: &str, signature: &str) -> bool {
        let signature_bytes = decode(signature).unwrap();
        self.rsa_private_key.verify_oaep::<Sha256>(message.as_bytes(), &signature_bytes).is_ok()
    }

    pub fn encrypt(&self, plaintext: &str) -> String {
        let nonce = rand_bytes(NONCE_SIZE).unwrap();
        let mut cipher = Cipher::new(Cipher::aes_256_gcm(), &self.aes_key, &nonce);
        let mut ciphertext = cipher.encrypt(plaintext.as_bytes()).unwrap();

        let mac = Hmac::<Sha256>::new_varkey(&self.hmac_key).unwrap().digest(&ciphertext).to_vec();

        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

        let mut result = Vec::new();
        result.extend_from_slice(&nonce);
        result.extend_from_slice(&mac);
        result.extend_from_slice(&timestamp.to_be_bytes());
        result.extend_from_slice(&ciphertext);

        encode(&result)
    }

    pub fn decrypt(&mut self, encrypted_data: &str) -> String {
        let data = decode(encrypted_data).unwrap();

        let nonce = &data[0..NONCE_SIZE];
        let mac = &data[NONCE_SIZE..NONCE_SIZE + HMAC_KEY_SIZE];
        let timestamp = u64::from_be_bytes(data[NONCE_SIZE + HMAC_KEY_SIZE..NONCE_SIZE + HMAC_KEY_SIZE + 8].try_into().unwrap());
        let ciphertext = &data[NONCE_SIZE + HMAC_KEY_SIZE + 8..];

        if (SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() - timestamp) > TIMESTAMP_TOLERANCE {
            panic!("Replay attack detected!");
        }

        let expected_mac = Hmac::<Sha256>::new_varkey(&self.hmac_key).unwrap().digest(&ciphertext).to_vec();
        if mac != &expected_mac {
            panic!("Data integrity compromised!");
        }

        let mut cipher = Cipher::new(Cipher::aes_256_gcm(), &self.aes_key, nonce);
        let plaintext = cipher.decrypt(ciphertext).unwrap();

        let mut decompressor = ZlibWriter::new(Vec::new(), Compression::default());
        decompressor.write_all(&plaintext).unwrap();

        String::from_utf8(decompressor.finish().unwrap()).unwrap()
    }

    pub fn encrypt_symmetric_key(&self) -> String {
        let encrypted_key = self.rsa_private_key.public_encrypt(&self.aes_key, Padding::PKCS1_OAEP).unwrap();
        encode(&encrypted_key)
    }

    pub fn decrypt_symmetric_key(&mut self, encrypted_key: &str) -> String {
        let encrypted_key_bytes = decode(encrypted_key).unwrap();
        let decrypted_key = self.rsa_private_key.private_decrypt(&encrypted_key_bytes, Padding::PKCS1_OAEP).unwrap();
        self.aes_key = decrypted_key;
        encode(&self.aes_key)
    }

    pub fn encrypt_metadata(&self, metadata: &str) -> String {
        let metadata_bytes = metadata.as_bytes();
        let nonce = rand_bytes(NONCE_SIZE).unwrap();
        let mut cipher = Cipher::new(Cipher::aes_256_gcm(), &self.aes_key, &nonce);
        let encrypted_metadata = cipher.encrypt(metadata_bytes).unwrap();
        encode(&encrypted_metadata)
    }

    pub fn decrypt_metadata(&self, encrypted_metadata: &str) -> String {
        let encrypted_metadata_bytes = decode(encrypted_metadata).unwrap();
        let nonce = rand_bytes(NONCE_SIZE).unwrap();
        let mut cipher = Cipher::new(Cipher::aes_256_gcm(), &self.aes_key, &nonce);
        let decrypted_metadata = cipher.decrypt(&encrypted_metadata_bytes).unwrap();
        String::from_utf8(decrypted_metadata).unwrap()
    }

    pub fn handshake(&mut self, peer_public_key_pem: &[u8]) -> String {
        let shared_secret = self.derive_shared_secret(peer_public_key_pem);
        let public_key = self.get_rsa_public_key();
        format!("Shared Secret: {}, Public Key: {}", shared_secret, encode(&public_key))
    }

    pub fn secure_message_exchange(&mut self, peer_public_key_pem: &[u8], message: &str) -> String {
        let handshake_data = self.handshake(peer_public_key_pem);
        let signed_message = self.sign_message(message);
        let encrypted_message = self.encrypt(message);
        format!("Handshake: {}, Signed Message: {}, Encrypted Message: {}", handshake_data, signed_message, encrypted_message)
    }

    pub fn authenticate_peer(&self, peer_public_key_pem: &[u8], signed_message: &str) -> bool {
        self.verify_signature(signed_message, &encode(peer_public_key_pem))
    }
}
