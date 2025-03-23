use openssl::rsa::{Rsa, Padding};
use openssl::ec::{EcKey, EcGroup};
use openssl::ssl::SslMethod;
use openssl::symm::{Cipher, Crypter, Mode};
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::dh::Dh;
use openssl::bn::BigNum;
use std::time::{SystemTime, UNIX_EPOCH};
use std::io::{Read, Write};
use serde::{Serialize, Deserialize};
use serde_json;
use std::collections::HashMap;
use zlib::deflate;
use std::fs;
use std::path::Path;

const AES_KEY_SIZE: usize = 32; // 256-bit
const HMAC_KEY_SIZE: usize = 32;
const NONCE_SIZE: usize = 12;
const RSA_KEY_SIZE: usize = 4096;
const TIMESTAMP_TOLERANCE: u64 = 30; // Seconds for replay attack protection

pub struct Encryption {
    rsa_private_key: Rsa<openssl::rsa::Private>,
    rsa_public_key: Rsa<openssl::rsa::Public>,
    ephemeral_ecdh_private_key: Option<EcKey<openssl::pkey::Private>>,
    ephemeral_ecdh_public_key: Option<EcKey<openssl::pkey::Public>>,
    shared_secret: Option<Vec<u8>>,
    aes_key: Option<Vec<u8>>,
    hmac_key: Option<Vec<u8>>,
}

impl Encryption {
    pub fn new() -> Self {
        let rsa_private_key = Rsa::generate(RSA_KEY_SIZE).expect("Failed to generate RSA key");
        let rsa_public_key = rsa_private_key.public_key().expect("Failed to get public RSA key");
        Encryption {
            rsa_private_key,
            rsa_public_key,
            ephemeral_ecdh_private_key: None,
            ephemeral_ecdh_public_key: None,
            shared_secret: None,
            aes_key: None,
            hmac_key: None,
        }
    }

    pub fn generate_ephemeral_keys(&mut self) {
        let group = EcGroup::from_curve_name(openssl::nid::Nid::SECP384R1).expect("Invalid curve");
        let private_key = EcKey::generate(&group).expect("Failed to generate ephemeral key");
        self.ephemeral_ecdh_private_key = Some(private_key.clone());
        self.ephemeral_ecdh_public_key = Some(private_key);
    }

    pub fn derive_shared_secret(&mut self, peer_public_key_pem: &[u8]) -> String {
        self.generate_ephemeral_keys();
        let peer_public_key = EcKey::public_key_from_pem(peer_public_key_pem).expect("Failed to load peer's public key");
        let shared_secret = self.ephemeral_ecdh_private_key.as_ref().unwrap().agree(&peer_public_key).expect("Failed to compute shared secret");

        // Deriving AES and HMAC keys using HKDF (we'll use SHA256)
        let hkdf = openssl::kdf::Hkdf::new(MessageDigest::sha256(), &shared_secret);
        let key_material = hkdf.expand(&[], AES_KEY_SIZE + HMAC_KEY_SIZE).expect("Failed to derive keys");

        self.aes_key = Some(key_material[..AES_KEY_SIZE].to_vec());
        self.hmac_key = Some(key_material[AES_KEY_SIZE..].to_vec());

        // Returning base64 encoded AES key
        base64::encode(&self.aes_key.as_ref().unwrap())
    }

    pub fn sign_message(&self, message: &str) -> String {
        let signature = self.rsa_private_key.sign_oaep(MessageDigest::sha256(), message.as_bytes()).expect("Failed to sign message");
        base64::encode(&signature)
    }

    pub fn verify_signature(&self, message: &str, signature: &str) -> bool {
        let signature_bytes = base64::decode(signature).expect("Failed to decode signature");
        self.rsa_public_key.verify_oaep(MessageDigest::sha256(), message.as_bytes(), &signature_bytes).is_ok()
    }

    pub fn encrypt(&self, plaintext: &str) -> String {
        let compressed_data = deflate(plaintext.as_bytes());

        let nonce: Vec<u8> = openssl::rand::rand_bytes(NONCE_SIZE).expect("Failed to generate nonce");
        let cipher = Cipher::aes_256_gcm();
        let mut encryptor = Crypter::new(cipher, Mode::Encrypt, &self.aes_key.as_ref().unwrap(), Some(&nonce)).expect("Failed to create encryptor");

        let mut ciphertext = vec![0; compressed_data.len() + cipher.block_size()];
        let len = encryptor.update(&compressed_data, &mut ciphertext).expect("Failed to encrypt");
        let final_len = encryptor.finalize(&mut ciphertext[len..]).expect("Failed to finalize encryption");

        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).expect("Time went backwards").as_secs();

        let mac = openssl::hmac::Hmac::new(MessageDigest::sha256(), &self.hmac_key.as_ref().unwrap()).expect("Failed to create HMAC");
        let mac = mac.digest(&ciphertext).expect("Failed to compute HMAC");

        base64::encode([&nonce, &mac, &timestamp.to_be_bytes(), &ciphertext].concat())
    }

    pub fn decrypt(&self, encrypted_data: &str) -> String {
        let data = base64::decode(encrypted_data).expect("Failed to decode encrypted data");

        let nonce = &data[..NONCE_SIZE];
        let mac = &data[NONCE_SIZE..NONCE_SIZE + 32];
        let timestamp = u64::from_be_bytes(data[NONCE_SIZE + 32..NONCE_SIZE + 40].try_into().expect("Invalid timestamp"));
        let ciphertext = &data[NONCE_SIZE + 40..];

        if timestamp + TIMESTAMP_TOLERANCE < SystemTime::now().duration_since(UNIX_EPOCH).expect("Time went backwards").as_secs() {
            panic!("Replay attack detected!");
        }

        let expected_mac = openssl::hmac::Hmac::new(MessageDigest::sha256(), &self.hmac_key.as_ref().unwrap()).expect("Failed to create HMAC");
        let expected_mac = expected_mac.digest(ciphertext).expect("Failed to compute expected HMAC");

        if expected_mac != mac {
            panic!("Data integrity compromised!");
        }

        let cipher = Cipher::aes_256_gcm();
        let mut decryptor = Crypter::new(cipher, Mode::Decrypt, &self.aes_key.as_ref().unwrap(), Some(&nonce)).expect("Failed to create decryptor");

        let mut decrypted_data = vec![0; ciphertext.len() + cipher.block_size()];
        let len = decryptor.update(ciphertext, &mut decrypted_data).expect("Failed to decrypt");
        let final_len = decryptor.finalize(&mut decrypted_data[len..]).expect("Failed to finalize decryption");

        String::from_utf8_lossy(&decrypted_data[..len + final_len]).into_owned()
    }

    // File encryption
    pub fn encrypt_file(&self, input_file_path: &str, output_file_path: &str) {
        let file_data = fs::read(input_file_path).expect("Failed to read file");
        let compressed_data = deflate(&file_data);

        let nonce = openssl::rand::rand_bytes(NONCE_SIZE).expect("Failed to generate nonce");

        let cipher = Cipher::aes_256_gcm();
        let mut encryptor = Crypter::new(cipher, Mode::Encrypt, &self.aes_key.as_ref().unwrap(), Some(&nonce)).expect("Failed to create encryptor");

        let mut ciphertext = vec![0; compressed_data.len() + cipher.block_size()];
        let len = encryptor.update(&compressed_data, &mut ciphertext).expect("Failed to encrypt");
        let final_len = encryptor.finalize(&mut ciphertext[len..]).expect("Failed to finalize encryption");

        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).expect("Time went backwards").as_secs();

        let mac = openssl::hmac::Hmac::new(MessageDigest::sha256(), &self.hmac_key.as_ref().unwrap()).expect("Failed to create HMAC");
        let mac = mac.digest(&ciphertext).expect("Failed to compute HMAC");

        let mut output_data = vec![];
        output_data.extend_from_slice(&nonce);
        output_data.extend_from_slice(&mac);
        output_data.extend_from_slice(&timestamp.to_be_bytes());
        output_data.extend_from_slice(&ciphertext);

        fs::write(output_file_path, output_data).expect("Failed to write to output file");
    }

    // File decryption
    pub fn decrypt_file(&self, input_file_path: &str, output_file_path: &str) {
        let file_data = fs::read(input_file_path).expect("Failed to read file");

        let nonce = &file_data[..NONCE_SIZE];
        let mac = &file_data[NONCE_SIZE..NONCE_SIZE + 32];
        let timestamp = u64::from_be_bytes(file_data[NONCE_SIZE + 32..NONCE_SIZE + 40].try_into().expect("Invalid timestamp"));
        let ciphertext = &file_data[NONCE_SIZE + 40..];

        if timestamp + TIMESTAMP_TOLERANCE < SystemTime::now().duration_since(UNIX_EPOCH).expect("Time went backwards").as_secs() {
            panic!("Replay attack detected!");
        }

        let expected_mac = openssl::hmac::Hmac::new(MessageDigest::sha256(), &self.hmac_key.as_ref().unwrap()).expect("Failed to create HMAC");
        let expected_mac = expected_mac.digest(ciphertext).expect("Failed to compute expected HMAC");

        if expected_mac != mac {
            panic!("Data integrity compromised!");
        }

        let cipher = Cipher::aes_256_gcm();
        let mut decryptor = Crypter::new(cipher, Mode::Decrypt, &self.aes_key.as_ref().unwrap(), Some(&nonce)).expect("Failed to create decryptor");

        let mut decrypted_data = vec![0; ciphertext.len() + cipher.block_size()];
        let len = decryptor.update(ciphertext, &mut decrypted_data).expect("Failed to decrypt");
        let final_len = decryptor.finalize(&mut decrypted_data[len..]).expect("Failed to finalize decryption");

        fs::write(output_file_path, decrypted_data[..len + final_len].to_vec()).expect("Failed to write to output file");
    }
}

fn main() {
    let encryption = Encryption::new();

    // Use your encryption methods here, for example:
    let shared_secret = encryption.derive_shared_secret(b"peer_public_key_pem");
    println!("Shared secret: {}", shared_secret);

    // Encrypt and decrypt a file
    encryption.encrypt_file("input.txt", "encrypted_file.txt");
    encryption.decrypt_file("encrypted_file.txt", "decrypted_file.txt");
}
