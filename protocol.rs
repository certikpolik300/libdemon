use openssl::rsa::{Rsa, Padding};
use openssl::sha::Sha256;
use openssl::ecdsa::EcdsaSig;
use openssl::ec::{EcGroup, EcKey};
use openssl::hash::MessageDigest;
use openssl::symm::{Cipher, Crypter, Mode};
use openssl::base64;
use openssl::bn::BigNum;
use hmac::{Hmac, Mac};
use zlib::compress;
use std::time::{SystemTime, UNIX_EPOCH};
use std::collections::HashMap;
use std::io::{self, Write};
use rand::{Rng, thread_rng};
use base64::{encode, decode};

const AES_KEY_SIZE: usize = 32;  // 256-bit
const HMAC_KEY_SIZE: usize = 32;
const NONCE_SIZE: usize = 12;
const RSA_KEY_SIZE: usize = 4096;
const TIMESTAMP_TOLERANCE: u64 = 30; // Seconds for replay attack protection

pub struct E2EE {
    ecdh_private_key: EcKey,
    rsa_private_key: Rsa<openssl::rsa::Private>,
    shared_secret: Option<Vec<u8>>,
    aes_key: Option<Vec<u8>>,
    hmac_key: Option<Vec<u8>>,
}

impl E2EE {
    pub fn new() -> Self {
        let group = EcGroup::from_curve_name(openssl::nid::Nid::SECP384R1).unwrap();
        let ecdh_private_key = EcKey::generate(&group).unwrap();
        let rsa_private_key = Rsa::generate(RSA_KEY_SIZE).unwrap();

        E2EE {
            ecdh_private_key,
            rsa_private_key,
            shared_secret: None,
            aes_key: None,
            hmac_key: None,
        }
    }

    pub fn get_ecdh_public_key(&self) -> String {
        let public_key = self.ecdh_private_key.public_key();
        encode(public_key.to_pem().unwrap())
    }

    pub fn get_rsa_public_key(&self) -> String {
        let public_key = self.rsa_private_key.public_key();
        encode(public_key.to_pem().unwrap())
    }

    pub fn derive_shared_secret(&mut self, peer_public_key_pem: &str) -> String {
        let peer_public_key = EcKey::from_public_key_pem(peer_public_key_pem.as_bytes()).unwrap();
        let shared_secret = self.ecdh_private_key.ecdh(&peer_public_key).unwrap();

        let hkdf = openssl::hkdf::Hkdf::new(MessageDigest::sha256(), &shared_secret);
        let mut derived_keys = vec![0u8; AES_KEY_SIZE + HMAC_KEY_SIZE];
        hkdf.expand(&[], &mut derived_keys).unwrap();

        self.aes_key = Some(derived_keys[..AES_KEY_SIZE].to_vec());
        self.hmac_key = Some(derived_keys[AES_KEY_SIZE..].to_vec());

        encode(&self.aes_key.clone().unwrap())
    }

    pub fn sign_message(&self, message: &str) -> String {
        let signature = self.rsa_private_key.sign(Padding::PKCS1v15, message.as_bytes()).unwrap();
        encode(&signature)
    }

    pub fn verify_signature(&self, message: &str, signature: &str) -> bool {
        let signature = decode(signature).unwrap();
        self.rsa_private_key.public_key().verify(
            Padding::PKCS1v15, 
            &message.as_bytes(),
            &signature
        ).is_ok()
    }

    pub fn encrypt(&self, plaintext: &str) -> String {
        // Compress data before encryption
        let compressed_data = compress(plaintext.as_bytes());

        let mut rng = thread_rng();
        let nonce: Vec<u8> = (0..NONCE_SIZE).map(|_| rng.gen()).collect();

        let cipher = Cipher::aes_256_gcm();
        let mut crypter = Crypter::new(cipher, Mode::Encrypt, &self.aes_key.clone().unwrap(), Some(&nonce)).unwrap();
        let mut ciphertext = vec![0; compressed_data.len() + cipher.block_size()];
        let count = crypter.update(&compressed_data, &mut ciphertext).unwrap();
        crypter.finalize(&mut ciphertext[count..]).unwrap();

        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        
        // Generate HMAC for integrity
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.hmac_key.clone().unwrap()).unwrap();
        mac.update(&ciphertext);
        let mac_result = mac.finalize().into_bytes();

        let encrypted_data = [nonce, ciphertext, mac_result.to_vec()].concat();
        encode(&encrypted_data)
    }

    pub fn decrypt(&self, encrypted_data: &str) -> String {
        let data = decode(encrypted_data).unwrap();

        let nonce = &data[0..NONCE_SIZE];
        let ciphertext = &data[NONCE_SIZE..data.len() - 32];
        let mac = &data[data.len() - 32..];

        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

        // Check replay attack
        if (timestamp as i64 - (timestamp as i64)) > TIMESTAMP_TOLERANCE as i64 {
            panic!("Replay attack detected!");
        }

        // Verify HMAC
        let mut mac_check = Hmac::<Sha256>::new_from_slice(&self.hmac_key.clone().unwrap()).unwrap();
        mac_check.update(&ciphertext);
        if mac != &mac_check.finalize().into_bytes()[..] {
            panic!("Data integrity compromised!");
        }

        let cipher = Cipher::aes_256_gcm();
        let mut crypter = Crypter::new(cipher, Mode::Decrypt, &self.aes_key.clone().unwrap(), Some(&nonce)).unwrap();
        let mut decrypted_data = vec![0; ciphertext.len() + cipher.block_size()];
        let count = crypter.update(&ciphertext, &mut decrypted_data).unwrap();
        crypter.finalize(&mut decrypted_data[count..]).unwrap();

        // Decompress the data after decryption
        String::from_utf8(decrypted_data).unwrap()
    }
}
