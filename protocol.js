const crypto = require('crypto');
const elliptic = require('elliptic');
const forge = require('node-forge');
const zlib = require('zlib');

// Constants
const AES_KEY_SIZE = 32; // 256-bit
const HMAC_KEY_SIZE = 32;
const NONCE_SIZE = 12;
const RSA_KEY_SIZE = 4096;
const TIMESTAMP_TOLERANCE = 30; // Seconds for replay attack protection

class Encryption {
    constructor() {
        // ECDH (Elliptic Curve Diffie-Hellman) Key Exchange
        this.ecdh = new elliptic.ec('p384');
        this.ecdhPrivateKey = this.ecdh.genKeyPair();
        this.ecdhPublicKey = this.ecdhPrivateKey.getPublic();

        // RSA (4096-bit RSA keys)
        this.rsa = forge.pki.rsa;
        this.rsaPrivateKey = this.rsa.generateKeyPair(RSA_KEY_SIZE);
        this.rsaPublicKey = this.rsaPrivateKey.publicKey;

        this.sharedSecret = null;
    }

    // Get the ECDH public key (PEM encoded)
    getEcdhPublicKey() {
        return this.ecdhPublicKey.encode('pem');
    }

    // Get the RSA public key (PEM encoded)
    getRsaPublicKey() {
        return forge.pki.publicKeyToPem(this.rsaPublicKey);
    }

    // Derive shared secret using ECDH
    deriveSharedSecret(peerPublicKeyPem) {
        const peerPublicKey = this.ecdh.keyFromPublic(peerPublicKeyPem, 'pem');
        const sharedSecret = this.ecdhPrivateKey.derive(peerPublicKey.getPublic());
        
        // Use HKDF to derive AES and HMAC keys
        const hkdf = crypto.createHmac('sha256', sharedSecret.toString(16));
        hkdf.update('E2EE Key Derivation');
        const keyMaterial = hkdf.digest();

        this.aesKey = keyMaterial.slice(0, AES_KEY_SIZE);
        this.hmacKey = keyMaterial.slice(AES_KEY_SIZE, AES_KEY_SIZE + HMAC_KEY_SIZE);

        return this.aesKey.toString('base64');
    }

    // Sign the message using RSA
    signMessage(message) {
        const md = forge.md.sha256.create();
        md.update(message);
        const signature = this.rsaPrivateKey.sign(md);
        return forge.util.encode64(signature);
    }

    // Verify the signature using RSA
    verifySignature(message, signature) {
        const md = forge.md.sha256.create();
        md.update(message);
        const decodedSignature = forge.util.decode64(signature);
        return this.rsaPublicKey.verify(md.digest().bytes(), decodedSignature);
    }

    // Encrypt the plaintext message using AES-256-GCM
    encrypt(plaintext) {
        const compressedData = zlib.deflateSync(plaintext);
        const nonce = crypto.randomBytes(NONCE_SIZE);
        const cipher = crypto.createCipheriv('aes-256-gcm', this.aesKey, nonce);
        const ciphertext = Buffer.concat([cipher.update(compressedData), cipher.final()]);
        const tag = cipher.getAuthTag();

        // Create HMAC for integrity
        const mac = crypto.createHmac('sha256', this.hmacKey).update(ciphertext).digest();

        // Include timestamp for replay protection
        const timestamp = Buffer.alloc(8);
        timestamp.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 1000)), 0);

        return Buffer.concat([nonce, tag, timestamp, mac, ciphertext]).toString('base64');
    }

    // Decrypt the encrypted data using AES-256-GCM
    decrypt(encryptedData) {
        const data = Buffer.from(encryptedData, 'base64');
        const nonce = data.slice(0, NONCE_SIZE);
        const tag = data.slice(NONCE_SIZE, NONCE_SIZE + 16);
        const timestamp = data.slice(NONCE_SIZE + 16, NONCE_SIZE + 24);
        const mac = data.slice(NONCE_SIZE + 24, NONCE_SIZE + 56);
        const ciphertext = data.slice(NONCE_SIZE + 56);

        // Replay protection: check timestamp
        if (Math.abs(Date.now() / 1000 - timestamp.readBigUInt64BE(0)) > TIMESTAMP_TOLERANCE) {
            throw new Error('Replay attack detected!');
        }

        // Verify HMAC
        const expectedMac = crypto.createHmac('sha256', this.hmacKey).update(ciphertext).digest();
        if (!crypto.timingSafeEqual(mac, expectedMac)) {
            throw new Error('Data integrity compromised!');
        }

        const decipher = crypto.createDecipheriv('aes-256-gcm', this.aesKey, nonce);
        decipher.setAuthTag(tag);
        const decryptedData = Buffer.concat([decipher.update(ciphertext), decipher.final()]);

        // Decompress the data after decryption
        return zlib.inflateSync(decryptedData).toString();
    }

    // Encrypt the symmetric AES key using RSA
    encryptSymmetricKey() {
        return forge.util.encode64(this.rsaPublicKey.encrypt(this.aesKey));
    }

    // Decrypt the symmetric AES key using RSA
    decryptSymmetricKey(encryptedKey) {
        const decodedKey = forge.util.decode64(encryptedKey);
        this.aesKey = this.rsaPrivateKey.decrypt(decodedKey);
        return this.aesKey.toString('base64');
    }
}

module.exports = Encryption;
