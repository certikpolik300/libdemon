const crypto = require('crypto');
const zlib = require('zlib');

const AES_KEY_SIZE = 32;
const HMAC_KEY_SIZE = 32;
const NONCE_SIZE = 12;
const RSA_KEY_SIZE = 4096;
const TIMESTAMP_TOLERANCE = 30;

class E2EE {
    constructor() {
        this.ecdh = crypto.createECDH('secp384r1');
        this.ecdh.generateKeys();
        this.rsa = crypto.generateKeyPairSync('rsa', {
            modulusLength: RSA_KEY_SIZE,
            publicKeyEncoding: { type: 'spki', format: 'pem' },
            privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
        });
        this.sharedSecret = null;
    }

    getECDHPublicKey() {
        return this.ecdh.getPublicKey('base64');
    }

    getRSAPublicKey() {
        return this.rsa.publicKey;
    }

    deriveSharedSecret(peerPublicKey) {
        const sharedSecret = this.ecdh.computeSecret(Buffer.from(peerPublicKey, 'base64'));
        const kdf = crypto.createHmac('sha256', sharedSecret);
        let keyMaterial = kdf.digest();
        this.aesKey = keyMaterial.slice(0, AES_KEY_SIZE);
        this.hmacKey = keyMaterial.slice(AES_KEY_SIZE, AES_KEY_SIZE + HMAC_KEY_SIZE);
        return this.aesKey.toString('base64');
    }

    signMessage(message) {
        const sign = crypto.createSign('SHA256');
        sign.update(message);
        sign.end();
        return sign.sign(this.rsa.privateKey, 'base64');
    }

    verifySignature(message, signature) {
        const verify = crypto.createVerify('SHA256');
        verify.update(message);
        verify.end();
        return verify.verify(this.rsa.publicKey, Buffer.from(signature, 'base64'));
    }

    encrypt(plaintext) {
        const compressedData = zlib.deflateSync(plaintext);
        const nonce = crypto.randomBytes(NONCE_SIZE);
        const cipher = crypto.createCipheriv('aes-256-gcm', this.aesKey, nonce);
        const ciphertext = Buffer.concat([cipher.update(compressedData), cipher.final()]);
        const tag = cipher.getAuthTag();
        const mac = crypto.createHmac('sha256', this.hmacKey).update(ciphertext).digest();
        const timestamp = Buffer.alloc(8);
        timestamp.writeUInt32BE(Math.floor(Date.now() / 1000), 0);
        return Buffer.concat([nonce, tag, timestamp, mac, ciphertext]).toString('base64');
    }

    decrypt(encryptedData) {
        const data = Buffer.from(encryptedData, 'base64');
        const nonce = data.slice(0, NONCE_SIZE);
        const tag = data.slice(NONCE_SIZE, NONCE_SIZE + 16);
        const timestamp = data.slice(NONCE_SIZE + 16, NONCE_SIZE + 24).readUInt32BE(0);
        const mac = data.slice(NONCE_SIZE + 24, NONCE_SIZE + 56);
        const ciphertext = data.slice(NONCE_SIZE + 56);
        if (Math.abs(Date.now() / 1000 - timestamp) > TIMESTAMP_TOLERANCE) {
            throw new Error('Replay attack detected!');
        }
        const expectedMac = crypto.createHmac('sha256', this.hmacKey).update(ciphertext).digest();
        if (!crypto.timingSafeEqual(mac, expectedMac)) {
            throw new Error('Data integrity compromised!');
        }
        const decipher = crypto.createDecipheriv('aes-256-gcm', this.aesKey, nonce);
        decipher.setAuthTag(tag);
        const decryptedData = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
        return zlib.inflateSync(decryptedData).toString();
    }
}

module.exports = E2EE;
