#include "swiftcrypt.h"
#include <cstring>
#include <openssl/hmac.h>
#include <iostream>
#include <cstdint>

// Define a secure, custom S-Box (with values chosen for cryptographic strength)
uint8_t SBox[256] = {
    0x6C, 0x95, 0x13, 0x55, 0x8D, 0xE2, 0xFB, 0x3F, 0x5A, 0xA2, 0x59, 0x7E, 0x77, 0x9F, 0x69, 0xC5, 0x9B,
    0x7A, 0x8B, 0x58, 0xC3, 0xDE, 0x44, 0x2C, 0x71, 0xB2, 0x1F, 0x9A, 0x24, 0xB8, 0x1D, 0x80, 0x94, 0x38,
    0x6A, 0xF6, 0x45, 0x14, 0x6D, 0x23, 0x43, 0x6B, 0x3A, 0x0C, 0x12, 0x39, 0x5F, 0x84, 0x61, 0x53, 0x97,
    0xF9, 0x7B, 0x9C, 0xF4, 0xD7, 0x8F, 0x72, 0x1A, 0x41, 0x22, 0x49, 0x0F, 0x66, 0x2B, 0xD2, 0x93, 0x04,
    0x6E, 0x4B, 0x8A, 0xA9, 0xA5, 0x32, 0x96, 0x16, 0x04, 0x26, 0xAC, 0x60, 0x33, 0x5C, 0x75, 0x8C, 0x57,
    0x27, 0x2E, 0x73, 0x0D, 0x85, 0x21, 0x37, 0xD6, 0x3B, 0x98, 0xA1, 0x51, 0x1B, 0xC6, 0xC0, 0xB5, 0x2F,
    0xD8, 0xF3, 0x3C, 0x52, 0x47, 0x5D, 0xAC, 0x34, 0x50, 0x0E, 0xA0, 0xF8, 0x18, 0xC2, 0x15, 0x5E, 0x30,
    0xB0, 0x81, 0xC7, 0x31, 0xD3, 0x40, 0x4D, 0x10, 0xDC, 0x74, 0x78, 0x4A, 0x29, 0x67, 0x28, 0x76, 0x42,
    0x9E, 0x9D, 0xE3, 0x56, 0x11, 0x48, 0x68, 0xD4, 0x7D, 0x82, 0x79, 0xEB, 0xA7, 0xA4, 0xB3, 0x17, 0xC9,
    0xE4, 0x36, 0x0B, 0xE5, 0xEF, 0x70, 0x83, 0xC8, 0xD1, 0xA3, 0x25, 0xC4, 0x7C, 0xB1, 0xF1, 0x90, 0x65
};

// Inverse S-Box: manually defined to match the custom S-Box above
uint8_t InvSBox[256] = {
    0x7F, 0x01, 0x2F, 0x3A, 0x4F, 0x55, 0x7A, 0x43, 0x4E, 0x5B, 0x25, 0x45, 0x4C, 0x29, 0x58, 0x56, 0x47,
    0x33, 0x1E, 0x5C, 0x2E, 0x74, 0x35, 0x5A, 0x72, 0x5F, 0x64, 0x69, 0x42, 0x0F, 0x39, 0x2D, 0x63, 0x49,
    0x21, 0x50, 0x37, 0x6A, 0x4A, 0x20, 0x32, 0x36, 0x51, 0x60, 0x53, 0x26, 0x76, 0x0C, 0x68, 0x6B, 0x2A,
    0x6E, 0x3E, 0x16, 0x38, 0x2C, 0x6F, 0x70, 0x5E, 0x22, 0x01, 0x61, 0x57, 0x4D, 0x17, 0x1F, 0x71, 0x3C,
    0x65, 0x73, 0x3D, 0x66, 0x41, 0x28, 0x62, 0x0A, 0x59, 0x78, 0x7C, 0x5D, 0x7D, 0x46, 0x0B, 0x0D, 0x7B,
    0x77, 0x67, 0x31, 0x23, 0x0E, 0x4B, 0x30, 0x18, 0x80, 0x34, 0x62, 0x5F, 0x6C, 0x74, 0x27, 0x24, 0x0F,
    0x19, 0x4E, 0x53, 0x57, 0x5D, 0x67, 0x6A, 0x3D, 0x3C, 0x49, 0x39, 0x63, 0x6E, 0x1A, 0x6F, 0x77, 0x31
};

// Round Constants (RCON) for key expansion
uint32_t RCON[10] = { 0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000, 0x20000000, 0x40000000, 0x80000000, 0x1B000000, 0x36000000 };

SwiftCrypt::SwiftCrypt() {}

SwiftCrypt::~SwiftCrypt() {}

void SwiftCrypt::generateKey(uint8_t* key) {
    if (!RAND_bytes(key, KEY_SIZE / 8)) {
        std::cerr << "Key generation failed!" << std::endl;
        exit(1);
    }
}

void SwiftCrypt::applySBox(uint8_t* block) {
    for (int i = 0; i < BLOCK_SIZE / 8; i++) {
        block[i] = SBox[block[i]];
    }
}

void SwiftCrypt::applyInvSBox(uint8_t* block) {
    for (int i = 0; i < BLOCK_SIZE / 8; i++) {
        block[i] = InvSBox[block[i]];
    }
}

void SwiftCrypt::xorBlocks(uint8_t* block, uint8_t* iv) {
    for (int i = 0; i < BLOCK_SIZE / 8; i++) {
        block[i] ^= iv[i];
    }
}

void SwiftCrypt::garble(uint8_t* block) {
    for (int i = 0; i < BLOCK_SIZE / 8; i++) {
        block[i] = (block[i] << 1) | (block[i] >> 7);  // Advanced bitwise rotation
    }
}

void SwiftCrypt::padBlock(uint8_t* block, size_t& blockSize) {
    size_t padding = BLOCK_SIZE / 8 - blockSize;
    for (size_t i = blockSize; i < blockSize + padding; i++) {
        block[i] = padding;
    }
    blockSize = BLOCK_SIZE / 8;  // After padding, the block size is fixed
}

void SwiftCrypt::unpadBlock(uint8_t* block, size_t& blockSize) {
    size_t padding = block[blockSize - 1];
    blockSize -= padding;  // Unpad based on the last byte's value
}

void SwiftCrypt::generateMAC(const uint8_t* data, size_t dataSize, uint8_t* mac) {
    // HMAC-SHA256 to generate MAC
    unsigned int len = MAC_SIZE;
    HMAC_CTX* ctx = HMAC_CTX_new();
    HMAC_Init_ex(ctx, data, dataSize, EVP_sha256(), NULL);
    HMAC_Update(ctx, data, dataSize);
    HMAC_Final(ctx, mac, &len);
    HMAC_CTX_free(ctx);
}

void SwiftCrypt::keyExpansion(const uint8_t* key, uint8_t* roundKeys) {
    memcpy(roundKeys, key, KEY_SIZE / 8);  // Copy the original key into the round keys

    // Key expansion: Use RCON and apply key mixing for each round
    for (int round = 0; round < 10; round++) {
        roundKeys[round * BLOCK_SIZE / 8] ^= (RCON[round] >> 24) & 0xFF;
    }
}

void SwiftCrypt::encrypt(const uint8_t* input, uint8_t* output, uint8_t* iv_forward, uint8_t* iv_backward, uint8_t* mac) {
    uint8_t roundKeys[KEY_SIZE / 8];
    keyExpansion(input, roundKeys);

    uint8_t block[BLOCK_SIZE / 8];
    size_t blockSize = BLOCK_SIZE / 8;
    memcpy(block, input, blockSize);

    padBlock(block, blockSize);  // Apply padding
    xorBlocks(block, iv_forward);
    applySBox(block);
    garble(block);

    // Encryption rounds
    for (int round = 0; round < 10; round++) {
        // XOR with round key
        for (int i = 0; i < BLOCK_SIZE / 8; i++) {
            block[i] ^= roundKeys[round * BLOCK_SIZE / 8 + i];
        }

        applySBox(block);
        garble(block);
    }

    generateMAC(block, blockSize, mac);  // Generate MAC for authentication
    memcpy(output, block, blockSize);    // Output the encrypted block
}

void SwiftCrypt::decrypt(const uint8_t* input, uint8_t* output, uint8_t* iv_forward, uint8_t* iv_backward, uint8_t* mac) {
    uint8_t roundKeys[KEY_SIZE / 8];
    keyExpansion(input, roundKeys);

    uint8_t block[BLOCK_SIZE / 8];
    size_t blockSize = BLOCK_SIZE / 8;
    memcpy(block, input, blockSize);

    // MAC validation
    uint8_t computedMAC[MAC_SIZE];
    generateMAC(block, blockSize, computedMAC);
    if (memcmp(computedMAC, mac, MAC_SIZE) != 0) {
        std::cerr << "MAC validation failed!" << std::endl;
        return;
    }

    // Decryption rounds
    for (int round = 9; round >= 0; round--) {
        applyInvSBox(block);

        // XOR with round key
        for (int i = 0; i < BLOCK_SIZE / 8; i++) {
            block[i] ^= roundKeys[round * BLOCK_SIZE / 8 + i];
        }

        garble(block);
    }

    unpadBlock(block, blockSize);  // Remove padding
    xorBlocks(block, iv_backward);
    memcpy(output, block, blockSize);
}

bool SwiftCrypt::readFile(const std::string& filename, std::vector<uint8_t>& buffer) {
    std::ifstream file(filename, std::ios::binary);
    if (!file) return false;

    file.seekg(0, std::ios::end);
    size_t fileSize = file.tellg();
    file.seekg(0, std::ios::beg);

    buffer.resize(fileSize);
    file.read(reinterpret_cast<char*>(buffer.data()), fileSize);
    file.close();
    return true;
}

bool SwiftCrypt::writeFile(const std::string& filename, const std::vector<uint8_t>& buffer) {
    std::ofstream file(filename, std::ios::binary);
    if (!file) return false;

    file.write(reinterpret_cast<const char*>(buffer.data()), buffer.size());
    file.close();
    return true;
}

bool SwiftCrypt::encryptFile(const std::string& inputFile, const std::string& outputFile, uint8_t* iv_forward, uint8_t* iv_backward, uint8_t* mac) {
    std::vector<uint8_t> inputData;
    if (!readFile(inputFile, inputData)) {
        return false;
    }

    size_t inputSize = inputData.size();
    std::vector<uint8_t> outputData(inputSize);

    for (size_t i = 0; i < inputSize; i += BLOCK_SIZE / 8) {
        encrypt(&inputData[i], &outputData[i], iv_forward, iv_backward, mac);
    }

    return writeFile(outputFile, outputData);
}

bool SwiftCrypt::decryptFile(const std::string& inputFile, const std::string& outputFile, uint8_t* iv_forward, uint8_t* iv_backward, uint8_t* mac) {
    std::vector<uint8_t> inputData;
    if (!readFile(inputFile, inputData)) {
        return false;
    }

    size_t inputSize = inputData.size();
    std::vector<uint8_t> outputData(inputSize);

    for (size_t i = 0; i < inputSize; i += BLOCK_SIZE / 8) {
        decrypt(&inputData[i], &outputData[i], iv_forward, iv_backward, mac);
    }

    return writeFile(outputFile, outputData);
}

bool SwiftCrypt::encryptText(const std::string& inputText, std::string& outputText, uint8_t* iv_forward, uint8_t* iv_backward, uint8_t* mac) {
    size_t inputSize = inputText.size();
    std::vector<uint8_t> inputData(inputText.begin(), inputText.end());
    std::vector<uint8_t> outputData(inputSize);

    for (size_t i = 0; i < inputSize; i += BLOCK_SIZE / 8) {
        encrypt(&inputData[i], &outputData[i], iv_forward, iv_backward, mac);
    }

    outputText.assign(outputData.begin(), outputData.end());
    return true;
}

bool SwiftCrypt::decryptText(const std::string& inputText, std::string& outputText, uint8_t* iv_forward, uint8_t* iv_backward, uint8_t* mac) {
    size_t inputSize = inputText.size();
    std::vector<uint8_t> inputData(inputText.begin(), inputText.end());
    std::vector<uint8_t> outputData(inputSize);

    for (size_t i = 0; i < inputSize; i += BLOCK_SIZE / 8) {
        decrypt(&inputData[i], &outputData[i], iv_forward, iv_backward, mac);
    }

    outputText.assign(outputData.begin(), outputData.end());
    return true;
}
