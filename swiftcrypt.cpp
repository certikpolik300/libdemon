#include "swiftcrypt.h"
#include <cstring>
#include <openssl/hmac.h>

// S-Box and Inverse S-Box: You must define a secure, unique S-box (this is an example).
uint8_t SBox[256] = { /* Define custom, secure S-box values */ };
uint8_t InvSBox[256] = { /* Define inverse S-box values */ };

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
