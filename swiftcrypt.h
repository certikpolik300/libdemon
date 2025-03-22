#ifndef SWIFTCrypt_H
#define SWIFTCrypt_H

#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <openssl/rand.h>
#include <openssl/sha.h>

#define BLOCK_SIZE 128 // 128 bits block size
#define KEY_SIZE 1024 // 1024 bits key size
#define MAC_SIZE 32 // HMAC-SHA256 size

// S-Box and Inverse S-Box (unique S-box must be defined)
extern uint8_t SBox[256];
extern uint8_t InvSBox[256];

// Round Constants (RCON) for key expansion
extern uint32_t RCON[10];

class SwiftCrypt {
public:
    SwiftCrypt();
    ~SwiftCrypt();

    // Key generation function
    void generateKey(uint8_t* key);

    // Encryption and Decryption functions
    void encrypt(const uint8_t* input, uint8_t* output, uint8_t* iv_forward, uint8_t* iv_backward, uint8_t* mac);
    void decrypt(const uint8_t* input, uint8_t* output, uint8_t* iv_forward, uint8_t* iv_backward, uint8_t* mac);

    // File encryption/decryption
    bool encryptFile(const std::string& inputFile, const std::string& outputFile, uint8_t* iv_forward, uint8_t* iv_backward, uint8_t* mac);
    bool decryptFile(const std::string& inputFile, const std::string& outputFile, uint8_t* iv_forward, uint8_t* iv_backward, uint8_t* mac);

    // Text encryption/decryption
    bool encryptText(const std::string& inputText, std::string& outputText, uint8_t* iv_forward, uint8_t* iv_backward, uint8_t* mac);
    bool decryptText(const std::string& inputText, std::string& outputText, uint8_t* iv_forward, uint8_t* iv_backward, uint8_t* mac);

private:
    // Helper functions for key expansion and operations
    void applySBox(uint8_t* block);
    void applyInvSBox(uint8_t* block);
    void xorBlocks(uint8_t* block, uint8_t* iv);
    void garble(uint8_t* block);
    void padBlock(uint8_t* block, size_t& blockSize);
    void unpadBlock(uint8_t* block, size_t& blockSize);

    // MAC generation function (HMAC-SHA256)
    void generateMAC(const uint8_t* data, size_t dataSize, uint8_t* mac);

    // Round key expansion
    void keyExpansion(const uint8_t* key, uint8_t* roundKeys);

    // File reading and writing
    bool readFile(const std::string& filename, std::vector<uint8_t>& buffer);
    bool writeFile(const std::string& filename, const std::vector<uint8_t>& buffer);
};

#endif // SWIFTCrypt_H
