#ifndef SWIFTCrypt_H
#define SWIFTCrypt_H

#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <openssl/rand.h>

// Constants for block size and key size
#define BLOCK_SIZE 128 // 128 bits block size
#define KEY_SIZE 1024 // 1024 bits key size

// S-Box and Inverse S-Box (unique S-box must be defined)
extern uint8_t SBox[256];
extern uint8_t InvSBox[256];

// Round constants (RCON) for key expansion
extern uint32_t RCON[10];

// SwiftCrypt class definition
class SwiftCrypt {
public:
    SwiftCrypt();
    ~SwiftCrypt();

    // Key generation function
    void generateKey(uint8_t* key);

    // Encryption/Decryption functions
    void encrypt(const uint8_t* input, uint8_t* output, uint8_t* iv_forward, uint8_t* iv_backward);
    void decrypt(const uint8_t* input, uint8_t* output, uint8_t* iv_forward, uint8_t* iv_backward);

    // File encryption/decryption
    bool encryptFile(const std::string& inputFile, const std::string& outputFile, uint8_t* iv_forward, uint8_t* iv_backward);
    bool decryptFile(const std::string& inputFile, const std::string& outputFile, uint8_t* iv_forward, uint8_t* iv_backward);

    // Text encryption/decryption
    bool encryptText(const std::string& inputText, std::string& outputText, uint8_t* iv_forward, uint8_t* iv_backward);
    bool decryptText(const std::string& inputText, std::string& outputText, uint8_t* iv_forward, uint8_t* iv_backward);

private:
    // Helper functions for key expansion and operations
    void applySBox(uint8_t* block);
    void applyInvSBox(uint8_t* block);
    void xorBlocks(uint8_t* block, uint8_t* iv);
    void garble(uint8_t* block);

    // Encryption and decryption round key expansion
    void keyExpansion(const uint8_t* key, uint8_t* roundKeys);

    // File reading and writing
    bool readFile(const std::string& filename, std::vector<uint8_t>& buffer);
    bool writeFile(const std::string& filename, const std::vector<uint8_t>& buffer);
};

#endif // SWIFTCrypt_H
