#ifndef SWIFT_CRYPT_H
#define SWIFT_CRYPT_H

#include <vector>
#include <string>
#include <cstdint>

class SwiftCrypt {
public:
    SwiftCrypt(const std::vector<uint8_t>& key, const std::vector<uint8_t>& ivForward, const std::vector<uint8_t>& ivBackward);
    std::vector<uint8_t> encrypt(const std::vector<uint8_t>& plaintext);
    std::vector<uint8_t> decrypt(const std::vector<uint8_t>& ciphertext);
    void encrypt_file(const std::string& inputFile, const std::string& outputFile);
    void decrypt_file(const std::string& inputFile, const std::string& outputFile);
    std::string encrypt_text(const std::string& text);
    std::string decrypt_text(const std::string& cipherText);

private:
    std::vector<uint8_t> key;
    std::vector<uint8_t> ivForward;
    std::vector<uint8_t> ivBackward;
    static const size_t blockSize = 16;
    static const size_t keySize = 128;
    static const std::vector<uint8_t> sBox;
    static const std::vector<uint8_t> invSBox;
    static const std::vector<uint8_t> rCon;

    void keyExpansion();
    void addRoundKey(std::vector<uint8_t>& state, const std::vector<uint8_t>& roundKey);
    void subBytes(std::vector<uint8_t>& state);
    void invSubBytes(std::vector<uint8_t>& state);
    void shiftRows(std::vector<uint8_t>& state);
    void invShiftRows(std::vector<uint8_t>& state);
    void mixColumns(std::vector<uint8_t>& state);
    void invMixColumns(std::vector<uint8_t>& state);
    std::vector<uint8_t> xorVectors(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b);
    void printHex(const std::vector<uint8_t>& data);

    std::vector<std::vector<uint8_t>> roundKeys;
};

#endif // SWIFT_CRYPT_H
