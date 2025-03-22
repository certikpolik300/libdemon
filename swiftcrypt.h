#ifndef SWIFTCrypt_H
#define SWIFTCrypt_H

#include <vector>
#include <string>
#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>

class SwiftCrypt {
public:
    // Constructor with 1024-bit key
    SwiftCrypt(const std::vector<uint8_t>& key);
    ~SwiftCrypt();

    // Encryption and Decryption Functions
    std::vector<uint8_t> encrypt_text(const std::vector<uint8_t>& plaintext);
    std::vector<uint8_t> decrypt_text(const std::vector<uint8_t>& ciphertext);
    void encrypt_file(const std::string& input_filename, const std::string& output_filename);
    void decrypt_file(const std::string& input_filename, const std::string& output_filename);

private:
    // Helper functions
    void generate_round_keys();
    std::vector<uint8_t> apply_round(const std::vector<uint8_t>& data, int round);
    std::vector<uint8_t> xor_blocks(const std::vector<uint8_t>& block1, const std::vector<uint8_t>& block2);
    void print_hex(const std::vector<uint8_t>& data);
    std::vector<uint8_t> garble_effect(const std::vector<uint8_t>& data);

    // S-box and Inverse S-box (custom, static, not generated)
    static const std::vector<uint8_t> S_BOX;
    static const std::vector<uint8_t> INVERSE_S_BOX;

    // Round constants (RCON)
    static const std::vector<uint8_t> RCON;

    // Key and Round keys
    std::vector<uint8_t> key_;
    std::vector<std::vector<uint8_t>> round_keys_;
    
    // IVs for encryption and decryption
    std::vector<uint8_t> iv_forward_;
    std::vector<uint8_t> iv_backward_;
};

#endif // SWIFTCrypt_H
