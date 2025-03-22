#ifndef SWIFTCRYPT_H
#define SWIFTCRYPT_H

#include <iostream>
#include <vector>
#include <string>
#include <fstream>
#include <sstream>
#include <openssl/rand.h>

#define BLOCK_SIZE 128 // Example block size, you can modify as per requirement
#define KEY_SIZE 1024

class SwiftCrypt {
public:
    // Constructor to initialize keys and IVs
    SwiftCrypt(const std::vector<uint8_t>& key, const std::vector<uint8_t>& iv_forward, const std::vector<uint8_t>& iv_backward);
    
    // Encrypt and Decrypt functions for file and text
    void encrypt_file(const std::string& input_file, const std::string& output_file);
    void decrypt_file(const std::string& input_file, const std::string& output_file);
    
    std::string encrypt_text(const std::string& plaintext);
    std::string decrypt_text(const std::string& ciphertext);
    
private:
    std::vector<uint8_t> key;
    std::vector<uint8_t> iv_forward;
    std::vector<uint8_t> iv_backward;
    
    // Internal helper functions
    void generate_round_keys();
    std::vector<uint8_t> xor_blocks(const std::vector<uint8_t>& block1, const std::vector<uint8_t>& block2);
    std::vector<uint8_t> encrypt_block(const std::vector<uint8_t>& block);
    std::vector<uint8_t> decrypt_block(const std::vector<uint8_t>& block);
    
    // S-Box and inverse S-Box functions
    std::vector<uint8_t> sbox(const std::vector<uint8_t>& input);
    std::vector<uint8_t> inverse_sbox(const std::vector<uint8_t>& input);
    
    // Key expansion and RCON (Round Constants)
    void expand_key();
    std::vector<uint8_t> apply_rcon(const std::vector<uint8_t>& key, int round);
    
    // Encryption/Decryption logic with chaining and garbling effects
    void chaining_and_garbling(std::vector<uint8_t>& block, bool is_encryption);
    void print_hex(const std::vector<uint8_t>& data);
    
    // Utility functions for file reading and writing
    void read_file(const std::string& file_name, std::vector<uint8_t>& data);
    void write_file(const std::string& file_name, const std::vector<uint8_t>& data);
};

#endif
