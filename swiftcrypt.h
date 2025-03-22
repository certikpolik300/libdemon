#ifndef SWIFT_CRYPT_H
#define SWIFT_CRYPT_H

#include <cstdint>
#include <vector>
#include <string>

class SwiftCrypt {
public:
    SwiftCrypt(const std::vector<uint8_t>& key, const std::vector<uint8_t>& iv_forward, const std::vector<uint8_t>& iv_backward);

    std::vector<uint8_t> encrypt(const std::vector<uint8_t>& plaintext);
    std::vector<uint8_t> decrypt(const std::vector<uint8_t>& ciphertext);

    void encrypt_file(const std::string& input_filename, const std::string& output_filename);
    void decrypt_file(const std::string& input_filename, const std::string& output_filename);

    std::string encrypt_text(const std::string& plaintext);
    std::string decrypt_text(const std::string& ciphertext);

private:
    std::vector<uint8_t> key;
    std::vector<uint8_t> iv_forward;
    std::vector<uint8_t> iv_backward;
    
    static const uint8_t SBOX[256];
    static const uint8_t INV_SBOX[256];
    static const uint32_t RCON[10];

    std::vector<uint8_t> add_round_key(const std::vector<uint8_t>& state, const std::vector<uint8_t>& round_key);
    std::vector<uint8_t> sub_bytes(const std::vector<uint8_t>& state);
    std::vector<uint8_t> inv_sub_bytes(const std::vector<uint8_t>& state);
    std::vector<uint8_t> shift_rows(const std::vector<uint8_t>& state);
    std::vector<uint8_t> inv_shift_rows(const std::vector<uint8_t>& state);
    std::vector<uint8_t> mix_columns(const std::vector<uint8_t>& state);
    std::vector<uint8_t> inv_mix_columns(const std::vector<uint8_t>& state);

    // Key expansion and round key generation
    std::vector<uint8_t> expand_key(const std::vector<uint8_t>& key);

    // Helper functions for file operations
    std::vector<uint8_t> read_file(const std::string& filename);
    void write_file(const std::string& filename, const std::vector<uint8_t>& data);
};

#endif // SWIFT_CRYPT_H
