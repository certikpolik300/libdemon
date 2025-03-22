#include <iostream>
#include <vector>
#include <fstream>
#include <iomanip>
#include <random>
#include <sstream>
#include <cstring>

constexpr int KEY_SIZE = 1024; // 1024-bit key
constexpr int BLOCK_SIZE = 128; // Block size in bits
constexpr int ROUNDS = 32; // Number of rounds

// Unique S-box and inverse S-box values
const std::vector<uint8_t> SBOX = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
    0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc,
    0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a,
    0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
    0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b,
    0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85,
    0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
    0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17,
    0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88,
    0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
    0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9,
    0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6,
    0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
    0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94,
    0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68,
    0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

const std::vector<uint8_t> INV_SBOX = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38,
    0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87,
    0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d,
    0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2,
    0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16,
    0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda,
    0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a,
    0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02,
    0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea,
    0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85,
    0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89,
    0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20,
    0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31,
    0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d,
    0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0,
    0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26,
    0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};

// Helper functions
std::vector<uint8_t> generate_random_bytes(size_t length);
std::string bytes_to_hex(const std::vector<uint8_t>& data);
void xor_blocks(std::vector<uint8_t>& block1, const std::vector<uint8_t>& block2);
std::vector<uint8_t> pad(const std::vector<uint8_t>& data);
std::vector<uint8_t> unpad(const std::vector<uint8_t>& data);

class SwiftCrypt {
public:
    SwiftCrypt(const std::vector<uint8_t>& key, const std::vector<uint8_t>& iv_fwd, const std::vector<uint8_t>& iv_bwd);
    std::vector<uint8_t> encrypt_block(const std::vector<uint8_t>& plaintext);
    std::vector<uint8_t> decrypt_block(const std::vector<uint8_t>& ciphertext);
    std::vector<uint8_t> encrypt_text(const std::string& plaintext);
    std::string decrypt_text(const std::vector<uint8_t>& ciphertext);
    void encrypt_file(const std::string& input_filename, const std::string& output_filename);
    void decrypt_file(const std::string& input_filename, const std::string& output_filename);

private:
    std::vector<uint8_t> key_;
    std::vector<uint8_t> iv_fwd_;
    std::vector<uint8_t> iv_bwd_;
    std::vector<std::vector<uint8_t>> round_keys_;
    void generate_round_keys();
    void substitute_bytes(std::vector<uint8_t>& block);
    void inverse_substitute_bytes(std::vector<uint8_t>& block);
    void apply_round_key(std::vector<uint8_t>& block, int round);
    std::vector<uint8_t> rcon_;
};

SwiftCrypt::SwiftCrypt(const std::vector<uint8_t>& key, const std::vector<uint8_t>& iv_fwd, const std::vector<uint8_t>& iv_bwd) 
    : key_(key), iv_fwd_(iv_fwd), iv_bwd_(iv_bwd) {
    rcon_ = generate_random_bytes(ROUNDS); // Unique RCON
    generate_round_keys();
}

void SwiftCrypt::generate_round_keys() {
    round_keys_.resize(ROUNDS, std::vector<uint8_t>(BLOCK_SIZE / 8));

    // Initialize the first round key with the provided key
    for (int i = 0; i < BLOCK_SIZE / 8; ++i) {
        round_keys_[0][i] = key_[i];
    }

    // Generate the round keys using the key schedule algorithm
    for (int round = 1; round < ROUNDS; ++round) {
        std::vector<uint8_t> temp = round_keys_[round - 1];

        // Rotate
        uint8_t t = temp[0];
        for (int i = 0; i < BLOCK_SIZE / 8 - 1; ++i) {
            temp[i] = temp[i + 1];
        }
        temp[BLOCK_SIZE / 8 - 1] = t;

        // Substitute using S-box
        for (int i = 0; i < BLOCK_SIZE / 8; ++i) {
            temp[i] = SBOX[temp[i]];
        }

        // Add round constant
        temp[0] ^= rcon_[round];

        // XOR with the previous round key
        for (int i = 0; i < BLOCK_SIZE / 8; ++i) {
            round_keys_[round][i] = round_keys_[round - 1][i] ^ temp[i];
        }
    }
}

void SwiftCrypt::substitute_bytes(std::vector<uint8_t>& block) {
    for (auto& byte : block) {
        byte = SBOX[byte];
    }
}

void SwiftCrypt::inverse_substitute_bytes(std::vector<uint8_t>& block) {
    for (auto& byte : block) {
        byte = INV_SBOX[byte];
    }
}

void SwiftCrypt::apply_round_key(std::vector<uint8_t>& block, int round) {
    for (size_t i = 0; i < block.size(); ++i) {
        block[i] ^= round_keys_[round][i];
    }
}

std::vector<uint8_t> SwiftCrypt::encrypt_block(const std::vector<uint8_t>& plaintext) {
    std::vector<uint8_t> block = plaintext;
    xor_blocks(block, iv_fwd_);
    for (int round = 0; round < ROUNDS; ++round) {
        substitute_bytes(block);
        apply_round_key(block, round);
    }
    xor_blocks(block, iv_fwd_);
    return block;
}

std::vector<uint8_t> SwiftCrypt::decrypt_block(const std::vector<uint8_t>& ciphertext) {
    std::vector<uint8_t> block = ciphertext;
    xor_blocks(block, iv_bwd_);
    for (int round = ROUNDS - 1; round >= 0; --round) {
        apply_round_key(block, round);
        inverse_substitute_bytes(block);
    }
    xor_blocks(block, iv_bwd_);
    return block;
}

std::vector<uint8_t> SwiftCrypt::encrypt_text(const std::string& plaintext) {
    std::vector<uint8_t> padded_data = pad(std::vector<uint8_t>(plaintext.begin(), plaintext.end()));
    std::vector<uint8_t> ciphertext;
    for (size_t i = 0; i < padded_data.size(); i += BLOCK_SIZE / 8) {
        std::vector<uint8_t> block(padded_data.begin() + i, padded_data.begin() + i + BLOCK_SIZE / 8);
        std::vector<uint8_t> encrypted_block = encrypt_block(block);
        xor_blocks(encrypted_block, ciphertext);
        ciphertext.insert(ciphertext.end(), encrypted_block.begin(), encrypted_block.end());
    }
    return ciphertext;
}

std::string SwiftCrypt::decrypt_text(const std::vector<uint8_t>& ciphertext) {
    std::vector<uint8_t> plaintext;
    for (size_t i = 0; i < ciphertext.size(); i += BLOCK_SIZE / 8) {
        std::vector<uint8_t> block(ciphertext.begin() + i, ciphertext.begin() + i +BLOCK_SIZE / 8);
        std::vector<uint8_t> decrypted_block = decrypt_block(block);
        xor_blocks(decrypted_block, plaintext);
        plaintext.insert(plaintext.end(), decrypted_block.begin(), decrypted_block.end());
    }
    return std::string(plaintext.begin(), plaintext.end());
}

void SwiftCrypt::encrypt_file(const std::string& input_filename, const std::string& output_filename) {
    std::ifstream input_file(input_filename, std::ios::binary);
    std::ofstream output_file(output_filename, std::ios::binary);

    std::vector<uint8_t> buffer((std::istreambuf_iterator<char>(input_file)), std::istreambuf_iterator<char>());
    std::vector<uint8_t> ciphertext = encrypt_text(std::string(buffer.begin(), buffer.end()));

    output_file.write(reinterpret_cast<const char*>(ciphertext.data()), ciphertext.size());
}

void SwiftCrypt::decrypt_file(const std::string& input_filename, const std::string& output_filename) {
    std::ifstream input_file(input_filename, std::ios::binary);
    std::ofstream output_file(output_filename, std::ios::binary);

    std::vector<uint8_t> buffer((std::istreambuf_iterator<char>(input_file)), std::istreambuf_iterator<char>());
    std::string plaintext = decrypt_text(buffer);

    output_file.write(plaintext.c_str(), plaintext.size());
}

std::vector<uint8_t> generate_random_bytes(size_t length) {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);

    std::vector<uint8_t> bytes(length);
    for (size_t i = 0; i < length; ++i) {
        bytes[i] = static_cast<uint8_t>(dis(gen));
    }
    return bytes;
}

std::string bytes_to_hex(const std::vector<uint8_t>& data) {
    std::ostringstream oss;
    for (const auto& byte : data) {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
    }
    return oss.str();
}

void xor_blocks(std::vector<uint8_t>& block1, const std::vector<uint8_t>& block2) {
    for (size_t i = 0; i < block1.size(); ++i) {
        block1[i] ^= block2[i];
    }
}

std::vector<uint8_t> pad(const std::vector<uint8_t>& data) {
    std::vector<uint8_t> padded_data = data;
    size_t padding_size = BLOCK_SIZE / 8 - (data.size() % (BLOCK_SIZE / 8));
    padded_data.insert(padded_data.end(), padding_size, static_cast<uint8_t>(padding_size));
    return padded_data;
}

std::vector<uint8_t> unpad(const std::vector<uint8_t>& data) {
    std::vector<uint8_t> unpadded_data = data;
    size_t padding_size = unpadded_data.back();
    unpadded_data.erase(unpadded_data.end() - padding_size, unpadded_data.end());
    return unpadded_data;
}

int main() {
    std::vector<uint8_t> key = generate_random_bytes(BLOCK_SIZE / 8);
    std::vector<uint8_t> iv_fwd = generate_random_bytes(BLOCK_SIZE / 8);
    std::vector<uint8_t> iv_bwd = generate_random_bytes(BLOCK_SIZE / 8);

    SwiftCrypt swiftCrypt(key, iv_fwd, iv_bwd);

    std::string plaintext = "This is a secret message.";
    std::vector<uint8_t> ciphertext = swiftCrypt.encrypt_text(plaintext);
    std::string decrypted_text = swiftCrypt.decrypt_text(ciphertext);

    std::cout << "Plaintext: " << plaintext << std::endl;
    std::cout << "Ciphertext (hex): " << bytes_to_hex(ciphertext) << std::endl;
    std::cout << "Decrypted text: " << decrypted_text << std::endl;

    return 0;
}
