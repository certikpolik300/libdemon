#include "SwiftCrypt.h"
#include <fstream>
#include <iostream>
#include <iomanip>
#include <algorithm>
#include <sstream>

const uint8_t SwiftCrypt::SBOX[256] = {
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

const uint8_t SwiftCrypt::INV_SBOX[256] = {
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


const uint32_t SwiftCrypt::RCON[10] = {
    0x01000000, 0x02000000, 0x04000000, 0x08000000,
    0x10000000, 0x20000000, 0x40000000, 0x80000000,
    0x1B000000, 0x36000000
};

SwiftCrypt::SwiftCrypt(const std::vector<uint8_t>& key, const std::vector<uint8_t>& iv_forward, const std::vector<uint8_t>& iv_backward)
    : key(key), iv_forward(iv_forward), iv_backward(iv_backward) {}

std::vector<uint8_t> SwiftCrypt::encrypt(const std::vector<uint8_t>& plaintext) {
    std::vector<uint8_t> ciphertext(plaintext.size());
    std::vector<uint8_t> state = iv_forward;
    std::vector<uint8_t> expanded_key = expand_key(key);

    for (size_t i = 0; i < plaintext.size(); i += 16) {
        std::vector<uint8_t> block(plaintext.begin() + i, plaintext.begin() + i + 16);
        block = add_round_key(block, std::vector<uint8_t>(expanded_key.begin(), expanded_key.begin() + 16));
        for (int round = 1; round < 10; ++round) {
            block = sub_bytes(block);
            block = shift_rows(block);
            block = mix_columns(block);
            block = add_round_key(block, std::vector<uint8_t>(expanded_key.begin() + round * 16, expanded_key.begin() + (round + 1) * 16));
        }
        block = sub_bytes(block);
        block = shift_rows(block);
        block = add_round_key(block, std::vector<uint8_t>(expanded_key.begin() + 10 * 16, expanded_key.begin() + 11 * 16));
        std::copy(block.begin(), block.end(), ciphertext.begin() + i);
    }

    return ciphertext;
}

std::vector<uint8_t> SwiftCrypt::decrypt(const std::vector<uint8_t>& ciphertext) {
    std::vector<uint8_t> plaintext(ciphertext.size());
    std::vector<uint8_t> state = iv_backward;
    std::vector<uint8_t> expanded_key = expand_key(key);

    for (size_t i = 0; i < ciphertext.size(); i += 16) {
        std::vector<uint8_t> block(ciphertext.begin() + i, ciphertext.begin() + i + 16);
        block = add_round_key(block, std::vector<uint8_t>(expanded_key.begin() + 10 * 16, expanded_key.begin() + 11 * 16));
        block = inv_shift_rows(block);
        block = inv_sub_bytes(block);
        for (int round = 9; round > 0; --round) {
            block = add_round_key(block, std::vector<uint8_t>(expanded_key.begin() + round * 16, expanded_key.begin() + (round + 1) * 16));
            block = inv_mix_columns(block);
            block = inv_shift_rows(block);
            block = inv_sub_bytes(block);
        }
        block = add_round_key(block, std::vector<uint8_t>(expanded_key.begin(), expanded_key.begin() + 16));
        std::copy(block.begin(), block.end(), plaintext.begin() + i);
    }

    return plaintext;
}

void SwiftCrypt::encrypt_file(const std::string& input_filename, const std::string& output_filename) {
    std::vector<uint8_t> plaintext = read_file(input_filename);
    std::vector<uint8_t> ciphertext = encrypt(plaintext);
    write_file(output_filename, ciphertext);
}

void SwiftCrypt::decrypt_file(const std::string& input_filename, const std::string& output_filename) {
    std::vector<uint8_t> ciphertext = read_file(input_filename);
    std::vector<uint8_t> plaintext = decrypt(ciphertext);
    write_file(output_filename, plaintext);
}

std::string SwiftCrypt::encrypt_text(const std::string& plaintext) {
    std::vector<uint8_t> plaintext_bytes(plaintext.begin(), plaintext.end());
    std::vector<uint8_t> ciphertext = encrypt(plaintext_bytes);

    std::ostringstream oss;
    for (auto byte : ciphertext) {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
    }
    return oss.str();
}

std::string SwiftCrypt::decrypt_text(const std::string& ciphertext) {
    std::vector<uint8_t> ciphertext_bytes;

    for (size_t i = 0; i < ciphertext.length(); i += 2) {
        std::string byte_string = ciphertext.substr(i, 2);
        uint8_t byte = static_cast<uint8_t>(strtol(byte_string.c_str(), nullptr, 16));
        ciphertext_bytes.push_back(byte);
    }

    std::vector<uint8_t> plaintext = decrypt(ciphertext_bytes);
    return std::string(plaintext.begin(), plaintext.end());
}

std::vector<uint8_t> SwiftCrypt::add_round_key(const std::vector<uint8_t>& state, const std::vector<uint8_t>& round_key) {
    std::vector<uint8_t> new_state(state.size());
    for (size_t i = 0; i < state.size(); ++i) {
        new_state[i] = state[i] ^ round_key[i];
    }
    return new_state;
}

std::vector<uint8_t> SwiftCrypt::sub_bytes(const std::vector<uint8_t>& state) {
    std::vector<uint8_t> new_state(state.size());
    for (size_t i = 0; i < state.size(); ++i) {
        new_state[i] = SBOX[state[i]];
    }
    return new_state;
}

std::vector<uint8_t> SwiftCrypt::inv_sub_bytes(const std::vector<uint8_t>& state) {
    std::vector<uint8_t> new_state(state.size());
    for (size_t i = 0; i < state.size(); ++i) {
        new_state[i] = INV_SBOX[state[i]];
    }
    return new_state;
}

std::vector<uint8_t> SwiftCrypt::shift_rows(const std::vector<uint8_t>& state) {
    std::vector<uint8_t> new_state(state.size());
    new_state[0] = state[0];
    new_state[1] = state[5];
    new_state[2] = state[10];
    new_state[3] = state[15];
    new_state[4] = state[4];
    new_state[5] = state[9];
    new_state[6] = state[14];
    new_state[7] = state[3];
    new_state[8] = state[8];
    new_state[9] = state[13];
    new_state[10] = state[2];
    new_state[11] = state[7];
    new_state[12] = state[12];
    new_state[13] = state[1];
    new_state[14] = state[6];
    new_state[15] = state[11];
    return new_state;
}

std::vector<uint8_t> SwiftCrypt::inv_shift_rows(const std::vector<uint8_t>& state) {
    std::vector<uint8_t> new_state(state.size());
    new_state[0] = state[0];
    new_state[1] = state[13];
    new_state[2] = state[10];
    new_state[3] = state[7];
    new_state[4] = state[4];
    new_state[5] = state[1];
    new_state[6] = state[14];
    new_state[7] = state[11];
    new_state[8] = state[8];
    new_state[9] = state[5];
    new_state[10] = state[2];
    new_state[11] = state[15];
    new_state[12] = state[12];
    new_state[13] = state[9];
    new_state[14] = state[6];
    new_state[15] = state[3];
    return new_state;
}

std::vector<uint8_t> SwiftCrypt::mix_columns(const std::vector<uint8_t>& state) {
    std::vector<uint8_t> new_state(state.size());
    for (int i = 0; i < 4; ++i) {
        new_state[i * 4 + 0] = static_cast<uint8_t>(0x02 * state[i * 4 + 0] ^ 0x03 * state[i * 4 + 1] ^ state[i * 4 + 2] ^ state[i * 4 + 3]);
        new_state[i * 4 + 1] = static_cast<uint8_t>(state[i * 4 + 0] ^ 0x02 * state[i * 4 + 1] ^ 0x03 * state[i * 4 + 2] ^ state[i * 4 + 3]);
        new_state[i * 4 + 2] = static_cast<uint8_t>(state[i * 4 + 0] ^ state[i * 4 + 1] ^ 0x02 * state[i * 4 + 2] ^ 0x03 * state[i * 4 + 3]);
        new_state[i * 4 + 3] = static_cast<uint8_t>(0x03 * state[i * 4 + 0] ^ state[i * 4 + 1] ^ state[i * 4 + 2] ^ 0x02 * state[i * 4 + 3]);
    }
    return new_state;
}

std::vector<uint8_t> SwiftCrypt::inv_mix_columns(const std::vector<uint8_t>& state) {
    std::vector<uint8_t> new_state(state.size());
    for (int i = 0; i < 4; ++i) {
        new_state[i * 4 + 0] = static_cast<uint8_t>(0x0e * state[i * 4 + 0] ^ 0x0b * state[i * 4 + 1] ^ 0x0d * state[i * 4 + 2] ^ 0x09 * state[i * 4 + 3]);
        new_state[i * 4 + 1] = static_cast<uint8_t>(0x09 * state[i * 4 + 0] ^ 0x0e * state[i * 4 + 1] ^ 0x0b * state[i * 4 + 2] ^ 0x0d * state[i * 4 + 3]);
        new_state[i * 4 + 2] = static_cast<uint8_t>(0x0d * state[i * 4 + 0] ^ 0x09 * state[i * 4 + 1] ^ 0x0e * state[i * 4 + 2] ^ 0x0b * state[i * 4 + 3]);
        new_state[i * 4 + 3] = static_cast<uint8_t>(0x0b * state[i * 4 + 0] ^ 0x0d * state[i * 4 + 1] ^ 0x09 * state[i * 4 + 2] ^ 0x0e * state[i * 4 + 3]);
    }
    return new_state;
}

std::vector<uint8_t> SwiftCrypt::expand_key(const std::vector<uint8_t>& key) {
    std::vector<uint8_t> expanded_key(176);
    std::copy(key.begin(), key.end(), expanded_key.begin());

    for (int i = 16; i < 176; i += 4) {
        std::vector<uint8_t> temp(expanded_key.begin() + i - 4, expanded_key.begin() + i);

        if (i % 16 == 0) {
            std::rotate(temp.begin(), temp.begin() + 1, temp.end());
            for (auto& byte : temp) {
                byte = SBOX[byte];
            }
            temp[0] ^= (RCON[(i / 16) - 1] >> 24) & 0xff;
        }

        for (int j = 0; j < 4; ++j) {
            expanded_key[i + j] = expanded_key[i + j - 16] ^ temp[j];
        }
    }

    return expanded_key;
}

std::vector<uint8_t> SwiftCrypt::read_file(const std::string& filename) {
    std::ifstream file(filename, std::ios::binary);
    return std::vector<uint8_t>((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
}

void SwiftCrypt::write_file(const std::string& filename, const std::vector<uint8_t>& data) {
    std::ofstream file(filename, std::ios::binary);
    std::copy(data.begin(), data.end(), std::ostreambuf_iterator<char>(file));
}
