#include "SwiftCrypt.h"
#include <fstream>
#include <iostream>
#include <iomanip>
#include <algorithm>
#include <sstream>

const uint8_t SwiftCrypt::SBOX[256] = {
    // Add your unique SBOX values here
};

const uint8_t SwiftCrypt::INV_SBOX[256] = {
    // Add your unique INV_SBOX values here
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
