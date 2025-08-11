#include "Crypto.hpp"
#include <random>
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <openssl/sha.h>

std::string Crypto::generateKey() {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);
    
    std::string key;
    for (int i = 0; i < 32; ++i) {
        key += static_cast<char>(dis(gen));
    }
    return base64Encode(std::vector<uint8_t>(key.begin(), key.end()));
}


std::vector<uint8_t> Crypto::xorCipher(const std::vector<uint8_t>& data, const std::string& key) {
    std::vector<uint8_t> result;
    result.reserve(data.size());
    
    for (size_t i = 0; i < data.size(); ++i) {
        result.push_back(data[i] ^ key[i % key.length()]);
    }
    
    return result;
}

std::string Crypto::encrypt(const std::string& plaintext, const std::string& key) {
    std::vector<uint8_t> data(plaintext.begin(), plaintext.end());
    auto encrypted = xorCipher(data, key);
    return base64Encode(encrypted);
}

std::string Crypto::decrypt(const std::string& ciphertext, const std::string& key) {
    auto data = base64Decode(ciphertext);
    auto decrypted = xorCipher(data, key);
    return std::string(decrypted.begin(), decrypted.end());
}

std::string Crypto::base64Encode(const std::vector<uint8_t>& data) {
    const std::string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string result;
    
    for (size_t i = 0; i < data.size(); i += 3) {
        uint32_t temp = data[i] << 16;
        if (i + 1 < data.size()) temp |= data[i + 1] << 8;
        if (i + 2 < data.size()) temp |= data[i + 2];
        
        result += chars[(temp >> 18) & 0x3F];
        result += chars[(temp >> 12) & 0x3F];
        result += (i + 1 < data.size()) ? chars[(temp >> 6) & 0x3F] : '=';
        result += (i + 2 < data.size()) ? chars[temp & 0x3F] : '=';
    }
    
    return result;
}

std::vector<uint8_t> Crypto::base64Decode(const std::string& encoded) {
    const std::string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::vector<uint8_t> result;
    
    for (size_t i = 0; i < encoded.length(); i += 4) {
        uint32_t temp = 0;
        for (int j = 0; j < 4; ++j) {
            if (i + j < encoded.length() && encoded[i + j] != '=') {
                temp = (temp << 6) | chars.find(encoded[i + j]);
            } else {
                temp <<= 6;
            }
        }
        
        result.push_back((temp >> 16) & 0xFF);
        if (encoded[i + 2] != '=') result.push_back((temp >> 8) & 0xFF);
        if (encoded[i + 3] != '=') result.push_back(temp & 0xFF);
    }
    
    return result;
}

#include <openssl/evp.h>
#include <openssl/sha.h>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>

std::string Crypto::hashPassword(const std::string& password) {
    // Create and initialize context
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) throw std::runtime_error("Failed to create EVP_MD_CTX");

    unsigned char hash[SHA256_DIGEST_LENGTH];
    unsigned int hash_len = 0;

    // Initialize with SHA256
    if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("EVP_DigestInit_ex failed");
    }

    // Update with password data
    if (EVP_DigestUpdate(ctx, password.data(), password.size()) != 1) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("EVP_DigestUpdate failed");
    }

    // Finalize the hash
    if (EVP_DigestFinal_ex(ctx, hash, &hash_len) != 1) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("EVP_DigestFinal_ex failed");
    }

    EVP_MD_CTX_free(ctx);

    // Convert to hex string
    std::stringstream ss;
    for (unsigned int i = 0; i < hash_len; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    }
    return ss.str();
}

bool Crypto::verifyPassword(const std::string& password, const std::string& hash) {
    return hashPassword(password) == hash;
}
