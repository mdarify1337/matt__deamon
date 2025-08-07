#pragma once

#include <string>
#include <vector>
#include <cstdint>

class Crypto {
public:
    static std::string generateKey();
    static std::string encrypt(const std::string& plaintext, const std::string& key);
    static std::string decrypt(const std::string& ciphertext, const std::string& key);
    static std::string hashPassword(const std::string& password);
    static bool verifyPassword(const std::string& password, const std::string& hash);

private:
    static std::vector<uint8_t> xorCipher(const std::vector<uint8_t>& data, const std::string& key);
    static std::string base64Encode(const std::vector<uint8_t>& data);
    static std::vector<uint8_t> base64Decode(const std::string& encoded);
};