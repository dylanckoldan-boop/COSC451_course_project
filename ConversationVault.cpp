#include "ConversationVault.h"
#include "AESCipher.h"
#include <algorithm>
#include <fstream>
#include <sstream>
#include <stdexcept>

std::string ConversationVault::vaultFilename(const std::string& userA, const std::string& userB) {
    // Sort the two usernames alphabetically so both participants land on
    // the identical filename independently, regardless of who's
    // "sender" vs "receiver" for any given message.
    std::string first = userA;
    std::string second = userB;
    if (second < first) {
        std::swap(first, second);
    }
    return first + "_" + second + "_secure.dat";
}

void ConversationVault::seal(const std::string& userA, const std::string& userB,
                              const std::string& key, const std::string& content) {
    AESCipher cipher;
    std::string encrypted = cipher.encrypt(content, key);

    std::string filename = vaultFilename(userA, userB);
    // Binary mode matters here -- the ciphertext contains raw bytes
    // (including the prepended IV), not just printable text.
    std::ofstream out(filename, std::ios::binary);
    out.write(encrypted.data(), static_cast<std::streamsize>(encrypted.size()));
}

bool ConversationVault::open(const std::string& userA, const std::string& userB,
                              const std::string& key, std::string& outContent) {
    std::string filename = vaultFilename(userA, userB);
    std::ifstream in(filename, std::ios::binary);
    if (!in.is_open()) {
        return false; // no vault file exists yet for this pair
    }

    std::ostringstream buffer;
    buffer << in.rdbuf();
    std::string encrypted = buffer.str();

    AESCipher cipher;
    try {
        outContent = cipher.decrypt(encrypted, key);
        return true;
    } catch (const std::exception&) {
        // Wrong key (or a corrupted file) -- Crypto++'s PKCS7 unpadding
        // check failed. Not crash-worthy, just "can't open it."
        return false;
    }
}
