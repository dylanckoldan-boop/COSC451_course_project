#include "PasswordHasher.h"
#include <cryptopp/pwdbased.h>
#include <cryptopp/sha.h>
#include <cryptopp/osrng.h>
#include <cryptopp/misc.h>

namespace {
    const unsigned int PBKDF2_ITERATIONS = 100000;
    const size_t SALT_BYTES = 16;
    const size_t HASH_BYTES = 32; // SHA-256 output size
}

std::string PasswordHasher::generateSalt() {
    CryptoPP::AutoSeededRandomPool rng;
    std::string salt(SALT_BYTES, '\0');
    rng.GenerateBlock(reinterpret_cast<CryptoPP::byte*>(&salt[0]), salt.size());
    return salt;
}

std::string PasswordHasher::hash(const std::string& password, const std::string& salt) {
    CryptoPP::PKCS5_PBKDF2_HMAC<CryptoPP::SHA256> pbkdf2;
    std::string derived(HASH_BYTES, '\0');
    pbkdf2.DeriveKey(
        reinterpret_cast<CryptoPP::byte*>(&derived[0]), derived.size(),
        0, // "purpose" byte -- unused by PBKDF2
        reinterpret_cast<const CryptoPP::byte*>(password.data()), password.size(),
        reinterpret_cast<const CryptoPP::byte*>(salt.data()), salt.size(),
        PBKDF2_ITERATIONS);
    return derived;
}

bool PasswordHasher::verify(const std::string& attempt, const std::string& salt, const std::string& expectedHash) {
    std::string attemptHash = hash(attempt, salt);
    if (attemptHash.size() != expectedHash.size()) return false;
    return CryptoPP::VerifyBufsEqual(
        reinterpret_cast<const CryptoPP::byte*>(attemptHash.data()),
        reinterpret_cast<const CryptoPP::byte*>(expectedHash.data()),
        attemptHash.size());
}

std::string PasswordHasher::deriveKey(const std::string& password, const std::string& salt) {
    // HASH_BYTES is 32, which is exactly an AES-256 key length.
    return hash(password, salt);
}
