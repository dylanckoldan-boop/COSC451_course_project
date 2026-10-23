#pragma once
#include <string>

/*
 * PasswordHasher
 * --------------
 * Salted password hashing via PBKDF2-HMAC-SHA256 (Crypto++). Exists so
 * accounts.db never stores a password itself -- only a random per-account
 * salt and the derived hash. Fulfills the "swap for a hash comparison"
 * note left in Account.cpp back in Week 1.
 *
 * Why salted: identical passwords produce different hashes per account,
 * so precomputed (rainbow table) attacks don't carry across users.
 * Why PBKDF2 with many iterations: makes each brute-force guess
 * deliberately slow, unlike a single fast SHA-256 pass.
 *
 * Data travels: Account's constructor calls generateSalt() + hash() once
 * at creation -> both are stored on the Account and persisted by
 * UserStore -> at login, Account::checkPassword() calls verify() with
 * the attempt and the stored salt/hash.
 */
class PasswordHasher {
public:
    static std::string generateSalt();
    static std::string hash(const std::string& password, const std::string& salt);
    // Constant-time comparison, so response timing doesn't leak how many
    // leading bytes of a guess matched.
    static bool verify(const std::string& attempt, const std::string& salt, const std::string& expectedHash);

    // Derives a 32-byte AES-256 key from a password -- used by Account to
    // encrypt its RSA private key at rest. Same PBKDF2 math as hash(),
    // named separately because it serves a different purpose.
    //
    // CRITICAL: callers must pass a DIFFERENT salt here than the one used
    // for the stored password hash. With the same salt, this function's
    // output would be byte-for-byte identical to the hash sitting in
    // accounts.db -- meaning anyone who can read that file would already
    // hold the key that decrypts the private key. Separate salts make
    // the two outputs independent.
    static std::string deriveKey(const std::string& password, const std::string& salt);
};
