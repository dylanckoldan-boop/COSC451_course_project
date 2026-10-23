#pragma once
#include <string>
#include <vector>
#include "RSAKeys.h"

/*
 * AccountRecord
 * -------------
 * The persisted shape of an Account -- exactly what UserStore writes to
 * and reads from accounts.db.
 *
 * Note what's NOT here: the plaintext password (only salt + hash), the
 * RSA primes p and q (never needed after key generation), and the
 * plaintext private exponent d. Only an AES-encrypted copy of d is
 * stored, unlockable solely with the account's password.
 */
struct AccountRecord {
    std::string username;
    std::string salt;          // raw bytes -- for the password hash
    std::string passwordHash;  // raw bytes (PBKDF2 output)
    std::vector<std::string> contacts;
    std::string n, e;          // RSA public key components (decimal strings)
    std::string keySalt;       // raw bytes -- a SEPARATE salt, for deriving
                               // the key that encrypts d (see PasswordHasher.h)
    std::string encryptedD;    // raw bytes -- AES-encrypted private exponent
};

/*
 * Account
 * -------
 * Each account generates its own RSA keypair ONCE, at creation. The
 * public half (n, e) is always available. The private half (d) is
 * stored only in encrypted form, and exists in readable form in memory
 * only between login (unlockPrivateKey) and logout (lockPrivateKey).
 *
 * This replaces the earlier "behavioral honor system" around
 * getPrivateKey() with an actual mechanism: while an account is locked,
 * getPrivateKey() returns an empty string, so no code path can decrypt
 * that account's messages unless that user has logged in with the right
 * password during this session.
 *
 * Data travels:
 *   create:  (username, password) ctor -> hash password, generate RSA
 *            keys, encrypt d under a password-derived key, discard the
 *            plaintext d -> account starts LOCKED.
 *   login:   AccountManager::login -> checkPassword -> unlockPrivateKey
 *            (decrypts d into memory).
 *   logout:  Menu::handleLogout -> lockPrivateKey (wipes d from memory).
 *   save/load: toRecord() / fromRecord() <-> UserStore <-> accounts.db.
 */
class Account {
private:
    std::string username;
    std::string passwordSalt;
    std::string passwordHash;
    std::string keySalt;
    std::string encryptedD;
    std::vector<std::string> contactList;
    RSAKeyPair rsaKeys;       // d / privateKey only populated while unlocked
    bool unlocked = false;

public:
    Account() = default;
    Account(const std::string& username, const std::string& password);

    static Account fromRecord(const AccountRecord& record);
    AccountRecord toRecord() const;

    const std::string& getUsername() const;
    bool checkPassword(const std::string& attempt) const;

    void addContact(const std::string& contactUsername);
    bool isContact(const std::string& contactUsername) const;
    const std::vector<std::string>& getContacts() const;

    const std::string& getPublicKey() const;

    // Decrypts d into memory. Returns false if the password can't decrypt
    // it (wrong password, or a tampered accounts.db).
    bool unlockPrivateKey(const std::string& password);
    // Overwrites and clears d from memory.
    void lockPrivateKey();
    bool isUnlocked() const;
    // Empty string while locked -- any RSA decrypt attempted with it fails.
    const std::string& getPrivateKey() const;
};
