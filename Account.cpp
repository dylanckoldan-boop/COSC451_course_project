#include "Account.h"
#include "PasswordHasher.h"
#include "AESCipher.h"
#include <algorithm>

Account::Account(const std::string& username, const std::string& password)
    : username(username),
      passwordSalt(PasswordHasher::generateSalt()),
      keySalt(PasswordHasher::generateSalt()),
      rsaKeys(RSAKeys::generate(1024)) {
    // The plaintext password is used only here, to derive (1) the stored
    // password hash and (2) the key that encrypts d. It's never stored.
    passwordHash = PasswordHasher::hash(password, passwordSalt);

    // Encrypt d under a key derived from the password with a SEPARATE
    // salt (see PasswordHasher::deriveKey for why that matters).
    std::string keyEncryptionKey = PasswordHasher::deriveKey(password, keySalt);
    AESCipher aes;
    encryptedD = aes.encrypt(rsaKeys.d, keyEncryptionKey);

    // Discard the plaintext private key -- a new account starts locked,
    // exactly like one loaded from disk. Only login unlocks it.
    lockPrivateKey();
}

Account Account::fromRecord(const AccountRecord& record) {
    Account acc;
    acc.username = record.username;
    acc.passwordSalt = record.salt;
    acc.passwordHash = record.passwordHash;
    acc.keySalt = record.keySalt;
    acc.encryptedD = record.encryptedD;
    acc.contactList = record.contacts;

    acc.rsaKeys.n = record.n;
    acc.rsaKeys.e = record.e;
    acc.rsaKeys.publicKey = record.n + "," + record.e;
    acc.unlocked = false; // d stays encrypted until this user logs in
    return acc;
}

AccountRecord Account::toRecord() const {
    AccountRecord record;
    record.username = username;
    record.salt = passwordSalt;
    record.passwordHash = passwordHash;
    record.contacts = contactList;
    record.n = rsaKeys.n;
    record.e = rsaKeys.e;
    record.keySalt = keySalt;
    record.encryptedD = encryptedD; // never the plaintext d, even if unlocked
    return record;
}

const std::string& Account::getUsername() const {
    return username;
}

bool Account::checkPassword(const std::string& attempt) const {
    return PasswordHasher::verify(attempt, passwordSalt, passwordHash);
}

void Account::addContact(const std::string& contactUsername) {
    if (!isContact(contactUsername)) {
        contactList.push_back(contactUsername);
    }
}

bool Account::isContact(const std::string& contactUsername) const {
    return std::find(contactList.begin(), contactList.end(), contactUsername) != contactList.end();
}

const std::vector<std::string>& Account::getContacts() const {
    return contactList;
}

const std::string& Account::getPublicKey() const {
    return rsaKeys.publicKey;
}

bool Account::unlockPrivateKey(const std::string& password) {
    std::string keyEncryptionKey = PasswordHasher::deriveKey(password, keySalt);
    AESCipher aes;
    try {
        rsaKeys.d = aes.decrypt(encryptedD, keyEncryptionKey);
    } catch (const std::exception&) {
        lockPrivateKey();
        return false; // AES padding check failed: wrong key or tampered data
    }
    rsaKeys.privateKey = rsaKeys.n + "," + rsaKeys.d;
    unlocked = true;
    return true;
}

void Account::lockPrivateKey() {
    // Overwrite before clearing, so the old characters don't just sit in
    // the string's buffer. (Best effort -- a standard std::string can't
    // guarantee no copies were ever made elsewhere in memory.)
    std::fill(rsaKeys.d.begin(), rsaKeys.d.end(), '\0');
    std::fill(rsaKeys.privateKey.begin(), rsaKeys.privateKey.end(), '\0');
    rsaKeys.d.clear();
    rsaKeys.privateKey.clear();
    unlocked = false;
}

bool Account::isUnlocked() const {
    return unlocked;
}

const std::string& Account::getPrivateKey() const {
    return rsaKeys.privateKey; // empty while locked
}
