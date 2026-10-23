#include "AccountManager.h"
#include "UserStore.h"
#include <cstdio>
#include <vector>

bool AccountManager::accountExists(const std::string& username) const {
    return accounts.find(username) != accounts.end();
}

bool AccountManager::createAccount(const std::string& username, const std::string& password) {
    if (accountExists(username)) {
        return false; // Menu is responsible for telling the user why it failed
    }
    accounts[username] = Account(username, password);
    return true;
}

Account* AccountManager::login(const std::string& username, const std::string& password) {
    auto it = accounts.find(username);
    if (it == accounts.end()) {
        return nullptr; // no such account
    }
    if (!it->second.checkPassword(password)) {
        return nullptr; // wrong password
    }
    // Correct password: decrypt this account's private key into memory for
    // the session. If this fails despite a correct password, accounts.db
    // was tampered with -- the login still succeeds, but the account stays
    // locked, and Menu warns that its encrypted messages can't be read.
    it->second.unlockPrivateKey(password);
    return &it->second; // pointer into the map -- valid as long as AccountManager lives
}

Account* AccountManager::findAccount(const std::string& username) {
    auto it = accounts.find(username);
    if (it == accounts.end()) {
        return nullptr;
    }
    return &it->second;
}

StoreLoadResult AccountManager::loadFromDisk() {
    std::vector<AccountRecord> records;
    StoreLoadResult result = UserStore::load(storePath, records);

    if (result != StoreLoadResult::Ok) {
        // Set the file aside rather than letting the next save() overwrite
        // it -- whatever's in it isn't silently destroyed.
        std::string backup = storePath +
            (result == StoreLoadResult::LegacyFormat ? ".v1-backup" : ".unreadable");
        std::remove(backup.c_str());
        std::rename(storePath.c_str(), backup.c_str());
        return result;
    }

    for (const AccountRecord& rec : records) {
        accounts[rec.username] = Account::fromRecord(rec);
    }
    return result;
}

bool AccountManager::saveToDisk() const {
    std::vector<AccountRecord> records;
    for (const auto& entry : accounts) {
        records.push_back(entry.second.toRecord());
    }
    return UserStore::save(storePath, records);
}

size_t AccountManager::accountCount() const {
    return accounts.size();
}
