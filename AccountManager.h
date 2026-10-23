#pragma once
#include <string>
#include <unordered_map>
#include "Account.h"
#include "UserStore.h"

/*
 * AccountManager
 * --------------
 * Owns the table of every Account. As of this week it also loads that
 * table from accounts.db at startup and writes it back whenever an
 * account or contact list changes, so accounts and their RSA keypairs
 * persist across application runs.
 */
class AccountManager {
private:
    std::unordered_map<std::string, Account> accounts; // key = username
    std::string storePath = "accounts.db";

public:
    bool createAccount(const std::string& username, const std::string& password);
    Account* login(const std::string& username, const std::string& password);
    Account* findAccount(const std::string& username);
    bool accountExists(const std::string& username) const;

    // Called once at startup. On Ok, accounts are restored. Otherwise the
    // file is renamed aside (preserved, never overwritten) and the program
    // continues with no saved accounts:
    //   Unreadable   -> accounts.db.unreadable
    //   LegacyFormat -> accounts.db.v1-backup (contains UNENCRYPTED private
    //                   keys -- delete it once you no longer need it)
    StoreLoadResult loadFromDisk();
    // Login also unlocks the account's private key for this session (see
    // Account::unlockPrivateKey). Menu should check isUnlocked() after.
    // Called after any change worth keeping (new account, new contact).
    bool saveToDisk() const;
    size_t accountCount() const;
};
