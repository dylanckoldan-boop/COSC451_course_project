#pragma once
#include "Account.h"
#include <string>
#include <vector>

/*
 * UserStore
 * ---------
 * Reads and writes accounts.db. Only knows about AccountRecord (plain
 * data), never the live Account object, so the file format lives in
 * exactly one place.
 *
 * File format (V2): a version header line, then one account per line,
 * each field hex-encoded (see HexUtil.h) and separated by tabs:
 *   username  salt  passwordHash  contacts  n  e  keySalt  encryptedD
 * where `contacts` is a comma-separated list of hex-encoded usernames.
 *
 * V1 (the first persistence version) stored d in plaintext. A V1 file is
 * recognized and reported as LegacyFormat rather than silently loaded,
 * since its private keys can't be retroactively protected without each
 * user's password.
 */
enum class StoreLoadResult {
    Ok,            // loaded, or no file yet (first run)
    Unreadable,    // file exists but is corrupted / unrecognized
    LegacyFormat   // a V1 file, with unencrypted private keys
};

class UserStore {
public:
    static StoreLoadResult load(const std::string& path, std::vector<AccountRecord>& out);
    static bool save(const std::string& path, const std::vector<AccountRecord>& records);
};
