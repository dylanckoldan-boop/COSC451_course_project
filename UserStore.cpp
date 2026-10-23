#include "UserStore.h"
#include "HexUtil.h"
#include <fstream>

namespace {
    const char* const FILE_HEADER = "WYRMWOOD_ACCOUNTS_V2";
    const char* const LEGACY_V1_HEADER = "WYRMWOOD_ACCOUNTS_V1";
    const size_t FIELD_COUNT = 8;
}

StoreLoadResult UserStore::load(const std::string& path, std::vector<AccountRecord>& out) {
    out.clear();

    std::ifstream in(path);
    if (!in.is_open()) {
        return StoreLoadResult::Ok; // no file yet -- a normal first run
    }

    std::string line;
    if (!std::getline(in, line)) {
        return StoreLoadResult::Ok; // empty file -- treat like a fresh start
    }
    HexUtil::stripCR(line);
    if (line == LEGACY_V1_HEADER) {
        return StoreLoadResult::LegacyFormat;
    }
    if (line != FILE_HEADER) {
        return StoreLoadResult::Unreadable;
    }

    // Parse everything into a local vector first, and only hand it back
    // if the WHOLE file parsed -- never return a half-loaded user list.
    std::vector<AccountRecord> parsed;
    while (std::getline(in, line)) {
        HexUtil::stripCR(line);
        if (line.empty()) continue;

        std::vector<std::string> fields = HexUtil::split(line, '\t');
        if (fields.size() != FIELD_COUNT) return StoreLoadResult::Unreadable;

        AccountRecord rec;
        if (!HexUtil::fromHex(fields[0], rec.username) ||
            !HexUtil::fromHex(fields[1], rec.salt) ||
            !HexUtil::fromHex(fields[2], rec.passwordHash) ||
            !HexUtil::fromHex(fields[4], rec.n) ||
            !HexUtil::fromHex(fields[5], rec.e) ||
            !HexUtil::fromHex(fields[6], rec.keySalt) ||
            !HexUtil::fromHex(fields[7], rec.encryptedD)) {
            return StoreLoadResult::Unreadable;
        }

        for (const std::string& contactHex : HexUtil::split(fields[3], ',')) {
            if (contactHex.empty()) continue; // account with no contacts
            std::string contact;
            if (!HexUtil::fromHex(contactHex, contact)) return StoreLoadResult::Unreadable;
            rec.contacts.push_back(contact);
        }

        parsed.push_back(rec);
    }

    out = parsed;
    return StoreLoadResult::Ok;
}

bool UserStore::save(const std::string& path, const std::vector<AccountRecord>& records) {
    std::ofstream out(path, std::ios::trunc);
    if (!out.is_open()) return false;

    out << FILE_HEADER << "\n";
    for (const AccountRecord& rec : records) {
        std::string contactsField;
        for (size_t i = 0; i < rec.contacts.size(); i++) {
            if (i > 0) contactsField += ',';
            contactsField += HexUtil::toHex(rec.contacts[i]);
        }

        out << HexUtil::toHex(rec.username) << '\t'
            << HexUtil::toHex(rec.salt) << '\t'
            << HexUtil::toHex(rec.passwordHash) << '\t'
            << contactsField << '\t'
            << HexUtil::toHex(rec.n) << '\t'
            << HexUtil::toHex(rec.e) << '\t'
            << HexUtil::toHex(rec.keySalt) << '\t'
            << HexUtil::toHex(rec.encryptedD) << '\n';
    }
    return out.good();
}
