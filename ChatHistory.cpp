#include "ChatHistory.h"
#include "HexUtil.h"
#include "HybridCrypto.h"
#include <fstream>
#include <iostream>
#include <cstdio>

namespace {
    const char* const LOG_HEADER = "WYRMWOOD_CHATLOG_V1";
    const size_t FIELD_COUNT = 7;
}

void ChatHistory::addToMemory(const Message& msg) {
    // Same Message recorded under both parties so each account's point of
    // view is independently retrievable.
    historyByAccount[msg.sender].push_back(msg);
    historyByAccount[msg.receiver].push_back(msg);
    totalMessages++;
}

bool ChatHistory::appendToDisk(const Message& msg) const {
    // Write the header only when starting a brand-new (or empty) log.
    bool needsHeader = true;
    {
        std::ifstream existing(logPath);
        std::string firstLine;
        if (existing.is_open() && std::getline(existing, firstLine)) {
            needsHeader = false;
        }
    }

    std::ofstream out(logPath, std::ios::app);
    if (!out.is_open()) return false;
    if (needsHeader) out << LOG_HEADER << "\n";

    // Every field hex-encoded: AES ciphertext and session keys are raw
    // binary and could otherwise contain tabs/newlines that break the file.
    out << HexUtil::toHex(msg.sender) << '\t'
        << HexUtil::toHex(msg.receiver) << '\t'
        << HexUtil::toHex(msg.plaintext) << '\t'
        << HexUtil::toHex(msg.ciphertext) << '\t'
        << HexUtil::toHex(msg.cipherName) << '\t'
        << HexUtil::toHex(msg.key) << '\t'
        << HexUtil::toHex(msg.timestamp) << '\n';
    return out.good();
}

void ChatHistory::addMessage(const Message& msg) {
    addToMemory(msg);
    if (!appendToDisk(msg)) {
        std::cout << "[ChatHistory] WARNING: could not save message to " << logPath
                  << " -- it won't survive a restart.\n";
    }
}

bool ChatHistory::loadFromDisk() {
    std::ifstream in(logPath);
    if (!in.is_open()) {
        return true; // no log yet -- normal first run
    }

    std::string line;
    if (!std::getline(in, line)) {
        return true; // empty log
    }
    HexUtil::stripCR(line);

    // Parse everything first; only commit to memory if the whole file is good.
    std::vector<Message> parsed;
    bool ok = (line == LOG_HEADER);
    while (ok && std::getline(in, line)) {
        HexUtil::stripCR(line);
        if (line.empty()) continue;

        std::vector<std::string> f = HexUtil::split(line, '\t');
        if (f.size() != FIELD_COUNT) { ok = false; break; }

        std::string sender, receiver, plaintext, ciphertext, cipherName, key, timestamp;
        if (!HexUtil::fromHex(f[0], sender) || !HexUtil::fromHex(f[1], receiver) ||
            !HexUtil::fromHex(f[2], plaintext) || !HexUtil::fromHex(f[3], ciphertext) ||
            !HexUtil::fromHex(f[4], cipherName) || !HexUtil::fromHex(f[5], key) ||
            !HexUtil::fromHex(f[6], timestamp)) {
            ok = false;
            break;
        }
        parsed.push_back(Message(sender, receiver, plaintext, ciphertext, cipherName, key, timestamp));
    }
    in.close();

    if (!ok) {
        // Preserve the unreadable log instead of letting the next
        // appendToDisk() build on top of a broken file.
        std::string backup = logPath + ".unreadable";
        std::remove(backup.c_str());
        std::rename(logPath.c_str(), backup.c_str());
        return false;
    }

    for (const Message& msg : parsed) {
        addToMemory(msg); // memory only -- these are already on disk
    }
    return true;
}

size_t ChatHistory::messageCount() const {
    return totalMessages;
}

const std::vector<Message>& ChatHistory::getHistoryFor(const std::string& username) const {
    static const std::vector<Message> empty; // returned if the account has no history yet
    auto it = historyByAccount.find(username);
    if (it == historyByAccount.end()) {
        return empty;
    }
    return it->second;
}

void ChatHistory::writeToFile(const std::string& username) const {
    // Writes a human-readable transcript to <username>_chat_history.txt in
    // the working directory (the project folder when run from Visual
    // Studio). Now regenerated from the persisted history, so it includes
    // messages from previous sessions too.
    std::string filename = username + "_chat_history.txt";
    std::ofstream out(filename);
    if (!out.is_open()) {
        std::cout << "[ChatHistory] ERROR: could not open " << filename << " for writing.\n";
        return;
    }

    out << "Chat History for: " << username << "\n";
    out << "==================================================\n";

    for (const Message& msg : getHistoryFor(username)) {
        std::string direction = (msg.sender == username) ? "SENT TO " + msg.receiver
                                                           : "RECEIVED FROM " + msg.sender;
        out << "[" << msg.timestamp << "] " << direction << "\n";

        if (msg.cipherName == HybridCrypto::label()) {
            // This file sits in the project folder where anyone can open
            // it, and writeToFile has no private key -- so hybrid messages
            // appear here ONLY as ciphertext. Reading them requires logging
            // in as a participant (Menu > View Chat History).
            out << "  Cipher used : " << msg.cipherName
                << " (session key RSA-wrapped for each participant)\n";
            out << "  Plaintext   : [encrypted -- only " << msg.sender << " or " << msg.receiver
                << " can read this, by logging in]\n";
            out << "  Ciphertext  : " << HexUtil::toHex(msg.ciphertext) << "\n";
        } else {
            out << "  Cipher used : " << msg.cipherName << " (key: " << msg.key << ")\n";
            out << "  Plaintext   : " << msg.plaintext << "\n";
            out << "  Ciphertext  : " << msg.ciphertext << "\n";
        }
        out << "--------------------------------------------------\n";
    }

    out.close();
    std::cout << "[ChatHistory] Transcript written to " << filename << "\n";
}
