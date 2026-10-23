#pragma once
#include <string>
#include <vector>
#include <unordered_map>
#include "Message.h"

/*
 * ChatHistory
 * -----------
 * Stores every Message that has crossed the MessageChannel, indexed by
 * username so the SAME conversation can be viewed from either account's
 * point of view.
 *
 * As of this week, every message is also appended to chat_log.db the
 * moment it's sent, and that log is read back at startup -- so history
 * survives restarts. The <username>_chat_history.txt files are still
 * human-readable VIEWS regenerated from memory by writeToFile(); the
 * .db log is the actual source of truth they're rebuilt from.
 *
 * Data travels: MessageChannel::send() -> addMessage() -> in-memory map
 * AND one appended line in chat_log.db. At startup, Menu calls
 * loadFromDisk() -> each logged line goes back into the in-memory map
 * only (not re-appended, which would duplicate it).
 */
class ChatHistory {
private:
    // key = account username, value = every message that touched that account
    std::unordered_map<std::string, std::vector<Message>> historyByAccount;
    size_t totalMessages = 0;          // each message counted once, not twice
    std::string logPath = "chat_log.db";

    void addToMemory(const Message& msg);
    bool appendToDisk(const Message& msg) const;

public:
    void addMessage(const Message& msg);
    const std::vector<Message>& getHistoryFor(const std::string& username) const;
    void writeToFile(const std::string& username) const;

    // Returns false if chat_log.db existed but couldn't be read -- the
    // file is then renamed to chat_log.db.unreadable and history starts empty.
    bool loadFromDisk();
    size_t messageCount() const;
};
