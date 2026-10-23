#pragma once
#include <string>

/*
 * ConversationVault
 * ------------------
 * Encrypts a conversation's content into a single shared file that both
 * participants can independently open with the same key -- entirely
 * separate from ChatHistory's per-message .txt transcripts (Week 1's
 * plaintext-visualization files stay exactly as they were). Triggered by
 * an explicit menu action, not automatically on every message send.
 *
 * Filename is derived from BOTH usernames, sorted alphabetically, so
 * either participant computes the same filename independently with no
 * lookup needed: alice + bob -> "alice_bob_secure.dat" regardless of
 * which of them calls seal()/open() or who initiated the conversation.
 *
 * Data travels: Menu gathers both usernames + a shared AES key (already
 * validated via AESKey) + content to protect -> seal() encrypts via
 * AESCipher and writes the file -> later, Menu calls open() with the
 * same two usernames + a key; the right key recovers the content, the
 * wrong key makes AESCipher::decrypt() throw, which open() catches and
 * reports as "couldn't open" rather than crashing or returning garbage.
 */
class ConversationVault {
public:
    static std::string vaultFilename(const std::string& userA, const std::string& userB);

    static void seal(const std::string& userA, const std::string& userB,
                      const std::string& key, const std::string& content);

    // Returns true and fills outContent on success. Returns false (wrong
    // key, or no vault file exists yet) without throwing.
    static bool open(const std::string& userA, const std::string& userB,
                      const std::string& key, std::string& outContent);
};
