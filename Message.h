#pragma once
#include <string>

/*
 * Message
 * -------
 * A single unit of communication between two accounts. It deliberately
 * carries BOTH the plaintext and ciphertext (plus which cipher/key made
 * the ciphertext) because this is a visualization sandbox — the whole
 * point of the assignment is to be able to SEE the encryption happen,
 * not to hide the plaintext from yourself as the developer.
 *
 * Data travels: built inside Menu when a user composes a message ->
 * plaintext is run through a Cipher's encrypt() to fill in ciphertext ->
 * the completed Message is handed to MessageChannel::send() -> stored
 * into ChatHistory under both sender's and receiver's history -> later
 * read back out and written to a .txt transcript.
 */
class Message {
public:
    std::string sender;
    std::string receiver;
    std::string plaintext;    // exactly what the user typed via cin
    std::string ciphertext;   // output of Cipher::encrypt(plaintext, key)
    std::string cipherName;   // e.g. "Caesar Cipher" -- which algorithm secured this message
    std::string key;          // the shift/keyword used, kept so decrypt() can be demonstrated
    std::string timestamp;    // simple ordering label (sequence number or clock time)

    Message() = default;
    Message(const std::string& sender, const std::string& receiver,
            const std::string& plaintext, const std::string& ciphertext,
            const std::string& cipherName, const std::string& key,
            const std::string& timestamp);
};
