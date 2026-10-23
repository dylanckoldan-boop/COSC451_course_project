#pragma once
#include <string>

/*
 * Cipher (abstract interface / Strategy pattern)
 * -----------------------------------------------
 * This is the ONE contract every cipher algorithm in this project must
 * satisfy. Menu and Message never know or care WHICH cipher is running —
 * they just hold a Cipher* and call encrypt()/decrypt() on it. This is
 * what lets a new cipher (Week 2, Week 3, ...) be dropped in as its own
 * pair of files without touching Account, Message, ChatHistory, or Menu.
 *
 * Data travels: Menu selects a concrete cipher (e.g. new CaesarCipher())
 * -> passes plaintext + key into encrypt() -> the returned ciphertext is
 * stored on a Message object -> later, decrypt() is called with the same
 * key to demonstrate/verify the round trip before both strings are
 * written to the .txt transcript.
 */
class Cipher {
public:
    virtual ~Cipher() = default;

    // plaintext  -> ciphertext, using the supplied key (shift # for Caesar,
    // keyword for Vigenere). Implemented per-cipher, NOT here.
    virtual std::string encrypt(const std::string& plaintext, const std::string& key) const = 0;

    // ciphertext -> plaintext, the inverse of encrypt() using the same key.
    virtual std::string decrypt(const std::string& ciphertext, const std::string& key) const = 0;

    // Human-readable label stored on Message/ChatHistory so a reader of the
    // transcript file knows which algorithm secured that specific message.
    virtual std::string name() const = 0;
};
