#pragma once
#include "Cipher.h"

/*
 * CaesarCipher
 * ------------
 * *** STUDENT-OWNED FILE — this is your Week 1 deliverable, not mine. ***
 * Implement the classical single-alphabet shift cipher in CaesarCipher.cpp:
 *   encrypt(): shift each alphabetic character forward by `key` positions
 *              (wrapping z -> a), leave non-letters unchanged.
 *   decrypt(): shift backward by `key` positions to reverse encrypt().
 * The .cpp file currently contains a placeholder pass-through so the rest
 * of the application (menus, accounts, chat history, file I/O) can be run
 * and tested end-to-end before you fill in the real algorithm.
 */
class CaesarCipher : public Cipher {
public:
    std::string encrypt(const std::string& plaintext, const std::string& key) const override;
    std::string decrypt(const std::string& ciphertext, const std::string& key) const override;
    std::string name() const override { return "Caesar Cipher"; }
};
