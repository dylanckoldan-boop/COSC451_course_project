#pragma once
#include "Cipher.h"

/*
 * VigenereCipher
 * --------------
 * *** STUDENT-OWNED FILE — this is your Week 1 deliverable, not mine. ***
 * Implement the polyalphabetic Vigenere cipher in VigenereCipher.cpp:
 *   encrypt(): repeat `key` (a keyword) across the plaintext and shift
 *              each letter by the corresponding key letter's alphabet
 *              position (A=0 ... Z=25), wrapping as needed.
 *   decrypt(): shift backward by the same repeating key to reverse it.
 * The .cpp file currently contains a placeholder pass-through, same as
 * CaesarCipher, for end-to-end testing before you implement the real logic.
 */
class VigenereCipher : public Cipher {
public:
    std::string encrypt(const std::string& plaintext, const std::string& key) const override;
    std::string decrypt(const std::string& ciphertext, const std::string& key) const override;
    std::string name() const override { return "Vigenere Cipher"; }
};
