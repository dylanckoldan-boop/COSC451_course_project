#pragma once
#include "Cipher.h"

/*
 * AESCipher
 * ---------
 * Implements the Cipher interface using Crypto++'s AES in CBC mode with
 * PKCS#7 padding. Unlike CaesarCipher/VigenereCipher/DESCipher, this is
 * NOT hand-rolled -- Part 1 of the Week 3 assignment explicitly allows an
 * established library for AES, and this class's job is to call it
 * correctly (CBC mode, IV handling, PKCS7 padding, key-length selection)
 * and expose the same Cipher interface everything else in this project
 * already relies on.
 *
 * Key length: Crypto++ auto-selects AES-128/192/256 based on the byte
 * length of `key` (16/24/32). AESKey is responsible for guaranteeing
 * `key` is already one of those exact lengths before it reaches here.
 *
 * IV handling: CBC mode needs a random, unique IV per encryption --
 * reusing one leaks information across messages under the same key.
 * encrypt() generates one and prepends its 16 raw bytes to the returned
 * ciphertext; decrypt() reads those bytes back off before decrypting the
 * rest. This means ciphertext from this class is raw binary, not
 * printable text or a '0'/'1' string like DESCipher's -- keep that in
 * mind wherever this ciphertext gets written or displayed.
 */
class AESCipher : public Cipher {
public:
    std::string encrypt(const std::string& plaintext, const std::string& key) const override;
    std::string decrypt(const std::string& ciphertext, const std::string& key) const override;
    std::string name() const override { return "AES"; }
};
