#pragma once
#include "Cipher.h"

/*
 * DESCipher
 * ---------
 * *** STUDENT-OWNED FILE -- Week 2 deliverable. ***
 * Implements the Cipher interface for the Data Encryption Standard.
 * By the time `key` reaches encrypt()/decrypt() here, Menu has already
 * run it through DESKey for validation/padding -- assume it's the actual
 * key material DES needs, not raw untrusted user input.
 *
 * TODO: implement DES (Feistel network: initial permutation, 16 rounds of
 * expansion/S-box substitution/permutation with round keys derived via
 * key schedule, final permutation) per your assignment spec.
 */
class DESCipher : public Cipher {
public:
    std::string encrypt(const std::string& plaintext, const std::string& key) const override;
    std::string decrypt(const std::string& ciphertext, const std::string& key) const override;
    std::string name() const override { return "DES"; }
};
