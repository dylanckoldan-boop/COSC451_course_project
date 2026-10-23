#pragma once
#include "Cipher.h"
#include <string>

/*
 * RSACipher + free functions
 * --------------------------
 * Two ways to call the same underlying RSA math:
 *
 * - RSACipher (implements Cipher): encrypt(plaintext, "n,e") /
 *   decrypt(ciphertext, "n,d") -- fits the same polymorphic Cipher*
 *   pattern every other algorithm in this project uses, for
 *   chooseCipher()/handleSendMessage()'s normal flow.
 *
 * - RSAEncrypt(text, e, n) / RSADecrypt(text, d, n): the same operation,
 *   but taking the exponent and modulus as separate decimal-string
 *   arguments instead of one combined "n,x" string -- convenient when
 *   you already have an RSAKeyPair's individual e/n/d fields in hand
 *   (e.g. in a benchmark loop), without needing to format/parse a
 *   combined key string just to call through Cipher's interface.
 *
 * RSACipher::encrypt/decrypt are implemented IN TERMS OF these free
 * functions (not duplicated logic) -- the free functions are where the
 * actual big-integer math and the message-size guard live.
 */
std::string RSAEncrypt(const std::string& plaintext, const std::string& e, const std::string& n);
std::string RSADecrypt(const std::string& ciphertext, const std::string& d, const std::string& n);

class RSACipher : public Cipher {
public:
    std::string encrypt(const std::string& plaintext, const std::string& key) const override;
    std::string decrypt(const std::string& ciphertext, const std::string& key) const override;
    std::string name() const override { return "RSA"; }
};
