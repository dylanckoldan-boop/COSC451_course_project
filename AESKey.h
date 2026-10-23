#pragma once
#include <string>

/*
 * AESKey
 * ------
 * Mirrors DESKey's role and shape exactly: validate/pad raw user input
 * into key material a Cipher can use, kept separate from the algorithm
 * itself. The difference from DESKey is the target length -- AES offers
 * three valid key sizes (128/192/256-bit = 16/24/32 bytes), chosen at
 * construction time rather than being a single fixed size like DES's 8.
 *
 * Data travels: Menu reads a raw key string from cin -> constructs an
 * AESKey with the desired size -> Menu checks isValid() and, if false,
 * shows getValidationError() and re-prompts -> once valid, Menu passes
 * getKeyMaterial() into AESCipher::encrypt/decrypt (or into
 * ConversationVault, which forwards it the same way).
 */
enum class AESKeySize {
    AES128 = 16,
    AES192 = 24,
    AES256 = 32
};

class AESKey {
private:
    std::string rawInput;
    std::string keyMaterial;
    bool valid = false;
    std::string validationError;
    AESKeySize size;

public:
    explicit AESKey(const std::string& userInput, AESKeySize keySize = AESKeySize::AES256);

    bool isValid() const;
    std::string getKeyMaterial() const;
    std::string getValidationError() const;
    size_t getKeyLengthBytes() const;
};
