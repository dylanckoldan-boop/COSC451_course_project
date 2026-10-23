#include "AESKey.h"
#include <iostream>

AESKey::AESKey(const std::string& userInput, AESKeySize keySize)
    : rawInput(userInput), size(keySize) {
    if (rawInput.empty()) {
        valid = false;
        validationError = "Key cannot be empty.";
        return;
    }

    size_t targetLength = static_cast<size_t>(size);
    keyMaterial = rawInput;

    if (keyMaterial.length() < targetLength) {
        std::cout << "Key is shorter than " << targetLength
                   << " bytes. Padding with null bytes.\n";
        keyMaterial += std::string(targetLength - keyMaterial.length(), '\0');
    } else if (keyMaterial.length() > targetLength) {
        std::cout << "Key is longer than " << targetLength
                   << " bytes. Truncating.\n";
        keyMaterial = keyMaterial.substr(0, targetLength);
    }

    valid = true;
}

bool AESKey::isValid() const { return valid; }
std::string AESKey::getKeyMaterial() const { return keyMaterial; }
std::string AESKey::getValidationError() const { return validationError; }
size_t AESKey::getKeyLengthBytes() const { return static_cast<size_t>(size); }
