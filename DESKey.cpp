#include "DESKey.h"
#include <iostream>

/*
 * *** STUDENT-OWNED FILE ***
 * TODO (Week 2): Replace this placeholder logic with your real DES key
 * validation and padding scheme. Right now it accepts ANY non-empty input
 * and copies it through unchanged (truncated/left as-is, no real padding),
 * purely so Menu's DES flow can be built and tested before your key logic
 * exists. This is NOT a valid DES key length check -- do not leave it
 * this way for submission.
 * 9/9/26 edits begin from here: DES keys are 8 bytes (64 bits) long, but only 56 bits are used for the key; the remaining 8 bits are used for parity. Therefore, a valid DES key should be exactly 8 bytes long. You should implement a check to ensure that the input is exactly 8 bytes and handle parity bits appropriately.
 */
DESKey::DESKey(const std::string& userInput) : rawInput(userInput) {
    //std::cout << "[DESKey] TODO not yet implemented -- accepting any non-empty key as a placeholder.\n";
	//empty key check
    if (rawInput.empty()) {
        valid = false;
        validationError = "Key cannot be empty.";
        return;
    }

    // Placeholder only: real DES key material (8 bytes / 64 bits, with
    // parity considerations) is NOT the same thing as "whatever the user
    // typed." Implement your actual validation + padding rule here.
	// 9/9/2026 edits: Check if the input is exactly 8 bytes long
    keyMaterial = rawInput;
	while (keyMaterial.length() < 8) {
		// notify user that the key is too short and will be padded with null bytes
		if (keyMaterial.length() == 7) {
			std::cout << "Key is too short. Padding with null bytes to make it 8 bytes long.\n";
		}
		keyMaterial += '\0'; // Pad with null bytes if less than 8 bytes
	}
	while (keyMaterial.length() > 8) {
		// notify user that the key is too long and will be truncated
		if (keyMaterial.length() == 9) {
			std::cout << "Key is too long. Truncating to 8 bytes.\n";
		}
		keyMaterial = keyMaterial.substr(0, 8); // Truncate to 8 bytes if more than 8 bytes
	}
    valid = true;
}

bool DESKey::isValid() const {
    return valid;
}

std::string DESKey::getKeyMaterial() const {
    return keyMaterial;
}

std::string DESKey::getValidationError() const {
    return validationError;
}
