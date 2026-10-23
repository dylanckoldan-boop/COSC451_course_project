#pragma once
#include <string>

/*
 * DESKey
 * ------
 * *** STUDENT-OWNED FILE -- Week 2 deliverable. ***
 * DES needs a 64-bit (8-byte) key. This class is where the "is this key
 * usable" question and any padding/truncation policy live, kept SEPARATE
 * from DESCipher so the algorithm itself never has to worry about
 * malformed input -- by the time DESCipher::encrypt/decrypt sees a key,
 * it's already been through here.
 *
 * Data travels: Menu reads a raw key string from cin -> constructs a
 * DESKey with it -> Menu checks isValid() and, if false, shows
 * getValidationError() and re-prompts -> once valid, Menu passes
 * getKeyMaterial() (not the raw input) into DESCipher::encrypt/decrypt.
 *
 * TODO (Week 2): decide and implement your key format rule -- e.g. exactly
 * 8 ASCII characters, or a 16-character hex string representing 8 bytes --
 * and your padding/truncation policy if the user's input doesn't match it
 * exactly. Wire the real logic into isValid() / getKeyMaterial() below.
 */
class DESKey {
private:
    std::string rawInput;     // exactly what the user typed at the console
    std::string keyMaterial;  // validated/padded key, ready for DESCipher
    bool valid = false;
    std::string validationError;

public:
    explicit DESKey(const std::string& userInput);

    bool isValid() const;
    std::string getKeyMaterial() const;
    std::string getValidationError() const;
};
