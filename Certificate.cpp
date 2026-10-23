#include "Certificate.h"

namespace {
    // One field in length-prefixed form: "<byte count>:<bytes>,".
    // The count says exactly where each field ends, so no field's
    // contents -- whatever characters they contain -- can be read as part
    // of the next field. That is what makes toBeSigned() unambiguous.
    std::string lengthPrefixed(const std::string& value) {
        return std::to_string(value.size()) + ":" + value + ",";
    }
}

std::string Certificate::toBeSigned() const {
    // Every field except `signature` (it can't cover itself), in a fixed
    // order. The header's example no longer collides: subject "ab" +
    // issuer "c" encodes as "2:ab,1:c," but subject "a" + issuer "bc"
    // encodes as "1:a,2:bc,".
    return lengthPrefixed(serialNumber) +
           lengthPrefixed(subject) +
           lengthPrefixed(issuer) +
           lengthPrefixed(publicKey) +
           lengthPrefixed(expiryDate);
}

std::string Certificate::describe() const {
    std::string sigPreview = signature.empty() ? "(none)" : signature.substr(0, 24) + "...";
    std::string keyPreview = publicKey.empty() ? "(none)" : publicKey.substr(0, 24) + "...";
    return "        Subject    : " + subject + "\n"
           "        Issuer     : " + issuer + "\n"
           "        Serial     : " + serialNumber + "\n"
           "        Expires    : " + expiryDate + "\n"
           "        Public key : " + keyPreview + "\n"
           "        Signature  : " + sigPreview + "\n";
}
