#include "DigitalSignature.h"
#include "SSLUtil.h"
#include <cryptopp/integer.h>
#include <cryptopp/nbtheory.h>
#include <stdexcept>

using CryptoPP::Integer;

namespace {
    // True for a non-empty run of decimal digits. CryptoPP::Integer's
    // string constructor never rejects bad text -- it skips characters it
    // doesn't recognize ("12x3" -> 123), and a trailing 'h' switches it
    // to hex -- so strings from outside are checked before parsing.
    bool isDecimal(const std::string& text) {
        return !text.empty() && text.find_first_not_of("0123456789") == std::string::npos;
    }

    // Splits a key in RSAKeys' "n,exponent" format into Integers.
    bool parseKey(const std::string& key, Integer& n, Integer& exponent) {
        size_t comma = key.find(',');
        if (comma == std::string::npos) return false;
        std::string nText = key.substr(0, comma);
        std::string expText = key.substr(comma + 1);
        if (!isDecimal(nText) || !isDecimal(expText)) return false;
        n = Integer(nText.c_str());
        exponent = Integer(expText.c_str());
        return n > Integer::One() && exponent.IsPositive();
    }
}

std::string DigitalSignature::sign(const std::string& message, const std::string& privateKey) {
    Integer n, d;
    if (!parseKey(privateKey, n, d)) {
        throw std::invalid_argument("DigitalSignature::sign: private key must be \"n,d\" in decimal");
    }

    Integer h = SSLUtil::fromBytes(SSLUtil::sha256(message));
    if (h >= n) {
        // Only possible with a toy key of 256 bits or fewer.
        throw std::invalid_argument("DigitalSignature::sign: key too small to sign a 256-bit hash");
    }

    // signature = h^d mod n. (Production RSA pads h first -- PKCS#1 v1.5 or
    // PSS; this is the textbook "hash + private key" form.)
    return SSLUtil::toDecimal(a_exp_b_mod_c(h, d, n));
}

bool DigitalSignature::verify(const std::string& message, const std::string& signature,
                              const std::string& publicKey) {
    try {
        Integer n, e;
        if (!parseKey(publicKey, n, e) || !isDecimal(signature)) return false;

        // A genuine signature is always below n. Rejecting anything else
        // stops "s + n" from passing as a second valid signature.
        Integer s(signature.c_str());
        if (s >= n) return false;

        // recovered = s^e mod n, compared with the hash AS INTEGERS. A hash
        // whose first byte is 0x00 comes back from the math one byte short;
        // comparing byte strings would reject ~1 in 256 genuine signatures.
        Integer recovered = a_exp_b_mod_c(s, e, n);
        return recovered == SSLUtil::fromBytes(SSLUtil::sha256(message));
    } catch (...) {
        return false; // malformed input is simply an invalid signature
    }
}
