#include "RSACipher.h"
#include <cryptopp/integer.h>
#include <sstream>
#include <stdexcept>
#include <vector>

using CryptoPP::Integer;
using CryptoPP::byte;

static Integer bytesToInteger(const std::string& text) {
    return Integer(reinterpret_cast<const byte*>(text.data()), text.size());
}

static std::string integerToBytes(const Integer& value) {
    size_t size = value.MinEncodedSize();
    std::vector<byte> buffer(size);
    value.Encode(buffer.data(), size);
    return std::string(reinterpret_cast<char*>(buffer.data()), size);
}

static std::string integerToDecimalString(const Integer& value) {
    std::ostringstream oss;
    oss << value;
    std::string s = oss.str();
    if (!s.empty() && s.back() == '.') s.pop_back();
    return s;
}

std::string RSAEncrypt(const std::string& plaintext, const std::string& e, const std::string& n) {
    Integer E(e.c_str());
    Integer N(n.c_str());

    Integer m = bytesToInteger(plaintext);
    if (m >= N) {
        throw std::invalid_argument(
            "Message too large for this RSA key -- textbook RSA has no block "
            "splitting, so the whole message must fit under the modulus n. "
            "Use a larger key or a shorter message/session key.");
    }

    Integer c = a_exp_b_mod_c(m, E, N);
    return integerToDecimalString(c);
}

std::string RSADecrypt(const std::string& ciphertext, const std::string& d, const std::string& n) {
    Integer D(d.c_str());
    Integer N(n.c_str());

    Integer c(ciphertext.c_str());
    Integer m = a_exp_b_mod_c(c, D, N);
    return integerToBytes(m);
}

// RSACipher just parses the combined "n,x" key string and forwards to
// the free functions above -- same math, no duplicated logic.
static void splitKey(const std::string& key, std::string& n, std::string& x) {
    size_t comma = key.find(',');
    if (comma == std::string::npos) {
        throw std::invalid_argument("RSA key must be formatted as \"n,exponent\".");
    }
    n = key.substr(0, comma);
    x = key.substr(comma + 1);
}

std::string RSACipher::encrypt(const std::string& plaintext, const std::string& key) const {
    std::string n, e;
    splitKey(key, n, e);
    return RSAEncrypt(plaintext, e, n);
}

std::string RSACipher::decrypt(const std::string& ciphertext, const std::string& key) const {
    std::string n, d;
    splitKey(key, n, d);
    return RSADecrypt(ciphertext, d, n);
}
