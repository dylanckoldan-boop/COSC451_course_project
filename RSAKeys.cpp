#include "RSAKeys.h"
#include <cryptopp/integer.h>
#include <cryptopp/osrng.h>
#include <cryptopp/nbtheory.h>
#include <sstream>
#include <stdexcept>

using CryptoPP::Integer;
using CryptoPP::AutoSeededRandomPool;

// Serializes a CryptoPP::Integer to a plain decimal string via its
// stream insertion operator -- human-readable, and directly re-parseable
// by the Integer(const char*) constructor.
static std::string toDecimalString(const Integer& value) {
    std::ostringstream oss;
    oss << value;
    std::string s = oss.str();
    // CryptoPP appends a trailing '.' to indicate decimal base -- strip
    // it so the string round-trips cleanly through Integer's own
    // constructor and isn't confusing in printed output.
    if (!s.empty() && s.back() == '.') {
        s.pop_back();
    }
    return s;
}

RSAKeyPair RSAKeys::generate(unsigned int keyBits) {
    AutoSeededRandomPool rng;

    unsigned int primeBits = keyBits / 2;
    Integer minP = Integer::Power2(primeBits - 1);
    Integer maxP = Integer::Power2(primeBits) - 1;

    Integer p(rng, minP, maxP, Integer::PRIME);
    Integer q(rng, minP, maxP, Integer::PRIME);
    // In the (extremely unlikely) event the RNG hands back the same
    // prime twice, n = p*q would factor trivially -- regenerate q.
    while (q == p) {
        q = Integer(rng, minP, maxP, Integer::PRIME);
    }

    Integer n = p * q;
    Integer phi = (p - 1) * (q - 1);
    Integer e(65537L); // the conventional public exponent

    // *** STUDENT DECISION POINT ***
    // Computing d such that d = e^-1 mod phi is the assignment's
    // explicitly named "write a function to compute the private
    // exponent" requirement. Two legitimate ways to do it:
    //
    //   Option A (reuse your own Week 4 work): adapt mod_inverse's
    //   Extended Euclidean logic from NumberTheory.cpp to operate on
    //   CryptoPP::Integer instead of uint64_t, and call that here.
    //
    //   Option B (use Crypto++'s own primitive): phi.InverseMod(e) --
    //   arguably a big-integer arithmetic primitive like +/-/*, same
    //   category as a_exp_b_mod_c being fine to use for encrypt/decrypt.
    //
    // This is intentionally NOT decided for you -- pick one and replace
    // the line below with your actual computation.
    //Integer d = Integer::Zero(); // TODO: replace with your computed d
	Integer d = e.InverseMod(phi); // Using Crypto++'s built-in function for modular inverse
    // This is decision to use the Crypto++ built-in function for modular inverse is already optimized and secure.
	// It is a more realistic approach for a production-level RSA implementation, and it is acceptable for this assignment.

    RSAKeyPair keys;
    keys.p = toDecimalString(p);
    keys.q = toDecimalString(q);
    keys.n = toDecimalString(n);
    keys.phi = toDecimalString(phi);
    keys.e = toDecimalString(e);
    keys.d = toDecimalString(d);
    keys.publicKey = keys.n + "," + keys.e;
    keys.privateKey = keys.n + "," + keys.d;
    return keys;
}
