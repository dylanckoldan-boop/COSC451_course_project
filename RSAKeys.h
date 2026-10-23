#pragma once
#include <string>

/*
 * RSAKeys
 * -------
 * Key generation for RSA. Unlike DESKey/AESKey (which validate a key the
 * USER typed in), RSA keys aren't something a person types -- they're
 * generated. generate() produces a fresh keypair and returns both halves
 * serialized as decimal-string pairs ("n,e" for public, "n,d" for
 * private) so they can be handed straight into RSACipher::encrypt()/
 * decrypt() as the `key` parameter, and are directly printable to
 * satisfy the assignment's "clear console output showing public and
 * private keys" requirement.
 *
 * *** STUDENT DECISION POINT, not a stub: *** how d gets computed inside
 * generate() (in RSAKeys.cpp) is a real choice with two legitimate
 * answers -- see the comment there before you touch it.
 */
struct RSAKeyPair {
    std::string publicKey;  // "n,e" -- give this to encrypt()
    std::string privateKey; // "n,d" -- give this to decrypt()
    // Kept for display/debugging only -- never transmitted in real RSA.
    std::string p, q, n, phi, e, d;
};

class RSAKeys {
public:
    // keyBits = bit length of the modulus n (p and q are each ~keyBits/2
    // bits). 512 is fast for testing; the assignment's Part 3 discussion
    // of 1024 vs 2048-bit security implies you'll want to demo a larger
    // size at least once for the real deliverable output.
    static RSAKeyPair generate(unsigned int keyBits = 512);
};
