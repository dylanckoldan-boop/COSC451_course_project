#pragma once
#include <string>

/*
 * DigitalSignature
 * ----------------
 * *** -- Week 6 deliverable. ***
 * RSA signatures over SHA-256 hashes ("hashed message + private key," per
 * the assignment). Used for certificates (CA signs) and for Diffie-Hellman
 * parameters (server signs).
 *
 * The math mirrors RSA encryption with the keys' roles swapped:
 *   sign:   h = SHA-256(message);  signature = h^d mod n   (PRIVATE key)
 *   verify: recovered = signature^e mod n;  valid iff recovered == SHA-256(message)
 *                                                          (PUBLIC key)
 * Only the private-key holder can produce a value that the public key
 * maps back to the right hash; anyone can check it.
 *
 * Keys use the same "n,d" / "n,e" decimal-string format as RSACipher.
 * Useful pieces: SSLUtil::sha256, SSLUtil::fromBytes / toBytes /
 * toDecimal, CryptoPP::Integer, a_exp_b_mod_c (as in RSACipher.cpp).
 *
 * Watch for the leading-zero trap from Week 5: a hash starting with byte
 * 0x00 comes back one byte short from signature^e mod n. Comparing the
 * hashes as BYTE STRINGS then rejects about 1 in 256 genuine signatures
 * -- compare them as Integers, or restore the length with
 * SSLUtil::leftPad first. The test suite signs 1,000 certificates
 * specifically to catch this.
 */
class DigitalSignature {
public:
    // Returns the signature as a decimal string.
    static std::string sign(const std::string& message, const std::string& privateKey);
    // Never throws: malformed input is simply an invalid signature.
    static bool verify(const std::string& message, const std::string& signature,
                       const std::string& publicKey);
};
