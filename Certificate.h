#pragma once
#include <string>

/*
 * Certificate
 * -----------
 * ***  (toBeSigned) -- Week 6 deliverable. ***
 * A mock X.509-style digital certificate: a CA's signed statement that
 * "this public key belongs to this entity, until this date."
 *
 * Data travels: CertificateAuthority::issue() fills every field, then
 * signs toBeSigned() with the CA's private key -> the server sends the
 * certificate inside its ServerHello -> the client's
 * CertificateValidator recomputes toBeSigned() from the fields AS
 * RECEIVED and checks the signature with the issuer's public key. Any
 * field changed after signing -- in storage or in transit -- produces
 * different toBeSigned() bytes, and the signature check fails.
 */
struct Certificate {
    std::string serialNumber;   // unique per certificate (hex)
    std::string subject;        // entity name, e.g. "www.securechat.com"
    std::string issuer;         // CA name, e.g. "StudentCA"
    std::string publicKey;      // the SUBJECT's RSA public key, "n,e"
    std::string expiryDate;     // "YYYY-MM-DD"
    std::string signature;      // CA's RSA signature over toBeSigned() (decimal string)

    // The exact bytes the CA signs -- every field EXCEPT
    // signature (a signature can't cover itself).
    //
    // Two properties matter:
    //  1. Complete: a field left out can be changed without breaking the
    //     signature. Leave out publicKey, and an attacker can swap in
    //     their own key under a perfectly valid signature.
    //  2. Unambiguous: different certificates must never produce the same
    //     bytes. Plain concatenation fails this: subject "ab" + issuer
    //     "c" and subject "a" + issuer "bc" both give "abc". Use a
    //     separator that can't appear inside a field, or prefix each
    //     field with its length.
    std::string toBeSigned() const;

    // Multi-line, human-readable summary for the handshake log (provided).
    std::string describe() const;
};
