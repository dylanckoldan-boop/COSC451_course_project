#pragma once
#include <string>
#include "Certificate.h"
#include "RSAKeys.h"

/*
 * CertificateAuthority
 * --------------------
 * ***  (issue - help) -- Week 6 deliverable. ***
 * A mock CA ("StudentCA"). Its own RSA keypair is what makes its
 * certificates trustworthy: clients that trust this CA hold its public
 * key, and only this CA holds the private key that produces signatures
 * that public key verifies.
 *
 * Data travels: the scenario runner creates the CA -> calls issue() for
 * a server's hostname + public key -> the server presents the returned
 * certificate in its ServerHello -> clients verify it using
 * getPublicKey(), registered in their CertificateValidator.
 */
class CertificateAuthority {
private:
    std::string name;
    RSAKeyPair keys;

public:
    // Generates the CA's keypair (provided).
    explicit CertificateAuthority(const std::string& name, unsigned int keyBits = 1024);

    const std::string& getName() const;
    const std::string& getPublicKey() const;

    // Fill in every field (issuer = this CA's name, a
    // fresh serial number), then sign cert.toBeSigned() with this CA's
    // PRIVATE key using DigitalSignature::sign.
    Certificate issue(const std::string& subject, const std::string& subjectPublicKey,
                      const std::string& expiryDate) const;
};
