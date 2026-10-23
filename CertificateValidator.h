#pragma once
#include <map>
#include <string>
#include <vector>
#include "Certificate.h"

/*
 * ValidationResult
 * ----------------
 * One flag per check, plus clear log lines. Flags are kept
 * separate (instead of one bool) so the test scenarios can confirm each
 * attack was rejected by the RIGHT check -- a validator that rejects
 * everything would otherwise "pass" every attack test while being broken.
 */
struct ValidationResult {
    bool issuerTrusted = false;
    bool signatureValid = false;
    bool notExpired = false;
    bool hostnameMatches = false;
    // Only meaningful for Diffie-Hellman: did the server's signature over
    // its DH parameters verify? Stays true for RSA key exchange, where
    // there are no signed parameters.
    bool dhParamsAuthentic = true;

    std::vector<std::string> log; // e.g. "[PASS] Issuer 'issuerCA' is trusted"

    bool valid() const {
        return issuerTrusted && signatureValid && notExpired && hostnameMatches && dhParamsAuthentic;
    }
};

/*
 * CertificateValidator
 * --------------------
 * ***  (validate) -- Week 6 deliverable. ***
 * The client's trust store: which CAs it trusts, and each one's public
 * key. In real life this ships with the operating system or browser.
 *
 * Data travels: scenario runner calls addTrustedCA() for issuerCA ->
 * SimulatedClient holds a reference to this validator -> calls
 * validate() on the certificate from the ServerHello.
 */
class CertificateValidator {
private:
    std::map<std::string, std::string> trustedCAs; // CA name -> CA public key "n,e"

public:
    void addTrustedCA(const std::string& caName, const std::string& caPublicKey);

    // Run EVERY check (don't stop at the first failure --
    // the full report makes better log output), set each flag, and add a
    // log line per check:
    //  1. issuerTrusted   -- cert.issuer is in trustedCAs. (Needed first:
    //                        it supplies the public key for check 2. If
    //                        the issuer is unknown, signatureValid stays
    //                        false -- there's no key to check it with.)
    //  2. signatureValid  -- DigitalSignature::verify(cert.toBeSigned(),
    //                        cert.signature, <issuer's public key>)
    //  3. notExpired      -- today <= cert.expiryDate (ISO dates compare
    //                        correctly as strings)
    //  4. hostnameMatches -- cert.subject == expectedHostname. Not in the
    //                        assignment's list, but it's the check that
    //                        stops a MITM presenting a VALID certificate
    //                        for a different site.
    // Leave dhParamsAuthentic alone; SimulatedClient sets it for DHE.
    ValidationResult validate(const Certificate& cert, const std::string& expectedHostname,
                              const std::string& today) const;
};
