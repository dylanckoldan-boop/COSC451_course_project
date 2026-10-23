#include "CertificateValidator.h"
#include "DigitalSignature.h"

namespace {
    // "YYYY-MM-DD" -- the one shape in which comparing dates as strings
    // gives the same answer as comparing them as dates.
    bool isISODate(const std::string& date) {
        if (date.size() != 10 || date[4] != '-' || date[7] != '-') return false;
        for (size_t i = 0; i < date.size(); i++) {
            if (i == 4 || i == 7) continue;
            if (date[i] < '0' || date[i] > '9') return false;
        }
        return true;
    }
}

void CertificateValidator::addTrustedCA(const std::string& caName, const std::string& caPublicKey) {
    trustedCAs[caName] = caPublicKey;
}

ValidationResult CertificateValidator::validate(const Certificate& cert, const std::string& expectedHostname,
                                                const std::string& today) const {
    ValidationResult result;

    // 1. Is the issuer a CA we trust? Its entry supplies the key for check 2.
    auto ca = trustedCAs.find(cert.issuer);
    result.issuerTrusted = ca != trustedCAs.end();
    result.log.push_back(result.issuerTrusted
        ? "[PASS] Issuer '" + cert.issuer + "' is trusted"
        : "[FAIL] Issuer '" + cert.issuer + "' is not trusted (not in the client's trust store)");

    // 2. Did that CA sign these exact fields? toBeSigned() is rebuilt from
    //    the certificate AS RECEIVED, so any edit made after signing shows up.
    if (result.issuerTrusted) {
        result.signatureValid = DigitalSignature::verify(cert.toBeSigned(), cert.signature, ca->second);
        result.log.push_back(result.signatureValid
            ? "[PASS] Certificate signature verifies with " + cert.issuer + "'s public key"
            : "[FAIL] Certificate signature does not verify -- altered after signing, or forged");
    } else {
        result.log.push_back("[FAIL] Certificate signature not checked -- no trusted key for '" +
                             cert.issuer + "'");
    }

    // 3. Still in date? Valid through the expiry date itself.
    if (!isISODate(cert.expiryDate)) {
        result.log.push_back("[FAIL] Expiry date '" + cert.expiryDate + "' is not a YYYY-MM-DD date");
    } else {
        result.notExpired = today <= cert.expiryDate;
        result.log.push_back(result.notExpired
            ? "[PASS] Not expired -- valid through " + cert.expiryDate + " (today is " + today + ")"
            : "[FAIL] Expired -- valid only through " + cert.expiryDate + " (today is " + today + ")");
    }

    // 4. Is it for the site the client meant to reach? This stops a MITM
    //    presenting a genuine certificate that belongs to some other site.
    result.hostnameMatches = cert.subject == expectedHostname;
    result.log.push_back(result.hostnameMatches
        ? "[PASS] Issued to '" + cert.subject + "', the host the client asked for"
        : "[FAIL] Issued to '" + cert.subject + "', but the client asked for '" + expectedHostname + "'");

    // dhParamsAuthentic is left at its default; SimulatedClient sets it for DHE.
    return result;
}
