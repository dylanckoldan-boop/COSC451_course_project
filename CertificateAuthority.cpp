#include "CertificateAuthority.h"
#include "DigitalSignature.h"
#include "SSLUtil.h"
#include "HexUtil.h"

CertificateAuthority::CertificateAuthority(const std::string& name, unsigned int keyBits)
    : name(name), keys(RSAKeys::generate(keyBits)) {}

const std::string& CertificateAuthority::getName() const {
    return name;
}

const std::string& CertificateAuthority::getPublicKey() const {
    return keys.publicKey;
}

Certificate CertificateAuthority::issue(const std::string& subject, const std::string& subjectPublicKey,
                                        const std::string& expiryDate) const {
    Certificate cert;
    cert.serialNumber = HexUtil::toHex(SSLUtil::randomBytes(8)); // 64 random bits: unique in practice
    cert.subject = subject;
    cert.issuer = name;
    cert.publicKey = subjectPublicKey;
    cert.expiryDate = expiryDate;

    // Signed last, over every other field. Only this CA's private key can
    // produce a signature that its public key (in clients' trust stores)
    // will verify.
    cert.signature = DigitalSignature::sign(cert.toBeSigned(), keys.privateKey);
    return cert;
}
