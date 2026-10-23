#include "SSLScenarios.h"
#include "SSLHandshake.h"
#include "SSLUtil.h"
#include "CertificateAuthority.h"
#include "CertificateValidator.h"
#include "RSAKeys.h"
#include <cryptopp/integer.h>
#include <cryptopp/nbtheory.h>
#include <iostream>
#include <iomanip>
#include <string>
#include <vector>

namespace {

const char* const HOST = "www.securechat.com";

// The simulated world every scenario runs in.
struct World {
    CertificateAuthority issuerCA;   // trusted by the client
    CertificateAuthority evilCA;      // NOT trusted by the client
    CertificateValidator validator;   // the client's trust store
    RSAKeyPair serverKeys;            // the honest server's long-term keys
    RSAKeyPair attackerKeys;
    Certificate goodCert;             // issuerCA-issued, valid, for HOST
    std::string today;

    World()
        : issuerCA("issuerCA"), evilCA("EvilCA"),
          serverKeys(RSAKeys::generate(1024)), attackerKeys(RSAKeys::generate(1024)),
          today(SSLUtil::todayISODate()) {
        validator.addTrustedCA(issuerCA.getName(), issuerCA.getPublicKey());
        goodCert = issuerCA.issue(HOST, serverKeys.publicKey, SSLUtil::dateYearsFromToday(1));
    }
};

// The exact check outcome a correct implementation produces for an attack.
struct Expected {
    bool issuerTrusted, signatureValid, notExpired, hostnameMatches, dhParamsAuthentic;
};

std::string flagWord(bool ok) { return ok ? "ok" : "FAILED"; }

std::string describeFlags(const ValidationResult& v) {
    return "issuer " + flagWord(v.issuerTrusted) + ", signature " + flagWord(v.signatureValid) +
           ", expiry " + flagWord(v.notExpired) + ", hostname " + flagWord(v.hostnameMatches) +
           ", DH params " + flagWord(v.dhParamsAuthentic);
}

std::string describeExpected(const Expected& e) {
    ValidationResult v;
    v.issuerTrusted = e.issuerTrusted; v.signatureValid = e.signatureValid;
    v.notExpired = e.notExpired; v.hostnameMatches = e.hostnameMatches;
    v.dhParamsAuthentic = e.dhParamsAuthentic;
    return describeFlags(v);
}

bool matches(const ValidationResult& v, const Expected& e) {
    return v.issuerTrusted == e.issuerTrusted && v.signatureValid == e.signatureValid &&
           v.notExpired == e.notExpired && v.hostnameMatches == e.hostnameMatches &&
           v.dhParamsAuthentic == e.dhParamsAuthentic;
}

struct Tally {
    int pass = 0, fail = 0;
    void record(bool ok, const std::string& label, const std::string& detail = "") {
        (ok ? pass : fail)++;
        std::cout << (ok ? "  [PASS] " : "  [FAIL] ") << label << "\n";
        if (!detail.empty()) std::cout << "         " << detail << "\n";
    }
};

bool runHonest(World& w, bool useDHE, bool verbose, Tally* tally) {
    KeyExchangeMethod method = useDHE ? KeyExchangeMethod::DHE : KeyExchangeMethod::RSA;
    SimulatedServer server(HOST, w.serverKeys, w.goodCert, method);
    SimulatedClient client(HOST, w.validator);
    HandshakeResult r = runHandshake(client, server, w.today, verbose);

    bool keysAgree = r.success && client.getSessionKey() == server.getSessionKey()
                     && client.getSessionKey().size() == 32;
    if (tally) {
        std::string label = std::string("Honest ") + (useDHE ? "DHE" : "RSA") +
                            " handshake succeeds with matching 32-byte session keys";
        std::string detail;
        if (!r.success) detail = "stopped at " + r.failedStage + ": " + r.reason;
        else if (!keysAgree) detail = "completed, but the session keys differ or aren't 32 bytes";
        tally->record(keysAgree, label, detail);
    }
    return keysAgree;
}

struct Attack {
    std::string name;
    std::string explanation;  // what the attacker is attempting, for the log
    Expected expected;
};

void runAttacks(World& w, bool verbose, Tally& tally) {
    // A: a genuinely expired certificate (signed by issuerCA, expiry in the past)
    Certificate expiredCert = w.issuerCA.issue(HOST, w.serverKeys.publicKey, "2020-01-01");

    // B: the attacker takes that expired cert and edits the date forward,
    //    hoping nobody notices the signature no longer matches
    Certificate extendedCert = expiredCert;
    extendedCert.expiryDate = SSLUtil::dateYearsFromToday(5);

    // C: a certificate for HOST from a CA the client doesn't trust
    Certificate evilCert = w.evilCA.issue(HOST, w.attackerKeys.publicKey, SSLUtil::dateYearsFromToday(1));

    // D: a perfectly valid issuerCA certificate -- for the attacker's OWN site
    Certificate otherSiteCert = w.issuerCA.issue("www.evil-site.com", w.attackerKeys.publicKey,
                                                  SSLUtil::dateYearsFromToday(1));

    struct Case {
        Attack attack;
        Certificate cert;
        RSAKeyPair keys;
        KeyExchangeMethod method;
        ServerHelloTamper tamper;
    };

    std::string attackerPublicKey = w.attackerKeys.publicKey;
    std::vector<Case> cases;

    cases.push_back({{"Expired certificate",
                      "Server presents a genuine issuerCA certificate that expired on 2020-01-01.",
                      {true, true, false, true, true}},
                     expiredCert, w.serverKeys, KeyExchangeMethod::RSA, ServerHelloTamper()});

    cases.push_back({{"Forged expiry date (certificate edited after signing)",
                      "Attacker edits the expired certificate's date to five years from now.",
                      {true, false, true, true, true}},
                     extendedCert, w.serverKeys, KeyExchangeMethod::RSA, ServerHelloTamper()});

    cases.push_back({{"Untrusted issuer",
                      "Attacker presents a certificate for www.securechat.com signed by EvilCA.",
                      {false, false, true, true, true}},
                     evilCert, w.attackerKeys, KeyExchangeMethod::RSA, ServerHelloTamper()});

    cases.push_back({{"Impostor with a valid certificate for a different site",
                      "Attacker answers for www.securechat.com using a real issuerCA certificate "
                      "issued to www.evil-site.com.",
                      {true, true, true, false, true}},
                     otherSiteCert, w.attackerKeys, KeyExchangeMethod::RSA, ServerHelloTamper()});

    cases.push_back({{"Man-in-the-middle swaps the certificate's public key (RSA)",
                      "Honest server, but an attacker on the wire replaces the certificate's public "
                      "key with their own, hoping the client encrypts the pre-master to them.",
                      {true, false, true, true, true}},
                     w.goodCert, w.serverKeys, KeyExchangeMethod::RSA,
                     [attackerPublicKey](ServerHello& sh) { sh.certificate.publicKey = attackerPublicKey; }});

    // The attacker's own DH value: g^m mod p for a secret m only they know.
    CryptoPP::Integer p = SSLUtil::dhGroup14Prime();
    CryptoPP::Integer m = SSLUtil::fromBytes(SSLUtil::randomBytes(32));
    std::string attackerDH = SSLUtil::toDecimal(a_exp_b_mod_c(SSLUtil::dhGroup14Generator(), m, p));
    cases.push_back({{"Man-in-the-middle swaps the DH public value (DHE)",
                      "Honest server and valid certificate, but an attacker on the wire replaces the "
                      "server's DH public value with their own, to compute the session key themselves.",
                      {true, true, true, true, false}},
                     w.goodCert, w.serverKeys, KeyExchangeMethod::DHE,
                     [attackerDH](ServerHello& sh) { sh.dhServerPublic = attackerDH; }});

    for (const Case& c : cases) {
        if (verbose) {
            std::cout << "\n\n######## ATTACK: " << c.attack.name << " ########\n"
                      << c.attack.explanation << "\n";
        }
        SimulatedServer server(HOST, c.keys, c.cert, c.method);
        SimulatedClient client(HOST, w.validator);
        HandshakeResult r = runHandshake(client, server, w.today, verbose, c.tamper);

        bool rejectedAtRightStage = !r.success && r.failedStage == "CertificateVerification";
        bool rightReasons = matches(r.validation, c.attack.expected);
        std::string detail;
        if (r.success) {
            detail = "the handshake SUCCEEDED -- the attack was not detected";
        } else if (!rejectedAtRightStage) {
            detail = "stopped at " + r.failedStage + " (" + r.reason + "), expected CertificateVerification";
        } else if (!rightReasons) {
            detail = "rejected, but for the wrong reasons:\n"
                     "         expected: " + describeExpected(c.attack.expected) + "\n"
                     "         got:      " + describeFlags(r.validation);
        }
        if (verbose) std::cout << "\n";
        tally.record(rejectedAtRightStage && rightReasons, "Attack rejected: " + c.attack.name, detail);
    }
}

void runReliability(World& w, Tally& tally) {
    // ~1 in 256 SHA-256 hashes starts with byte 0x00; across 1,000 genuine
    // certificates that's about 4 expected cases, so a verify() that
    // drops leading zero bytes fails here almost every run (98%+).
    const int COUNT = 1000;
    int rejected = 0;
    for (int i = 0; i < COUNT; i++) {
        Certificate cert = w.issuerCA.issue(HOST, w.serverKeys.publicKey, SSLUtil::dateYearsFromToday(1));
        if (!w.validator.validate(cert, HOST, w.today).signatureValid) rejected++;
    }
    tally.record(rejected == 0,
                 "All 1,000 genuine certificates verify (leading-zero hash check)",
                 rejected ? std::to_string(rejected) + " genuine signatures were rejected" : "");
}

void runTiming(World& w, Tally& tally) {
    const int ROUNDS = 10;
    double totals[2] = {0.0, 0.0};
    bool allOk = true;
    for (int m = 0; m < 2 && allOk; m++) {
        KeyExchangeMethod method = m ? KeyExchangeMethod::DHE : KeyExchangeMethod::RSA;
        for (int i = 0; i < ROUNDS; i++) {
            SimulatedServer server(HOST, w.serverKeys, w.goodCert, method);
            SimulatedClient client(HOST, w.validator);
            HandshakeResult r = runHandshake(client, server, w.today, false);
            if (!r.success) { allOk = false; break; }
            totals[m] += r.seconds;
        }
    }
    if (!allOk) {
        tally.record(false, "RSA vs DHE timing comparison", "skipped -- honest handshakes are failing");
        return;
    }
    std::cout << std::fixed << std::setprecision(4)
              << "\n  Average full-handshake time over " << ROUNDS << " runs each:\n"
              << "    RSA key exchange (1024-bit RSA)              : " << totals[0] / ROUNDS << " s\n"
              << "    DHE key exchange (2048-bit group + signature): " << totals[1] / ROUNDS << " s\n"
              << "  DHE costs extra modular exponentiations per handshake -- the price of\n"
              << "  forward secrecy (fresh secrets each session).\n";
    std::cout.unsetf(std::ios::fixed);
    tally.record(true, "RSA vs DHE timing comparison");
}

} // namespace

namespace SSLScenarios {

void runHonestHandshake(bool useDHE) {
    std::cout << "\nSetting up issuerCA, the server's keys, and its certificate...\n";
    World w;
    runHonest(w, useDHE, true, nullptr);
}

void runAttackScenarios(bool verbose) {
    std::cout << "\nSetting up issuerCA, EvilCA, the server, and an attacker...\n";
    World w;
    Tally tally;
    runAttacks(w, verbose, tally);
    std::cout << "\nAttack scenarios: " << tally.pass << " passed, " << tally.fail << " failed.\n";
}

void runFullSuite() {
    std::cout << "\nSetting up issuerCA, EvilCA, the server, and an attacker...\n";
    World w;
    Tally tally;
    std::cout << "\n--- Honest handshakes ---\n";
    runHonest(w, false, false, &tally);
    runHonest(w, true, false, &tally);
    std::cout << "\n--- Attacks ---\n";
    runAttacks(w, false, tally);
    std::cout << "\n--- Signature reliability ---\n";
    runReliability(w, tally);
    std::cout << "\n--- Performance ---\n";
    runTiming(w, tally);
    std::cout << "\nFull suite: " << tally.pass << " passed, " << tally.fail << " failed.\n";
}

} // namespace SSLScenarios
