#include "SSLHandshake.h"
#include "SSLUtil.h"
#include "HexUtil.h"
#include "DigitalSignature.h"
#include "RSACipher.h"
#include "AESCipher.h"
#include <cryptopp/integer.h>
#include <cryptopp/nbtheory.h>
#include <algorithm>
#include <chrono>
#include <iostream>
#include <stdexcept>

const char* const SUITE_RSA = "TLS_RSA_WITH_AES_256_CBC_SHA256";
const char* const SUITE_DHE = "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256";

using CryptoPP::Integer;

// =====================================================================
// Handshake logic (Week 6). The RSA and AES work goes through the
// project's own RSACipher and AESCipher; signatures through
// DigitalSignature.
// =====================================================================

namespace {
    const char* const PROTOCOL_VERSION = "TLS 1.2 (simulated)";
    const size_t RANDOM_LENGTH = 32;      // client and server randoms
    const size_t PREMASTER_LENGTH = 48;   // RSA pre-master secret, as in TLS
    const size_t DH_PRIVATE_LENGTH = 32;  // 256-bit DH exponents (see newDHPrivate)

    // Each direction has its own label, so a side's own Finished can't be
    // bounced back to it as though the peer had sent it.
    const char* const CLIENT_FINISHED_LABEL = "client finished";
    const char* const SERVER_FINISHED_LABEL = "server finished";

    // What SimulatedClient offers, in preference order: DHE (forward
    // secrecy) first, then RSA.
    std::vector<std::string> offeredSuites() {
        return {SUITE_DHE, SUITE_RSA};
    }

    // True for a non-empty run of decimal digits. CryptoPP::Integer's
    // string constructor accepts malformed text without complaint (see
    // DigitalSignature.cpp), so values off the wire are checked first.
    bool isDecimal(const std::string& text) {
        return !text.empty() && text.find_first_not_of("0123456789") == std::string::npos;
    }

    // Overwrites a secret before discarding it, so it doesn't linger in memory.
    void wipe(std::string& secret) {
        std::fill(secret.begin(), secret.end(), '\0');
        secret.clear();
    }

    // "<byte count>:<bytes>," -- the same unambiguous encoding that
    // Certificate::toBeSigned() uses.
    std::string lengthPrefixed(const std::string& value) {
        return std::to_string(value.size()) + ":" + value + ",";
    }

    // The bytes the server signs for DHE, and the client rebuilds to check.
    // Both randoms are included, so a signature recorded from an earlier
    // handshake won't verify in this one.
    std::string dhSignedContent(const std::string& clientRandom, const std::string& serverRandom,
                                const std::string& prime, const std::string& generator,
                                const std::string& serverPublic) {
        return lengthPrefixed(clientRandom) + lengthPrefixed(serverRandom) +
               lengthPrefixed(prime) + lengthPrefixed(generator) + lengthPrefixed(serverPublic);
    }

    // A fresh, single-use DH exponent. 256 random bits is the usual size
    // for a 2048-bit group: no weaker than the group itself, and about 8x
    // faster to exponentiate than a full 2048-bit exponent. (Re-drawn in
    // the 1-in-2^255 case that it comes out as 0 or 1.)
    std::string newDHPrivate() {
        std::string x;
        do {
            x = SSLUtil::randomBytes(DH_PRIVATE_LENGTH);
        } while (SSLUtil::fromBytes(x) <= Integer::One());
        return x;
    }

    // Parses a DH public value and requires 1 < Y < p-1. The values left
    // out (0, 1 and p-1) would pin the shared secret to 0 or +/-1 -- a
    // "secret" anyone could guess.
    bool parseDHPublic(const std::string& text, const Integer& p, Integer& value) {
        if (!isDecimal(text)) return false;
        value = Integer(text.c_str());
        return value > Integer::One() && value < p - Integer::One();
    }

    // Finished, either direction: encrypt a fixed label under the session key...
    bool buildFinished(const std::string& sessionKey, const char* label, Finished& out,
                       std::string& error) {
        if (sessionKey.empty()) {
            error = "no session key yet -- cannot build Finished";
            return false;
        }
        try {
            out.encryptedVerifyData = AESCipher().encrypt(label, sessionKey);
            return true;
        } catch (const std::exception& ex) {
            error = std::string("could not encrypt Finished: ") + ex.what();
            return false;
        }
    }

    // ...and the receiving side decrypts it under ITS key and expects that
    // exact label. A different key almost always fails AES's padding check
    // (an exception); if the padding happens to pass, the label won't match.
    bool checkFinished(const std::string& sessionKey, const char* expectedLabel, const Finished& in,
                       std::string& error) {
        if (!sessionKey.empty()) {
            try {
                if (AESCipher().decrypt(in.encryptedVerifyData, sessionKey) == expectedLabel) return true;
            } catch (const std::exception&) {
                // wrong key -- reported below
            }
        }
        error = std::string("Finished did not decrypt to \"") + expectedLabel +
                "\" -- the two sides do not share a session key";
        return false;
    }
}

std::string deriveSessionKey(const std::string& preMasterSecret,
                             const std::string& clientRandom,
                             const std::string& serverRandom) {
    // SHA-256's 32-byte output is exactly an AES-256 key.
    return SSLUtil::sha256(preMasterSecret + clientRandom + serverRandom);
}

// ---------------- Server ----------------

bool SimulatedServer::handleClientHello(const ClientHello& in, ServerHello& out) {
    out = ServerHello();
    wipe(dhPrivate);
    wipe(sessionKey);
    error.clear();

    // Use the suite this server is configured for -- but only if it was offered.
    const char* suite = (method == KeyExchangeMethod::DHE) ? SUITE_DHE : SUITE_RSA;
    if (std::find(in.cipherSuites.begin(), in.cipherSuites.end(), suite) == in.cipherSuites.end()) {
        error = std::string("client did not offer ") + suite + ", the only suite this server accepts";
        return false;
    }

    clientRandom = in.clientRandom;
    serverRandom = SSLUtil::randomBytes(RANDOM_LENGTH);

    out.version = PROTOCOL_VERSION;
    out.chosenCipherSuite = suite;
    out.serverRandom = serverRandom;
    out.certificate = certificate;

    if (method == KeyExchangeMethod::DHE) {
        // A secret b for this handshake only; publish B = g^b mod p.
        Integer p = SSLUtil::dhGroup14Prime();
        Integer g = SSLUtil::dhGroup14Generator();
        dhPrivate = newDHPrivate();
        out.dhPrime = SSLUtil::toDecimal(p);
        out.dhGenerator = SSLUtil::toDecimal(g);
        out.dhServerPublic = SSLUtil::toDecimal(a_exp_b_mod_c(g, SSLUtil::fromBytes(dhPrivate), p));

        // Signed with the private key behind the certificate, so the client
        // can tell B came from the certificate's owner and not a MITM.
        try {
            out.dhParamsSignature = DigitalSignature::sign(
                dhSignedContent(clientRandom, serverRandom, out.dhPrime, out.dhGenerator, out.dhServerPublic),
                keys.privateKey);
        } catch (const std::exception& ex) {
            error = std::string("could not sign the DH parameters: ") + ex.what();
            return false;
        }
    }
    return true;
}

bool SimulatedServer::handleKeyExchange(const ClientKeyExchange& in) {
    std::string preMaster;

    if (method == KeyExchangeMethod::RSA) {
        if (in.encryptedPreMaster.empty()) {
            error = "expected an RSA-encrypted pre-master secret";
            return false;
        }
        // Only this server's private key opens what the client encrypted
        // to the certificate's public key.
        try {
            preMaster = RSACipher().decrypt(in.encryptedPreMaster, keys.privateKey);
        } catch (const std::exception&) {
            preMaster.clear();
        }
        // RSA's math drops leading 0x00 bytes; leftPad restores all 48. If
        // the result can't be a 48-byte pre-master, real TLS (RFC 5246,
        // 7.4.7.1) continues with a random one instead of reporting it --
        // a distinct error would help an attacker test forged ciphertexts
        // (Bleichenbacher's attack). The mismatch then fails at Finished.
        if (preMaster.empty() || !SSLUtil::leftPad(preMaster, PREMASTER_LENGTH)) {
            preMaster = SSLUtil::randomBytes(PREMASTER_LENGTH);
        }
    } else {
        // DHE: the shared secret is A^b mod p, equal to the client's B^a mod p.
        Integer p = SSLUtil::dhGroup14Prime();
        Integer A;
        if (dhPrivate.empty() || !parseDHPublic(in.dhClientPublic, p, A)) {
            error = "expected the client's DH public value A, with 1 < A < p-1";
            return false;
        }
        preMaster = SSLUtil::toBytes(a_exp_b_mod_c(A, SSLUtil::fromBytes(dhPrivate), p));
        // Discarding b is what makes DHE forward-secret: a later break-in
        // finds nothing that can recompute this session's key.
        wipe(dhPrivate);
    }

    sessionKey = deriveSessionKey(preMaster, clientRandom, serverRandom);
    wipe(preMaster);
    return true;
}

bool SimulatedServer::createFinished(Finished& out) {
    return buildFinished(sessionKey, SERVER_FINISHED_LABEL, out, error);
}

bool SimulatedServer::verifyFinished(const Finished& in) {
    return checkFinished(sessionKey, CLIENT_FINISHED_LABEL, in, error);
}

// ---------------- Client ----------------

bool SimulatedClient::createClientHello(ClientHello& out) {
    // A new handshake starts from a clean slate.
    serverRandom.clear();
    chosenSuite.clear();
    serverPublicKey.clear();
    dhPrime.clear();
    dhGenerator.clear();
    dhServerPublic.clear();
    wipe(sessionKey);
    error.clear();

    clientRandom = SSLUtil::randomBytes(RANDOM_LENGTH);
    out.version = PROTOCOL_VERSION;
    out.cipherSuites = offeredSuites();
    out.clientRandom = clientRandom;
    return true;
}

ValidationResult SimulatedClient::verifyServer(const ServerHello& in, const std::string& today) {
    serverPublicKey.clear();

    std::vector<std::string> offered = offeredSuites();
    if (std::find(offered.begin(), offered.end(), in.chosenCipherSuite) == offered.end()) {
        // Rejected outright; the certificate flags stay false ("not verified").
        error = "server chose cipher suite '" + in.chosenCipherSuite + "', which this client never offered";
        ValidationResult rejected;
        rejected.log.push_back("[FAIL] Server chose cipher suite '" + in.chosenCipherSuite +
                               "', which this client never offered");
        return rejected;
    }
    serverRandom = in.serverRandom;
    chosenSuite = in.chosenCipherSuite;

    ValidationResult result = validator.validate(in.certificate, expectedHostname, today);

    if (chosenSuite == SUITE_DHE) {
        // The certificate vouches for the server's key; this signature
        // extends that to B. It is checked against OUR clientRandom, so it
        // can't be a signature replayed from another handshake.
        bool signedOk = DigitalSignature::verify(
            dhSignedContent(clientRandom, serverRandom, in.dhPrime, in.dhGenerator, in.dhServerPublic),
            in.dhParamsSignature, in.certificate.publicKey);
        result.log.push_back(signedOk
            ? "[PASS] DH parameters are signed by the certificate's key"
            : "[FAIL] DH parameters' signature does not verify -- altered in transit, or replayed");

        // Signed values must also be safe to use: the known group only,
        // and 1 < B < p-1.
        Integer p = SSLUtil::dhGroup14Prime();
        Integer B;
        bool groupOk = in.dhPrime == SSLUtil::toDecimal(p) &&
                       in.dhGenerator == SSLUtil::toDecimal(SSLUtil::dhGroup14Generator());
        bool valueOk = groupOk && parseDHPublic(in.dhServerPublic, p, B);
        if (!groupOk) {
            result.log.push_back("[FAIL] DH group is not RFC 3526 Group 14, the only group this client accepts");
        } else if (!valueOk) {
            result.log.push_back("[FAIL] DH public value B is out of range (must be 1 < B < p-1)");
        }
        result.dhParamsAuthentic = signedOk && valueOk;
    }

    // Keep the server's key material only once everything has checked out.
    if (result.valid()) {
        serverPublicKey = in.certificate.publicKey;
        dhPrime = in.dhPrime;
        dhGenerator = in.dhGenerator;
        dhServerPublic = in.dhServerPublic;
    }
    return result;
}

bool SimulatedClient::createKeyExchange(ClientKeyExchange& out) {
    out = ClientKeyExchange();
    if (serverPublicKey.empty()) {
        error = "the server has not been authenticated -- refusing to send key material";
        return false;
    }

    std::string preMaster;
    try {
        if (chosenSuite == SUITE_RSA) {
            // RSA: the client invents the pre-master and encrypts it to the
            // certificate's key, so only the certificate's owner can read it.
            preMaster = SSLUtil::randomBytes(PREMASTER_LENGTH);
            out.encryptedPreMaster = RSACipher().encrypt(preMaster, serverPublicKey);
        } else {
            // DHE: a fresh secret a; send A = g^a mod p and keep B^a mod p.
            // toBytes drops leading zero bytes on both sides alike (so does
            // real TLS 1.2), so client and server still get identical bytes.
            Integer p(dhPrime.c_str());
            Integer g(dhGenerator.c_str());
            Integer B(dhServerPublic.c_str());
            std::string a = newDHPrivate();
            Integer aValue = SSLUtil::fromBytes(a);
            wipe(a);
            out.dhClientPublic = SSLUtil::toDecimal(a_exp_b_mod_c(g, aValue, p));
            preMaster = SSLUtil::toBytes(a_exp_b_mod_c(B, aValue, p));
        }
    } catch (const std::exception& ex) {
        error = std::string("could not build the key exchange: ") + ex.what();
        return false;
    }

    sessionKey = deriveSessionKey(preMaster, clientRandom, serverRandom);
    wipe(preMaster);
    return true;
}

bool SimulatedClient::createFinished(Finished& out) {
    return buildFinished(sessionKey, CLIENT_FINISHED_LABEL, out, error);
}

bool SimulatedClient::verifyFinished(const Finished& in) {
    return checkFinished(sessionKey, SERVER_FINISHED_LABEL, in, error);
}

// =====================================================================
// PROVIDED -- constructors, logging, and the stage-by-stage orchestrator.
// =====================================================================

SimulatedServer::SimulatedServer(const std::string& hostname, const RSAKeyPair& keys,
                                 const Certificate& cert, KeyExchangeMethod method)
    : hostname(hostname), keys(keys), certificate(cert), method(method) {}

SimulatedClient::SimulatedClient(const std::string& expectedHostname,
                                 const CertificateValidator& validator)
    : expectedHostname(expectedHostname), validator(validator) {}

namespace {
    // First `n` hex digits of a binary value, so logs stay readable.
    std::string preview(const std::string& bytes, size_t n = 16) {
        if (bytes.empty()) return "(empty)";
        std::string hex = HexUtil::toHex(bytes);
        return hex.size() > n ? hex.substr(0, n) + "..." : hex;
    }
    std::string previewText(const std::string& text, size_t n = 24) {
        if (text.empty()) return "(empty)";
        return text.size() > n ? text.substr(0, n) + "..." : text;
    }

    HandshakeResult fail(HandshakeResult r, const std::string& stage, const std::string& reason,
                         bool verbose) {
        r.success = false;
        r.failedStage = stage;
        r.reason = reason;
        if (verbose) {
            std::cout << "\n  !! HANDSHAKE ABORTED at " << stage << ": " << reason << "\n"
                      << "     No session key was established; no application data is sent.\n";
        }
        return r;
    }
}

HandshakeResult runHandshake(SimulatedClient& client, SimulatedServer& server,
                             const std::string& today, bool verbose,
                             const ServerHelloTamper& tamper) {
    HandshakeResult result;
    std::chrono::steady_clock::time_point start = std::chrono::steady_clock::now();
    const char* methodName = server.getMethod() == KeyExchangeMethod::DHE ? "DHE" : "RSA";

    if (verbose) std::cout << "\n=== SSL Handshake Simulation (server configured for " << methodName << ") ===\n";

    // 1. ClientHello
    ClientHello clientHello;
    if (!client.createClientHello(clientHello)) {
        return fail(result, "ClientHello", client.lastError(), verbose);
    }
    if (verbose) {
        std::cout << "\n[1] Client -> Server: ClientHello\n"
                  << "    Version       : " << clientHello.version << "\n"
                  << "    Cipher suites : ";
        for (size_t i = 0; i < clientHello.cipherSuites.size(); i++) {
            std::cout << (i ? ", " : "") << clientHello.cipherSuites[i];
        }
        std::cout << "\n    Client random : " << preview(clientHello.clientRandom) << "\n";
    }

    // 2. ServerHello
    ServerHello serverHello;
    if (!server.handleClientHello(clientHello, serverHello)) {
        return fail(result, "ServerHello", server.lastError(), verbose);
    }
    if (tamper) {
        tamper(serverHello);
        if (verbose) std::cout << "\n    *** ATTACKER modified the ServerHello in transit ***\n";
    }
    if (verbose) {
        std::cout << "\n[2] Server -> Client: ServerHello\n"
                  << "    Version       : " << serverHello.version << "\n"
                  << "    Chosen suite  : " << serverHello.chosenCipherSuite << "\n"
                  << "    Server random : " << preview(serverHello.serverRandom) << "\n"
                  << "    Certificate   :\n" << serverHello.certificate.describe();
        if (!serverHello.dhServerPublic.empty()) {
            std::cout << "    DH group      : RFC 3526 Group 14 (2048-bit), g = " << serverHello.dhGenerator << "\n"
                      << "    DH public (B) : " << previewText(serverHello.dhServerPublic) << "\n"
                      << "    DH signature  : " << previewText(serverHello.dhParamsSignature) << "\n";
        }
    }

    // 3. Certificate verification (client side)
    result.validation = client.verifyServer(serverHello, today);
    if (verbose) {
        std::cout << "\n[3] Client: Certificate Verification\n";
        for (const std::string& line : result.validation.log) std::cout << "    " << line << "\n";
    }
    if (!result.validation.valid()) {
        return fail(result, "CertificateVerification", "server could not be authenticated", verbose);
    }

    // 4. Key exchange
    ClientKeyExchange keyExchange;
    if (!client.createKeyExchange(keyExchange)) {
        return fail(result, "KeyExchange", client.lastError(), verbose);
    }
    if (verbose) {
        std::cout << "\n[4] Client -> Server: ClientKeyExchange\n";
        if (!keyExchange.encryptedPreMaster.empty())
            std::cout << "    Encrypted pre-master : " << previewText(keyExchange.encryptedPreMaster) << "\n";
        if (!keyExchange.dhClientPublic.empty())
            std::cout << "    DH public (A)        : " << previewText(keyExchange.dhClientPublic) << "\n";
    }
    if (!server.handleKeyExchange(keyExchange)) {
        return fail(result, "KeyExchange", server.lastError(), verbose);
    }

    // 5. Session key setup -- each side derived its key independently.
    // Only a short fingerprint is printed (never the key itself), to show
    // whether the two sides agree.
    if (client.getSessionKey().empty() || server.getSessionKey().empty()) {
        return fail(result, "SessionKeySetup", "a session key was not derived", verbose);
    }
    if (verbose) {
        std::cout << "\n[5] Session Key Setup (computed independently on each side, never sent)\n"
                  << "    Client key fingerprint : " << preview(SSLUtil::sha256(client.getSessionKey()), 12) << "\n"
                  << "    Server key fingerprint : " << preview(SSLUtil::sha256(server.getSessionKey()), 12) << "\n";
    }

    // 6. Finished, both directions
    Finished clientFinished, serverFinished;
    if (!client.createFinished(clientFinished)) return fail(result, "Finished", client.lastError(), verbose);
    if (!server.verifyFinished(clientFinished)) return fail(result, "Finished", server.lastError(), verbose);
    if (!server.createFinished(serverFinished)) return fail(result, "Finished", server.lastError(), verbose);
    if (!client.verifyFinished(serverFinished)) return fail(result, "Finished", client.lastError(), verbose);
    if (verbose) {
        std::cout << "\n[6] Finished messages exchanged and verified both ways\n";
    }

    std::chrono::duration<double> elapsed = std::chrono::steady_clock::now() - start;
    result.seconds = elapsed.count();
    result.success = true;

    // Demonstration: the established channel carries application data,
    // encrypted with the shared session key (symmetric crypto from here on).
    if (verbose) {
        std::cout << "\n[Secure channel established in " << result.seconds << " s]\n";
        try {
            AESCipher aes;
            std::string appData = "Hello from the client over the secure channel!";
            std::string onTheWire = aes.encrypt(appData, client.getSessionKey());
            std::string received = aes.decrypt(onTheWire, server.getSessionKey());
            std::cout << "    Client sends (AES, on the wire): " << preview(onTheWire, 32) << "\n"
                      << "    Server decrypts               : " << received << "\n";
        } catch (const std::exception& ex) {
            // Finished should have caught mismatched keys -- if this fires,
            // the Finished checks aren't actually comparing anything.
            std::cout << "    Application data FAILED to decrypt (" << ex.what() << ")\n"
                      << "    -> the two session keys differ, but Finished didn't catch it.\n";
        }
    }
    return result;
}
