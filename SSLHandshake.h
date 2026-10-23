#pragma once
#include <functional>
#include <string>
#include <vector>
#include "Certificate.h"
#include "CertificateValidator.h"
#include "RSAKeys.h"

/*
 * SSL Handshake Simulation
 * ------------------------
 * ***  (SSLHandshake.cpp) -- Week 6 deliverable. ***
 *
 * Two simulated parties exchange message structs in-process -- no sockets,
 * per the assignment -- while runHandshake() logs every step:
 *
 *   1. ClientHello        client -> server   version, offered cipher suites, client random
 *   2. ServerHello        server -> client   chosen suite, server random, certificate
 *                                            (+ signed DH parameters, for DHE)
 *   3. Certificate check  client             CertificateValidator (+ DH param signature)
 *   4. Key exchange       client -> server   RSA: pre-master secret encrypted to the
 *                                                 server's certificate key
 *                                            DHE: client's DH public value
 *   5. Session key setup  both               deriveSessionKey(preMaster, clientRandom,
 *                                            serverRandom) -- computed independently
 *                                            on each side, never transmitted
 *   6. Finished           both directions    each side proves it holds the same key
 *
 * RSA vs DHE, in one sentence each:
 *   RSA: the client invents the pre-master secret and sends it encrypted
 *        with the server's long-term key -- steal that key later, and every
 *        recorded session can be decrypted.
 *   DHE: each side contributes a fresh, throwaway secret and the pre-master
 *        is computed, never sent -- stealing the long-term key later
 *        reveals nothing about past sessions (forward secrecy). TLS 1.3
 *        removed RSA key exchange for this reason.
 *
 * Simplifications versus real TLS:
 * ServerHello here also carries the certificate and DH parameters,
 * which real TLS sends as separate Certificate / ServerKeyExchange
 * messages; session keys come from one SHA-256 instead of TLS's
 * key-derivation function; and the Finished message proves key
 * agreement but doesn't cover a hash of the whole handshake transcript
 * (which real TLS does, to detect tampering with earlier messages).
 */

enum class KeyExchangeMethod { RSA, DHE };

// Cipher suite names, in the real TLS naming style. A client offers a
// list; the server picks one.
extern const char* const SUITE_RSA; // "TLS_RSA_WITH_AES_256_CBC_SHA256"
extern const char* const SUITE_DHE; // "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256"

struct ClientHello {
    std::string version;                   // e.g. "TLS 1.2 (simulated)"
    std::vector<std::string> cipherSuites; // offered, in preference order
    std::string clientRandom;              // 32 random bytes
};

struct ServerHello {
    std::string version;
    std::string chosenCipherSuite;         // must be one the client offered
    std::string serverRandom;              // 32 random bytes
    Certificate certificate;

    // DHE only (left empty for RSA). The server signs these with its
    // CERTIFICATE's private key -- without that signature, a
    // man-in-the-middle could replace dhServerPublic with their own
    // value. Sign clientRandom + serverRandom + the parameters, so an
    // attacker can't replay a signature captured from an older handshake.
    std::string dhPrime;                   // decimal
    std::string dhGenerator;               // decimal
    std::string dhServerPublic;            // decimal: g^b mod p
    std::string dhParamsSignature;         // DigitalSignature over the above
};

struct ClientKeyExchange {
    std::string encryptedPreMaster;        // RSA: pre-master, encrypted to the cert's public key
    std::string dhClientPublic;            // DHE: decimal g^a mod p
};

struct Finished {
    std::string encryptedVerifyData;       // AES(sessionKey, a known label)
};

// Both sides call this with the same three inputs, so
// they arrive at the same 32-byte AES-256 key without ever sending it.
// Simplest sound version: SSLUtil::sha256(preMaster + clientRandom + serverRandom).
// Mixing in BOTH randoms means a replayed old key exchange produces a
// different key, even if the pre-master repeats.
std::string deriveSessionKey(const std::string& preMasterSecret,
                             const std::string& clientRandom,
                             const std::string& serverRandom);

class SimulatedServer {
private:
    std::string hostname;
    RSAKeyPair keys;          // the long-term keypair the certificate vouches for
    Certificate certificate;
    KeyExchangeMethod method; // which suite this server is configured to choose

    // Per-handshake state:
    std::string clientRandom, serverRandom;
    std::string dhPrivate;    // DHE: b (raw bytes)
    std::string sessionKey;
    std::string error;

public:
    // Provided. `cert` doesn't have to be honest -- attack scenarios hand
    // impostor servers expired, forged, or wrong-site certificates.
    SimulatedServer(const std::string& hostname, const RSAKeyPair& keys,
                    const Certificate& cert, KeyExchangeMethod method);

    // Store clientRandom; pick the suite matching `method`
    // from the client's offers (fail if it isn't offered); generate
    // serverRandom; attach the certificate. For DHE also: pick a random
    // private b, compute B = g^b mod p (SSLUtil::dhGroup14*), fill the dh*
    // fields, and sign them with this server's private key.
    bool handleClientHello(const ClientHello& in, ServerHello& out);

    // Recover the pre-master secret -- RSA: decrypt with
    // this server's private key (restore its full length with
    // SSLUtil::leftPad!); DHE: A^b mod p -- then deriveSessionKey().
    bool handleKeyExchange(const ClientKeyExchange& in);

    // Finished messages. Each side encrypts a fixed label
    // (e.g. "server finished") with AESCipher under its session key; the
    // other side decrypts and checks the label. If the keys differ, AES
    // decryption fails or the label won't match.
    bool createFinished(Finished& out);
    bool verifyFinished(const Finished& in);

    const std::string& getSessionKey() const { return sessionKey; }
    const std::string& lastError() const { return error; }
    KeyExchangeMethod getMethod() const { return method; }
};

class SimulatedClient {
private:
    std::string expectedHostname;          // who the client MEANT to reach
    const CertificateValidator& validator;

    // Per-handshake state:
    std::string clientRandom, serverRandom;
    std::string chosenSuite;
    std::string serverPublicKey;           // from the certificate, once verified
    std::string dhPrime, dhGenerator, dhServerPublic; // DHE, from ServerHello
    std::string sessionKey;
    std::string error;

public:
    // Provided.
    SimulatedClient(const std::string& expectedHostname, const CertificateValidator& validator);

    // Version, BOTH suites (SUITE_DHE first, as the
    // stronger preference), a fresh 32-byte clientRandom.
    bool createClientHello(ClientHello& out);

    // Reject a chosen suite the client never offered;
    // store serverRandom, suite, and certificate public key; run
    // validator.validate(). For DHE, ALSO verify dhParamsSignature with the
    // certificate's public key and set result.dhParamsAuthentic (and add a
    // log line). Return the result -- runHandshake checks valid().
    ValidationResult verifyServer(const ServerHello& in, const std::string& today);

    // RSA: random 48-byte pre-master, encrypted with the
    // server's public key via RSACipher. DHE: random private a,
    // A = g^a mod p sent, pre-master = B^a mod p (SSLUtil::toBytes).
    // Either way, finish with deriveSessionKey().
    bool createKeyExchange(ClientKeyExchange& out);

    bool createFinished(Finished& out);    // see server
    bool verifyFinished(const Finished& in);

    const std::string& getSessionKey() const { return sessionKey; }
    const std::string& lastError() const { return error; }
};

// ---------------- Orchestration (provided) ----------------

struct HandshakeResult {
    bool success = false;
    std::string failedStage;     // "" on success, else e.g. "CertificateVerification"
    std::string reason;
    ValidationResult validation; // the client's certificate-check report
    double seconds = 0.0;        // total handshake time
};

// Lets a scenario play "attacker on the wire": called on the ServerHello
// between the server sending it and the client receiving it -- the same
// interception-point idea as MessageChannel::send from Week 1.
typedef std::function<void(ServerHello&)> ServerHelloTamper;

// Runs every stage in order, logging each message when `verbose`.
// Stops at the first stage that fails and reports which one.
HandshakeResult runHandshake(SimulatedClient& client, SimulatedServer& server,
                             const std::string& today, bool verbose,
                             const ServerHelloTamper& tamper = ServerHelloTamper());
